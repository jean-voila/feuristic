// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Corpus runner and benchmark for lib/fqr.
 *
 *   fqr_vectors <manifest.txt> [--bench] [--verbose] [--polarity-both]
 *
 * Reads the manifest written by gen_vectors.py, decodes every PBM image and
 * checks status, number of distinct codes, payloads and metadata. With
 * --bench it prints per-image timings and operation counters, plus totals
 * used for the Cortex-M4 estimates in docs/developer/lib-fqr.md.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fqr.h"
#include "tcheck.h"

TC_DEFINE_GLOBALS;

#define MAX_CODES_EXPECTED 8
#define MAX_GROUPS 8
#define MAX_FRAGS 16

typedef struct {
  int version;
  char ecc;
  int mask; /* -1 = any */
  int inverted;
  uint8_t *payload; /* NULL = any */
  size_t payload_len;
  long eci;                          /* -1 = none expected */
  int sa_index, sa_total, sa_parity; /* -1 = none */
  char group[32];
} exp_code_t;

typedef struct {
  char name[32];
  uint8_t *frag[MAX_FRAGS];
  size_t frag_len[MAX_FRAGS];
} group_t;

static uint8_t ws[FQR_WORKSPACE_SIZE];
static uint8_t pay[FQR_MAX_CODES][FQR_MAX_PAYLOAD_SIZE];
static group_t groups[MAX_GROUPS];
static unsigned n_groups;
static int verbose, bench;

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static uint8_t *load_pbm(const char *path, uint32_t *w, uint32_t *h,
                         size_t *stride) {
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    return NULL;
  }
  char magic[3] = {0};
  long vals[2];
  int nv = 0;
  if (fread(magic, 1, 2, f) != 2 || strcmp(magic, "P4") != 0) {
    fclose(f);
    return NULL;
  }
  while (nv < 2) {
    int c = fgetc(f);
    if (c == EOF) {
      fclose(f);
      return NULL;
    }
    if (c == '#') {
      while (c != '\n' && c != EOF) c = fgetc(f);
      continue;
    }
    if (isspace(c)) continue;
    long v = 0;
    while (c != EOF && isdigit(c)) {
      v = v * 10 + (c - '0');
      if (v > 100000) break;
      c = fgetc(f);
    }
    vals[nv++] = v;
  }
  if (vals[0] < 1 || vals[1] < 1 || vals[0] > 1024 || vals[1] > 1024) {
    fclose(f);
    return NULL;
  }
  *w = (uint32_t)vals[0];
  *h = (uint32_t)vals[1];
  *stride = (*w + 7u) / 8u;
  uint8_t *d = malloc(*stride * *h);
  if (d == NULL || fread(d, 1, *stride * *h, f) != *stride * *h) {
    free(d);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return d;
}

static uint8_t *parse_hex(const char *s, size_t *len) {
  size_t n = strlen(s) / 2;
  uint8_t *p = malloc(n + 1);
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    sscanf(s + 2 * i, "%2x", &v);
    p[i] = (uint8_t)v;
  }
  *len = n;
  return p;
}

static group_t *get_group(const char *name) {
  for (unsigned i = 0; i < n_groups; i++) {
    if (strcmp(groups[i].name, name) == 0) return &groups[i];
  }
  if (n_groups >= MAX_GROUPS) return NULL;
  group_t *g = &groups[n_groups++];
  memset(g, 0, sizeof *g);
  snprintf(g->name, sizeof g->name, "%s", name);
  return g;
}

static bool match(const exp_code_t *e, const fqr_result_t *r) {
  if (r->status != FQR_OK) return false;
  if (e->version && r->version != e->version) return false;
  if (e->ecc != '-' && "LMQH"[r->ecc_level] != e->ecc) return false;
  if (e->mask >= 0 && r->mask != e->mask) return false;
  if ((r->inverted ? 1 : 0) != e->inverted) return false;
  if (e->payload && (r->payload_len != e->payload_len ||
                     memcmp(r->payload, e->payload, e->payload_len) != 0))
    return false;
  if (e->eci >= 0 &&
      (r->eci_count < 1 || r->eci[0].designator != (uint32_t)e->eci))
    return false;
  if (e->sa_index >= 0) {
    if (!r->structured_append.present ||
        r->structured_append.index != e->sa_index ||
        r->structured_append.total != e->sa_total ||
        r->structured_append.parity != e->sa_parity)
      return false;
  }
  return true;
}

typedef struct {
  double ms_total, ms_max;
  uint64_t pixels, xpix, modules, attempts;
  unsigned images;
  char worst[256];
} benchsum_t;

static benchsum_t bsum;

static void run_image(const char *dir, const char *file, const char *status,
                      int count, const char *pol, exp_code_t *codes,
                      int ncodes) {
  char path[1024];
  snprintf(path, sizeof path, "%s/%s", dir, file);
  uint32_t w, h;
  size_t stride;
  uint8_t *d = load_pbm(path, &w, &h, &stride);
  CHECK_MSG(d != NULL, "cannot load %s", path);
  if (d == NULL) return;
  fqr_image_t img = {d, w, h, stride};
  fqr_result_t res[FQR_MAX_CODES];
  memset(res, 0, sizeof res);
  for (int i = 0; i < (int)FQR_MAX_CODES; i++) {
    res[i].payload = pay[i];
    res[i].payload_cap = sizeof pay[i];
  }
  fqr_options_t opt;
  fqr_stats_t st;
  memset(&opt, 0, sizeof opt);
  opt.stats = &st;
  opt.max_codes = FQR_MAX_CODES;
  opt.polarity = strcmp(pol, "both") == 0       ? FQR_POLARITY_BOTH
                 : strcmp(pol, "normal") == 0   ? FQR_POLARITY_NORMAL
                 : strcmp(pol, "inverted") == 0 ? FQR_POLARITY_INVERTED
                                                : FQR_POLARITY_AUTO;
  size_t n = 0;
  double t0 = now_ms();
  fqr_status_t s =
      fqr_decode(&img, ws, sizeof ws, &opt, res, FQR_MAX_CODES, &n);
  double dt = now_ms() - t0;

  bool ok = true;
  if (strcmp(status, "ok") == 0 || strcmp(status, "multiple") == 0) {
    ok = s == FQR_OK && (int)n == count;
    bool used[FQR_MAX_CODES] = {false};
    for (int i = 0; i < ncodes && ok; i++) {
      bool found = false;
      for (size_t k = 0; k < n && k < FQR_MAX_CODES && !found; k++) {
        if (!used[k] && match(&codes[i], &res[k])) {
          used[k] = true;
          found = true;
          if (codes[i].group[0]) {
            group_t *g = get_group(codes[i].group);
            int idx = res[k].structured_append.index;
            if (g && idx < MAX_FRAGS && g->frag[idx] == NULL) {
              g->frag[idx] = malloc(res[k].payload_len + 1);
              memcpy(g->frag[idx], res[k].payload, res[k].payload_len);
              g->frag_len[idx] = res[k].payload_len;
            }
          }
        }
      }
      ok = found;
    }
    if (ok && strcmp(status, "multiple") == 0) {
      fqr_result_t one;
      memset(&one, 0, sizeof one);
      one.payload = pay[0];
      one.payload_cap = sizeof pay[0];
      fqr_options_t o2 = opt;
      o2.stats = NULL;
      ok = fqr_decode_single(&img, ws, sizeof ws, &o2, &one) ==
           FQR_ERR_MULTIPLE_CODES;
    }
  } else {
    ok = n == 0 && s != FQR_OK;
    if (strcmp(status, "notfound") == 0) {
      /* "no code" images may still trip over look-alike triples. */
      ok = ok && (s == FQR_ERR_NOT_FOUND || s == FQR_ERR_FORMAT ||
                  s == FQR_ERR_ECC || s == FQR_ERR_DATA);
    }
  }
  CHECK_MSG(ok,
            "%s: expected %s/%d, got %s n=%zu (cands=%u triples=%u attempts=%u "
            "fmt=%u ecc=%u data=%u)",
            file, status, count, fqr_status_str(s), n, st.finder_candidates,
            st.triples_considered, st.decode_attempts, st.fail_format,
            st.fail_ecc, st.fail_data);
  if (verbose || bench) {
    printf("%-34s %4ux%-4u %8.2f ms  %-8s n=%zu px=%u xpx=%u mod=%u att=%u%s\n",
           file, w, h, dt, ok ? "ok" : "FAIL", n, st.pixels_scanned,
           st.crosscheck_pixels, st.modules_sampled, st.decode_attempts,
           st.budget_exhausted ? " BUDGET" : "");
  }
  bsum.images++;
  bsum.ms_total += dt;
  if (dt > bsum.ms_max) {
    bsum.ms_max = dt;
    snprintf(bsum.worst, sizeof bsum.worst, "%s (%ux%u)", file, w, h);
  }
  bsum.pixels += st.pixels_scanned;
  bsum.xpix += st.crosscheck_pixels;
  bsum.modules += st.modules_sampled;
  bsum.attempts += st.decode_attempts;
  free(d);
}

int main(int argc, char **argv) {
  const char *manifest = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--bench") == 0)
      bench = 1;
    else if (strcmp(argv[i], "--verbose") == 0)
      verbose = 1;
    else
      manifest = argv[i];
  }
  if (manifest == NULL) {
    fprintf(stderr, "usage: %s manifest.txt [--bench] [--verbose]\n", argv[0]);
    return 2;
  }
  FILE *f = fopen(manifest, "r");
  if (f == NULL) {
    fprintf(stderr, "cannot open %s\n", manifest);
    return 2;
  }
  char dir[1024];
  snprintf(dir, sizeof dir, "%s", manifest);
  char *slash = strrchr(dir, '/');
  if (slash)
    *slash = '\0';
  else
    snprintf(dir, sizeof dir, ".");

  char line[65536];
  char file[256] = "", status[32] = "", pol[32] = "";
  int count = 0, ncodes = 0, have_image = 0;
  static exp_code_t codes[MAX_CODES_EXPECTED];
  while (fgets(line, sizeof line, f) != NULL) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '#' || line[0] == '\0') continue;
    if (strncmp(line, "image ", 6) == 0 || strncmp(line, "group ", 6) == 0) {
      if (have_image) {
        run_image(dir, file, status, count, pol, codes, ncodes);
        for (int i = 0; i < ncodes; i++) free(codes[i].payload);
        have_image = 0;
      }
    }
    if (strncmp(line, "image ", 6) == 0) {
      if (sscanf(line + 6, "%255s %31s %d %31s", file, status, &count, pol) !=
          4) {
        CHECK_MSG(0, "bad manifest line: %s", line);
        continue;
      }
      ncodes = 0;
      have_image = 1;
    } else if (strncmp(line, "code ", 5) == 0 && ncodes < MAX_CODES_EXPECTED) {
      exp_code_t *e = &codes[ncodes++];
      memset(e, 0, sizeof *e);
      e->eci = -1;
      e->sa_index = e->sa_total = e->sa_parity = -1;
      char ecc[8], mask[8], hex[60000];
      char *rest = line + 5;
      int consumed = 0;
      if (sscanf(rest, "%d %7s %7s %d %59999s%n", &e->version, ecc, mask,
                 &e->inverted, hex, &consumed) != 5) {
        CHECK_MSG(0, "bad code line: %.80s", line);
        ncodes--;
        continue;
      }
      e->ecc = ecc[0];
      e->mask = mask[0] == '-' ? -1 : atoi(mask);
      e->payload = hex[0] == '-' ? NULL : parse_hex(hex, &e->payload_len);
      char *tok = strtok(rest + consumed, " ");
      while (tok != NULL) {
        if (strncmp(tok, "eci=", 4) == 0)
          e->eci = atol(tok + 4);
        else if (strncmp(tok, "sa=", 3) == 0)
          sscanf(tok + 3, "%d/%d/%d", &e->sa_index, &e->sa_total,
                 &e->sa_parity);
        else if (strncmp(tok, "group=", 6) == 0)
          snprintf(e->group, sizeof e->group, "%s", tok + 6);
        tok = strtok(NULL, " ");
      }
    } else if (strncmp(line, "group ", 6) == 0) {
      char name[32], hex[60000];
      if (sscanf(line + 6, "%31s %59999s", name, hex) == 2) {
        size_t len;
        uint8_t *want = parse_hex(hex, &len);
        group_t *g = get_group(name);
        uint8_t *cat = malloc(len + FQR_MAX_PAYLOAD_SIZE);
        size_t cl = 0;
        bool complete = g != NULL;
        for (int i = 0; g && i < MAX_FRAGS && g->frag[i]; i++) {
          if (cl + g->frag_len[i] <= len + FQR_MAX_PAYLOAD_SIZE) {
            memcpy(cat + cl, g->frag[i], g->frag_len[i]);
            cl += g->frag_len[i];
          }
        }
        CHECK_MSG(complete && cl == len && memcmp(cat, want, len) == 0,
                  "structured-append group %s does not reassemble", name);
        free(cat);
        free(want);
      }
    }
  }
  if (have_image) {
    run_image(dir, file, status, count, pol, codes, ncodes);
    for (int i = 0; i < ncodes; i++) free(codes[i].payload);
  }
  fclose(f);
  for (unsigned i = 0; i < n_groups; i++)
    for (int k = 0; k < MAX_FRAGS; k++) free(groups[i].frag[k]);
  if (bsum.images) {
    printf("%u images: total %.1f ms, mean %.2f ms, max %.2f ms [%s]\n",
           bsum.images, bsum.ms_total, bsum.ms_total / bsum.images, bsum.ms_max,
           bsum.worst);
    printf(
        "counters: %llu px scanned, %llu cross-check px, %llu modules sampled, "
        "%llu attempts\n",
        (unsigned long long)bsum.pixels, (unsigned long long)bsum.xpix,
        (unsigned long long)bsum.modules, (unsigned long long)bsum.attempts);
  }
  return tc_report("fqr_vectors");
}
