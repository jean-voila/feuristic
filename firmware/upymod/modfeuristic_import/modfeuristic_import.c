// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// feuristic_import: MicroPython module running the temporary "QR import"
// USB mode in the unprivileged coreapp (docs/architecture.md §5,
// docs/adr/0003-streaming-image-import.md):
//
//   bulk-pipe frames <-> lib/fmsc (BOT, SCSI, FAT12, stream tracker)
//                        -> lib/fimg (streaming PNG/JPEG -> 1-bpp bitmap)
//                        -> lib/fqr  (QR detection/decoding, after completion)
//
// The Python glue (src/feuristic/fw/import_mode.py) shuttles frames between
// io.USBPipe(io.USBIF_MSC) and this module, polls it and turns events into
// UI and application actions. Interpretation of the decoded payload is done
// in Python (apps/importer).
//
// Memory: the image decoder needs ~78-95 KiB of workspace plus the output
// bitmap. Both are allocated from the MicroPython heap when the session is
// created (after the caller freed what it could) and wiped on close. On
// T2B1 the fmsc context and its caches use the otherwise unused CCM region
// (.no_dma_buffers, 30 KiB, unprivileged), keeping the heap requirement
// within the T2B1 budget.

#include <stddef.h>
#include <string.h>

#include "py/mphal.h"
#include "py/objstr.h"
#include "py/runtime.h"

#include "fimg.h"
#include "fmsc.h"
#include "fqr.h"

#define IMPORT_TXQ_LEN 4
#define IMPORT_EVQ_LEN 8
#define IMPORT_FRAME_MAX 65
#define IMPORT_PAYLOAD_MAX 3072  // QR v40 holds at most 2953 bytes
#define IMPORT_CACHE_CLUSTERS 1
#define IMPORT_REORDER_SECTORS 8

// frame opcodes / events (firmware/kernel/usb/inc/io/usb_bulk.h)
#define OP_DATA 0x00
#define OP_ZLP 0x01
#define OP_STALL_IN 0x02
#define OP_STALL_OUT 0x03
#define EV_DATA 0x00
#define EV_RESET 0x01
#define EV_HALT_CLEARED 0x02

typedef struct {
  fmsc_ctx_t fmsc;
  uint8_t cache[IMPORT_CACHE_CLUSTERS * FMSC_CLUSTER_SIZE];
  uint8_t reorder[IMPORT_REORDER_SECTORS * FMSC_SECTOR_SIZE];
} import_static_t;

#if (defined(STM32F427xx) || defined(STM32F429xx)) && !defined(TREZOR_EMULATOR)
// T2B1: CCM, not initialised at startup (fmsc_init() initialises it)
static import_static_t g_static __attribute__((section(".no_dma_buffers")));
#define IMPORT_STATIC_IN_CCM 1
#endif

typedef enum {
  EVT_NONE = 0,
  EVT_STREAM_START,
  EVT_STREAM_COMPLETE,
  EVT_STREAM_ERROR,
  EVT_EJECTED,
  EVT_STOPPED,
  EVT_HOST_RESET,
  EVT_IMAGE_ERROR,
} import_evt_type_t;

typedef struct {
  uint8_t type;
  uint8_t code;
  uint32_t stream;
  char name[FMSC_LONG_NAME_MAX + 1];
} import_evt_t;

typedef struct _mp_obj_ImportSession_t {
  mp_obj_base_t base;
  import_static_t *st;
  bool st_owned;  // allocated from the heap (not CCM)
  uint8_t *fimg_ws;
  size_t fimg_ws_len;
  uint8_t *bitmap;
  size_t bitmap_len;
  uint8_t *payload;
  fimg_config_t fcfg;
  fimg_ctx_t *fimg;
  uint32_t active;    // stream id currently decoded (0 = none)
  bool image_failed;  // fimg reported an error for the active stream
  uint8_t image_err;  // fimg_status_t
  uint32_t ready;     // stream id completed, awaiting decode() (0 = none)
  uint32_t ready_size;
  char ready_name[FMSC_LONG_NAME_MAX + 1];
  uint8_t readme[FMSC_README_MAX];
  // tx queue of frames to write to the kernel
  uint8_t txq[IMPORT_TXQ_LEN][IMPORT_FRAME_MAX];
  uint8_t txlen[IMPORT_TXQ_LEN];
  uint8_t tx_head, tx_count;
  bool in_pending;  // a data packet is queued/in flight (fmsc waits)
  import_evt_t evq[IMPORT_EVQ_LEN];
  uint8_t ev_head, ev_count;
  bool closed;
} mp_obj_ImportSession_t;

static void push_frame(mp_obj_ImportSession_t *o, const uint8_t *frame,
                       size_t len) {
  if (o->tx_count >= IMPORT_TXQ_LEN || len > IMPORT_FRAME_MAX) {
    return;  // cannot happen with fmsc's one-packet-in-flight contract
  }
  uint8_t idx = (o->tx_head + o->tx_count) % IMPORT_TXQ_LEN;
  memcpy(o->txq[idx], frame, len);
  o->txlen[idx] = (uint8_t)len;
  o->tx_count++;
}

static void push_event(mp_obj_ImportSession_t *o, uint8_t type, uint8_t code,
                       uint32_t stream, const char *name) {
  if (o->ev_count >= IMPORT_EVQ_LEN) {
    // drop the oldest: the newest state matters most to the UI
    o->ev_head = (o->ev_head + 1) % IMPORT_EVQ_LEN;
    o->ev_count--;
  }
  import_evt_t *e = &o->evq[(o->ev_head + o->ev_count) % IMPORT_EVQ_LEN];
  e->type = type;
  e->code = code;
  e->stream = stream;
  e->name[0] = '\0';
  if (name != NULL) {
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
  }
  o->ev_count++;
}

static void decoder_reset(mp_obj_ImportSession_t *o) {
  o->fimg = NULL;
  o->active = 0;
  o->image_failed = false;
  o->image_err = 0;
  fimg_secure_zero(o->bitmap, o->bitmap_len);
}

// --- fmsc callbacks ----------------------------------------------------------

static void cb_send_in(void *user, const uint8_t *data, size_t len) {
  mp_obj_ImportSession_t *o = user;
  uint8_t frame[IMPORT_FRAME_MAX];
  frame[0] = OP_DATA;
  memcpy(&frame[1], data, len);
  push_frame(o, frame, len + 1);
  o->in_pending = true;
}

static void cb_stall(void *user, fmsc_ep_t ep) {
  mp_obj_ImportSession_t *o = user;
  uint8_t frame = (ep == FMSC_EP_IN) ? OP_STALL_IN : OP_STALL_OUT;
  push_frame(o, &frame, 1);
}

static bool cb_stream_start(void *user, uint32_t id) {
  mp_obj_ImportSession_t *o = user;
  if (o->active != 0 || o->ready != 0) {
    return false;  // one image at a time; the host copies files one by one
  }
  decoder_reset(o);
  fimg_status_t s = fimg_init(&o->fimg, o->fimg_ws, o->fimg_ws_len, &o->fcfg,
                              o->bitmap, o->bitmap_len);
  if (s != FIMG_OK) {
    o->fimg = NULL;
    return false;
  }
  o->active = id;
  push_event(o, EVT_STREAM_START, 0, id, NULL);
  return true;
}

static void cb_stream_data(void *user, uint32_t id, uint32_t offset,
                           const uint8_t *data, size_t len) {
  mp_obj_ImportSession_t *o = user;
  (void)offset;
  if (id != o->active || o->fimg == NULL || o->image_failed) {
    return;
  }
  fimg_status_t s = fimg_feed(o->fimg, data, len);
  if (s != FIMG_OK) {
    o->image_failed = true;
    o->image_err = (uint8_t)s;
  }
}

static void cb_stream_complete(void *user, uint32_t id,
                               const fmsc_file_name_t *name, uint32_t size) {
  mp_obj_ImportSession_t *o = user;
  if (id != o->active) {
    return;
  }
  // Decoding of the QR code is deferred to decode(): the host is waiting for
  // the status of the current SCSI command.
  o->ready = id;
  o->ready_size = size;
  const char *n = name->long_name[0] ? name->long_name : name->short_name;
  strncpy(o->ready_name, n, sizeof(o->ready_name) - 1);
  o->ready_name[sizeof(o->ready_name) - 1] = '\0';
  push_event(o, EVT_STREAM_COMPLETE, 0, id, o->ready_name);
}

static void cb_stream_error(void *user, uint32_t id,
                            fmsc_stream_error_t reason) {
  mp_obj_ImportSession_t *o = user;
  if (id == o->active) {
    decoder_reset(o);
  }
  push_event(o, EVT_STREAM_ERROR, (uint8_t)reason, id, NULL);
}

static void cb_event(void *user, fmsc_event_t ev) {
  mp_obj_ImportSession_t *o = user;
  uint8_t t = (ev == FMSC_EVT_EJECTED)   ? EVT_EJECTED
              : (ev == FMSC_EVT_STOPPED) ? EVT_STOPPED
                                         : EVT_HOST_RESET;
  if (ev == FMSC_EVT_HOST_RESET) {
    o->tx_count = 0;
    o->in_pending = false;
  }
  push_event(o, t, 0, 0, NULL);
}

// --- Python API
// -----------------------------------------------------------------

/// package: feuristic_import

/// class Session:
///     """
///     One QR-import USB session (FAT12 volume + image decoding).
///     """
static const mp_obj_type_t mod_feuristic_import_Session_type;

/// def __init__(self, readme: bytes, max_out: int, volume_id: int) -> None:
///     """
///     Allocate the decoder (bitmap side at most `max_out` pixels) and
///     initialise the volume with the given README.TXT content.
///     """
static mp_obj_t mod_feuristic_import_Session_make_new(const mp_obj_type_t *type,
                                                      size_t n_args,
                                                      size_t n_kw,
                                                      const mp_obj_t *args) {
  mp_arg_check_num(n_args, n_kw, 3, 3, false);
  mp_buffer_info_t readme = {0};
  mp_get_buffer_raise(args[0], &readme, MP_BUFFER_READ);
  mp_int_t max_out = mp_obj_get_int(args[1]);
  mp_uint_t volume_id = mp_obj_get_int_truncated(args[2]);
  if (readme.len > FMSC_README_MAX || max_out < 128 || max_out > 1024) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid import parameters"));
  }

  mp_obj_ImportSession_t *o =
      mp_obj_malloc_with_finaliser(mp_obj_ImportSession_t, type);
  memset(&o->st, 0, sizeof(*o) - offsetof(mp_obj_ImportSession_t, st));

#ifdef IMPORT_STATIC_IN_CCM
  o->st = &g_static;
  o->st_owned = false;
#else
  o->st = m_new(import_static_t, 1);
  o->st_owned = true;
#endif

  fimg_config_default(&o->fcfg);
  o->fcfg.max_out_width = (uint16_t)max_out;
  o->fcfg.max_out_height = (uint16_t)max_out;
  o->fcfg.max_out_pixels = 0;
  o->fimg_ws_len = fimg_workspace_size(&o->fcfg);
  if (o->fimg_ws_len < FQR_WORKSPACE_SIZE) {
    o->fimg_ws_len = FQR_WORKSPACE_SIZE;  // reused by fqr after decoding
  }
  o->bitmap_len = fimg_bitmap_size(&o->fcfg);
  o->fimg_ws = m_new(uint8_t, o->fimg_ws_len);
  o->bitmap = m_new(uint8_t, o->bitmap_len);
  o->payload = m_new(uint8_t, IMPORT_PAYLOAD_MAX);
  memcpy(o->readme, readme.buf, readme.len);

  fmsc_config_t cfg = {
      .cache_mem = o->st->cache,
      .cache_clusters = IMPORT_CACHE_CLUSTERS,
      .reorder_mem = o->st->reorder,
      .reorder_sectors = IMPORT_REORDER_SECTORS,
      .readme = o->readme,
      .readme_len = readme.len,
      .volume_id = (uint32_t)volume_id,
      .serial = NULL,
      .revision = NULL,
      .quiet_ms = 2000,
      .settle_ms = 15000,
  };
  fmsc_callbacks_t cb = {
      .user = o,
      .send_in = cb_send_in,
      .stall = cb_stall,
      .stream_start = cb_stream_start,
      .stream_data = cb_stream_data,
      .stream_complete = cb_stream_complete,
      .stream_error = cb_stream_error,
      .event = cb_event,
  };
  if (fmsc_init(&o->st->fmsc, &cfg, &cb) != FMSC_OK) {
    mp_raise_ValueError(MP_ERROR_TEXT("fmsc init failed"));
  }
  return MP_OBJ_FROM_PTR(o);
}

static mp_obj_ImportSession_t *live(mp_obj_t self) {
  mp_obj_ImportSession_t *o = MP_OBJ_TO_PTR(self);
  if (o->closed) {
    mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("session closed"));
  }
  return o;
}

/// def feed(self, frame: bytes) -> None:
///     """
///     Process one frame read from the MSC bulk pipe ([event][payload]).
///     """
static mp_obj_t mod_feuristic_import_Session_feed(mp_obj_t self,
                                                  mp_obj_t frame_obj) {
  mp_obj_ImportSession_t *o = live(self);
  mp_buffer_info_t f = {0};
  mp_get_buffer_raise(frame_obj, &f, MP_BUFFER_READ);
  const uint8_t *b = f.buf;
  if (f.len < 1 || f.len > IMPORT_FRAME_MAX) {
    return mp_const_none;
  }
  switch (b[0]) {
    case EV_DATA:
      fmsc_on_out_packet(&o->st->fmsc, &b[1], f.len - 1);
      break;
    case EV_RESET:
      o->tx_count = 0;
      o->in_pending = false;
      fmsc_bot_reset(&o->st->fmsc);
      break;
    case EV_HALT_CLEARED:
      if (f.len >= 2) {
        fmsc_on_clear_halt(&o->st->fmsc,
                           (b[1] & 0x80) ? FMSC_EP_IN : FMSC_EP_OUT);
      }
      break;
    default:
      break;
  }
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_feuristic_import_Session_feed_obj,
                                 mod_feuristic_import_Session_feed);

/// def tx(self) -> bytes | None:
///     """
///     Next frame to write to the MSC bulk pipe, or None.
///     """
static mp_obj_t mod_feuristic_import_Session_tx(mp_obj_t self) {
  mp_obj_ImportSession_t *o = live(self);
  if (o->tx_count == 0) {
    return mp_const_none;
  }
  return mp_obj_new_bytes(o->txq[o->tx_head], o->txlen[o->tx_head]);
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_import_Session_tx_obj,
                                 mod_feuristic_import_Session_tx);

/// def tx_done(self) -> None:
///     """
///     The frame returned by tx() was accepted by the kernel.
///     """
static mp_obj_t mod_feuristic_import_Session_tx_done(mp_obj_t self) {
  mp_obj_ImportSession_t *o = live(self);
  if (o->tx_count == 0) {
    return mp_const_none;
  }
  bool was_data = o->txq[o->tx_head][0] == OP_DATA;
  o->tx_head = (o->tx_head + 1) % IMPORT_TXQ_LEN;
  o->tx_count--;
  if (was_data && o->in_pending) {
    // The kernel accepts a packet only once the previous one was sent, so
    // fmsc may prepare the next one (one packet in flight).
    o->in_pending = false;
    fmsc_on_in_ready(&o->st->fmsc);
  }
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_import_Session_tx_done_obj,
                                 mod_feuristic_import_Session_tx_done);

/// def poll(self, now_ms: int) -> None:
///     """
///     Timers (quiet/settle periods). Call at least every 100 ms.
///     """
static mp_obj_t mod_feuristic_import_Session_poll(mp_obj_t self,
                                                  mp_obj_t now_obj) {
  mp_obj_ImportSession_t *o = live(self);
  fmsc_poll(&o->st->fmsc, (uint32_t)mp_obj_get_int_truncated(now_obj));
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_feuristic_import_Session_poll_obj,
                                 mod_feuristic_import_Session_poll);

/// def event(self) -> tuple | None:
///     """
///     Next event: (kind: str, stream: int, code: int, name: str) or None.
///     Kinds: "start", "complete", "stream_error", "ejected", "stopped",
///     "reset".
///     """
static mp_obj_t mod_feuristic_import_Session_event(mp_obj_t self) {
  mp_obj_ImportSession_t *o = live(self);
  if (o->ev_count == 0) {
    return mp_const_none;
  }
  import_evt_t *e = &o->evq[o->ev_head];
  o->ev_head = (o->ev_head + 1) % IMPORT_EVQ_LEN;
  o->ev_count--;
  qstr kind;
  switch (e->type) {
    case EVT_STREAM_START:
      kind = MP_QSTR_start;
      break;
    case EVT_STREAM_COMPLETE:
      kind = MP_QSTR_complete;
      break;
    case EVT_STREAM_ERROR:
      kind = MP_QSTR_stream_error;
      break;
    case EVT_EJECTED:
      kind = MP_QSTR_ejected;
      break;
    case EVT_STOPPED:
      kind = MP_QSTR_stopped;
      break;
    default:
      kind = MP_QSTR_reset;
      break;
  }
  mp_obj_t items[4] = {
      MP_OBJ_NEW_QSTR(kind),
      mp_obj_new_int_from_uint(e->stream),
      MP_OBJ_NEW_SMALL_INT(e->code),
      mp_obj_new_str(e->name, strlen(e->name)),
  };
  return mp_obj_new_tuple(4, items);
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_import_Session_event_obj,
                                 mod_feuristic_import_Session_event);

/// def decode(self) -> tuple | None:
///     """
///     If a completed image awaits, finish decoding it and look for exactly
///     one QR code. Returns None when nothing is pending, otherwise
///     ("qr", payload: bytes, name: str) or ("error", category: str,
///     detail: str, name: str). Categories: "image" (fimg status name in
///     detail), "no_qr", "multiple_qr", "qr_damaged", "truncated".
///     """
static mp_obj_t mod_feuristic_import_Session_decode(mp_obj_t self) {
  mp_obj_ImportSession_t *o = live(self);
  if (o->ready == 0) {
    return mp_const_none;
  }
  mp_obj_t name = mp_obj_new_str(o->ready_name, strlen(o->ready_name));
  mp_obj_t result = mp_const_none;
  fimg_info_t info = {0};
  const char *cat = NULL;
  const char *detail = "";

  if (o->image_failed) {
    cat = "image";
    detail = fimg_status_name((fimg_status_t)o->image_err);
  } else {
    fimg_status_t s = fimg_finish(o->fimg, &info);
    if (s != FIMG_OK) {
      cat = "image";
      detail = fimg_status_name(s);
    } else if (!info.complete || info.bytes_consumed > o->ready_size) {
      cat = "truncated";
    }
  }

  if (cat == NULL) {
    fqr_image_t img = {
        .data = o->bitmap,
        .width = info.out_width,
        .height = info.out_height,
        .stride = info.stride,
    };
    fqr_result_t res;
    memset(&res, 0, sizeof(res));
    res.payload = o->payload;
    res.payload_cap = IMPORT_PAYLOAD_MAX;
    // the fimg workspace is free once the bitmap is complete
    fqr_status_t q =
        fqr_decode_single(&img, o->fimg_ws, o->fimg_ws_len, NULL, &res);
    if (q == FQR_OK && res.status == FQR_OK) {
      mp_obj_t items[3] = {MP_OBJ_NEW_QSTR(MP_QSTR_qr),
                           mp_obj_new_bytes(o->payload, res.payload_len), name};
      result = mp_obj_new_tuple(3, items);
    } else if (q == FQR_ERR_MULTIPLE_CODES) {
      cat = "multiple_qr";
    } else if (q == FQR_ERR_NOT_FOUND) {
      cat = "no_qr";
    } else {
      cat = "qr_damaged";
    }
    fimg_secure_zero(o->payload, IMPORT_PAYLOAD_MAX);
  }

  if (cat != NULL) {
    mp_obj_t items[4] = {MP_OBJ_NEW_QSTR(MP_QSTR_error),
                         mp_obj_new_str(cat, strlen(cat)),
                         mp_obj_new_str(detail, strlen(detail)), name};
    result = mp_obj_new_tuple(4, items);
  }

  o->ready = 0;
  o->ready_size = 0;
  o->ready_name[0] = '\0';
  decoder_reset(o);
  fimg_secure_zero(o->fimg_ws, o->fimg_ws_len);
  return result;
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_import_Session_decode_obj,
                                 mod_feuristic_import_Session_decode);

/// def ejected(self) -> bool:
///     """
///     True once the host ejected the medium.
///     """
static mp_obj_t mod_feuristic_import_Session_ejected(mp_obj_t self) {
  mp_obj_ImportSession_t *o = live(self);
  return mp_obj_new_bool(fmsc_is_ejected(&o->st->fmsc));
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_import_Session_ejected_obj,
                                 mod_feuristic_import_Session_ejected);

/// def close(self) -> None:
///     """
///     Wipe every buffer (spec §3.3: temporary storage purged).
///     """
static mp_obj_t mod_feuristic_import_Session_close(mp_obj_t self) {
  mp_obj_ImportSession_t *o = MP_OBJ_TO_PTR(self);
  if (o->closed) {
    return mp_const_none;
  }
  o->closed = true;
  fmsc_wipe(&o->st->fmsc);
  fimg_secure_zero(o->st, sizeof(*o->st));
  if (o->fimg_ws) fimg_secure_zero(o->fimg_ws, o->fimg_ws_len);
  if (o->bitmap) fimg_secure_zero(o->bitmap, o->bitmap_len);
  if (o->payload) fimg_secure_zero(o->payload, IMPORT_PAYLOAD_MAX);
  fimg_secure_zero(o->txq, sizeof(o->txq));
  fimg_secure_zero(o->readme, sizeof(o->readme));
  if (o->st_owned) {
    m_del(import_static_t, o->st, 1);
  }
  m_del(uint8_t, o->fimg_ws, o->fimg_ws_len);
  m_del(uint8_t, o->bitmap, o->bitmap_len);
  m_del(uint8_t, o->payload, IMPORT_PAYLOAD_MAX);
  o->st = NULL;
  o->fimg_ws = o->bitmap = o->payload = NULL;
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_import_Session_close_obj,
                                 mod_feuristic_import_Session_close);

static const mp_rom_map_elem_t
    mod_feuristic_import_Session_locals_dict_table[] = {
        {MP_ROM_QSTR(MP_QSTR_feed),
         MP_ROM_PTR(&mod_feuristic_import_Session_feed_obj)},
        {MP_ROM_QSTR(MP_QSTR_tx),
         MP_ROM_PTR(&mod_feuristic_import_Session_tx_obj)},
        {MP_ROM_QSTR(MP_QSTR_tx_done),
         MP_ROM_PTR(&mod_feuristic_import_Session_tx_done_obj)},
        {MP_ROM_QSTR(MP_QSTR_poll),
         MP_ROM_PTR(&mod_feuristic_import_Session_poll_obj)},
        {MP_ROM_QSTR(MP_QSTR_event),
         MP_ROM_PTR(&mod_feuristic_import_Session_event_obj)},
        {MP_ROM_QSTR(MP_QSTR_decode),
         MP_ROM_PTR(&mod_feuristic_import_Session_decode_obj)},
        {MP_ROM_QSTR(MP_QSTR_ejected),
         MP_ROM_PTR(&mod_feuristic_import_Session_ejected_obj)},
        {MP_ROM_QSTR(MP_QSTR_close),
         MP_ROM_PTR(&mod_feuristic_import_Session_close_obj)},
        {MP_ROM_QSTR(MP_QSTR___del__),
         MP_ROM_PTR(&mod_feuristic_import_Session_close_obj)},
};
static MP_DEFINE_CONST_DICT(mod_feuristic_import_Session_locals_dict,
                            mod_feuristic_import_Session_locals_dict_table);

// clang-format off
static MP_DEFINE_CONST_OBJ_TYPE(mod_feuristic_import_Session_type,
  MP_QSTR_Session, MP_TYPE_FLAG_NONE,
  make_new, mod_feuristic_import_Session_make_new,
  locals_dict, &mod_feuristic_import_Session_locals_dict);
// clang-format on

/// MAX_FILE_SIZE: int  # largest accepted image file
static const mp_rom_map_elem_t mp_module_feuristic_import_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_feuristic_import)},
    {MP_ROM_QSTR(MP_QSTR_Session),
     MP_ROM_PTR(&mod_feuristic_import_Session_type)},
    {MP_ROM_QSTR(MP_QSTR_MAX_FILE_SIZE), MP_ROM_INT(FMSC_MAX_FILE_SIZE)},
};
static MP_DEFINE_CONST_DICT(mp_module_feuristic_import_globals,
                            mp_module_feuristic_import_globals_table);

const mp_obj_module_t mp_module_feuristic_import = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_feuristic_import_globals,
};

MP_REGISTER_MODULE(MP_QSTR_feuristic_import, mp_module_feuristic_import);
