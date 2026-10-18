// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// MicroPython module `feuristic_native`: RSA primitives for feuristic,
// backed by lib/frsa (BearSSL i31). Python-facing contract:
// src/feuristic/platform/crypto.py and mocks/feuristic_native.pyi.
//
// Memory discipline: every output object is allocated *before* any secret is
// computed, and secrets are computed directly into the output buffer, so an
// allocation failure (which longjmps out of the function) can never leave a
// secret behind on the C stack. Stack temporaries holding secrets are wiped
// by frsa itself; the blinding factor is wiped here.

#include <string.h>

#include "py/obj.h"
#include "py/objint.h"
#include "py/objstr.h"
#include "py/runtime.h"

#include <sys/rng.h>

#include "frsa.h"

/// package: feuristic_native

static void fn_wipe(void *buf, size_t len) {
  volatile uint8_t *v = (volatile uint8_t *)buf;
  while (len-- > 0) {
    *v++ = 0;
  }
}

static uint32_t fn_get_u32(mp_obj_t obj) {
  if (!mp_obj_is_int(obj)) {
    mp_raise_TypeError(MP_ERROR_TEXT("int expected"));
  }
  mp_uint_t v = mp_obj_int_get_uint_checked(obj);
  if (v > 0xFFFFFFFFu) {
    mp_raise_ValueError(MP_ERROR_TEXT("value out of range"));
  }
  return (uint32_t)v;
}

static void fn_get_buf(mp_obj_t obj, mp_buffer_info_t *buf, size_t max) {
  mp_get_buffer_raise(obj, buf, MP_BUFFER_READ);
  if (buf->len > max) {
    mp_raise_ValueError(MP_ERROR_TEXT("integer too large"));
  }
}

/// def rsa_complete(
///     p: AnyBytes, q: AnyBytes, e: int
/// ) -> tuple[bytes, bytes, bytes, bytes]:
///     """
///     Compute (n, dp, dq, qinv) from the RSA primes p, q (big-endian, at
///     most 128 bytes each) and the odd public exponent e (3 <= e < 2^32).
///     n is minimally encoded; dp, dq and qinv are (len(n) + 1) // 2 bytes.
///     Raises ValueError on invalid or inconsistent input.
///     """
static mp_obj_t mod_feuristic_native_rsa_complete(mp_obj_t p_obj,
                                                  mp_obj_t q_obj,
                                                  mp_obj_t e_obj) {
  mp_buffer_info_t p = {0}, q = {0};
  fn_get_buf(p_obj, &p, 4 * FRSA_MAX_FACTOR_BYTES);
  fn_get_buf(q_obj, &q, 4 * FRSA_MAX_FACTOR_BYTES);
  uint32_t e = fn_get_u32(e_obj);

  vstr_t n = {0}, dp = {0}, dq = {0}, qinv = {0};
  vstr_init_len(&n, FRSA_MAX_MODULUS_BYTES);
  vstr_init_len(&dp, FRSA_MAX_FACTOR_BYTES);
  vstr_init_len(&dq, FRSA_MAX_FACTOR_BYTES);
  vstr_init_len(&qinv, FRSA_MAX_FACTOR_BYTES);
  mp_obj_tuple_t *tuple = MP_OBJ_TO_PTR(mp_obj_new_tuple(4, NULL));

  size_t nlen = 0, clen = 0;
  int r = frsa_complete((const uint8_t *)p.buf, p.len, (const uint8_t *)q.buf,
                        q.len, e, (uint8_t *)n.buf, &nlen, (uint8_t *)dp.buf,
                        (uint8_t *)dq.buf, (uint8_t *)qinv.buf, &clen);
  if (r != FRSA_OK) {
    // frsa already zeroed the outputs on error
    vstr_clear(&n);
    vstr_clear(&dp);
    vstr_clear(&dq);
    vstr_clear(&qinv);
    mp_raise_ValueError(MP_ERROR_TEXT("invalid RSA key"));
  }
  // Shrinking a vstr never allocates.
  n.len = nlen;
  dp.len = clen;
  dq.len = clen;
  qinv.len = clen;
  tuple->items[0] = mp_obj_new_bytes_from_vstr(&n);
  tuple->items[1] = mp_obj_new_bytes_from_vstr(&dp);
  tuple->items[2] = mp_obj_new_bytes_from_vstr(&dq);
  tuple->items[3] = mp_obj_new_bytes_from_vstr(&qinv);
  return MP_OBJ_FROM_PTR(tuple);
}
static MP_DEFINE_CONST_FUN_OBJ_3(mod_feuristic_native_rsa_complete_obj,
                                 mod_feuristic_native_rsa_complete);

/// def rsa_private(
///     p: AnyBytes,
///     q: AnyBytes,
///     dp: AnyBytes,
///     dq: AnyBytes,
///     qinv: AnyBytes,
///     e: int,
///     n: AnyBytes,
///     block: AnyBytes,
/// ) -> bytes | None:
///     """
///     Raw RSA private operation block^d mod n (CRT, constant time,
///     randomly blinded). `block` must be len(n) bytes and < n; n must be
///     minimally encoded. Before the result is released it is verified with
///     the public key (result^e mod n == block) and n == p * q is checked;
///     returns None if any check fails (fault detected, inconsistent key or
///     invalid input). Takes ~0.37 s for RSA-2048 on a Cortex-M4 @ 168 MHz:
///     the caller must send keep-alives / CCID time extensions beforehand.
///     """
static mp_obj_t mod_feuristic_native_rsa_private(size_t n_args,
                                                 const mp_obj_t *args) {
  mp_buffer_info_t p = {0}, q = {0}, dp = {0}, dq = {0}, qinv = {0}, n = {0},
                   block = {0};
  (void)n_args;
  fn_get_buf(args[0], &p, 4 * FRSA_MAX_FACTOR_BYTES);
  fn_get_buf(args[1], &q, 4 * FRSA_MAX_FACTOR_BYTES);
  fn_get_buf(args[2], &dp, 4 * FRSA_MAX_FACTOR_BYTES);
  fn_get_buf(args[3], &dq, 4 * FRSA_MAX_FACTOR_BYTES);
  fn_get_buf(args[4], &qinv, 4 * FRSA_MAX_FACTOR_BYTES);
  uint32_t e = fn_get_u32(args[5]);
  fn_get_buf(args[6], &n, FRSA_MAX_MODULUS_BYTES);
  fn_get_buf(args[7], &block, FRSA_MAX_MODULUS_BYTES);
  if (n.len == 0 || block.len != n.len) {
    return mp_const_none;
  }

  vstr_t out = {0};
  vstr_init_len(&out, n.len);

  frsa_key key = {
      .p = (const uint8_t *)p.buf,
      .plen = p.len,
      .q = (const uint8_t *)q.buf,
      .qlen = q.len,
      .dp = (const uint8_t *)dp.buf,
      .dplen = dp.len,
      .dq = (const uint8_t *)dq.buf,
      .dqlen = dq.len,
      .qinv = (const uint8_t *)qinv.buf,
      .qinvlen = qinv.len,
      .n = (const uint8_t *)n.buf,
      .nlen = n.len,
      .e = e,
  };
  uint8_t blind[FRSA_MAX_MODULUS_BYTES];
  rng_fill_buffer(blind, n.len);
  int r = frsa_private(&key, (const uint8_t *)block.buf, block.len, blind,
                       n.len, (uint8_t *)out.buf);
  fn_wipe(blind, sizeof blind);
  if (r != FRSA_OK) {
    fn_wipe(out.buf, out.len);
    vstr_clear(&out);
    return mp_const_none;
  }
  return mp_obj_new_bytes_from_vstr(&out);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_feuristic_native_rsa_private_obj, 8, 8,
    mod_feuristic_native_rsa_private);

/// def rsa_public(n: AnyBytes, e: int, block: AnyBytes) -> bytes:
///     """
///     Raw RSA public operation block^e mod n. `n` must be odd, minimally
///     encoded and 512..2048 bits; `block` must be len(n) bytes and < n.
///     Raises ValueError otherwise.
///     """
static mp_obj_t mod_feuristic_native_rsa_public(mp_obj_t n_obj, mp_obj_t e_obj,
                                                mp_obj_t block_obj) {
  mp_buffer_info_t n = {0}, block = {0};
  fn_get_buf(n_obj, &n, FRSA_MAX_MODULUS_BYTES);
  uint32_t e = fn_get_u32(e_obj);
  fn_get_buf(block_obj, &block, FRSA_MAX_MODULUS_BYTES);
  if (n.len == 0 || block.len != n.len) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid RSA input"));
  }
  vstr_t out = {0};
  vstr_init_len(&out, n.len);
  if (frsa_public((const uint8_t *)n.buf, n.len, e,
                  (const uint8_t *)block.buf, block.len,
                  (uint8_t *)out.buf) != FRSA_OK) {
    vstr_clear(&out);
    mp_raise_ValueError(MP_ERROR_TEXT("invalid RSA input"));
  }
  return mp_obj_new_bytes_from_vstr(&out);
}
static MP_DEFINE_CONST_FUN_OBJ_3(mod_feuristic_native_rsa_public_obj,
                                 mod_feuristic_native_rsa_public);

/// def modpow(base: AnyBytes, exp: AnyBytes, mod: AnyBytes) -> bytes:
///     """
///     base^exp mod mod for an odd modulus 3 <= mod < 2^2048 (all values
///     big-endian, at most 256 bytes). The result has len(mod) bytes.
///     Constant time in the values of base, exp and mod. One 1024-bit
///     modpow with a 1024-bit exponent takes ~160 ms on a Cortex-M4.
///     """
static mp_obj_t mod_feuristic_native_modpow(mp_obj_t base_obj, mp_obj_t exp_obj,
                                            mp_obj_t mod_obj) {
  mp_buffer_info_t base = {0}, exp = {0}, mod = {0};
  fn_get_buf(base_obj, &base, FRSA_MAX_MODULUS_BYTES);
  fn_get_buf(exp_obj, &exp, FRSA_MAX_MODULUS_BYTES);
  fn_get_buf(mod_obj, &mod, FRSA_MAX_MODULUS_BYTES);
  if (mod.len == 0) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid modulus"));
  }
  vstr_t out = {0};
  vstr_init_len(&out, mod.len);
  if (frsa_modpow((const uint8_t *)base.buf, base.len,
                  (const uint8_t *)exp.buf, exp.len, (const uint8_t *)mod.buf,
                  mod.len, (uint8_t *)out.buf) != FRSA_OK) {
    fn_wipe(out.buf, out.len);
    vstr_clear(&out);
    mp_raise_ValueError(MP_ERROR_TEXT("invalid modulus"));
  }
  return mp_obj_new_bytes_from_vstr(&out);
}
static MP_DEFINE_CONST_FUN_OBJ_3(mod_feuristic_native_modpow_obj,
                                 mod_feuristic_native_modpow);

/// def rsa_sieve(candidate: AnyBytes) -> bool:
///     """
///     Constant-time trial division of an odd prime candidate (at most 256
///     bytes) by the first 2048 odd primes (3 .. 17881). Returns False if one
///     of them divides it (and for even candidates or candidates < 3).
///     """
static mp_obj_t mod_feuristic_native_rsa_sieve(mp_obj_t cand_obj) {
  mp_buffer_info_t cand = {0};
  fn_get_buf(cand_obj, &cand, FRSA_MAX_MODULUS_BYTES);
  int r = frsa_sieve((const uint8_t *)cand.buf, cand.len);
  if (r < 0) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid candidate"));
  }
  return mp_obj_new_bool(r == 1);
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_feuristic_native_rsa_sieve_obj,
                                 mod_feuristic_native_rsa_sieve);

/// def rsa_mr_round(candidate: AnyBytes, base: AnyBytes) -> bool:
///     """
///     One Miller-Rabin round (FIPS 186-5 B.3.1) on the odd candidate w
///     (5 <= w < 2^2048) with base b, 1 < b < w - 1. Returns True if w is a
///     probable prime for this base. Raises ValueError on invalid input.
///     """
static mp_obj_t mod_feuristic_native_rsa_mr_round(mp_obj_t cand_obj,
                                                  mp_obj_t base_obj) {
  mp_buffer_info_t cand = {0}, base = {0};
  fn_get_buf(cand_obj, &cand, FRSA_MAX_MODULUS_BYTES);
  fn_get_buf(base_obj, &base, FRSA_MAX_MODULUS_BYTES);
  int r = frsa_mr_round((const uint8_t *)cand.buf, cand.len,
                        (const uint8_t *)base.buf, base.len);
  if (r < 0) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid Miller-Rabin input"));
  }
  return mp_obj_new_bool(r == 1);
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_feuristic_native_rsa_mr_round_obj,
                                 mod_feuristic_native_rsa_mr_round);

static const mp_rom_map_elem_t mp_module_feuristic_native_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_feuristic_native)},
    {MP_ROM_QSTR(MP_QSTR_rsa_complete),
     MP_ROM_PTR(&mod_feuristic_native_rsa_complete_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_private),
     MP_ROM_PTR(&mod_feuristic_native_rsa_private_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_public),
     MP_ROM_PTR(&mod_feuristic_native_rsa_public_obj)},
    {MP_ROM_QSTR(MP_QSTR_modpow), MP_ROM_PTR(&mod_feuristic_native_modpow_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_sieve),
     MP_ROM_PTR(&mod_feuristic_native_rsa_sieve_obj)},
    {MP_ROM_QSTR(MP_QSTR_rsa_mr_round),
     MP_ROM_PTR(&mod_feuristic_native_rsa_mr_round_obj)},
};
static MP_DEFINE_CONST_DICT(mp_module_feuristic_native_globals,
                            mp_module_feuristic_native_globals_table);

const mp_obj_module_t mp_module_feuristic_native = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_feuristic_native_globals,
};

MP_REGISTER_MODULE(MP_QSTR_feuristic_native, mp_module_feuristic_native);
