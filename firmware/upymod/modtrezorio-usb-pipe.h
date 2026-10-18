// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// feuristic additions to the `trezorio` MicroPython module:
//
//  * `USBPipe`: variable-length access to a USB syshandle. Used for the
//    bulk-pipe interfaces (CCID, MSC — framed, see io/usb_bulk.h) and for
//    the CDC-ACM stream of the time-sync mode. Upstream `USBIF` only accepts
//    exactly 64-byte packets.
//  * `usb_set_mode()` / `usb_get_mode()`: exclusive USB modes
//    (io/usb_modes.h).
//
// Included from modtrezorio.c.

#include <io/usb_bulk.h>
#include <io/usb_modes.h>

/// package: trezorio.__init__

/// class USBPipe:
///     """
///     Variable-length USB interface (bulk pipe frames or CDC stream).
///     """
typedef struct _mp_obj_USBPipe_t {
  mp_obj_base_t base;
  mp_int_t handle;
} mp_obj_USBPipe_t;

/// def __init__(self, handle: int) -> None:
///     """
///     """
static mp_obj_t mod_trezorio_USBPipe_make_new(const mp_obj_type_t *type,
                                              size_t n_args, size_t n_kw,
                                              const mp_obj_t *args) {
  mp_arg_check_num(n_args, n_kw, 1, 1, false);
  mp_int_t handle = mp_obj_get_int(args[0]);
  if (handle != SYSHANDLE_USB_CCID && handle != SYSHANDLE_USB_MSC &&
      handle != SYSHANDLE_USB_VCP) {
    mp_raise_ValueError(MP_ERROR_TEXT("unsupported pipe handle"));
  }
  mp_obj_USBPipe_t *o = mp_obj_malloc(mp_obj_USBPipe_t, type);
  o->handle = handle;
  return MP_OBJ_FROM_PTR(o);
}

/// def iface_num(self) -> int:
///     """
///     Returns the syshandle number (use with `io.poll`).
///     """
static mp_obj_t mod_trezorio_USBPipe_iface_num(mp_obj_t self) {
  mp_obj_USBPipe_t *o = MP_OBJ_TO_PTR(self);
  return MP_OBJ_NEW_SMALL_INT(o->handle);
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorio_USBPipe_iface_num_obj,
                                 mod_trezorio_USBPipe_iface_num);

/// def read(self, buf: bytearray) -> int:
///     """
///     Reads whatever is available into `buf` (>= 65 bytes for bulk pipes).
///     Returns the number of bytes read (0 if nothing was available).
///     """
static mp_obj_t mod_trezorio_USBPipe_read(mp_obj_t self, mp_obj_t buf_obj) {
  mp_obj_USBPipe_t *o = MP_OBJ_TO_PTR(self);
  mp_buffer_info_t buf = {0};
  mp_get_buffer_raise(buf_obj, &buf, MP_BUFFER_WRITE);
  if (o->handle != SYSHANDLE_USB_VCP && buf.len < USB_BULK_FRAME_MAX) {
    mp_raise_ValueError(MP_ERROR_TEXT("Buffer too small"));
  }
  ssize_t r = syshandle_read(o->handle, buf.buf, buf.len);
  if (r < 0) {
    mp_raise_msg(&mp_type_OSError, MP_ERROR_TEXT("Read failed"));
  }
  return MP_OBJ_NEW_SMALL_INT(r);
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorio_USBPipe_read_obj,
                                 mod_trezorio_USBPipe_read);

/// def write(self, data: AnyBytes) -> int:
///     """
///     Writes one frame (bulk pipes) or a chunk of the stream (CDC).
///     Returns the number of bytes accepted (0 = not ready, retry after
///     polling for write readiness).
///     """
static mp_obj_t mod_trezorio_USBPipe_write(mp_obj_t self, mp_obj_t data_obj) {
  mp_obj_USBPipe_t *o = MP_OBJ_TO_PTR(self);
  mp_buffer_info_t data = {0};
  mp_get_buffer_raise(data_obj, &data, MP_BUFFER_READ);
  if (o->handle != SYSHANDLE_USB_VCP &&
      (data.len < 1 || data.len > USB_BULK_FRAME_MAX)) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid frame length"));
  }
  ssize_t r = syshandle_write(o->handle, data.buf, data.len);
  if (r < 0) {
    mp_raise_msg(&mp_type_OSError, MP_ERROR_TEXT("Write failed"));
  }
  return MP_OBJ_NEW_SMALL_INT(r);
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorio_USBPipe_write_obj,
                                 mod_trezorio_USBPipe_write);

static const mp_rom_map_elem_t mod_trezorio_USBPipe_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_iface_num),
     MP_ROM_PTR(&mod_trezorio_USBPipe_iface_num_obj)},
    {MP_ROM_QSTR(MP_QSTR_read), MP_ROM_PTR(&mod_trezorio_USBPipe_read_obj)},
    {MP_ROM_QSTR(MP_QSTR_write), MP_ROM_PTR(&mod_trezorio_USBPipe_write_obj)},
};
static MP_DEFINE_CONST_DICT(mod_trezorio_USBPipe_locals_dict,
                            mod_trezorio_USBPipe_locals_dict_table);

// clang-format off
MP_DEFINE_CONST_OBJ_TYPE(mod_trezorio_USBPipe_type,
  MP_QSTR_USBPipe, MP_TYPE_FLAG_NONE,
  make_new, mod_trezorio_USBPipe_make_new,
  locals_dict, &mod_trezorio_USBPipe_locals_dict);
// clang-format on

/// def usb_set_mode(mode: int, serial_number: str) -> None:
///     """
///     Re-configures the USB stack in one of the exclusive modes
///     (USB_MODE_NORMAL, USB_MODE_TIMESYNC, USB_MODE_IMPORT) and starts it.
///     The caller must stop USB and wait USB_MODE_DETACH_MS before.
///     """
static mp_obj_t mod_trezorio_usb_set_mode(mp_obj_t mode_obj,
                                          mp_obj_t serial_obj) {
  mp_int_t mode = mp_obj_get_int(mode_obj);
  if (mode < 0 || mode >= USB_MODE_COUNT) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid USB mode"));
  }
  size_t len = 0;
  const char *serial = mp_obj_str_get_data(serial_obj, &len);
  if (len > USB_MAX_STR_SIZE) {
    mp_raise_ValueError(MP_ERROR_TEXT("serial_number is invalid"));
  }
  usb_start_params_t params = {0};
  memcpy(params.serial_number, serial, len);
  params.serial_number[len] = '\0';
  params.usb21_landing = secfalse;
  if (sectrue != usb_set_mode((usb_mode_t)mode, &params)) {
    mp_raise_msg(&mp_type_RuntimeError,
                 MP_ERROR_TEXT("USB mode switch failed"));
  }
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorio_usb_set_mode_obj,
                                 mod_trezorio_usb_set_mode);

/// def usb_get_mode() -> int:
///     """
///     Returns the current USB mode.
///     """
static mp_obj_t mod_trezorio_usb_get_mode(void) {
  return MP_OBJ_NEW_SMALL_INT(usb_get_mode());
}
static MP_DEFINE_CONST_FUN_OBJ_0(mod_trezorio_usb_get_mode_obj,
                                 mod_trezorio_usb_get_mode);

/// USBIF_CCID: int  # handle of the CCID bulk pipe
/// USBIF_MSC: int  # handle of the MSC bulk pipe
/// USBIF_VCP: int  # handle of the CDC-ACM stream
/// USB_MODE_NORMAL: int
/// USB_MODE_TIMESYNC: int
/// USB_MODE_IMPORT: int
/// USB_MODE_DETACH_MS: int
#define FEURISTIC_TREZORIO_ENTRIES                                             \
  {MP_ROM_QSTR(MP_QSTR_USBPipe), MP_ROM_PTR(&mod_trezorio_USBPipe_type)},      \
      {MP_ROM_QSTR(MP_QSTR_usb_set_mode),                                      \
       MP_ROM_PTR(&mod_trezorio_usb_set_mode_obj)},                            \
      {MP_ROM_QSTR(MP_QSTR_usb_get_mode),                                      \
       MP_ROM_PTR(&mod_trezorio_usb_get_mode_obj)},                            \
      {MP_ROM_QSTR(MP_QSTR_USBIF_CCID), MP_ROM_INT(SYSHANDLE_USB_CCID)},       \
      {MP_ROM_QSTR(MP_QSTR_USBIF_MSC), MP_ROM_INT(SYSHANDLE_USB_MSC)},         \
      {MP_ROM_QSTR(MP_QSTR_USBIF_VCP), MP_ROM_INT(SYSHANDLE_USB_VCP)},         \
      {MP_ROM_QSTR(MP_QSTR_USB_MODE_NORMAL), MP_ROM_INT(USB_MODE_NORMAL)},     \
      {MP_ROM_QSTR(MP_QSTR_USB_MODE_TIMESYNC), MP_ROM_INT(USB_MODE_TIMESYNC)}, \
      {MP_ROM_QSTR(MP_QSTR_USB_MODE_IMPORT), MP_ROM_INT(USB_MODE_IMPORT)},     \
      {MP_ROM_QSTR(MP_QSTR_USB_MODE_DETACH_MS),                                \
       MP_ROM_INT(USB_MODE_DETACH_MS)},
