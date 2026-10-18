// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Generic "bulk pipe" USB class used by feuristic for CCID (smart-card
// reader) and MSC (Bulk-Only mass storage) interfaces.
//
// Design rule (docs/architecture.md §5.3): the privileged kernel class only
// moves bounded packets between the USB endpoints and the unprivileged
// coreapp. All protocol logic (CCID messages, BOT/SCSI, FAT12) runs in the
// coreapp. Endpoint control (ZLP, STALL) and class events (BOT reset, CCID
// ABORT, halt cleared) are multiplexed on the same syshandle with a one-byte
// frame header.
//
// coreapp -> kernel (syshandle_write):
//   - [USB_BULK_OP_DATA][1..64 bytes]   one bulk IN packet
//   - [USB_BULK_OP_ZLP]                 a zero-length bulk IN packet
//   - [USB_BULK_OP_STALL_IN]            stall the bulk IN endpoint
//   - [USB_BULK_OP_STALL_OUT]           stall the bulk OUT endpoint
//   - [USB_BULK_OP_INTR][1..8 bytes]    one interrupt IN packet
//
// kernel -> coreapp (syshandle_read):
//   - [USB_BULK_EV_DATA][0..64 bytes]   one bulk OUT packet
//   - [USB_BULK_EV_RESET][lo, hi]       class reset (BOT reset, CCID ABORT)
//   - [USB_BULK_EV_HALT_CLEARED][ep]    the host cleared an endpoint halt
//
// The emulator (io/usb/unix/usb.c) carries the very same frames in UDP
// datagrams, so host-side test tools exercise the exact same coreapp code.

#pragma once

#include <trezor_types.h>

#include <sys/sysevent.h>

#define USB_BULK_PACKET_LEN 64
#define USB_BULK_INTR_LEN 8
#define USB_BULK_FRAME_MAX (1 + USB_BULK_PACKET_LEN)

// coreapp -> kernel opcodes
#define USB_BULK_OP_DATA 0x00
#define USB_BULK_OP_ZLP 0x01
#define USB_BULK_OP_STALL_IN 0x02
#define USB_BULK_OP_STALL_OUT 0x03
#define USB_BULK_OP_INTR 0x04

// kernel -> coreapp events
#define USB_BULK_EV_DATA 0x00
#define USB_BULK_EV_RESET 0x01
#define USB_BULK_EV_HALT_CLEARED 0x02

typedef enum {
  USB_BULK_FLAVOR_CCID = 0,  // USB CCID rev 1.1 (class 0x0B)
  USB_BULK_FLAVOR_MSC = 1,   // USB MSC Bulk-Only Transport (class 0x08)
} usb_bulk_flavor_t;

/* usb_bulk_info_t describes one bulk-pipe interface. All pointers must stay
 * valid until the interface is removed (usb_deinit). */
typedef struct {
  syshandle_t handle;
  usb_bulk_flavor_t flavor;
  uint8_t iface_num;
  uint8_t iface_class;
  uint8_t iface_subclass;
  uint8_t iface_protocol;
  // Optional class-specific functional descriptor emitted between the
  // interface and endpoint descriptors (e.g. the 54-byte CCID descriptor).
  const uint8_t *class_desc;
  uint8_t class_desc_len;
#ifdef TREZOR_EMULATOR
  uint16_t emu_port;
#else
  uint8_t ep_in;    // bulk IN endpoint number (without direction bit)
  uint8_t ep_out;   // bulk OUT endpoint number
  uint8_t ep_intr;  // interrupt IN endpoint number, 0 = none
#endif
  uint8_t intr_interval;  // interrupt endpoint polling interval (ms)
} usb_bulk_info_t;

secbool __wur usb_bulk_add(const usb_bulk_info_t *info);
