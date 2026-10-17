// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Exclusive USB modes of the feuristic firmware (docs/architecture.md §5.2).
//
// The coreapp switches mode with usb_set_mode(). The kernel then rebuilds
// the whole USB configuration (usb_deinit → usb_init → class adds →
// usb_start). To make hosts notice a clean detach/re-enumeration the
// coreapp must call usb_stop() and wait >= USB_MODE_DETACH_MS before
// calling usb_set_mode() (the syscall itself never sleeps).

#pragma once

#include <trezor_types.h>

#include <io/usb.h>

#define USB_MODE_DETACH_MS 150

typedef enum {
  USB_MODE_NORMAL = 0,    // FIDO HID + CCID (+ debuglink in debug builds)
  USB_MODE_TIMESYNC = 1,  // CDC-ACM only
  USB_MODE_IMPORT = 2,    // MSC Bulk-Only (FAT12 import volume) only
} usb_mode_t;

#define USB_MODE_COUNT 3

// feuristic USB identity (pid.codes test PID until a dedicated PID is
// assigned — tracked as a release blocker in docs/release-checklist.md).
#define FEURISTIC_USB_VID 0x1209
#define FEURISTIC_USB_PID 0x0001
#define FEURISTIC_USB_RELEASE 0x0100

// CCID functional descriptor values mirrored by the coreapp CCID layer
// (src/feuristic/apps/card/ccid.py, docs/protocols/ccid.md).
#define FEURISTIC_CCID_MAX_MESSAGE_LEN (4096 + 10)

/**
 * Switches the USB configuration to `mode` and starts the stack with
 * `params` (serial number). Returns secfalse on invalid arguments or if the
 * stack could not be started; in that case the device stays detached.
 */
secbool usb_set_mode(usb_mode_t mode, const usb_start_params_t *params);

/** Returns the currently configured mode. */
usb_mode_t usb_get_mode(void);
