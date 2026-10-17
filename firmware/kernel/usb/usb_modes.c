// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// USB configuration of the feuristic firmware: three exclusive modes
// (NORMAL = FIDO HID + CCID, TIMESYNC = CDC-ACM, IMPORT = MSC).
// Replaces the firmware branch of upstream io/usb/usb_config.c; the
// bootloader and prodtest keep using the upstream configuration.

#if defined(KERNEL_MODE) && !defined(BOOTLOADER) && !defined(TREZOR_PRODTEST)

#include <trezor_bsp.h>
#include <trezor_model.h>
#include <trezor_rtl.h>

#include <io/usb.h>
#include <io/usb_bulk.h>
#include <io/usb_config.h>
#include <io/usb_hid.h>
#include <io/usb_modes.h>
#include <io/usb_vcp.h>
#ifdef USE_USB_IFACE_DEBUG
#include <io/usb_webusb.h>
#endif

#ifdef TREZOR_EMULATOR
#include <stdlib.h>
#endif

// Emulator UDP port offsets relative to TREZOR_UDP_PORT (default 21324).
// Must match tools/feuristic_emu and docs/developer/emulator.md.
#define USB_IFACE_BASE_PORT 21324
#define USB_PORT_DEBUG 1
#define USB_PORT_FIDO 2
#define USB_PORT_VCP 3
#define USB_PORT_CCID 7
#define USB_PORT_MSC 8

static usb_mode_t g_mode = USB_MODE_NORMAL;

#ifdef TREZOR_EMULATOR
static uint16_t emu_port(uint16_t offset) {
  const char *base = getenv("TREZOR_UDP_PORT");
  return offset + (base ? atoi(base) : USB_IFACE_BASE_PORT);
}
#endif

static secbool device_init(usb_mode_t mode) {
  usb_dev_info_t info = {
      .device_class = 0x00,
      .device_subclass = 0x00,
      .device_protocol = 0x00,
      .vendor_id = FEURISTIC_USB_VID,
      .product_id = FEURISTIC_USB_PID,
      .release_num = FEURISTIC_USB_RELEASE,
      .manufacturer = "feuristic project",
      .product = "feuristic security key",
      .serial_number = "000000000000000000000000",
      .interface = "feuristic",
      // No BOS/WebUSB/WinUSB descriptors: WinUSB would hijack interface 0
      .usb21_enabled = secfalse,
      .usb21_landing = secfalse,
  };
  if (mode == USB_MODE_TIMESYNC) {
    // CDC-ACM with Interface Association Descriptor
    info.device_class = 0xEF;
    info.device_subclass = 0x02;
    info.device_protocol = 0x01;
    strncpy(info.product, "feuristic time sync", USB_MAX_STR_SIZE);
  } else if (mode == USB_MODE_IMPORT) {
    strncpy(info.product, "feuristic import", USB_MAX_STR_SIZE);
  }
  return usb_init(&info);
}

// --- NORMAL mode -----------------------------------------------------------

static secbool add_fido_hid(uint8_t iface_num) {
  static const uint8_t report_map[] = {
      0x06, 0xd0, 0xf1,  // USAGE_PAGE (FIDO Alliance)
      0x09, 0x01,        // USAGE (U2F HID Authenticator Device)
      0xa1, 0x01,        // COLLECTION (Application)
      0x09, 0x20,        //  USAGE (Input Report Data)
      0x15, 0x00,        //  LOGICAL_MINIMUM (0)
      0x26, 0xff, 0x00,  //  LOGICAL_MAXIMUM (255)
      0x75, 0x08,        //  REPORT_SIZE (8)
      0x95, 0x40,        //  REPORT_COUNT (64)
      0x81, 0x02,        //  INPUT (Data,Var,Abs)
      0x09, 0x21,        //  USAGE (Output Report Data)
      0x15, 0x00,        //  LOGICAL_MINIMUM (0)
      0x26, 0xff, 0x00,  //  LOGICAL_MAXIMUM (255)
      0x75, 0x08,        //  REPORT_SIZE (8)
      0x95, 0x40,        //  REPORT_COUNT (64)
      0x91, 0x02,        //  OUTPUT (Data,Var,Abs)
      0xc0,              // END_COLLECTION
  };
  static uint8_t rx_buffer[USB_PACKET_LEN];
  const usb_hid_info_t hid = {
      .handle = SYSHANDLE_USB_WEBAUTHN,
      .report_desc = report_map,
      .report_desc_len = sizeof(report_map),
      .rx_buffer = rx_buffer,
      .max_packet_len = sizeof(rx_buffer),
      .iface_num = iface_num,
#ifdef TREZOR_EMULATOR
      .emu_port = emu_port(USB_PORT_FIDO),
#else
      .ep_in = 0x01,
      .ep_out = 0x01,
#endif
      .subclass = 0x00,
      .protocol = 0x00,
      .polling_interval = 1,
  };
  return usb_hid_add(&hid);
}

static secbool add_ccid(uint8_t iface_num) {
  // CCID class functional descriptor (USB CCID rev 1.1 §5.1), little endian.
  static const uint8_t ccid_desc[54] = {
      54,                      // bLength
      0x21,                    // bDescriptorType: CCID functional
      0x10, 0x01,              // bcdCCID 1.10
      0x00,                    // bMaxSlotIndex
      0x07,                    // bVoltageSupport: 5.0V, 3.0V, 1.8V
      0x02, 0x00, 0x00, 0x00,  // dwProtocols: T=1
      0xA0, 0x0F, 0x00, 0x00,  // dwDefaultClock 4000 kHz
      0xA0, 0x0F, 0x00, 0x00,  // dwMaximumClock 4000 kHz
      0x00,                    // bNumClockSupported
      0x80, 0x25, 0x00, 0x00,  // dwDataRate 9600 bps
      0x80, 0x25, 0x00, 0x00,  // dwMaxDataRate
      0x00,                    // bNumDataRatesSupported
      0xFE, 0x00, 0x00, 0x00,  // dwMaxIFSD 254
      0x00, 0x00, 0x00, 0x00,  // dwSynchProtocols
      0x00, 0x00, 0x00, 0x00,  // dwMechanical
      // dwFeatures: auto ATR config, auto activation, auto voltage, auto
      // clock, auto baud, auto parameters negotiation, auto PPS, short and
      // extended APDU level exchange
      0xFE, 0x00, 0x04, 0x00,
      // dwMaxCCIDMessageLength
      (FEURISTIC_CCID_MAX_MESSAGE_LEN) & 0xFF,
      (FEURISTIC_CCID_MAX_MESSAGE_LEN >> 8) & 0xFF, 0x00, 0x00,
      0xFF,        // bClassGetResponse: echo
      0xFF,        // bClassEnvelope: echo
      0x00, 0x00,  // wLcdLayout: none
      0x00,        // bPINSupport: none (PINs are handled by the host/device)
      0x01,        // bMaxCCIDBusySlots
  };
  const usb_bulk_info_t ccid = {
      .handle = SYSHANDLE_USB_CCID,
      .flavor = USB_BULK_FLAVOR_CCID,
      .iface_num = iface_num,
      .iface_class = 0x0B,
      .iface_subclass = 0x00,
      .iface_protocol = 0x00,
      .class_desc = ccid_desc,
      .class_desc_len = sizeof(ccid_desc),
#ifdef TREZOR_EMULATOR
      .emu_port = emu_port(USB_PORT_CCID),
#else
      .ep_in = 0x02,
      .ep_out = 0x02,
      .ep_intr = 0x04,
#endif
      .intr_interval = 16,
  };
  return usb_bulk_add(&ccid);
}

#ifdef USE_USB_IFACE_DEBUG
static secbool add_debuglink(uint8_t iface_num) {
  static uint8_t rx_buffer[USB_PACKET_LEN];
  const usb_webusb_info_t dbg = {
      .handle = SYSHANDLE_USB_DEBUG,
      .rx_buffer = rx_buffer,
      .iface_num = iface_num,
#ifdef TREZOR_EMULATOR
      .emu_port = emu_port(USB_PORT_DEBUG),
#else
      .ep_in = 0x03,
      .ep_out = 0x03,
#endif
      .subclass = 0x00,
      .protocol = 0x00,
      .polling_interval = 1,
      .max_packet_len = sizeof(rx_buffer),
  };
  return usb_webusb_add(&dbg);
}
#endif

// --- TIMESYNC mode ---------------------------------------------------------

#if defined(TREZOR_EMULATOR)
#define VCP_PACKET_LEN 64
#elif defined(USE_USB_HS) && !defined(USE_USB_HS_IN_FS)
#define VCP_PACKET_LEN 512
#else
#define VCP_PACKET_LEN 64
#endif

static secbool add_cdc_acm(uint8_t iface_num) {
  static uint8_t tx_packet[VCP_PACKET_LEN];
  static uint8_t tx_buffer[512];
  static uint8_t rx_packet[VCP_PACKET_LEN];
  static uint8_t rx_buffer[512];
  const usb_vcp_info_t vcp = {
      .handle = SYSHANDLE_USB_VCP,
      .tx_packet = tx_packet,
      .tx_buffer = tx_buffer,
      .rx_packet = rx_packet,
      .rx_buffer = rx_buffer,
      .tx_buffer_len = sizeof(tx_buffer),
      .rx_buffer_len = sizeof(rx_buffer),
      .max_packet_len = VCP_PACKET_LEN,
      .rx_intr_fn = NULL,
      .rx_intr_byte = 0,
      .iface_num = iface_num,
      .data_iface_num = iface_num + 1,
#ifdef TREZOR_EMULATOR
      .emu_port = emu_port(USB_PORT_VCP),
#else
      .ep_cmd = 0x02,
      .ep_in = 0x01,
      .ep_out = 0x01,
#endif
      .polling_interval = 10,
  };
  return usb_vcp_add(&vcp);
}

// --- IMPORT mode -----------------------------------------------------------

static secbool add_msc(uint8_t iface_num) {
  const usb_bulk_info_t msc = {
      .handle = SYSHANDLE_USB_MSC,
      .flavor = USB_BULK_FLAVOR_MSC,
      .iface_num = iface_num,
      .iface_class = 0x08,     // Mass Storage
      .iface_subclass = 0x06,  // SCSI transparent command set
      .iface_protocol = 0x50,  // Bulk-Only Transport
      .class_desc = NULL,
      .class_desc_len = 0,
#ifdef TREZOR_EMULATOR
      .emu_port = emu_port(USB_PORT_MSC),
#else
      .ep_in = 0x01,
      .ep_out = 0x01,
      .ep_intr = 0x00,
#endif
      .intr_interval = 0,
  };
  return usb_bulk_add(&msc);
}

// --- mode switching --------------------------------------------------------

static secbool configure_mode(usb_mode_t mode) {
  if (sectrue != device_init(mode)) {
    return secfalse;
  }
  secbool ok = secfalse;
  switch (mode) {
    case USB_MODE_NORMAL:
      ok = add_fido_hid(0);
      ok = secbool_and(ok, add_ccid(1));
#ifdef USE_USB_IFACE_DEBUG
      ok = secbool_and(ok, add_debuglink(2));
#endif
      break;
    case USB_MODE_TIMESYNC:
      ok = add_cdc_acm(0);
      break;
    case USB_MODE_IMPORT:
      ok = add_msc(0);
      break;
    default:
      ok = secfalse;
      break;
  }
  if (sectrue != ok) {
    usb_deinit();
    return secfalse;
  }
  g_mode = mode;
  return sectrue;
}

secbool usb_configure(usb_vcp_intr_callback_t vcp_intr_callback) {
  UNUSED(vcp_intr_callback);
  return configure_mode(USB_MODE_NORMAL);
}

secbool usb_set_mode(usb_mode_t mode, const usb_start_params_t *params) {
  if ((unsigned)mode >= USB_MODE_COUNT || params == NULL) {
    return secfalse;
  }
  usb_deinit();
  if (sectrue != configure_mode(mode)) {
    // Fall back to the normal configuration, left stopped
    (void)configure_mode(USB_MODE_NORMAL);
    return secfalse;
  }
  return usb_start(params);
}

usb_mode_t usb_get_mode(void) { return g_mode; }

#endif  // KERNEL_MODE && !BOOTLOADER && !TREZOR_PRODTEST
