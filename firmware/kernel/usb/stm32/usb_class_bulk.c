// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Generic bulk-pipe USB class (CCID / MSC BOT) for the STM32 USB stack of
// the upstream Trezor kernel. See inc/io/usb_bulk.h for the framing.
//
// The class is intentionally minimal: it owns one RX packet buffer and one
// TX packet buffer (both in kernel memory — data written by the coreapp is
// always copied before transmission), a tiny event queue, and the endpoint
// stall bookkeeping. It never interprets the payload.

#ifdef KERNEL_MODE

#include <trezor_rtl.h>

#include <io/usb_bulk.h>
#include <sec/random_delays.h>
#include <sys/irq.h>
#include <sys/sysevent_source.h>
#include "memzero.h"

#ifdef USE_SUSPEND
#include <io/suspend.h>
#endif

#include "usb_internal.h"

// MSC Bulk-Only Transport class requests
#define USB_MSC_REQ_GET_MAX_LUN 0xFE
#define USB_MSC_REQ_BOT_RESET 0xFF
// CCID class requests (CCID rev 1.1 §5.3)
#define USB_CCID_REQ_ABORT 0x01
#define USB_CCID_REQ_GET_CLOCK_FREQUENCIES 0x02
#define USB_CCID_REQ_GET_DATA_RATES 0x03

#define USB_BULK_EVQ_LEN 4

typedef struct __attribute__((packed)) {
  usb_interface_descriptor_t iface;
  // followed by: class descriptor (variable), ep_out, ep_in, [ep_intr]
} usb_bulk_iface_desc_t;

typedef struct {
  uint8_t type;
  uint8_t data[2];
  uint8_t len;
} usb_bulk_event_t;

typedef struct {
  syshandle_t handle;
  USBD_HandleTypeDef *dev_handle;
  usb_bulk_flavor_t flavor;
  uint8_t iface_num;
  uint8_t ep_in;
  uint8_t ep_out;
  uint8_t ep_intr;  // 0 = none (direction bit included otherwise)

  uint8_t rx_len;       // bytes in rx_buf, valid if rx_full
  uint8_t rx_full;      // a received packet waits to be read
  uint8_t in_idle;      // bulk IN endpoint can accept a packet
  uint8_t intr_idle;    // interrupt IN endpoint can accept a packet
  uint8_t in_stalled;   // we stalled bulk IN and wait for CLEAR_FEATURE
  uint8_t out_stalled;  // we stalled bulk OUT and wait for CLEAR_FEATURE
  uint8_t evq_head;
  uint8_t evq_count;
  usb_bulk_event_t evq[USB_BULK_EVQ_LEN];
  uint8_t max_lun;  // MSC GET MAX LUN answer (always 0)
} usb_bulk_state_t;

_Static_assert(sizeof(usb_bulk_state_t) <= USBD_CLASS_STATE_MAX_SIZE,
               "usb_bulk_state_t too large");

// Packet buffers live outside the per-interface state (which is limited to
// USBD_CLASS_STATE_MAX_SIZE bytes). feuristic uses at most one bulk-pipe
// interface of each flavor at a time.
static uint8_t g_rx_buf[2][USB_BULK_PACKET_LEN] __attribute__((aligned(4)));
static uint8_t g_tx_buf[2][USB_BULK_PACKET_LEN] __attribute__((aligned(4)));
static uint8_t g_intr_buf[2][USB_BULK_INTR_LEN] __attribute__((aligned(4)));

static const USBD_ClassTypeDef usb_bulk_class;
static const syshandle_vmt_t usb_bulk_handle_vmt;

static inline uint8_t *rx_buf(const usb_bulk_state_t *s) {
  return g_rx_buf[s->flavor];
}
static inline uint8_t *tx_buf(const usb_bulk_state_t *s) {
  return g_tx_buf[s->flavor];
}
static inline uint8_t *intr_buf(const usb_bulk_state_t *s) {
  return g_intr_buf[s->flavor];
}

secbool usb_bulk_add(const usb_bulk_info_t *info) {
  if (info->flavor != USB_BULK_FLAVOR_CCID &&
      info->flavor != USB_BULK_FLAVOR_MSC) {
    return secfalse;
  }
  if (info->ep_in == 0 || info->ep_out == 0 ||
      info->ep_in >= USBD_MAX_NUM_INTERFACES ||
      info->ep_out >= USBD_MAX_NUM_INTERFACES ||
      info->ep_intr >= USBD_MAX_NUM_INTERFACES) {
    return secfalse;
  }
  if (info->class_desc_len > 0 && info->class_desc == NULL) {
    return secfalse;
  }

  usb_bulk_state_t *state = usb_get_iface_state(info->iface_num, NULL);
  if (state == NULL) {
    return secfalse;
  }

  const uint8_t num_eps = info->ep_intr ? 3 : 2;
  const size_t desc_len = sizeof(usb_interface_descriptor_t) +
                          info->class_desc_len +
                          num_eps * sizeof(usb_endpoint_descriptor_t);
  uint8_t *d = usb_alloc_class_descriptors(desc_len);
  if (d == NULL) {
    return secfalse;
  }

  usb_interface_descriptor_t *iface = (usb_interface_descriptor_t *)d;
  iface->bLength = sizeof(usb_interface_descriptor_t);
  iface->bDescriptorType = USB_DESC_TYPE_INTERFACE;
  iface->bInterfaceNumber = info->iface_num;
  iface->bAlternateSetting = 0;
  iface->bNumEndpoints = num_eps;
  iface->bInterfaceClass = info->iface_class;
  iface->bInterfaceSubClass = info->iface_subclass;
  iface->bInterfaceProtocol = info->iface_protocol;
  iface->iInterface = USBD_IDX_INTERFACE_STR;
  d += sizeof(usb_interface_descriptor_t);

  if (info->class_desc_len > 0) {
    memcpy(d, info->class_desc, info->class_desc_len);
    d += info->class_desc_len;
  }

  usb_endpoint_descriptor_t *ep = (usb_endpoint_descriptor_t *)d;
  ep->bLength = sizeof(usb_endpoint_descriptor_t);
  ep->bDescriptorType = USB_DESC_TYPE_ENDPOINT;
  ep->bEndpointAddress = info->ep_out | USB_EP_DIR_OUT;
  ep->bmAttributes = USBD_EP_TYPE_BULK;
  ep->wMaxPacketSize = USB_BULK_PACKET_LEN;
  ep->bInterval = 0;
  ep++;

  ep->bLength = sizeof(usb_endpoint_descriptor_t);
  ep->bDescriptorType = USB_DESC_TYPE_ENDPOINT;
  ep->bEndpointAddress = info->ep_in | USB_EP_DIR_IN;
  ep->bmAttributes = USBD_EP_TYPE_BULK;
  ep->wMaxPacketSize = USB_BULK_PACKET_LEN;
  ep->bInterval = 0;
  ep++;

  if (info->ep_intr) {
    ep->bLength = sizeof(usb_endpoint_descriptor_t);
    ep->bDescriptorType = USB_DESC_TYPE_ENDPOINT;
    ep->bEndpointAddress = info->ep_intr | USB_EP_DIR_IN;
    ep->bmAttributes = USBD_EP_TYPE_INTR;
    ep->wMaxPacketSize = USB_BULK_INTR_LEN;
    ep->bInterval = info->intr_interval ? info->intr_interval : 16;
  }

  memset(state, 0, sizeof(*state));
  state->handle = info->handle;
  state->flavor = info->flavor;
  state->iface_num = info->iface_num;
  state->ep_in = info->ep_in | USB_EP_DIR_IN;
  state->ep_out = info->ep_out | USB_EP_DIR_OUT;
  state->ep_intr = info->ep_intr ? (info->ep_intr | USB_EP_DIR_IN) : 0;
  state->in_idle = 1;
  state->intr_idle = 1;

  usb_set_iface_class(info->iface_num, &usb_bulk_class);
  return sectrue;
}

// --- event queue (accessed from IRQ and thread context) -------------------

static void evq_push(usb_bulk_state_t *s, uint8_t type, const uint8_t *data,
                     uint8_t len) {
  if (s->evq_count >= USB_BULK_EVQ_LEN) {
    // Drop the oldest event: a newer reset supersedes older ones.
    s->evq_head = (s->evq_head + 1) % USB_BULK_EVQ_LEN;
    s->evq_count--;
  }
  usb_bulk_event_t *e =
      &s->evq[(s->evq_head + s->evq_count) % USB_BULK_EVQ_LEN];
  e->type = type;
  e->len = MIN(len, sizeof(e->data));
  if (e->len > 0) {
    memcpy(e->data, data, e->len);
  }
  s->evq_count++;
}

static bool configured(const usb_bulk_state_t *s) {
  return s->dev_handle != NULL &&
         s->dev_handle->dev_state == USBD_STATE_CONFIGURED;
}

// Detect host CLEAR_FEATURE(ENDPOINT_HALT): the stack clears the hardware
// stall without notifying the class, so we notice it by polling.
static void check_halt_cleared(usb_bulk_state_t *s) {
  if (!configured(s)) {
    return;
  }
  if (s->out_stalled && !USBD_LL_IsStallEP(s->dev_handle, s->ep_out)) {
    s->out_stalled = 0;
    s->rx_full = 0;
    USBD_LL_PrepareReceive(s->dev_handle, s->ep_out, rx_buf(s),
                           USB_BULK_PACKET_LEN);
    uint8_t ep = s->ep_out;
    evq_push(s, USB_BULK_EV_HALT_CLEARED, &ep, 1);
  }
  if (s->in_stalled && !USBD_LL_IsStallEP(s->dev_handle, s->ep_in)) {
    s->in_stalled = 0;
    s->in_idle = 1;
    uint8_t ep = s->ep_in;
    evq_push(s, USB_BULK_EV_HALT_CLEARED, &ep, 1);
  }
}

static bool can_read(usb_bulk_state_t *s) {
  if (!configured(s)) {
    return false;
  }
  irq_key_t key = irq_lock();
  check_halt_cleared(s);
  bool ready = s->evq_count > 0 || s->rx_full;
  irq_unlock(key);
  return ready;
}

static bool can_write(usb_bulk_state_t *s) {
  if (!configured(s)) {
    return false;
  }
  irq_key_t key = irq_lock();
  check_halt_cleared(s);
  bool ready = s->in_idle && !s->in_stalled;
  irq_unlock(key);
  return ready;
}

// --- USBD class callbacks -------------------------------------------------

static uint8_t usb_bulk_class_init(USBD_HandleTypeDef *dev, uint8_t cfg_idx) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)dev->pUserData;
  UNUSED(cfg_idx);

  s->dev_handle = dev;
  USBD_LL_OpenEP(dev, s->ep_in, USBD_EP_TYPE_BULK, USB_BULK_PACKET_LEN);
  USBD_LL_OpenEP(dev, s->ep_out, USBD_EP_TYPE_BULK, USB_BULK_PACKET_LEN);
  if (s->ep_intr) {
    USBD_LL_OpenEP(dev, s->ep_intr, USBD_EP_TYPE_INTR, USB_BULK_INTR_LEN);
  }

  s->rx_len = 0;
  s->rx_full = 0;
  s->in_idle = 1;
  s->intr_idle = 1;
  s->in_stalled = 0;
  s->out_stalled = 0;
  s->evq_head = 0;
  s->evq_count = 0;

  USBD_LL_PrepareReceive(dev, s->ep_out, rx_buf(s), USB_BULK_PACKET_LEN);

  if (s->flavor == USB_BULK_FLAVOR_CCID && s->ep_intr) {
    // RDR_to_PC_NotifySlotChange: slot 0 ICC present + changed (CCID §6.3.1)
    uint8_t *b = intr_buf(s);
    b[0] = 0x50;
    b[1] = 0x03;
    s->intr_idle = 0;
    USBD_LL_Transmit(dev, s->ep_intr, b, 2);
  }

  if (!syshandle_register(s->handle, &usb_bulk_handle_vmt, s)) {
    return USBD_FAIL;
  }
  return USBD_OK;
}

static uint8_t usb_bulk_class_deinit(USBD_HandleTypeDef *dev, uint8_t cfg_idx) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)dev->pUserData;
  UNUSED(cfg_idx);

  syshandle_unregister(s->handle);

  USBD_LL_FlushEP(dev, s->ep_in);
  USBD_LL_FlushEP(dev, s->ep_out);
  USBD_LL_CloseEP(dev, s->ep_in);
  USBD_LL_CloseEP(dev, s->ep_out);
  if (s->ep_intr) {
    USBD_LL_FlushEP(dev, s->ep_intr);
    USBD_LL_CloseEP(dev, s->ep_intr);
  }

  s->dev_handle = NULL;
  memzero(rx_buf(s), USB_BULK_PACKET_LEN);
  memzero(tx_buf(s), USB_BULK_PACKET_LEN);
  return USBD_OK;
}

static uint8_t usb_bulk_class_setup(USBD_HandleTypeDef *dev,
                                    USBD_SetupReqTypedef *req) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)dev->pUserData;

  wait_random();

  if ((req->bmRequest & USB_REQ_TYPE_MASK) == USB_REQ_TYPE_CLASS) {
    if (s->flavor == USB_BULK_FLAVOR_MSC) {
      switch (req->bRequest) {
        case USB_MSC_REQ_GET_MAX_LUN:
          if (req->wValue != 0 || req->wLength != 1) {
            break;
          }
          s->max_lun = 0;
          USBD_CtlSendData(dev, &s->max_lun, 1);
          return USBD_OK;
        case USB_MSC_REQ_BOT_RESET: {
          if (req->wValue != 0 || req->wLength != 0) {
            break;
          }
          // Bulk-Only Mass Storage Reset (BOT §3.1): discard pending data and
          // let the coreapp reset its BOT state. Halt conditions are kept as
          // they are; the host clears them separately.
          irq_key_t key = irq_lock();
          USBD_LL_FlushEP(dev, s->ep_in);
          s->in_idle = 1;
          s->rx_full = 0;
          if (!s->out_stalled) {
            USBD_LL_PrepareReceive(dev, s->ep_out, rx_buf(s),
                                   USB_BULK_PACKET_LEN);
          }
          evq_push(s, USB_BULK_EV_RESET, NULL, 0);
          irq_unlock(key);
          // usbd_ctlreq sends the status stage for wLength == 0 requests
          return USBD_OK;
        }
        default:
          break;
      }
    } else {  // CCID
      switch (req->bRequest) {
        case USB_CCID_REQ_ABORT: {
          // wValue = bSeq << 8 | bSlot (CCID §5.3.1)
          uint8_t data[2] = {req->wValue & 0xFF, req->wValue >> 8};
          irq_key_t key = irq_lock();
          evq_push(s, USB_BULK_EV_RESET, data, 2);
          irq_unlock(key);
          return USBD_OK;
        }
        case USB_CCID_REQ_GET_CLOCK_FREQUENCIES:
        case USB_CCID_REQ_GET_DATA_RATES:
          // bNumClockSupported / bNumDataRatesSupported are 0 in the
          // functional descriptor: these requests are not supported.
        default:
          break;
      }
    }
    USBD_CtlError(dev, req);
    return USBD_FAIL;
  }

  // Standard interface requests
  switch (req->bRequest) {
    case USB_REQ_SET_INTERFACE:
      if (req->wValue == 0) {
        USBD_CtlSendStatus(dev);
        return USBD_OK;
      }
      break;
    case USB_REQ_GET_INTERFACE: {
      static const uint8_t alt = 0;
      USBD_CtlSendData(dev, UNCONST(&alt), 1);
      return USBD_OK;
    }
    default:
      break;
  }
  USBD_CtlError(dev, req);
  return USBD_FAIL;
}

static uint8_t usb_bulk_class_data_in(USBD_HandleTypeDef *dev, uint8_t ep_num) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)dev->pUserData;
  if ((ep_num | USB_EP_DIR_IN) == s->ep_in) {
    wait_random();
    s->in_idle = 1;
  } else if (s->ep_intr && (ep_num | USB_EP_DIR_IN) == s->ep_intr) {
    s->intr_idle = 1;
  }
  return USBD_OK;
}

static uint8_t usb_bulk_class_data_out(USBD_HandleTypeDef *dev,
                                       uint8_t ep_num) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)dev->pUserData;
  if ((ep_num & ~USB_EP_DIR_MASK) == (s->ep_out & ~USB_EP_DIR_MASK)) {
    wait_random();
    uint32_t len = USBD_LL_GetRxDataSize(dev, ep_num);
    s->rx_len = (uint8_t)MIN(len, USB_BULK_PACKET_LEN);
    // Do not re-arm until the coreapp consumed the packet (flow control)
    s->rx_full = 1;
#ifdef USE_SUSPEND
    wakeup_flags_set(WAKEUP_FLAG_USB);
#endif
  }
  return USBD_OK;
}

static const USBD_ClassTypeDef usb_bulk_class = {
    .Init = usb_bulk_class_init,
    .DeInit = usb_bulk_class_deinit,
    .Setup = usb_bulk_class_setup,
    .EP0_TxSent = NULL,
    .EP0_RxReady = NULL,
    .DataIn = usb_bulk_class_data_in,
    .DataOut = usb_bulk_class_data_out,
    .SOF = NULL,
    .IsoINIncomplete = NULL,
    .IsoOUTIncomplete = NULL,
    .GetHSConfigDescriptor = NULL,
    .GetFSConfigDescriptor = NULL,
    .GetOtherSpeedConfigDescriptor = NULL,
    .GetDeviceQualifierDescriptor = NULL,
    .GetUsrStrDescriptor = NULL,
};

// --- syshandle interface (coreapp side) -----------------------------------

static void on_event_poll(void *context, bool read_awaited,
                          bool write_awaited) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)context;
  if (read_awaited && can_read(s)) {
    syshandle_signal_read_ready(s->handle, NULL);
  }
  if (write_awaited && can_write(s)) {
    syshandle_signal_write_ready(s->handle, NULL);
  }
}

static bool on_check_read_ready(void *context, systask_id_t task_id,
                                void *param) {
  UNUSED(task_id);
  UNUSED(param);
  return can_read((usb_bulk_state_t *)context);
}

static bool on_check_write_ready(void *context, systask_id_t task_id,
                                 void *param) {
  UNUSED(task_id);
  UNUSED(param);
  return can_write((usb_bulk_state_t *)context);
}

static ssize_t on_read(void *context, void *buffer, size_t buffer_size) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)context;
  uint8_t *out = (uint8_t *)buffer;

  if (s->dev_handle == NULL) {
    return -1;
  }
  if (buffer_size < USB_BULK_FRAME_MAX) {
    return -1;
  }

  ssize_t n = 0;
  irq_key_t key = irq_lock();
  check_halt_cleared(s);
  if (s->evq_count > 0) {
    // Events are delivered before data so that a reset discards stale state
    usb_bulk_event_t *e = &s->evq[s->evq_head];
    out[0] = e->type;
    memcpy(&out[1], e->data, e->len);
    n = 1 + e->len;
    s->evq_head = (s->evq_head + 1) % USB_BULK_EVQ_LEN;
    s->evq_count--;
  } else if (s->rx_full) {
    out[0] = USB_BULK_EV_DATA;
    memcpy(&out[1], rx_buf(s), s->rx_len);
    n = 1 + s->rx_len;
    s->rx_full = 0;
    if (!s->out_stalled) {
      USBD_LL_PrepareReceive(s->dev_handle, s->ep_out, rx_buf(s),
                             USB_BULK_PACKET_LEN);
    }
  }
  irq_unlock(key);
  return n;
}

static ssize_t on_write(void *context, const void *data, size_t data_size) {
  usb_bulk_state_t *s = (usb_bulk_state_t *)context;
  const uint8_t *in = (const uint8_t *)data;

  if (s->dev_handle == NULL || data_size < 1 ||
      data_size > USB_BULK_FRAME_MAX) {
    return -1;
  }
  if (!configured(s)) {
    return 0;
  }

  const uint8_t op = in[0];
  const size_t len = data_size - 1;
  ssize_t ret = 0;
  irq_key_t key = irq_lock();

  switch (op) {
    case USB_BULK_OP_DATA:
    case USB_BULK_OP_ZLP:
      if ((op == USB_BULK_OP_DATA && len == 0) ||
          (op == USB_BULK_OP_ZLP && len != 0)) {
        ret = -1;
        break;
      }
      if (!s->in_idle || s->in_stalled) {
        ret = 0;  // not ready, caller retries after polling
        break;
      }
      memcpy(tx_buf(s), &in[1], len);
      s->in_idle = 0;
      USBD_LL_Transmit(s->dev_handle, s->ep_in, tx_buf(s), (uint16_t)len);
      ret = (ssize_t)data_size;
      break;

    case USB_BULK_OP_STALL_IN:
      if (len != 0) {
        ret = -1;
        break;
      }
      USBD_LL_StallEP(s->dev_handle, s->ep_in);
      s->in_stalled = 1;
      ret = (ssize_t)data_size;
      break;

    case USB_BULK_OP_STALL_OUT:
      if (len != 0) {
        ret = -1;
        break;
      }
      USBD_LL_StallEP(s->dev_handle, s->ep_out);
      s->out_stalled = 1;
      s->rx_full = 0;
      ret = (ssize_t)data_size;
      break;

    case USB_BULK_OP_INTR:
      if (!s->ep_intr || len == 0 || len > USB_BULK_INTR_LEN) {
        ret = -1;
        break;
      }
      if (!s->intr_idle) {
        ret = 0;
        break;
      }
      memcpy(intr_buf(s), &in[1], len);
      s->intr_idle = 0;
      USBD_LL_Transmit(s->dev_handle, s->ep_intr, intr_buf(s), (uint16_t)len);
      ret = (ssize_t)data_size;
      break;

    default:
      ret = -1;
      break;
  }

  irq_unlock(key);
  return ret;
}

static const syshandle_vmt_t usb_bulk_handle_vmt = {
    .task_created = NULL,
    .task_killed = NULL,
    .check_read_ready = on_check_read_ready,
    .check_write_ready = on_check_write_ready,
    .poll = on_event_poll,
    .read = on_read,
    .write = on_write,
};

#endif  // KERNEL_MODE
