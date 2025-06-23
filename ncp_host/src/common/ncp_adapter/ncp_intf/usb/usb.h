/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef USB_H_
#define USB_H_

#include <libusb-1.0/libusb.h>
#include <stdint.h>
#include <unistd.h>
#include <stdint.h>


typedef struct
{
    uint16_t             productid;
    uint16_t             vendorid;
    uint16_t             usb_endpoint_in;
    uint16_t             usb_endpoint_out;
    libusb_device_handle *handle;
    libusb_context       *context;

} usb_device_t;

ncp_status_t  usb_init(usb_device_t *dev);
ncp_status_t  usb_send(usb_device_t *dev,int8_t *buf, uint32_t len);
ncp_status_t  usb_receive(usb_device_t *dev, int8_t *buf, uint32_t len, size_t *nb_bytes);
void usb_deinit(usb_device_t *dev);
ncp_status_t config_usb(usb_device_t *usb_dev);
void set_IntfEndpoints(struct libusb_device *req_device, usb_device_t *usb_dev, libusb_device **usb_devices_list, libusb_device_handle *dev_handle);
int usb_lpm_init();

#endif /* USB_H_ */