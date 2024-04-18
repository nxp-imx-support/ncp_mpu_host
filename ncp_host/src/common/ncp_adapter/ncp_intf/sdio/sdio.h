/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <termios.h>
#include <unistd.h>

#ifndef SDIO_H_
#define SDIO_H_

typedef struct
{
    uint8_t         *instance;
    int32_t         fd;
} sdio_device_t;

ncp_status_t  sdio_init(sdio_device_t *dev);
ncp_status_t  sdio_send(sdio_device_t *dev, uint8_t *buf, uint32_t len);
ncp_status_t  sdio_receive(sdio_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes);
void sdio_deinit(sdio_device_t *dev);

#endif /* SDIO_H_ */