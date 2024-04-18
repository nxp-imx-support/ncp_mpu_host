/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <termios.h>
#include <unistd.h>

#ifndef UART_H_
#define UART_H_

typedef struct
{
    uint8_t         *instance;
    uint32_t        rate;
    int32_t         fd;
    struct termios *tty;
} uart_device_t;

ncp_status_t  uart_init(uart_device_t *dev);
ncp_status_t  uart_send(uart_device_t *dev, uint8_t *buf, uint32_t len);
ncp_status_t  uart_receive(uart_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes);
void uart_deinit(uart_device_t *dev);

#endif /* UART_H_ */