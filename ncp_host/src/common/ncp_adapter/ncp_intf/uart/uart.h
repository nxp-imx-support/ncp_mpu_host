/*
 * Copyright 2024 - 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _UART_H_
#define _UART_H_

#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>

typedef struct
{
    const char     *instance;
    uint32_t        rate;
    int32_t         fd;
    struct termios *tty;
    uint8_t         flow_control;
} uart_device_t;

int uart_init(uart_device_t *dev);
int uart_send(uart_device_t *dev, uint8_t *buf, uint32_t len);
int uart_receive(uart_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes);
void uart_deinit(uart_device_t *dev);

#endif /* _UART_H_ */