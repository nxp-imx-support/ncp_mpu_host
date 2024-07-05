/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "ncp_adapter.h"
#include "uart.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/
/*
 * Init UART instance.
 */
ncp_status_t uart_init(uart_device_t *dev)
{
    struct termios *tty;
    int             fd;
    int             ret;

    fd = open(dev->instance, O_RDWR | O_NOCTTY);
    if (fd < 0)
    {
        ncp_adap_e("Failed to open UART instance \n");
        return NCP_STATUS_ERROR;
    }

    tty = malloc(sizeof(*tty));
    if (!tty)
    {
        ncp_adap_e("Failed to allocate UART TTY instance \n");
        close(fd);
        return NCP_STATUS_ERROR;
    }

    memset(tty, 0, sizeof(*tty));

    cfsetispeed(tty, dev->rate);
    cfsetospeed(tty, dev->rate);
    /*Local area connection mode*/
    tty->c_cflag |= CLOCAL;
    /*Serial data reception*/
    tty->c_cflag |= CREAD;
    /*Hardware flow control*/
    tty->c_cflag |= CRTSCTS; /*Enable hardware flow control*/
    /*Set data bit*/
    tty->c_cflag &= ~CSIZE; // bit mask for data bits.
    tty->c_cflag |= CS8;    // 8 data bits.
    /*Set parity bit*/
    tty->c_cflag &= ~PARENB; // Enable parity bit.
    tty->c_iflag &= ~INPCK;  // Enable parity check.
    /*Set stop bit*/
    tty->c_cflag &= ~CSTOPB;
    /*Raw output*/
    tty->c_oflag &= ~OPOST;
    tty->c_iflag &= ~(IXON | IXOFF | IXANY); // Disable XON/XOFF flow control both i/p and o/p
    tty->c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    /*Set wait time and minimum received uint8_tacters*/
    /*Time to wait for data (tenths of seconds). VTIME sepcifies the amount of time to wait for incoming characters in
    tenths of seconds.
    If VTIME is set to 0 (the default), reads will block (wait) indefinitely unless the NDELAY option is set on the port
    with open or fcntl.*/
    tty->c_cc[VTIME] = 0;
    tty->c_cc[VMIN]  = 0; // TMinimum number of characters to read.

    tcflush(fd, TCIFLUSH);

    ret = tcsetattr(fd, TCSANOW, tty);
    if (ret)
    {
        ncp_adap_e("Failed to set UART attributes \n");
        close(fd);
        free(tty);
        return NCP_STATUS_ERROR;
    }

    dev->fd  = fd;
    dev->tty = tty;

    return NCP_STATUS_SUCCESS;
}

/*
 * Receive UART data.
 */
ncp_status_t uart_receive(uart_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes)
{
    *nb_bytes = read(dev->fd, buf, len);
    if (*nb_bytes < 0)
    {
        ncp_adap_e("Failed to read UART data \n");
        return NCP_STATUS_ERROR;
    }

    return NCP_STATUS_SUCCESS;
}

/*
 * Send UART data.
 */
ncp_status_t uart_send(uart_device_t *dev, uint8_t *buf, uint32_t len)
{
    if (write(dev->fd, buf, len) < 0)
    {
        ncp_adap_e("Failed to write UART data \n");
        return NCP_STATUS_ERROR;
    }

    return NCP_STATUS_SUCCESS;
}

/*
 * Deinit UART instance.
 */
void uart_deinit(uart_device_t *dev)
{
    close(dev->fd);
    free(dev->tty);
}
