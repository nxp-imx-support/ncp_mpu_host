/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if CONFIG_NCP_UART
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "uart.h"
#include "ncp_log.h"

NCP_LOG_MODULE_DECLARE(ncp_uart);

/*******************************************************************************
 * Code
 ******************************************************************************/

int uart_init(uart_device_t *dev)
{
    struct termios *tty;
    int             fd;
    int             ret;

    fd = open((const char *)dev->instance, O_RDWR | O_NOCTTY);
    if (fd < 0)
    {
        NCP_LOG_ERR("Failed to open UART instance: %s", strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    tty = malloc(sizeof(*tty));
    if (!tty)
    {
        NCP_LOG_ERR("Failed to allocate UART TTY instance");
        close(fd);
        return -1;
    }

    if (tcgetattr(fd, tty) != 0)
    {
        NCP_LOG_ERR("Failed to get UART attributes");
        free(tty);
        close(fd);
        return -1;
    }

    cfsetispeed(tty, dev->rate);
    cfsetospeed(tty, dev->rate);

    tty->c_cflag |= CLOCAL | CREAD;

    if (dev->flow_control)
    {
        tty->c_cflag |= CRTSCTS;
    }
    else
    {
        tty->c_cflag &= ~CRTSCTS;
    }

    tty->c_cflag &= ~CSIZE;
    tty->c_cflag |= CS8;
    tty->c_cflag &= ~PARENB;
    tty->c_iflag &= ~INPCK;
    tty->c_cflag &= ~CSTOPB;

    tty->c_oflag &= ~OPOST;
    tty->c_iflag &= ~(IXON | IXOFF | IXANY);
    tty->c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    /* Raw mode */
    tty->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

    /* Configure read behavior */
    tty->c_cc[VTIME] = 0;
    tty->c_cc[VMIN]  = 1;

    /* Flush input buffer */
    tcflush(fd, TCIFLUSH);

    /* Apply new settings */
    ret = tcsetattr(fd, TCSANOW, tty);
    if (ret)
    {
        NCP_LOG_ERR("Failed to set UART attributes: %s", strerror(errno));
        free(tty);
        close(fd);
        return -1;
    }

    dev->fd  = fd;
    dev->tty = tty;

    NCP_LOG_DBG("UART initialized: %s @ %u baud", dev->instance, dev->rate);
    return 0;
}

int uart_receive(uart_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes)
{
    ssize_t bytes_read;

    bytes_read = read(dev->fd, buf, len);
    if (bytes_read < 0)
    {
        if (errno == EINTR)
        {
            *nb_bytes = 0;
            return 0;
        }
        NCP_LOG_ERR("Failed to read UART data: %s", strerror(errno));
        *nb_bytes = 0;
        return -1;
    }

    *nb_bytes = (size_t)bytes_read;
    return 0;
}

int uart_send(uart_device_t *dev, uint8_t *buf, uint32_t len)
{
    ssize_t bytes_written;
    uint32_t total_written = 0;

    NCP_LOG_DBG("UART sending %u bytes", len);

    while (total_written < len)
    {
        bytes_written = write(dev->fd, buf + total_written, len - total_written);
        if (bytes_written < 0)
        {
            if (errno == EINTR)
                continue;
            NCP_LOG_ERR("Failed to write UART data: %s", strerror(errno));
            return -1;
        }
        total_written += bytes_written;
    }

    tcdrain(dev->fd);

    NCP_LOG_DBG("UART sent %u bytes", len);
    return 0;
}

void uart_deinit(uart_device_t *dev)
{
    if (dev->fd >= 0)
    {
        tcflush(dev->fd, TCIOFLUSH);
        close(dev->fd);
    }
    if (dev->tty)
    {
        free(dev->tty);
        dev->tty = NULL;
    }
}
#endif /* CONFIG_NCP_UART */
