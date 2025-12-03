/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if CONFIG_NCP_SDIO
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "sdio.h"
#include "ncp_log.h"
#include <errno.h>

NCP_LOG_MODULE_DECLARE(ncp_sdio);

/*******************************************************************************
 * Code
 ******************************************************************************/
/*
 * Init SDIO instance.
 */
int sdio_init(sdio_device_t *dev)
{
    int fd;

    fd = open((char *)(dev->instance), O_RDWR | O_NOCTTY);
    if (fd < 0)
    {
        NCP_LOG_ERR("Failed to open SDIO instance: %s", strerror(errno));
        return -1;
    }

#if 0
    if (fcntl(fd, F_SETFL, 0) < 0)
    {
        printf("fcntl failed!\r\n");
        return NCP_STATUS_ERROR;
    }

    if (isatty(STDIN_FILENO) == 0)
    {
        printf("standard input isn't a terminal device\r\n");
        return NCP_STATUS_ERROR;
    }
#endif

    dev->fd  = fd;

    return 0;
}

/*
 * Receive SDIO data.
 */
int sdio_receive(sdio_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes)
{
    ssize_t bytes_read = 0;

    bytes_read = read(dev->fd, buf, len);
    if (bytes_read <= 0)
    {
        if (bytes_read < 0)
        {
           NCP_LOG_ERR("%s: Failed to read SDIO data ret=%ld", __FUNCTION__, bytes_read);
        }
        return -1;
    }
    else
    {
        NCP_LOG_DBG("%s: read SDIO data ret=%ld", __FUNCTION__, bytes_read);
    }

    *nb_bytes = bytes_read;

    return 0;
}

/*
 * Send SDIO data.
 */
int sdio_send(sdio_device_t *dev, uint8_t *buf, uint32_t len)
{
    ssize_t bytes_written;

    NCP_LOG_DBG("SDIO sending %u bytes", len);

    bytes_written = write(dev->fd, buf, len);
    if (bytes_written <= 0)
    {
        NCP_LOG_ERR("%s: Failed to write SDIO data ret=%ld", __FUNCTION__, bytes_written);
        return -1;
    }
    else
    {
        NCP_LOG_DBG("%s: write SDIO data ret=%ld", __FUNCTION__, bytes_written);
    }

    return 0;
}

/*
 * Deinit SDIO instance.
 */
void sdio_deinit(sdio_device_t *dev)
{
    close(dev->fd);
}
#endif /* CONFIG_NCP_SDIO */
