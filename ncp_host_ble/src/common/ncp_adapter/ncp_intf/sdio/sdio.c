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
#include "sdio.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/
/*
 * Init SDIO instance.
 */
ncp_status_t sdio_init(sdio_device_t *dev)
{
    int             fd;

    fd = open((char *)(dev->instance), O_RDWR | O_NOCTTY);
    if (fd < 0)
    {
        ncp_adap_e("Failed to open SDIO instance \n");
        return NCP_STATUS_ERROR;
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

    return NCP_STATUS_SUCCESS;
}

/*
 * Receive SDIO data.
 */
ncp_status_t sdio_receive(sdio_device_t *dev, uint8_t *buf, uint32_t len, size_t *nb_bytes)
{
    ssize_t ret = 0;

    ret = read(dev->fd, buf, len);
    if (ret <= 0)
    {
        if (ret < 0)
        {
            ncp_adap_e("%s: Failed to read SDIO data ret=%ld", __FUNCTION__, ret);
        }
        return NCP_STATUS_ERROR;
    }
    else
    {
        ncp_adap_d("%s: read SDIO data ret=%ld", __FUNCTION__, ret);
    }
    *nb_bytes = ret;

    return NCP_STATUS_SUCCESS;
}

/*
 * Send SDIO data.
 */
ncp_status_t sdio_send(sdio_device_t *dev, uint8_t *buf, uint32_t len)
{
    ssize_t ret = 0;

    ret = write(dev->fd, buf, len);
    if (ret <= 0)
    {
        ncp_adap_e("%s: Failed to write SDIO data ret=%ld", __FUNCTION__, ret);
        return NCP_STATUS_ERROR;
    }
    else
    {
        ncp_adap_d("%s: write SDIO data ret=%ld", __FUNCTION__, ret);
    }

    return NCP_STATUS_SUCCESS;
}

/*
 * Deinit SDIO instance.
 */
void sdio_deinit(sdio_device_t *dev)
{
    close(dev->fd);
}
