/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NCP_INTF_SDIO_H__
#define __NCP_INTF_SDIO_H__

#include "ncp_host_command.h"

typedef struct _NCP_CMD_SDIO_SET
{
    /** Command Header : Command */
    NCP_COMMAND header;
    /* value */
    int val;
} NCP_CMD_SDIO_SET;

#endif /* __NCP_INTF_SDIO_H__ */
