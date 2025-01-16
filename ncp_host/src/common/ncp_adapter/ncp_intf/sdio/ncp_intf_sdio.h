/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NCP_INTF_SDIO_H__
#define __NCP_INTF_SDIO_H__

#include <stddef.h>
#include <stdint.h>
#include "ncp_adapter.h"

typedef void (*tlv_send_callback_t)(void *arg);

ncp_status_t ncp_sdio_init(void *argv);
ncp_status_t ncp_sdio_deinit(void *argv);
ncp_status_t ncp_sdio_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb);
ncp_status_t ncp_sdio_receive(uint8_t *tlv_buf, size_t *tlv_sz);
ncp_status_t ncp_sdio_lpm_enter(int32_t pm_state);
ncp_status_t ncp_sdio_lpm_exit(int32_t pm_state);
#endif /* __NCP_INTF_SDIO_H__ */