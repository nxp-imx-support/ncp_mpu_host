/*
 * Copyright 2024 - 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef __NCP_ADAPTER_H__
#define __NCP_ADAPTER_H__

#include "ncp_common.h"

ncp_status_t ncp_adapter_init(char * dev_name, int role);
ncp_status_t ncp_adapter_deinit(void);
void         ncp_tlv_install_handler(uint8_t class, void *func_cb);
void         ncp_tlv_uninstall_handler(uint8_t class);

ncp_status_t ncp_tlv_send(void *tlv_buf, size_t tlv_sz);
#endif /* __NCP_ADAPTER_H__ */