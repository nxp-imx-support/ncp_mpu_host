/*
 * Copyright 2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
 
 #ifndef __OT_REDEFINED_CMDS_H__
 #define __OT_REDEFINED_CMDS_H__

 /* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */

#include <stdint.h>
#include "ncp_host_command.h"

/* -------------------------------------------------------------------------- */
/*                              Constants                                     */
/* -------------------------------------------------------------------------- */

/* Please use this file with caution, there is no separate system module in ot standalone.
 * We should redefine sleep related macros to handle in ot cmd.
 */
#undef NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM
#undef NCP_RSP_SYSTEM_POWERMGMT_MCU_SLEEP_CFM
#undef NCP_EVENT_MCU_SLEEP_ENTER
#undef NCP_EVENT_MCU_SLEEP_EXIT

#define NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM (NCP_CMD_15D4 | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000004)
#define NCP_RSP_SYSTEM_POWERMGMT_MCU_SLEEP_CFM (NCP_CMD_15D4 | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_EVENT_MCU_SLEEP_ENTER              (NCP_CMD_15D4 | NCP_CMD_SYSTEM_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000001)
#define NCP_EVENT_MCU_SLEEP_EXIT               (NCP_CMD_15D4 | NCP_CMD_SYSTEM_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000002)


/* Please use this file with caution, there is no separate system module in ot standalone.
 * In order to use host mbedtls, we need to redefine the ENCRYPT related macros(as an ot cmd). 
 */
#undef NCP_CMD_SYSTEM_CONFIG_ENCRYPT
#undef NCP_RSP_SYSTEM_CONFIG_ENCRYPT
#undef NCP_EVENT_SYSTEM_ENCRYPT
#undef NCP_EVENT_SYSTEM_ENCRYPT_STOP

#define NCP_CMD_SYSTEM_CONFIG_ENCRYPT (NCP_CMD_15D4 | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_CMD | 0x00000003)
#define NCP_RSP_SYSTEM_CONFIG_ENCRYPT (NCP_CMD_15D4 | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_EVENT_SYSTEM_ENCRYPT      (NCP_CMD_15D4 | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_EVENT | 0x00000003)
#define NCP_EVENT_SYSTEM_ENCRYPT_STOP (NCP_CMD_15D4 | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_EVENT | 0x00000004)

#endif /* __OT_REDEFINED_CMDS_H__ */