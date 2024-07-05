/** @file ncp_host_app_ot.h
 *
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_HOST_APP_OT_H__
#define __NCP_HOST_APP_OT_H__

#define NCP_TLV_CMD_TYPE 0X01
#define NCP_TLV_CMD_CLASS 0X02
#define NCP_TLV_CMD_SUBCLASS 0X01
#define NCP_TLV_CMD_RESULT 0X00
#define NCP_TLV_CMD_MSGTYPE 0X00
#define OT_CMD_INPUT_BUFF_LEN 256
#define OT_OPCODE_SIZE 1
#define SPACE_CHAR_SIZE 1
#define CARRIAGE_RETURN_CHAR_SIZE 1
#define ASCII_FOR_SPACE 32


int ot_ncp_init(void);
int ot_ncp_deinit(void);

int mpu_host_init_cli_commands_ot(void);
int mpu_host_deinit_cli_commands_ot(void);

#endif /*__NCP_HOST_APP_OT_H__*/
