/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "ncp_host_command.h"
#include "ncp_host_app.h"

#ifndef __NCP_CMD_SYSTEM_H__
#define __NCP_CMD_SYSTEM_H__



/* System NCP subclass */
#define NCP_CMD_SYSTEM_CONFIG      0x00000000
#define NCP_CMD_SYSTEM_TEST        0x00100000
#define NCP_CMD_SYSTEM_POWERMGMT   0x00200000
#define NCP_CMD_SYSTEM_ASYNC_EVENT 0x00300000

/* System Configure command */
#define NCP_CMD_SYSTEM_CONFIG_SET              (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_CMD | 0x00000001) /* set-device-cfg */
#define NCP_RSP_SYSTEM_CONFIG_SET              (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_SYSTEM_CONFIG_GET              (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_CMD | 0x00000002) /* get-device-cfg */
#define NCP_RSP_SYSTEM_CONFIG_GET              (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_RESP | 0x00000002) 
#define NCP_CMD_SYSTEM_CONFIG_SDIO_SET         (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_CMD | 0x00000003) /* set-sdio-cfg */
#define NCP_RSP_SYSTEM_CONFIG_SDIO_SET         (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_RESP | 0x00000003) 

#define NCP_CMD_SYSTEM_POWERMGMT_WAKE_CFG      (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000001) /* ncp-wake-cfg */
#define NCP_RSP_SYSTEM_POWERMGMT_WAKE_CFG      (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000001) 
#define NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP     (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000002) /* ncp-mcu-sleep */
#define NCP_RSP_SYSTEM_POWERMGMT_MCU_SLEEP     (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000002) 
#define NCP_CMD_SYSTEM_POWERMGMT_WAKEUP_HOST   (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000003) /* ncp-wakeup-host */
#define NCP_RSP_SYSTEM_POWERMGMT_WAKEUP_HOST   (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000003) 
#define NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000004)
#define NCP_RSP_SYSTEM_POWERMGMT_MCU_SLEEP_CFM (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000004)

#define NCP_EVENT_MCU_SLEEP_ENTER     (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000001)
#define NCP_EVENT_MCU_SLEEP_EXIT      (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000002)

#define NCP_CMD_SYSTEM_TEST_LOOPBACK  (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_TEST | NCP_MSG_TYPE_CMD | 0x00000001) /* test-loopback */
#define NCP_RSP_SYSTEM_TEST_LOOPBACK  (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_TEST | NCP_MSG_TYPE_RESP | 0x00000001)

#define NCP_CMD_SYSTEM_INVALID_CMD    (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_CMD | 0x0000000a) /* invalid command */
#define NCP_RSP_SYSTEM_INVALID_CMD    (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_RESP | 0x0000000a)


#define MODULE_NAME_MAX_LEN 16
#define VAR_NAME_MAX_LEN  32
#define CONFIG_VALUE_MAX_LEN 256

#define MCU_DEVICE_STATUS_ACTIVE 1
#define MCU_DEVICE_STATUS_SLEEP  2

#define NCP_COMMAND_LEN             4096 // The max number bytes which UART can receive.


typedef struct _NCP_CMD_SYSTEM_SDIO_SET
{
    /* value */
    int val;
} NCP_CMD_SYSTEM_SDIO_SET;

/*NCP system configuration*/
typedef struct _NCP_CMD_SYSTEM_CFG
{
    /* the name of system config file: sys, prov, wlan */
    char module_name[MODULE_NAME_MAX_LEN];
    /* the name of entry */
    char variable_name[VAR_NAME_MAX_LEN];
    /* set value/returned result */
    char value[CONFIG_VALUE_MAX_LEN];
} NCP_CMD_SYSTEM_CFG;

typedef struct _NCP_CMD_POWERMGMT_WAKE_CFG
{
    uint8_t wake_mode;
    uint8_t subscribe_evt;
    uint32_t wake_duration;
} NCP_CMD_POWERMGMT_WAKE_CFG;

typedef struct _NCP_CMD_POWERMGMT_MCU_SLEEP
{
    uint8_t enable;
    uint8_t is_manual;
    int rtc_timeout;
} NCP_CMD_POWERMGMT_MCU_SLEEP;

typedef struct _NCP_CMD_POWERMGMT_WAKEUP_HOST
{
    uint8_t enable;
} NCP_CMD_POWERMGMT_WAKEUP_HOST;

typedef struct _SYSTEM_NCPCmd_DS_COMMAND
{
    /** Command Header : Command */
    NCP_COMMAND header;
    /** Command Body */
    union
    {
        /** System configuration */
        NCP_CMD_SYSTEM_CFG system_cfg;
        NCP_CMD_POWERMGMT_WAKE_CFG wake_config;
        NCP_CMD_POWERMGMT_MCU_SLEEP mcu_sleep_config;
		NCP_CMD_SYSTEM_SDIO_SET sdio_set;
        /** wlan host wakeup */
        NCP_CMD_POWERMGMT_WAKEUP_HOST host_wakeup_ctrl;
    } params;

} SYSTEM_NCPCmd_DS_COMMAND;

int ncp_set_command(int argc, char **argv);

int ncp_get_command(int argc, char **argv);

int ncp_set_sdio(uint8_t *buf, uint32_t buf_len, uint32_t val);
int ncp_set_sdio_command(int argc, char **argv);
int ncp_system_app_init();
int ncp_host_system_command_init();
void ncp_system_app_deinit(void);



#endif /* __NCP_CMD_SYSTEM_H__ */
