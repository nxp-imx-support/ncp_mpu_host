/** @file ncp_host_command_system.c
 *
 *  @brief  This file provides API functions to build tlv commands and process tlv responses.
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "ncp_debug.h"
#include "ncp_system_command.h"
#include "ncp_host_command.h"
#include <string.h>
#include "unistd.h"
#include "ncp_tlv_adapter.h"

extern power_cfg_t global_power_config;
extern uint8_t ncp_device_status;
extern pthread_mutex_t gpio_wakeup_mutex;
extern pthread_mutex_t ncp_device_status_mutex;
extern uint8_t cmd_buf[NCP_COMMAND_LEN];

extern int mpu_host_register_commands(const struct mpu_host_cli_command *commands, int num_commands);

SYSTEM_NCPCmd_DS_COMMAND *ncp_host_get_cmd_buffer_sys()
{
    return (SYSTEM_NCPCmd_DS_COMMAND *)(cmd_buf);
}

int ncp_process_set_cfg_response(uint8_t *res)
{
    int ret;
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    ret                                = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_ERROR)
    {
        ncp_e("Failed to set system configuration!");
        return -NCP_FAIL;
    }

    (void)printf("Set system configuration successfully!\r\n");

    return NCP_SUCCESS;
}

int ncp_process_get_cfg_response(uint8_t *res)
{
    int ret;
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    ret                                = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_ERROR)
    {
        ncp_e("Failed to set system configuration!");
        return -NCP_FAIL;
    }

    NCP_CMD_SYSTEM_CFG *sys_cfg = (NCP_CMD_SYSTEM_CFG *)&cmd_res->params.system_cfg;
    (void)printf("%s = %s\r\n", sys_cfg->variable_name, sys_cfg->value);

    return NCP_SUCCESS;
}

/**
 * @brief      This function processes ncp device test loopback response from bridge_app
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int ncp_process_test_loopback_response(uint8_t *res)
{
    int ret;

    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    ret                            = cmd_res->header.result;
    if (ret == NCP_CMD_RESULT_ERROR)
    {
        ncp_e("%s: test loopback failed!", __FUNCTION__);
        return -NCP_FAIL;
    }

    (void)printf("Response test-loopback cmd size=0x%x:\r\n", cmd_res->header.size);

    return NCP_SUCCESS;
}

int ncp_wake_cfg_command(int argc, char **argv)
{
    SYSTEM_NCPCmd_DS_COMMAND *wake_cfg_cmd = (SYSTEM_NCPCmd_DS_COMMAND *)ncp_host_get_cmd_buffer_sys();
    uint8_t wake_mode               = 0;
    uint8_t subscribe_evt           = 0;
#if !CONFIG_NCP_BLE
    uint32_t wake_duration          = 0;
#endif

#if CONFIG_NCP_BLE
    if (argc != 3)
#else
    if (argc != 4)
#endif
    {
        printf("Error: invalid number of arguments\r\n");
        printf("Usage:\r\n");
#if CONFIG_NCP_BLE
        printf("    %s <wake_mode> <subscribe_evt>\r\n", argv[0]);
#else
        printf("    %s <wake_mode> <subscribe_evt> <wake_duration>\r\n", argv[0]);
#endif
        printf("    wake_mode    : INTF -- Interface wakeup\r\n");
        printf("                   GPIO -- GPIO wakeup\r\n");
        printf("                   WIFI-NB -- WIFI/BLE wakeup. For FRDM board only\r\n");
        printf("    subscribe_evt: 1 -- subscribe MPU device sleep status events\r\n");
        printf("                   0 -- no MPU device sleep status events\r\n");
#if !CONFIG_NCP_BLE
        printf("    wake_duration: Within the wake_duration, MCU device will keep active mode\r\n");
        printf("                   Unit is second\r\n");
        printf("Example:\r\n");
        printf("    ncp-wake-cfg INTF 0 5\r\n");
        printf("    ncp-wake-cfg GPIO 1 10\r\n");
#else
        printf("Example:\r\n");
        printf("    ncp-wake-cfg INTF 0\r\n");
        printf("    ncp-wake-cfg GPIO 1\r\n");
#endif
        return -WM_FAIL;
    }
    subscribe_evt = (uint8_t)atoi(argv[2]);
    if (subscribe_evt != 1 && subscribe_evt != 0)
    {
        printf("Invalid value of parameter subscribe_evt\r\n");
        return -WM_FAIL;
    }
    if (string_equal("INTF", argv[1]))
    {
        wake_mode = WAKE_MODE_INTF;
    }
    else if (string_equal("GPIO", argv[1]))
    {
        wake_mode = WAKE_MODE_GPIO;
    }
    else if (!strncmp(argv[1], "WIFI-NB", 7))
    {
        wake_mode = WAKE_MODE_WIFI_NB;
        subscribe_evt = 1;
    }
    else
    {
        printf("Invalid input of wake_mode\r\n");
        return -WM_FAIL;
    }
    wake_cfg_cmd->header.cmd                = NCP_CMD_SYSTEM_POWERMGMT_WAKE_CFG;
    wake_cfg_cmd->header.size               = NCP_CMD_HEADER_LEN;
    wake_cfg_cmd->header.result             = NCP_CMD_RESULT_OK;
    NCP_CMD_POWERMGMT_WAKE_CFG *wake_config = (NCP_CMD_POWERMGMT_WAKE_CFG *)&wake_cfg_cmd->params.wake_config;
    wake_config->wake_mode                  = wake_mode;
    wake_config->subscribe_evt              = subscribe_evt;
#if !CONFIG_NCP_BLE
    wake_duration                           = atoi(argv[3]);
    wake_config->wake_duration              = wake_duration;
#endif
    wake_cfg_cmd->header.size += sizeof(NCP_CMD_POWERMGMT_WAKE_CFG);

    global_power_config.wake_mode     = wake_mode;
    global_power_config.subscribe_evt = subscribe_evt;
#if !CONFIG_NCP_BLE
    global_power_config.wake_duration = wake_duration;
#endif

    return WM_SUCCESS;
}

int ncp_mcu_sleep_command(int argc, char **argv)
{
    SYSTEM_NCPCmd_DS_COMMAND *mcu_sleep_command = ncp_host_get_cmd_buffer_sys();
    uint8_t enable                               = 0;
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
    uint8_t is_manual                            = 0;
#endif
    int rtc_timeout_s                            = 0;

    if (argc < 2 || argc > 4)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("    %s <enable> <mode> <rtc_timeout>\r\n", argv[0]);
        (void)printf("    enable     : enable/disable mcu sleep\r\n");
        (void)printf("                 0 - disable mcu sleep\r\n");
        (void)printf("                 1 - enable mcu sleep\r\n");
        (void)printf("    mode       : Mode of how host enter low power.\r\n");
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
        (void)printf("                 manual - Manual mode. Need to use wlan-suspend command to enter low power.\r\n");
#endif
        (void)printf("                 pm     - Power Manager.\r\n");
        (void)printf("    rtc_timeout: RTC timer value. Unit is second. For Power Manager only!\r\n");
#if (CONFIG_NCP_BLE && CONFIG_NCP_USB)
        (void)printf("                 Note: Will be ignored when using USB interface wakeup!\r\n");
#endif
        (void)printf("Examples:\r\n");
        (void)printf("    ncp-mcu-sleep 1 pm 5\r\n");
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
        (void)printf("    ncp-mcu-sleep 1 manual\r\n");
#endif
        (void)printf("    ncp-mcu-sleep 0\r\n");
        return -NCP_FAIL;
    }
    enable = (uint8_t)atoi(argv[1]);
    if (enable != 0 && enable != 1)
    {
        (void)printf("Invalid value of parameter enable\r\n");
        return -NCP_FAIL;
    }
    if (enable)
    {
        if (argc < 3)
        {
            (void)printf("Invalid number of input!\r\n");
            (void)printf("Usage:\r\n");
            (void)printf("    ncp-mcu-sleep <enable> <mode> <rtc_timer>\r\n");
            return -NCP_FAIL;
        }
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
        if (!strncmp(argv[2], "manual", 6))
            is_manual = 1;
        else
#endif
        if (!strncmp(argv[2], "pm", 2))
        {
            if (argc != 4)
            {
                (void)printf("Error!Invalid number of inputs! Need to specify both <rtc_timeout> and <periodic>\r\n");
                return -NCP_FAIL;
            }
#if CONFIG_NCP_WIFI
#if CONFIG_NCP_USB
            if (global_power_config.wake_mode == WAKE_MODE_INTF)
            {
                (void)printf("Error! For USB interface with INTF mode, pm mode is not allowed\r\n");
                (void)printf("USB device enter/exit PM2 depends on signal from USB host");
                (void)printf("Please use manual mode");
                return -NCP_FAIL;
            }
#endif
#endif
            rtc_timeout_s = atoi(argv[3]);
            if (rtc_timeout_s == 0)
            {
                (void)printf("Error!Invalid value of <rtc_timeout>!\r\n");
                return -NCP_FAIL;
            }
        }
        else
        {
            (void)printf("Invalid input!\r\n");
            (void)printf("Usage:\r\n");
            (void)printf("    ncp-mcu-sleep <enable> <mode> <rtc_timer>\r\n");
            return -NCP_FAIL;
        }
    }
    mcu_sleep_command->header.cmd      = NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP;
    mcu_sleep_command->header.size     = NCP_CMD_HEADER_LEN;
    mcu_sleep_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_POWERMGMT_MCU_SLEEP *mcu_sleep_config =
        (NCP_CMD_POWERMGMT_MCU_SLEEP *)&mcu_sleep_command->params.mcu_sleep_config;
    mcu_sleep_config->enable       = enable;
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
    mcu_sleep_config->is_manual    = is_manual;
#endif
    mcu_sleep_config->rtc_timeout  = rtc_timeout_s;
    mcu_sleep_command->header.size += sizeof(NCP_CMD_POWERMGMT_MCU_SLEEP);

    global_power_config.enable      = enable;
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
    global_power_config.is_manual   = is_manual;
#endif
    global_power_config.rtc_timeout = rtc_timeout_s;
    if (global_power_config.wake_mode == 0)
    {
        global_power_config.wake_mode     = WAKE_MODE_GPIO;
        global_power_config.subscribe_evt = 1;
        global_power_config.wake_duration = 5;
    }
    return NCP_SUCCESS;
}

int ncp_process_wake_cfg_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    uint16_t result                    = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_OK)
        printf("Wake mode cfg is successful!\r\n");
    else
    {
        printf("Wake mode cfg is failed!\r\n");
        global_power_config.wake_mode     = 0;
        global_power_config.subscribe_evt = 0;
        global_power_config.wake_duration = 0;
    }
    return NCP_SUCCESS;
}


int ncp_process_mcu_sleep_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    uint16_t result                    = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_OK)
    {
        (void)printf("MCU sleep cfg is success!\r\n");
        /* Clear previous power configs if mcu sleep is disabled */
        if (global_power_config.enable == 0)
            (void)memset(&global_power_config, 0x0, sizeof(global_power_config));
    }
    else
        (void)printf("MCU sleep cfg is fail!\r\n");

    return NCP_SUCCESS;
}

int ncp_wakeup_host_command(int argc, char **argv)
{
    SYSTEM_NCPCmd_DS_COMMAND *wake_host_cmd = ncp_host_get_cmd_buffer_sys();
    uint8_t enable                           = 0;

    if (argc != 2)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("    %s <0/1>\r\n", argv[0]);
        (void)printf("    0-disable  1-enable\r\n");
#ifdef CONFIG_NCP_WIFI
        (void)printf("Make sure to configure wowlan conditions before enabling host wakeup\r\n");
        (void)printf("Once enabled, MCU only wakes up host if MCU is wokenup by WLAN\r\n");
#endif
        return -NCP_FAIL;
    }
    enable = (uint8_t)atoi(argv[1]);
    if (enable == 1)
    {
#ifdef CONFIG_NCP_WIFI
        if (!global_power_config.is_mef && !global_power_config.wake_up_conds)
        {
            (void)printf("Not configure wowlan conditions yet\r\n");
            (void)printf("Please configure wowlan conditions first\r\n");
            return -NCP_FAIL;
        }
#endif
    }

    wake_host_cmd->header.cmd      = NCP_CMD_SYSTEM_POWERMGMT_WAKEUP_HOST;
    wake_host_cmd->header.size     = NCP_CMD_HEADER_LEN;
    wake_host_cmd->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_POWERMGMT_WAKEUP_HOST *host_wakeup_ctrl =
        (NCP_CMD_POWERMGMT_WAKEUP_HOST *)&wake_host_cmd->params.host_wakeup_ctrl;
    host_wakeup_ctrl->enable        = enable;
    wake_host_cmd->header.size      += sizeof(NCP_CMD_POWERMGMT_WAKEUP_HOST);
    global_power_config.wakeup_host = enable;

    return NCP_SUCCESS;
}

int ncp_process_wakeup_host_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    uint16_t result                    = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_ERROR)
        (void)printf("wakeup host command is failed\r\n");
    else
        (void)printf("wakeup host command is successful\r\n");
    return NCP_SUCCESS;
}

int ncp_get_mcu_sleep_conf_command(int argc, char **argv)
{
    printf("MCU sleep: %s\r\n", global_power_config.enable ? "enabled" : "disabled");
    if (global_power_config.wake_mode == 0)
    {
        global_power_config.wake_mode     = WAKE_MODE_GPIO;
        global_power_config.subscribe_evt = 1;
        global_power_config.wake_duration = 5;
    }
    if (global_power_config.wake_mode == WAKE_MODE_WIFI_NB)
        printf("Wake mode: WIFI-NB\r\n");
    else
        printf("Wake mode: %s\r\n", global_power_config.wake_mode == WAKE_MODE_GPIO ? "GPIO" : "UART");
    printf("Subscribe event: %s\r\n", global_power_config.subscribe_evt ? "enabled" : "disabled");
    printf("Wake duration: %ds\r\n", global_power_config.wake_duration);
#ifdef CONFIG_NCP_WIFI
    printf("Wake up method: %s\r\n", global_power_config.is_mef ? "MEF" : "wowlan");
    if (!global_power_config.is_mef)
        printf("Wakeup bitmap: 0x%x\r\n", global_power_config.wake_up_conds);
    printf("MCU sleep method: %s\r\n", global_power_config.is_manual ? "Manual" : "Power Manager");
#else
    printf("MCU sleep method: Power Manager\r\n");
#endif
    printf("MCU rtc timeout: %ds\r\n", global_power_config.rtc_timeout);
    printf("Wakeup host: %s\r\n", global_power_config.wakeup_host ? "Enabled" : "Disabled");
    return NCP_SUCCESS;
}

/* Display the usage of test-loopback */
static void display_test_loopback_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("\ttest-loopback <string1> <string2> ... <stringN>\r\n");
}

int ncp_test_loopback_command(int argc, char **argv)
{
    int ret = NCP_SUCCESS;
    uint8_t *pos = 0;
    uint32_t copy_size = 0;
    int i = 1;
    SYSTEM_NCPCmd_DS_COMMAND *cmd = ncp_host_get_cmd_buffer_sys();
    (void)memset((uint8_t *)cmd, 0, NCP_COMMAND_LEN);
    cmd->header.cmd      = NCP_CMD_SYSTEM_TEST_LOOPBACK;
    cmd->header.size     = NCP_CMD_HEADER_LEN;
    cmd->header.result   = NCP_CMD_RESULT_OK;

    /* If number of arguments is not even then print error */
    if (argc < 2)
    {
        ret = -NCP_FAIL;
        goto end;
    }

    pos = (uint8_t *)cmd + sizeof(NCP_COMMAND);
    while ((i < argc) && (cmd->header.size < NCP_COMMAND_LEN))
    {
        copy_size = MIN(strlen(argv[i]), NCP_COMMAND_LEN - cmd->header.size);
        memcpy(pos, argv[i], copy_size);
        pos += copy_size;
        cmd->header.size += copy_size;
        //(void)printf("%s: copy_size=0x%x cmd->header.size=0x%x\r\n", __FUNCTION__, copy_size, cmd->header.size);
        //(void)printf("%s: argv[%d]=%s\r\n", __FUNCTION__, i, argv[i]);
        i++;
    }

    return NCP_SUCCESS;

end:
    ncp_e("Incorrect usage");
    display_test_loopback_usage();

    return ret;
}

void ncp_mpu_sleep_cfm(NCP_COMMAND *header)
{
    header->cmd      = NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM;
    header->size     = NCP_CMD_HEADER_LEN;
    header->result   = NCP_CMD_RESULT_OK;
}

int system_process_sleep_status(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *event = (SYSTEM_NCPCmd_DS_COMMAND *)res;

    if (event->header.cmd == NCP_EVENT_MCU_SLEEP_ENTER)
    {
        NCP_COMMAND sleep_cfm;
        int status = 0;
#if !CONFIG_NCP_BLE
        if(global_power_config.subscribe_evt)
            printf("NCP device enters sleep mode!\r\n");
#endif

        /* Wait for command response semaphore. */
        sem_wait(&cmd_sem);

        memset(&sleep_cfm, 0x0, sizeof(sleep_cfm));
        ncp_mpu_sleep_cfm(&sleep_cfm);
        status = (int)ncp_tlv_send((void *)&sleep_cfm, sleep_cfm.size);
        if(status != WM_SUCCESS)
            printf("Failed to send mpu sleep cfm\r\n");

        ncp_device_status = NCP_DEVICE_STATUS_PRE_SLEEP;
        sem_post(&cmd_sem);
        usleep(100000); // Wait 100ms to make sure NCP device enters low power.
        ncp_device_status = NCP_DEVICE_STATUS_SLEEP;
        pthread_mutex_lock(&gpio_wakeup_mutex);

        pthread_mutex_lock(&ncp_device_status_mutex);
        pthread_mutex_unlock(&ncp_device_status_mutex);
    }
    else
    {
#if !CONFIG_NCP_BLE
        if(global_power_config.subscribe_evt)
            printf("NCP device exits sleep mode!\r\n");
#endif
        ncp_device_status = NCP_DEVICE_STATUS_ACTIVE;
        pthread_mutex_unlock(&gpio_wakeup_mutex);
    }
    return WM_SUCCESS;
}

int system_process_event(uint8_t *res)
{
    int ret                        = -NCP_FAIL;
    SYSTEM_NCPCmd_DS_COMMAND *evt = (SYSTEM_NCPCmd_DS_COMMAND *)res;

    switch (evt->header.cmd)
    {
        case NCP_EVENT_MCU_SLEEP_ENTER:
        case NCP_EVENT_MCU_SLEEP_EXIT:
            ret = system_process_sleep_status(res);
            break;
        default:
            printf("Invaild event!\r\n");
            break;
    }
    return ret;
}

/**
 * @brief       This function processes response from ncp device
 *
 * @param res   A pointer to uint8_t
 * @return      Status returned
 */
int system_process_response(uint8_t *res)
{
    int ret                            = -NCP_FAIL;
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    switch (cmd_res->header.cmd)
    {
        case NCP_RSP_SYSTEM_CONFIG_SET:
            ret = ncp_process_set_cfg_response(res);
            break;
        case NCP_RSP_SYSTEM_CONFIG_GET:
            ret = ncp_process_get_cfg_response(res);
            break;
        case NCP_RSP_SYSTEM_TEST_LOOPBACK:
            ret = ncp_process_test_loopback_response(res);
            break;
        case NCP_RSP_SYSTEM_POWERMGMT_WAKE_CFG:
            ret = ncp_process_wake_cfg_response(res);
            break;
        case NCP_RSP_SYSTEM_POWERMGMT_MCU_SLEEP:
            ret = ncp_process_mcu_sleep_response(res);
            break;
        case NCP_RSP_SYSTEM_POWERMGMT_WAKEUP_HOST:
            ret = ncp_process_wakeup_host_response(res);
            break;
        default:
            ncp_e("Invaild response cmd!");
            break;
    }
    return ret;
}



/**
 * @brief  This function prepares set system configuration command
 *
 * @return Status returned
 */
int ncp_set_command(int argc, char **argv)
{
    const char *mod, *var, *val;
    SYSTEM_NCPCmd_DS_COMMAND *sys_cfg_command = (SYSTEM_NCPCmd_DS_COMMAND *)ncp_host_get_cmd_buffer_sys();

    if (argc < 4)
    {
        printf("Error: Invalid parameter number!\r\n");
        return FALSE;
    }

    /* module name */
    mod = argv[1];
    if (*mod == '\0')
    {
        printf("Error: Module name is invalid params!\r\n");
        return FALSE;
    }
    /* variable name */
    var = argv[2];
    if (*var == '\0')
    {
        printf("Error: Variable name is invalid params!\r\n");
        return FALSE;
    }
    /* variable value */
    val = argv[3];
    if (*val == '\0')
    {
        printf("Error: Variable value is invalid params!\r\n");
        return FALSE;
    }

    sys_cfg_command->header.cmd      = NCP_CMD_SYSTEM_CONFIG_SET;
    sys_cfg_command->header.size     = NCP_CMD_HEADER_LEN;
    sys_cfg_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_SYSTEM_CFG *sys_cfg = (NCP_CMD_SYSTEM_CFG *)&sys_cfg_command->params.system_cfg;
    strcpy(sys_cfg->module_name, mod);
    strcpy(sys_cfg->variable_name, var);
    strcpy(sys_cfg->value, val);

    sys_cfg_command->header.size += sizeof(NCP_CMD_SYSTEM_CFG);

    return TRUE;
}

/**
 * @brief  This function prepares get device configuration command
 *
 * @return Status returned
 */
int ncp_get_command(int argc, char **argv)
{
    const char *module, *var;
    SYSTEM_NCPCmd_DS_COMMAND *sys_cfg_command = (SYSTEM_NCPCmd_DS_COMMAND *)ncp_host_get_cmd_buffer_sys();

    if (argc < 3)
    {
        printf("Error: Invalid parameter number!\r\n");
        return FALSE;
    }

    /* module name */
    module = argv[1];
    if (*module == '\0')
    {
        printf("Error: Module name is invalid params!\r\n");
        return FALSE;
    }
    /* variable name */
    var = argv[2];
    if (*var == '\0')
    {
        printf("Error: Variable name is invalid params!\r\n");
        return FALSE;
    }

    sys_cfg_command->header.cmd      = NCP_CMD_SYSTEM_CONFIG_GET;
    sys_cfg_command->header.size     = NCP_CMD_HEADER_LEN;
    sys_cfg_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_SYSTEM_CFG *sys_cfg = (NCP_CMD_SYSTEM_CFG *)&sys_cfg_command->params.system_cfg;
    strcpy(sys_cfg->module_name, module);
    strcpy(sys_cfg->variable_name, var);
    strcpy(sys_cfg->value, "");

    sys_cfg_command->header.size += sizeof(NCP_CMD_SYSTEM_CFG);

    return TRUE;
}

int ncp_set_sdio(uint8_t *buf, uint32_t buf_len, uint32_t val)
{
    SYSTEM_NCPCmd_DS_COMMAND *sys_cfg_command = (SYSTEM_NCPCmd_DS_COMMAND *)buf;

    if (!buf || buf_len < (sizeof(NCP_COMMAND) + sizeof(NCP_CMD_SYSTEM_SDIO_SET)))
    {
        printf("Error: Invalid buf %p or buf_len %u!\r\n", buf, buf_len);
        return FALSE;
    }

    sys_cfg_command->header.cmd      = NCP_CMD_SYSTEM_CONFIG_SDIO_SET;
    sys_cfg_command->header.size     = NCP_CMD_HEADER_LEN;
    sys_cfg_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_SYSTEM_SDIO_SET *sdio_set = (NCP_CMD_SYSTEM_SDIO_SET *)&sys_cfg_command->params.sdio_set;
    sdio_set->val = val;

    sys_cfg_command->header.size += sizeof(NCP_CMD_SYSTEM_SDIO_SET);

    return TRUE;
}

/**
 * @brief  This function prepares set system configuration command
 *
 * @return Status returned
 */
int ncp_set_sdio_command(int argc, char **argv)
{
    int val = 0;
    SYSTEM_NCPCmd_DS_COMMAND *sys_cfg_command = (SYSTEM_NCPCmd_DS_COMMAND *)ncp_host_get_cmd_buffer_sys();

    if (argc < 2)
    {
        printf("Error: Invalid parameter number!\r\n");
        return FALSE;
    }

    /* module name */
    val = atoi(argv[1]);
    if (val <= 0)
    {
        printf("Error: val=%d is invalid params!\r\n", val);
        return FALSE;
    }

    ncp_set_sdio((uint8_t *)sys_cfg_command, NCP_COMMAND_LEN, val);

    return TRUE;
}



/**
 * @brief      command list
 *
 */
static struct mpu_host_cli_command ncp_host_app_cli_commands_system[] = {
#if !(COFNIG_NCP_SDIO_TEST_LOOPBACK)
	{"ncp-set", "<module_name> <variable_name> <value>", ncp_set_command},
	{"ncp-get", "<module_name> <variable_name>", ncp_get_command},
#if 0
	{"ncp-set-sdio", "<value>", ncp_set_sdio_command},
#endif

#else
    {"test-loopback", NULL, ncp_test_loopback_command},
#endif
    {"ncp-wake-cfg", NULL, ncp_wake_cfg_command},
    {"ncp-mcu-sleep", NULL, ncp_mcu_sleep_command},
    {"ncp-wakeup-host", NULL, ncp_wakeup_host_command},
    {"ncp-get-mcu-sleep-config", NULL, ncp_get_mcu_sleep_conf_command},
};

/**
 * @brief      Register ncp_host_cli commands
 *
 * @return     Status returned
 */
int ncp_host_system_command_init()
{
    if (mpu_host_register_commands(ncp_host_app_cli_commands_system,
                                       sizeof(ncp_host_app_cli_commands_system) / sizeof(struct mpu_host_cli_command)) != 0)
        return -NCP_FAIL;

    return NCP_SUCCESS;
}

