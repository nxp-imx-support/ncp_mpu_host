/** @file ncp_host_command_system.c
 *
 *  @brief  This file provides API functions to build tlv commands and process tlv responses.
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "ncp_system_command.h"
#include "ncp_host_command.h"
#include <string.h>
#include "unistd.h"
#include "ncp_tlv_adapter.h"
#if CONFIG_NCP_USE_ENCRYPT
#include "mbedtls_host.h"
#endif
#include "ncp_log.h"

NCP_LOG_MODULE_DECLARE(ncp_system);

extern uint8_t cmd_buf[NCP_COMMAND_LEN];

extern int mpu_host_register_commands(const struct mpu_host_cli_command *commands, int num_commands);

extern sem_t ncp_dev_reset_semaphore;

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
        NCP_LOG_ERR("Failed to set system configuration!");
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
        NCP_LOG_ERR("Failed to set system configuration!");
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
        NCP_LOG_ERR("%s: test loopback failed!", __FUNCTION__);
        return -NCP_FAIL;
    }

    (void)printf("Response test-loopback cmd size=0x%x:\r\n", cmd_res->header.size);

    return NCP_SUCCESS;
}

void ncp_dev_reset_block(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *ncp_dev_reset_command = (SYSTEM_NCPCmd_DS_COMMAND *)res;

    if (ncp_dev_reset_command->header.cmd == NCP_CMD_SYSTEM_CONFIG_DEVICE_RESET)
    {
        sem_wait(&ncp_dev_reset_semaphore);
    }
}

int ncp_dev_reset_command(int argc, char **argv)
{
    SYSTEM_NCPCmd_DS_COMMAND *ncp_dev_reset_command = ncp_host_get_cmd_buffer_sys();

    ncp_dev_reset_command->header.cmd      = NCP_CMD_SYSTEM_CONFIG_DEVICE_RESET;
    ncp_dev_reset_command->header.size     = NCP_CMD_HEADER_LEN;
    ncp_dev_reset_command->header.result   = NCP_CMD_RESULT_OK;

    ncp_adapter_set_cb(ncp_dev_reset_block);

    return NCP_SUCCESS;
}

/**
 * @brief      This function processes device reset response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int ncp_process_dev_reset_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("Failed to reset ncp device\r\n");
        sem_post(&ncp_dev_reset_semaphore);
        ncp_adapter_set_cb(NULL);
        return -NCP_FAIL;
    }

    (void)printf("ncp-dev-reset succeeded!\r\n");

    return NCP_SUCCESS;
}


int ncp_mcu_sleep_command(int argc, char **argv)
{
    SYSTEM_NCPCmd_DS_COMMAND *mcu_sleep_command = ncp_host_get_cmd_buffer_sys();
    NCP_CMD_POWERMGMT_MCU_SLEEP *mcu_sleep_config =
        (NCP_CMD_POWERMGMT_MCU_SLEEP *)&mcu_sleep_command->params.mcu_sleep_config;
    ncp_pm_cfg_t *power_cfg = ncp_pm_get_config();
    uint8_t enable          = 0;
    uint8_t pm_mode         = 0;
    uint32_t timeout_ms     = 0xffffffffUL;

    if (argc < 2 || argc > 4)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("    %s <enable> <pm_mode> <timeout_ms>\r\n", argv[0]);
        (void)printf("    enable     : enable/disable mcu sleep\r\n");
        (void)printf("                 0 - disable mcu sleep\r\n");
        (void)printf("                 1 - enable mcu sleep\r\n");
        (void)printf("    pm_mode    : 1 -- PM1\r\n");
        (void)printf("                 2 -- PM2\r\n");
        (void)printf("                 3 -- PM3\r\n");
        (void)printf("    timeout_ms : duration of enter low power mode (in msec).\r\n");
#if CONFIG_NCP_USB
        (void)printf("                Note: Will be ignored when using USB interface!\r\n");
#endif
        (void)printf("Examples: enter PM2 5s\r\n");
        (void)printf("    ncp-mcu-sleep 1 2 5000\r\n");
        (void)printf("    ncp-mcu-sleep 0\r\n");
        return -NCP_FAIL;
    }

    enable = (uint8_t)atoi(argv[1]);
    if (enable != 0 && enable != 1)
    {
        (void)printf("Invalid value of parameter <enable>\r\n");
        return -NCP_FAIL;
    }

    if (enable)
    {
        pm_mode = (uint8_t)atoi(argv[2]);
        if (pm_mode <1 || pm_mode > 3)
        {
            (void)printf("Invalid power management mode. Must be 1, 2, or 3.\r\n");
            return -NCP_FAIL;
        }

#if CONFIG_NCP_USB
        if (pm_mode == 2)
        {
            (void)printf("Error! For USB interface with PM2 mode is not allowed\r\n");
            (void)printf("USB device enter/exit PM2 depends on signal from USB host");
            return -NCP_FAIL;
        }
#endif
        timeout_ms = atoi(argv[3]);
    }

    mcu_sleep_command->header.cmd      = NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP;
    mcu_sleep_command->header.size     = NCP_CMD_HEADER_LEN;
    mcu_sleep_command->header.result   = NCP_CMD_RESULT_OK;

    mcu_sleep_config->enable       = enable;
    mcu_sleep_config->pm_mode      = pm_mode;
    mcu_sleep_config->timeout      = timeout_ms;
    mcu_sleep_command->header.size += sizeof(NCP_CMD_POWERMGMT_MCU_SLEEP);

    power_cfg->enable  = enable;
    power_cfg->pm_mode = pm_mode;
    power_cfg->timeout = timeout_ms;

    return NCP_SUCCESS;
}

int ncp_process_mcu_sleep_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    uint16_t result                   = cmd_res->header.result;
    ncp_pm_cfg_t *power_cfg           = ncp_pm_get_config();

    if (result == NCP_CMD_RESULT_OK)
    {
        (void)printf("MCU sleep cfg is success!\r\n");
        /* Clear previous power configs if mcu sleep is disabled */
        if (power_cfg->enable == 0)
            (void)memset(power_cfg, 0x0, sizeof(ncp_pm_cfg_t));
    }
    else
    {
        (void)printf("MCU sleep cfg is fail!\r\n");
        power_cfg->enable  = 0;
        power_cfg->pm_mode = 0;
        power_cfg->timeout = 0;
    }

    return NCP_SUCCESS;
}

int ncp_wakeup_host_command(int argc, char **argv)
{
    SYSTEM_NCPCmd_DS_COMMAND *wake_host_cmd = ncp_host_get_cmd_buffer_sys();
    uint8_t enable                          = 0;
    ncp_pm_cfg_t *power_cfg                 = ncp_pm_get_config();

    if (argc != 2)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("    %s <0/1>\r\n", argv[0]);
        (void)printf("    0-disable  1-enable\r\n");
        (void)printf("Make sure to configure wowlan conditions before enabling host wakeup\r\n");
        (void)printf("Once enabled, MCU only wakes up host if MCU is wokenup by WLAN\r\n");
        return -NCP_FAIL;
    }

    enable = (uint8_t)atoi(argv[1]);
    if (enable == 1)
    {
#ifdef CONFIG_NCP_WIFI
        if (!power_cfg->is_mef && !power_cfg->wake_up_conds)
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

    power_cfg->wakeup_host = enable;

    return NCP_SUCCESS;
}

int ncp_process_wakeup_host_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;
    uint16_t result                   = cmd_res->header.result;
    ncp_pm_cfg_t *power_cfg           = ncp_pm_get_config();

    if (result == NCP_CMD_RESULT_ERROR)
    {
        if (power_cfg->wakeup_host)
        {
            power_cfg->wakeup_host = 0;
        }
        (void)printf("wakeup host command is failed\r\n");
    }
    else
        (void)printf("wakeup host command is successful\r\n");
    return NCP_SUCCESS;
}

int ncp_process_host_type_response(uint8_t *res)
{
    SYSTEM_NCPCmd_DS_COMMAND *cmd_res = (SYSTEM_NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("Failed to set ncp host type\r\n");
        return -NCP_FAIL;
    }

    (void)printf("ncp-host-type succeeded!\r\n");

    return NCP_SUCCESS;
}

int ncp_process_dev_reset_event(uint8_t *res)
{
    sem_post(&ncp_dev_reset_semaphore);
    ncp_adapter_set_cb(NULL);
    (void)printf("device reset complete\r\n");

    return NCP_SUCCESS;
}

int ncp_get_mcu_sleep_conf_command(int argc, char **argv)
{
    ncp_pm_cfg_t *power_cfg = ncp_pm_get_config();

    (void)printf("MCU sleep     : %s\r\n", power_cfg->enable ? "enabled" : "disabled");
    (void)printf("PM mode       : PM%d\r\n", power_cfg->pm_mode);
#if CONFIG_NCP_WIFI
    (void)printf("Wake up method: %s\r\n", power_cfg->is_mef ? "MEF" : "wowlan");
    if (!power_cfg->is_mef)
        (void)printf("Wakeup bitmap: 0x%x\r\n", power_cfg->wake_up_conds);
#endif
    (void)printf("Duration      : %d ms\r\n", power_cfg->timeout);
    (void)printf("Wakeup host   : %s\r\n", power_cfg->wakeup_host ? "Enabled" : "Disabled");
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
    NCP_LOG_ERR("Incorrect usage");
    display_test_loopback_usage();

    return ret;
}

int system_process_event(uint8_t *res)
{
    int ret                        = -NCP_FAIL;
    SYSTEM_NCPCmd_DS_COMMAND *evt = (SYSTEM_NCPCmd_DS_COMMAND *)res;

    switch (evt->header.cmd)
    {
#if CONFIG_NCP_USE_ENCRYPT
        case NCP_EVENT_SYSTEM_ENCRYPT:
            ret = ncp_process_encrypt_event(res);
            break;
        case NCP_EVENT_SYSTEM_ENCRYPT_STOP:
            ret = ncp_process_encrypt_stop_event(res);
            break;
#endif
        case NCP_EVENT_SYSTEM_DEV_RESET:
            ret = ncp_process_dev_reset_event(res);
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
        case NCP_RSP_SYSTEM_POWERMGMT_MCU_SLEEP:
            ret = ncp_process_mcu_sleep_response(res);
            break;
        case NCP_RSP_SYSTEM_POWERMGMT_WAKEUP_HOST:
            ret = ncp_process_wakeup_host_response(res);
            break;
#if CONFIG_NCP_USE_ENCRYPT
        case NCP_RSP_SYSTEM_CONFIG_ENCRYPT:
            ret = ncp_process_encrypt_response(res);
            break;
#endif
        case NCP_RSP_SYSTEM_HOST_TYPE:
            ret = ncp_process_host_type_response(res);
            break;
        case NCP_RSP_SYSTEM_CONFIG_DEVICE_RESET:
            ret = ncp_process_dev_reset_response(res);
            break;
        default:
            NCP_LOG_ERR("Invaild response cmd!");
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

int ncp_set_host_type(int host_type)
{
#ifdef CONFIG_NCP_SPI
    SYSTEM_NCPCmd_DS_COMMAND *sys_cfg_command = (SYSTEM_NCPCmd_DS_COMMAND *)ncp_host_get_cmd_buffer_sys();
    NCP_CMD_HOST_TYPE *host_type_para = (NCP_CMD_HOST_TYPE *)&sys_cfg_command->params.host_type;
    host_type_para->host_type = host_type;
    sys_cfg_command->header.cmd      = NCP_CMD_SYSTEM_HOST_TYPE;
    sys_cfg_command->header.size     = NCP_CMD_HEADER_LEN;
    sys_cfg_command->header.result   = NCP_CMD_RESULT_OK;
    sys_cfg_command->header.size += sizeof(NCP_CMD_HOST_TYPE);
    send_tlv_command(NULL);
#endif
    return NCP_SUCCESS;
}

/**
 * @brief      command list
 *
 */
static struct mpu_host_cli_command ncp_host_app_cli_commands_system[] = {
#if !(CONFIG_NCP_SDIO_TEST_LOOPBACK)
	{"ncp-set", "<module_name> <variable_name> <value>", ncp_set_command},
	{"ncp-get", "<module_name> <variable_name>", ncp_get_command},
#else
    {"test-loopback", NULL, ncp_test_loopback_command},
#endif
    {"ncp-mcu-sleep", NULL, ncp_mcu_sleep_command},
    {"ncp-wakeup-host", NULL, ncp_wakeup_host_command},
    {"ncp-get-mcu-sleep-config", NULL, ncp_get_mcu_sleep_conf_command},
#if CONFIG_NCP_USE_ENCRYPT
    {"ncp-encrypt", NULL, ncp_encrypt_command},
    {"ncp-dbg-encrypt-stop", NULL, ncp_dbg_encrypt_stop_command},
#endif
    {"ncp-dev-reset", NULL, ncp_dev_reset_command},
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

