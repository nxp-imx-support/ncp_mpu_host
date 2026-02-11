/** @file ncp_host_command_system.h
 *
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_HOST_COMMAND_SYSTEM_H__
#define __NCP_HOST_COMMAND_SYSTEM_H__

/**
 * This API is used to set a configuration parameter value in flash.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 4.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: ncp-set \n
 *                    argv[1]: string value of module_name (Required) \n
 *                             This parameter takes a valid module name. \n
 *                    argv[2]: string value of variable_name (Required) \n
 *                             This parameter takes a valid parameter name under the module name specified. \n
 *                    argv[3]: string value of value (Required) \n
 *                             This parameter takes a valid value for the module name and parameter name specified. \n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int ncp_set_command(int argc, char **argv);

/**
 * This API can be used to process set configuration response.
 *
 * \param[in] res    A pointer to \ref SYSTEM_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int ncp_process_set_cfg_response(uint8_t *res);

/**
 * This API is used to get a configuration parameter value in flash.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 3.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: ncp-get \n
 *                    argv[1]: string value of module_name (Required) \n
 *                             This parameter takes a valid module name. \n
 *                    argv[2]: string value of variable_name (Required) \n
 *                             This parameter takes a valid parameter name under the module name specified. \n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int ncp_get_command(int argc, char **argv);

/**
 * This API can be used to process get configuration response.
 *
 * \param[in] res    A pointer to \ref SYSTEM_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int ncp_process_get_cfg_response(uint8_t *res);

/**
 * This API is used to do ncp device reset processing.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: ncp-dev-reset
 *
 * \return WM_SUCCESS if success.
 */
int ncp_dev_reset_command(int argc, char **argv);

/**
 * This API is used to process the response for the ncp device reset command.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response. \n
 *                   Response body refer to \ref NCP_CMD_SYSTEM_CONFIG_DEVICE_RESET.
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 */
int ncp_process_dev_reset_response(uint8_t *res);
#endif /* __NCP_HOST_COMMAND_SYSTEM_H__ */