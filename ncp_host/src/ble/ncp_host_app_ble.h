/** @file ncp_host_app_ble.h
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_HOST_APP_BLE_H__
#define __NCP_HOST_APP_BLE_H__

int ble_ncp_init(void);
int ble_ncp_deinit(void);

int ble_ncp_app_init(void);
int ble_ncp_app_deinit(void);

#endif /*__NCP_HOST_APP_BLE_H__*/
