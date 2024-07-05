/** @file ncp_host_app_wifi.h
 *
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_HOST_APP_WIFI_H__
#define __NCP_HOST_APP_WIFI_H__

int wifi_ncp_init();
int wifi_ncp_deinit();

int wifi_ncp_app_init();
int wifi_ncp_app_deinit();

int wifi_ncp_app_task_init(void *send_data, void *recv_data);
int wifi_ncp_app_task_deinit();

#endif /*__NCP_HOST_APP_WIFI_H__*/
