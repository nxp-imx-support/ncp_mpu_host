/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_host_command_wifi.h"
#include "ncp_cmd_node.h"

typedef struct ncp_current_network_t
{
    uint16_t result;
    NCP_WLAN_NETWORK sta_network;
} ncp_current_network;

char * wlan_ncp_get_state(void);
bool wlan_ncp_remove_network(NCP_WLAN_NETWORK * network);
bool wlan_ncp_add_network(char * ssid, char * key_mgmt, int8_t mode, int8_t frequency, char * network_name);
bool wlan_ncp_disconnect(void);
bool wlan_ncp_scan(void);
bool wlan_ncp_get_scan_result_count(uint8_t * count);
bool wlan_ncp_connect(char * network_name);
int wlan_ncp_get_current_network(NCP_WLAN_NETWORK * net_work);
bool wlan_ncp_remove_all_networks();
int wlan_ncp_get_scan_result(unsigned int index, NCP_WLAN_SCAN_RESULT * res);

