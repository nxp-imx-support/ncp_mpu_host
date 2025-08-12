/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */

#include "ncp_adapter.h"
#include "ncp_intf_uart.h"
#include "ncp_tlv_adapter.h"
#include "uart.h"

#include "ncp_matter_ble.h"
#include "ncp_host_app_ble.h"

/* -------------------------------------------------------------------------- */
/*                               Variables                                    */
/* -------------------------------------------------------------------------- */

struct bt_conn_cb test_conn_cb;
struct bt_svc_cb test_svc_cb;

/* -------------------------------------------------------------------------- */
/*                           Function prototypes                              */
/* -------------------------------------------------------------------------- */

static void matter_ble_ncp_mainloop(void);
static void matter_ble_call_api(uint8_t *userinputcmd, uint8_t userinputcmd_len);

/* -------------------------------------------------------------------------- */
/*                              Private Functions                             */
/* -------------------------------------------------------------------------- */

static void matter_ble_ncp_mainloop(void)
{
    uint8_t user_cmd[256];
    uint8_t input_cmd_length = 0;
    uint8_t tempcharc;

    while (1)
    {
        /*Receive command from user*/
        scanf("%c", &tempcharc);

        if (tempcharc == '\n')
        {
            /*User pressed enter*/
            if (input_cmd_length != 0)
            {
                matter_ble_call_api(user_cmd, input_cmd_length);
                input_cmd_length   = 0;
            }
            else
            {
                /*No command entered*/
                printf("> ");
                continue;
            }
        }
        else
        {
            /*Continue reading characters from the user*/
            *(user_cmd + input_cmd_length) = tempcharc;
            input_cmd_length++;
        }

    }

    return;
}


void test_connected(uint16_t conId, uint8_t err)
{
    printf("test ble connected, conid: %d, err: %d \n", conId, err);
}

void test_disconnected(uint16_t conId, uint8_t reason)
{
    printf("test ble disconnected, conid: %d, reason: %d \n", conId, reason);
}

void test_rx_write(uint16_t conId, void *buf, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++)
    {
        printf("%d, ", *((uint8_t *)buf + i));
    }
    printf(" -> test done. \n");
}

void test_ccc_config(uint16_t conId, uint16_t value)
{
    printf("test ccc config, conid: %d, value: %d \n", conId, value);
}

void test_tx_ind_confirm(uint16_t conId, uint8_t err)
{
    printf("test indcation confirm, conid: %d, err: %d \n", conId, err);;
}

static void matter_ble_call_api(uint8_t *userinputcmd, uint8_t userinputcmd_len)
{

    /* For easy input, you can enter the first number of function*/

    if (memcmp("set_adv_data", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_set_adv_data \n");

        uint8_t matter_service[10] = {0xF6, 0xFF, 0x00, 0x00, 0x0f, 0xf1, 0xff, 0x05, 0x80, 0x00};
        uint8_t matter_name[10] = {'M', 'a', 't', 't', 'e', 'r', ' ', 'B', 'L', 'E'};

        struct bt_data ad[2];
        ad[0].data_len = 10;
        ad[0].type = 0x16; //BT_DATA_SVC_DATA16
        ad[0].data = matter_service;
        ad[1].data_len = 10;
        ad[1].type = 0x09; //BT_DATA_NAME_COMPLETE
        ad[1].data = matter_name;

        ncp_bt_set_adv_data(ad, 2);
    }
    else if (memcmp("adv_start", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_le_adv_start \n");

        ncp_bt_le_adv_start();
    }
    else if (memcmp("adv_stop", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_le_adv_stop \n");

        ncp_bt_le_adv_stop();
    }
    else if (memcmp("register_conn_cb", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_conn_cb_register \n");

        memset(&test_conn_cb, 0, sizeof(test_conn_cb));
        test_conn_cb.connected = test_connected;
        test_conn_cb.disconnected = test_disconnected;

        ncp_bt_conn_cb_register(&test_conn_cb);
    }
    else if (memcmp("conn_idx", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_conn_index \n");

        uint16_t conn_id = 0;

        ncp_bt_conn_index(conn_id);
    }
    else if (memcmp("conn_ref", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_conn_ref \n");

        uint16_t conn_id = 0;

        ncp_bt_conn_ref(conn_id);
    }
    else if (memcmp("conn_unref", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_conn_unref \n");

        uint16_t conn_id = 0;

        ncp_bt_conn_unref(conn_id);
    }
    else if (memcmp("get_name", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_get_name \n");

        uint16_t conn_id = 0;

        ncp_bt_get_name(conn_id);
    }
    else if (memcmp("get_mtu", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_gatt_get_mtu \n");

        uint16_t conn_id = 0;

        ncp_bt_gatt_get_mtu(conn_id);
    }
    else if (memcmp("conn_disconnect", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_conn_disconnect \n");

        uint16_t conn_id = 0;
        uint8_t reason = 0x16;

        ncp_bt_conn_disconnect(conn_id, reason);
    }
    else if (memcmp("register_service", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_gatt_service_register \n");

        ncp_bt_gatt_service_register();
    }
    else if (memcmp("register_svc_cb", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_matter_svc_cb_register \n");

        memset(&test_svc_cb, 0, sizeof(test_svc_cb));
        test_svc_cb.rx_write_cb = test_rx_write;
        test_svc_cb.tx_ccc_write_cb = test_ccc_config;
        test_svc_cb.tx_ind_confirm_cb = test_tx_ind_confirm;

        ncp_bt_matter_svc_cb_register(&test_svc_cb);
    }
    else if (memcmp("unregister_service", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_gatt_service_unregister \n");

        ncp_bt_gatt_service_unregister();
    }
    else if (memcmp("send_indicate", userinputcmd, userinputcmd_len) == 0)
    {
        printf("call: ncp_bt_gatt_indicate \n");

        uint16_t conn_id = 0;
        uint8_t data[8] = {'I', 'n', 'd', 'i', 'c', 'a', 't', 'e'};

        ncp_bt_gatt_indicate(conn_id, data, sizeof(data));
    }
    


    return;
}

/*
**-----------------------------------------------------------------
**
**                    __  __       _       
**                   |  \/  | __ _(_)_ __  
**                   | |\/| |/ _` | | '_ \ 
**                   | |  | | (_| | | | | |
**                   |_|  |_|\__,_|_|_| |_|
**
**-----------------------------------------------------------------
*/

/**
 * @brief Main entry.
 *
 * Test matter ncp ble api.
 * Note: resolve main function redefine conflict with ncp_host_app.c before building.
 */
void main_o(int argc, char *argv[])
{
    int ret;

    ret = ncp_adapter_init(argv[1]);

    if (ret != NCP_STATUS_SUCCESS)
    {
        printf("ERROR: ncp_adapter_init \n");
    }

    ret = ble_ncp_init();

    if ( ret != NCP_STATUS_SUCCESS)
    {
        printf("ERROR: ble_ncp_init \n");
    }

    printf("> ");

    /*Call main task*/
    matter_ble_ncp_mainloop();

    return;
}

