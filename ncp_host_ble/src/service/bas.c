/** @file bas.c
 *
 *  @brief  This file provides the battery service profile.
 *
 *  Copyright 2023 - 2024 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <semaphore.h>
#include <unistd.h>

#include <mpu_bridge_command.h>
#include <mpu_bridge_app.h>


#include <service.h>
#include <bas.h>

#if defined(CONFIG_NCP_BAS)

/**
 * @brief Battery Service (BAS)
 * @defgroup bt_hts Battery Service (BAS)
 * @ingroup bluetooth
 * @{
 */

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern send_data_t *service_S_D;
extern sem_t bas_sem;
extern sem_t cmd_sem;
extern pthread_t bas_service_thread;
// ble-set-value command paramters
static uint8_t battery_level = 100U;
MCP_SET_VALUE_CMD bas_value;
bool bas_cccd_written = false;
/*******************************************************************************
 * Prototypes
 ******************************************************************************/


/*******************************************************************************
 * Definitions
 ******************************************************************************/
static struct host_gatt_attr bas_profile [] = {
    /* BAS Primary Serivce Declaration */
    GATT_PRIMARY_SERVICE(UUID_BAS),
    /* BAS Level Charatristic Declaration */
    GATT_CHARACTERISTIC(UUID_BAS_BATTERY_LEVEL, BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_NONE),
    /* Client Characteristic Configuration of BAS battery level */
    GATT_CCC(BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
};
/*******************************************************************************
 * Code
 ******************************************************************************/
static void peripheral_bas_send_tlv_command(void)
{
    if(service_S_D != NULL)
    {
        send_tlv_command(service_S_D);
    }
    else
    {
        printf("Failed to send command! Unknow serial port.\r\n");
    }
}

void peripheral_bas_event_put(void)
{
    sem_post(&bas_sem);
}

void peripheral_bas_start(void)
{
    static bool is_started = false;
    if(!is_started)
    {
        is_started = true;
        if (sem_init(&bas_sem, 0, 1) == -1)
        {
            printf("Failed to init service semaphore!\r\n");
            exit(EXIT_FAILURE);
        }
        sem_wait(&bas_sem);
        bas_service_thread = pthread_create(&bas_service_thread, NULL, (void *)peripheral_bas_task, NULL);
        if (bas_service_thread != 0)
        {
            printf("Failed to creat bas service Thread!\r\n");
            exit(EXIT_FAILURE);
        }
        else
        {
            printf("Success to create bas service Thread!\r\n");
        }
        printf("BAS profile at host side starting...\n");
        return;
    }
    printf("BAS profile at host side already started\n");
    return;
}

void peripheral_bas_indicate(uint8_t value)
{
    bas_cccd_written = (value == BT_GATT_CCC_NOTIFY) ? true : false;
}

void peripheral_bas_task(void)
{
    /* Battery level measurements simulation */
    int argc = ARRAY_SIZE(bas_profile);
    int arg = 0;

    NCPCmd_DS_COMMAND *host_service_add_command     = ncp_mpu_bridge_get_command_buffer();
    MCP_CMD_SERVICE_ADD *host_service_add_tlv       = (MCP_CMD_SERVICE_ADD *)&host_service_add_command->params.host_svc_add;
    uint8_t *ptlv_pos                               = host_service_add_tlv->tlv_buf;
    uint32_t tlv_buf_len                            = 0;
    gatt_add_service_cmd_t *add_service_tlv         = NULL;
    gatt_add_characteristic_cmd_t *add_chrc_tlv     = NULL;
    gatt_add_descriptor_cmd_t *add_desc_tlv         = NULL;

    //wait ble-start-service command
    sem_wait(&cmd_sem);
    printf("Send 'ble-host-svc-add prim 180f chrc 2a19 10 00 ccc 2902 03 start' to add BAS profile to ncp device side\n");

    do
    {
        if(bas_profile[arg].type == NCP_BRIDGE_CMD_GATT_ADD_SERVICE_TLV)
        {
            add_service_tlv = (gatt_add_service_cmd_t *)ptlv_pos;
            add_service_tlv->type = 0;// primary service
            add_service_tlv->uuid_length = bas_profile[arg].uuid_length;
            memcpy(add_service_tlv->uuid, bas_profile[arg].uuid, add_service_tlv->uuid_length);
            add_service_tlv->header.type = NCP_BRIDGE_CMD_GATT_ADD_SERVICE_TLV;
            add_service_tlv->header.size = sizeof(gatt_add_service_cmd_t) - NCP_BRIDGE_TLV_HEADER_LEN - (SERVER_MAX_UUID_LEN - add_service_tlv->uuid_length);

            ptlv_pos += add_service_tlv->header.size + NCP_BRIDGE_TLV_HEADER_LEN;
            tlv_buf_len += add_service_tlv->header.size + NCP_BRIDGE_TLV_HEADER_LEN;
            arg ++;
        }
        else if(bas_profile[arg].type == NCP_BRIDGE_CMD_GATT_ADD_CHRC_TLV)
        {
            add_chrc_tlv = (gatt_add_characteristic_cmd_t *)ptlv_pos;
            add_chrc_tlv->svc_id = 0;
            add_chrc_tlv->uuid_length = bas_profile[arg].uuid_length;
            memcpy(add_chrc_tlv->uuid, bas_profile[arg].uuid, add_chrc_tlv->uuid_length);
            add_chrc_tlv->properties = bas_profile[arg].properties;
            add_chrc_tlv->permissions = bas_profile[arg].permissions;

            add_chrc_tlv->header.type = NCP_BRIDGE_CMD_GATT_ADD_CHRC_TLV;
            add_chrc_tlv->header.size = sizeof(gatt_add_characteristic_cmd_t) - NCP_BRIDGE_TLV_HEADER_LEN - (SERVER_MAX_UUID_LEN - add_chrc_tlv->uuid_length);
            ptlv_pos += add_chrc_tlv->header.size + NCP_BRIDGE_TLV_HEADER_LEN;
            tlv_buf_len += add_chrc_tlv->header.size + NCP_BRIDGE_TLV_HEADER_LEN;
            arg ++;

        }
        else if(bas_profile[arg].type == NCP_BRIDGE_CMD_GATT_ADD_DESC_TLV)
        {
            add_desc_tlv = (gatt_add_descriptor_cmd_t *)ptlv_pos;
            add_desc_tlv->char_id = 0;
            add_desc_tlv->uuid_length = bas_profile[arg].uuid_length;
            memcpy(add_desc_tlv->uuid, bas_profile[arg].uuid, add_desc_tlv->uuid_length);
            add_desc_tlv->permissions = bas_profile[arg].permissions;

            add_desc_tlv->header.type = NCP_BRIDGE_CMD_GATT_ADD_DESC_TLV;
            add_desc_tlv->header.size = sizeof(gatt_add_descriptor_cmd_t) - NCP_BRIDGE_TLV_HEADER_LEN - (SERVER_MAX_UUID_LEN - add_desc_tlv->uuid_length);
            ptlv_pos += add_desc_tlv->header.size + NCP_BRIDGE_TLV_HEADER_LEN;
            tlv_buf_len += add_desc_tlv->header.size + NCP_BRIDGE_TLV_HEADER_LEN;
            arg ++;
        }
    } while (arg < argc);

#if defined(NCP_BLE_HOST_SERVICE_AUTO_START)
    gatt_start_service_cmd_t *start_service_tlv = (gatt_start_service_cmd_t *)ptlv_pos;

    start_service_tlv->started = 1;
    start_service_tlv->header.type = NCP_BRIDGE_CMD_GATT_START_SVC_TLV;
    start_service_tlv->header.size = sizeof(gatt_start_service_cmd_t) - NCP_BRIDGE_TLV_HEADER_LEN;
    ptlv_pos += sizeof(gatt_start_service_cmd_t);
    tlv_buf_len += sizeof(gatt_start_service_cmd_t);
#endif

    host_service_add_tlv->tlv_buf_len = tlv_buf_len;

    host_service_add_command->header.cmd      = NCP_BRIDGE_CMD_BLE_HOST_SERVICE_ADD;
    host_service_add_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN + sizeof(host_service_add_tlv->tlv_buf_len) + tlv_buf_len;
    host_service_add_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
    host_service_add_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

    /* Send host service add command */
    peripheral_bas_send_tlv_command();

    while(1)
    {
        if(bas_cccd_written)
        {
            /* battery level simulation */
            battery_level--;
	    if (!battery_level) {
		    battery_level = 100U;
	    }

            bas_value.uuid_length = 2;
            bas_value.uuid[0] = (UUID_BAS_BATTERY_LEVEL >> 0) & 0xFF;
            bas_value.uuid[1] = (UUID_BAS_BATTERY_LEVEL >> 8) & 0xFF;
            bas_value.len = 1;
            memcpy(&bas_value.value, &battery_level, 1);

            //send Set value command
            write_charateristic_command_local(&bas_value);
            peripheral_bas_send_tlv_command();
            sem_wait(&bas_sem);
        }
        sleep(1);
    }
}
#endif
