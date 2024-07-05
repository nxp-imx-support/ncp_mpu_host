/** @file hrs.c
 *
 *  @brief  This file provides the health rate service profile.
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
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

#include <ncp_host_command_ble.h>
#include <ncp_host_app.h>


#include <service.h>
#include <hr.h>

#ifdef CONFIG_NCP_HRS

/**
 * @brief Health Rate Service (HRS)
 * @defgroup bt_hrs Health Rate Service (HRS)
 * @ingroup bluetooth
 * @{
 */

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern send_data_t *service_S_D;
extern sem_t hrs_sem;
extern sem_t cmd_sem;
extern pthread_t hrs_service_thread;

static uint8_t heartrate = 90U;
static uint8_t hrm[2];
// ble-set-value command paramters
MCP_SET_VALUE_CMD hrs_value;
bool hrs_cccd_written = false;
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Definitions
 ******************************************************************************/
static struct host_gatt_attr hrs_profile [] = {
    /* HRS Promary Serivce Declaration */
    GATT_PRIMARY_SERVICE(UUID_HRS),
    /* HRS Measurement Charatristic Declaration */
    GATT_CHARACTERISTIC(UUID_HRS_MEASUREMENT, BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_NONE),
    /* Client Characteristic Configuration of HRS MeasurementDeclaration */
    GATT_CCC(BT_GATT_PERM_READ | BT_GATT_PERM_WRITE), 
    /* HRS Body Charatristic Declaration */
    GATT_CHARACTERISTIC(UUID_HRS_BODY_SENSOR, BT_GATT_CHRC_INDICATE, BT_GATT_PERM_READ),
    /* HRS Control Charatristic Declaration */
    GATT_CHARACTERISTIC(UUID_HRS_CONTROL_POINT, BT_GATT_CHRC_INDICATE, BT_GATT_PERM_NONE),
};
/*******************************************************************************
 * Code
 ******************************************************************************/
static void peripheral_hrs_send_tlv_command(void)
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

void peripheral_hrs_event_put(void)
{
    sem_post(&hrs_sem);
}

void peripheral_hrs_start(void)
{
    static bool is_started = false;
    if(!is_started)
    {
        is_started = true;
        if (sem_init(&hrs_sem, 0, 1) == -1)
        {
            printf("Failed to init service semaphore!\r\n");
            exit(EXIT_FAILURE);
        }
        sem_wait(&hrs_sem);
        hrs_service_thread = pthread_create(&hrs_service_thread, NULL, (void *)peripheral_hrs_task, NULL);
        if (hrs_service_thread != 0)
        {
            printf("Failed to create hrs service Thread!\r\n");
            exit(EXIT_FAILURE);
        }
        else
        {
            printf("Success to create hrs service Thread!\r\n");
        }
        printf("HRS profile at host side starting...\n");
        return;
    }
    printf("HRS profile at host side already started\n");
    return;
}

void peripheral_hrs_indicate(uint8_t value)
{
    hrs_cccd_written = (value == BT_GATT_CCC_NOTIFY) ? true : false;
}

void peripheral_hrs_task(void)
{
    int argc = ARRAY_SIZE(hrs_profile);
    int arg = 0;

    NCPCmd_DS_COMMAND *host_service_add_command     = mpu_host_get_ble_command_buffer();
    MCP_CMD_SERVICE_ADD *host_service_add_tlv       = (MCP_CMD_SERVICE_ADD *)&host_service_add_command->params.host_svc_add;
    uint8_t *ptlv_pos                               = host_service_add_tlv->tlv_buf;
    uint32_t tlv_buf_len                            = 0;
    gatt_add_service_cmd_t *add_service_tlv         = NULL;
    gatt_add_characteristic_cmd_t *add_chrc_tlv     = NULL;
    gatt_add_descriptor_cmd_t *add_desc_tlv         = NULL;

    //wait ble-start-service command
    sem_wait(&cmd_sem);
    printf("Send 'ble-host-svc-add prim 180d chrc 2a37 10 00 ccc 2902 03 chrc 2a38 20 01 chrc 2a39 20 00 start' to add HRS profile to ncp device side\n");

    do
    {
        if(hrs_profile[arg].type == NCP_CMD_GATT_ADD_SERVICE_TLV)
        {
            add_service_tlv = (gatt_add_service_cmd_t *)ptlv_pos;
            add_service_tlv->type = 0;// primary service
            add_service_tlv->uuid_length = hrs_profile[arg].uuid_length;
            memcpy(add_service_tlv->uuid, hrs_profile[arg].uuid, add_service_tlv->uuid_length);
            add_service_tlv->header.type = NCP_CMD_GATT_ADD_SERVICE_TLV;
            add_service_tlv->header.size = sizeof(gatt_add_service_cmd_t) - NCP_TLV_HEADER_LEN - (SERVER_MAX_UUID_LEN - add_service_tlv->uuid_length);

            ptlv_pos += add_service_tlv->header.size + NCP_TLV_HEADER_LEN;
            tlv_buf_len += add_service_tlv->header.size + NCP_TLV_HEADER_LEN;
            arg ++;
        }
        else if(hrs_profile[arg].type == NCP_CMD_GATT_ADD_CHRC_TLV)
        {
            add_chrc_tlv = (gatt_add_characteristic_cmd_t *)ptlv_pos;
            add_chrc_tlv->svc_id = 0;
            add_chrc_tlv->uuid_length = hrs_profile[arg].uuid_length;
            memcpy(add_chrc_tlv->uuid, hrs_profile[arg].uuid, add_chrc_tlv->uuid_length);
            add_chrc_tlv->properties = hrs_profile[arg].properties;
            add_chrc_tlv->permissions = hrs_profile[arg].permissions;

            add_chrc_tlv->header.type = NCP_CMD_GATT_ADD_CHRC_TLV;
            add_chrc_tlv->header.size = sizeof(gatt_add_characteristic_cmd_t) - NCP_TLV_HEADER_LEN - (SERVER_MAX_UUID_LEN - add_chrc_tlv->uuid_length);
            ptlv_pos += add_chrc_tlv->header.size + NCP_TLV_HEADER_LEN;
            tlv_buf_len += add_chrc_tlv->header.size + NCP_TLV_HEADER_LEN;
            arg ++;

        }
        else if(hrs_profile[arg].type == NCP_CMD_GATT_ADD_DESC_TLV)
        {
            add_desc_tlv = (gatt_add_descriptor_cmd_t *)ptlv_pos;
            add_desc_tlv->char_id = 0;
            add_desc_tlv->uuid_length = hrs_profile[arg].uuid_length;
            memcpy(add_desc_tlv->uuid, hrs_profile[arg].uuid, add_desc_tlv->uuid_length);
            add_desc_tlv->permissions = hrs_profile[arg].permissions;

            add_desc_tlv->header.type = NCP_CMD_GATT_ADD_DESC_TLV;
            add_desc_tlv->header.size = sizeof(gatt_add_descriptor_cmd_t) - NCP_TLV_HEADER_LEN - (SERVER_MAX_UUID_LEN - add_desc_tlv->uuid_length);
            ptlv_pos += add_desc_tlv->header.size + NCP_TLV_HEADER_LEN;
            tlv_buf_len += add_desc_tlv->header.size + NCP_TLV_HEADER_LEN;
            arg ++;
        }
    } while (arg < argc);

#if defined(NCP_BLE_HOST_SERVICE_AUTO_START)
    gatt_start_service_cmd_t *start_service_tlv = (gatt_start_service_cmd_t *)ptlv_pos;

    start_service_tlv->started = 1;
    start_service_tlv->header.type = NCP_CMD_GATT_START_SVC_TLV;
    start_service_tlv->header.size = sizeof(gatt_start_service_cmd_t) - NCP_TLV_HEADER_LEN;
    ptlv_pos += sizeof(gatt_start_service_cmd_t);
    tlv_buf_len += sizeof(gatt_start_service_cmd_t);
#endif

    host_service_add_tlv->tlv_buf_len = tlv_buf_len;

    host_service_add_command->header.cmd      = NCP_CMD_BLE_HOST_SERVICE_ADD;
    host_service_add_command->header.size     = NCP_CMD_HEADER_LEN + sizeof(host_service_add_tlv->tlv_buf_len) + tlv_buf_len;
    host_service_add_command->header.result   = NCP_CMD_RESULT_OK;

    /* Send host service add command */
    peripheral_hrs_send_tlv_command();

    while(1)
    {
        if(hrs_cccd_written)
        {
            /* Heartrate measurements simulation */
            heartrate++;
            if (heartrate == 160U) {
                heartrate = 90U;
            }
            hrm[0] = 0x06; /* uint8, sensor contact */
            hrm[1] = heartrate;

            hrs_value.uuid_length = 2;
            hrs_value.uuid[0] = (UUID_HRS_MEASUREMENT >> 0) & 0xFF;
            hrs_value.uuid[1] = (UUID_HRS_MEASUREMENT >> 8) & 0xFF;
            hrs_value.len = 2;
            memcpy(&hrs_value.value, hrm, 2);

            //send Set value command
            write_charateristic_command_local(&hrs_value);
            peripheral_hrs_send_tlv_command();
            sem_wait(&hrs_sem);
        }
        sleep(1);
    }
}
#endif
