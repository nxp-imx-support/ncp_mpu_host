/** @file hrc.c
 *
 *  @brief  This file provides the Heart Rate client proflie.
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

#ifdef CONFIG_NCP_HRC
/**
 * @brief Heart Rate Client (HRC)
 * @defgroup bt_hrs Heart Rate Client (HRC)
 * @ingroup bluetooth
 * @{
 */

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern send_data_t *service_S_D;
extern sem_t hrc_sem;

// ble-set-value command paramters
le_addr_t hrc_conn_addrss;
MCP_DISC_PRIM_UUID_CMD hrc_discover_primary;
MCP_DISC_CHRC_UUID_CMD hrc_discover_characteristics;
MCP_DISC_CHRC_UUID_CMD hrc_discover_descriptors;
// NCP_CFG_INDICATE_CMD hrc_cfg_indicate;


// static bool is_found = false;
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
static void central_hrc_send_tlv_command(void)
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

void central_hrc_start(void)
{
    NCPCmd_DS_COMMAND *start_service_command = mpu_host_get_ble_command_buffer();
    (void)memset((uint8_t *)start_service_command, 0, NCP_COMMAND_LEN);

    start_service_command->header.cmd      = NCP_CMD_BLE_GATT_START_SERVICE;
    start_service_command->header.size     = NCP_CMD_HEADER_LEN;
    start_service_command->header.result   = NCP_CMD_RESULT_OK;

    MCP_CMD_START_SERVICE *start_service = (MCP_CMD_START_SERVICE *)&start_service_command->params.host_start_svc;

    start_service->svc_id = 5; //Central_HRC
    start_service->form_host = 1;

    start_service_command->header.size += sizeof(MCP_CMD_START_SERVICE);
    
    printf("HRC profile at host side starting...\n");
    central_hrc_send_tlv_command();
    return;
}
#if 0
void central_hrc_event_put(void)
{
    sem_post(&hrc_sem);
}

void central_notify(uint8_t *data)
{
    struct temp_measurement temp_measurement;
    uint32_t temperature;

    /* temperature value display */
    temp_measurement = *(struct temp_measurement*)data;
    temperature = sys_get_le32(temp_measurement.temperature);

    if ((temp_measurement.flags & 0x01) == hts_unit_celsius_c)
    {
        printf("Temperature %d degrees Celsius \n", temperature);
    }
    else
    {
        printf("Temperature %d degrees Fahrenheit \n", temperature);
    }
}

void central_hrc_found(NCP_DEVICE_ADV_REPORT_EV * data)
{
    uint8_t len = 0;
    uint16_t uuid;
    
    while((len < data->eir_data_len) && !is_found)
    {
        adv_data_t adv_data;
        adv_data.data_len = data->eir_data[len ++];
        adv_data.type = data->eir_data[len ++];
        adv_data.data = &(data->eir_data[len]);
        len += (adv_data.data_len - 1);

        /* search for the HTS UUID in the advertising data */
        if((adv_data.type == BT_DATA_UUID16_ALL) || (adv_data.type == BT_DATA_UUID16_SOME))
        {
            if ((adv_data.data_len - 1) % sizeof(uint16_t) != 0U)
            {
                (void)printf("AD malformed\n");
                break;
            }
            for (uint8_t i = 0; i < adv_data.data_len; i += sizeof(uint16_t))
            {
                memcpy(&uuid, &adv_data.data[i], sizeof(uuid));
                if(uuid == UUID_HTS)
                {
                    (void)printf("Found the temperature server - stop scanning\n");
                    memcpy(hrc_conn_addrss.address, data->address, 6);
                    hrc_conn_addrss.type = data->address_type;
                    is_found = true;
                    ble_stop_scan_command(0, NULL);
                    central_hrc_send_tlv_command();
                    return;
                }
            }
        }
    }
}

void central_hrc_get_primary_service(MCP_DISC_PRIM_RP * param)
{
    for (uint8_t i = 0; i < param->services_count; i ++)
    {
        hts_attr = param->services[i];
        if((hts_attr.uuid_length == 2) && (sys_get_le16(hts_attr.uuid) == UUID_HTS))
        {
            central_hrc_event_put();
        } 
    }
}

void central_hrc_get_characteristics(MCP_DISC_CHRC_RP *param)
{
    for (uint8_t i = 0; i < param->characteristics_count; i ++)
    {
        hts_measurement_attr = param->characteristics[i];
        if((hts_measurement_attr.uuid_length == 2) && (sys_get_le16(hts_measurement_attr.uuid) == UUID_HTS_MEASUREMENT))
        {
            central_hrc_event_put();
        } 
    }
}

void central_hrc_get_ccc(MCP_DISC_ALL_DESC_RP * param)
{
    for (uint8_t i = 0; i < param->descriptors_count; i ++)
    {
        hts_ccc_attr = param->descriptors[i];
        if((hts_ccc_attr.uuid_length == 2) && (sys_get_le16(hts_ccc_attr.uuid) == UUID_GATT_CCC))
        {
            central_hrc_event_put();
        } 
    }
}
#endif

void central_hrc_task(void)
{
#if 0
    central_hrc_event_get(HRC_EVENT_DEVICE_FOUND);

    if (is_found)
    {
        (void)printf("Send 'ble-connect' to connect temperature server\n");
        ble_connect_command_local((NCP_CMD_CONNECT *)&hrc_conn_addrss);
        central_hrc_send_tlv_command();
        sem_wait(&hrc_sem);
    }
    // discover BT_UUID_HTS
    (void)printf("Send 'ble-discover-prim' to discover BT_UUID_HTS\n");
    //address
    memcpy(hrc_discover_primary.address, hrc_conn_addrss.address, 6);
    hrc_discover_primary.address_type = hrc_conn_addrss.type;
    hrc_discover_primary.uuid_length = 2;
    sys_put_le16(UUID_HTS, hrc_discover_primary.uuid);
    ble_disc_prim_command_local(&hrc_discover_primary);
    central_hrc_send_tlv_command();
    sem_wait(&hrc_sem);

    // discover BT_UUID_HTS_MEASUREMENT
    (void)printf("Send 'ble-discover-chrc' to discover BT_UUID_HTS_MEASUREMENT\n");
    memcpy(hrc_discover_characteristics.address, hrc_conn_addrss.address, 6);
    hrc_discover_characteristics.address_type = hrc_conn_addrss.type;
    hrc_discover_characteristics.start_handle = hts_attr.start_handle + 1;
    hrc_discover_characteristics.end_handle = 0xFFFF;
    hrc_discover_characteristics.uuid_length = 2;
    sys_put_le16(UUID_HTS_MEASUREMENT, hrc_discover_characteristics.uuid);
    ble_disc_chrc_command_local(&hrc_discover_characteristics);
    central_hrc_send_tlv_command();
    sem_wait(&hrc_sem);

    // discover BT_GATT_CCC
    (void)printf("Send 'ble-discover-desc' to discover BT_GATT_CCC\n");
    memcpy(hrc_discover_descriptors.address, hrc_conn_addrss.address, 6);
    hrc_discover_descriptors.address_type = hrc_conn_addrss.type;
    hrc_discover_descriptors.start_handle = hts_measurement_attr.characteristic_handle +1;
    hrc_discover_descriptors.end_handle = 0xFFFF;
    hrc_discover_descriptors.uuid_length = 2;
    sys_put_le16(UUID_GATT_CCC, hrc_discover_descriptors.uuid);
    ble_disc_desc_command_local(&hrc_discover_descriptors);
    central_hrc_send_tlv_command();
    sem_wait(&hrc_sem);

    // Configure indicate
    (void)printf("Send 'ble-cfg-indicate' to enable service indicate\n");
    memcpy(hrc_cfg_indicate.address, hrc_conn_addrss.address, 6);
    hrc_cfg_indicate.address_type = hrc_conn_addrss.type;
    hrc_cfg_indicate.enable= 1;
    hrc_cfg_indicate.ccc_handle = hts_ccc_attr.descriptor_handle;
    ble_cfg_indicate_command_local(&hrc_cfg_indicate);
    central_hrc_send_tlv_command();
#endif
    while(1)
    {
        sleep(1);
    }
}
#endif
