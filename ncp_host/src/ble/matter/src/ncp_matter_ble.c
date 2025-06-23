/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* -------------------------------------------------------------------------- */
/*                           Includes                                         */
/* -------------------------------------------------------------------------- */

#include "ncp_adapter.h"
#include "ncp_intf_uart.h"
#include "ncp_tlv_adapter.h"

#include "ncp_host_app_ble.h"
#include "ncp_host_command.h"
#include "ncp_host_command_ble.h"

#include "ncp_matter_ble.h"

/* -------------------------------------------------------------------------- */
/*                           Constants                                        */
/* -------------------------------------------------------------------------- */

#define NCP_CMD_SEQ_ZERO 0x0000
#define NCP_CMD_RES_OK   0x0000
#define NCP_CMD_RSVD     0x0000

#define NCP_COMMAND_LEN  4096
#define NCP_CMD_HEADER_LEN sizeof(NCP_COMMAND)

/* -------------------------------------------------------------------------- */
/*                           Types                                            */
/* -------------------------------------------------------------------------- */

#define NCP_DEBUG    0
#define NCP_BLE_ONLY 0


/* -------------------------------------------------------------------------- */
/*                           Variables                                        */
/* -------------------------------------------------------------------------- */

uint8_t tlv_cmd_buf[NCP_COMMAND_LEN];

int matter_mtu_size= 23; //default MTU size

struct bt_conn_cb *matter_conn_cb = NULL;
struct bt_svc_cb *matter_svc_cb = NULL;

uint8_t matter_rx_wait_flag = 1;

/* -------------------------------------------------------------------------- */
/*                           Function prototypes                              */
/* -------------------------------------------------------------------------- */



/* -------------------------------------------------------------------------- */
/*                           INT Functions                                    */
/* -------------------------------------------------------------------------- */

NCPCmd_DS_COMMAND *ncp_get_ble_command_buffer()
{
    return (NCPCmd_DS_COMMAND *)(tlv_cmd_buf);
}

void wait_for_rx(void)
{
    uint32_t max_wait   = 0;
    matter_rx_wait_flag = 1;

    while (matter_rx_wait_flag == 1 && max_wait < 200000)
    {
        max_wait++;
        usleep(10); /*Let sleep and other process to run*/
    }
    if (matter_rx_wait_flag == 1)
    {
        printf("wait more than 2 seconds \n");
    }

    return;
}
 

/* -------------------------------------------------------------------------- */
/*                           API Functions                                    */
/* -------------------------------------------------------------------------- */

/**
 * @brief Set advertisement data
 * 
 * Set advertisement data.
 * 
 * @param ad Data to be used in advertisement packets.
 * @param ad_len Advertising data length.
 * 
 * @return Zero on success or (negative) error code otherwise.
 * @return -ENOMEM No free connection objects available for connectable advertiser.
 */
int ncp_bt_set_adv_data(const struct bt_data *ad, uint8_t ad_len)
{
    printf("ncp_log: ncp_bt_set_adv_data \n");

    uint32_t total_len = 0;
    uint8_t adv_len = 0;

    NCPCmd_DS_COMMAND *set_adv_data_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)set_adv_data_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_SET_ADV_DATA *set_adv_data = (MCP_CMD_SET_ADV_DATA *)&set_adv_data_command->params.set_adv_data;

    for (int i = 0; i < ad_len; i++)
    {
        *(set_adv_data->adv_data + total_len) = ad[i].data_len + 1; //type(1 byte) + data(data_len byte)
        total_len++;
        *(set_adv_data->adv_data + total_len) = ad[i].type;
        total_len++;
    	memcpy(set_adv_data->adv_data + total_len, ad[i].data, ad[i].data_len);
    	total_len += ad[i].data_len;

        adv_len += ad[i].data_len + 2; //data_len(1 byte) + type(1 byte) + data(data_len byte)
    }

    set_adv_data->adv_length = adv_len; 
    total_len++;

    total_len += NCP_CMD_HEADER_LEN;
	
    set_adv_data_command->header.cmd      = NCP_CMD_BLE_GAP_SET_ADV_DATA;
    set_adv_data_command->header.size     = total_len;
    set_adv_data_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    set_adv_data_command->header.result   = NCP_CMD_RES_OK;
    set_adv_data_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send set adv data TLV \n");
#endif

	ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();

#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/**
 * @brief Start advertising
 * 
 * Start advertising.
 * 
 * @return Zero on success or (negative) error code otherwise.
 * @return -ENOMEM No free connection objects available for connectable advertiser.
 */
int ncp_bt_le_adv_start()
{
    printf("ncp_log: ncp_bt_le_adv_start \n");

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *start_adv_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)start_adv_command, 0, NCP_COMMAND_LEN);

    total_len += NCP_CMD_HEADER_LEN;

    start_adv_command->header.cmd      = NCP_CMD_BLE_GAP_START_ADV;
    start_adv_command->header.size     = total_len;
    start_adv_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    start_adv_command->header.result   = NCP_CMD_RES_OK;
    start_adv_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send start adv TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();

#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/**
 * @brief Stop advertising
 *
 * Stops ongoing advertising.
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int ncp_bt_le_adv_stop()
{
    printf("ncp_log: ncp_bt_le_adv_stop \n");

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *stop_adv_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)stop_adv_command, 0, NCP_COMMAND_LEN);

    total_len += NCP_CMD_HEADER_LEN;

    stop_adv_command->header.cmd      = NCP_CMD_BLE_GAP_STOP_ADV;
    stop_adv_command->header.size     = total_len;
    stop_adv_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    stop_adv_command->header.result   = NCP_CMD_RES_OK;
    stop_adv_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send stop adv TLV \n");
#endif
    
    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
    
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/**
 * @brief Enable Bluetooth
 *
 * Initialize bluetooth.
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int ncp_bt_enable()
{
    printf("ncp_log: ncp_bt_enable \n");

    /**
     * BT init automatically after device reset
     * For ble only init ncp driver here.
     * For coex init ncp driver on ncp_host_main (ncp_host_app.c).
     */

#if NCP_BLE_ONLY
    int ret;

    ret = ncp_adapter_init("/dev/ttyUSB0");

    if (ret != NCP_STATUS_SUCCESS)
    {
        printf("ERROR: ncp_adapter_init \n");
    }

    ret = ble_ncp_init();

    if ( ret != NCP_STATUS_SUCCESS)
    {
        printf("ERROR: ble_ncp_init \n");
    }
#endif

    return NCP_STATUS_SUCCESS;
}

/**
 * @brief Create a new identity.
 *
 * @param addr Address to use for the new identity.
 * @param irk  Identity Resolving Key (16 bytes) to be used with this identity.
 *
 * @return Identity identifier (>= 0) in case of success, or a negative
 *         error code on failure.
 */
int ncp_bt_id_create(bt_addr_le_t *addr, uint8_t *irk)
{
    printf("ncp_log: ncp_bt_id_create \n");

    /**
     * This api is not neccessary.
     * Matter call this api before bt enable, but bt enable automatically after ncp device reset.
     */

    return NCP_STATUS_SUCCESS;
}


/**
 * @brief Set Bluetooth Device Name
 *
 * @param name New name
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int ncp_bt_set_name(const char *name)
{
    printf("ncp_log: ncp_bt_set_name \n");

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *set_name_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)set_name_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_SET_NAME *set_device_name = (MCP_CMD_SET_NAME *)&set_name_command->params.set_dev_name;
	memcpy(set_device_name->name, name, strlen(name));
	total_len += strlen(name);

	total_len += NCP_CMD_HEADER_LEN;

    set_name_command->header.cmd      = NCP_CMD_BLE_VENDOR_SET_DEVICE_NAME;
    set_name_command->header.size     = total_len;
    set_name_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    set_name_command->header.result   = NCP_CMD_RES_OK;
    set_name_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send set name TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
        
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/**
 * @brief Get Bluetooth Device Name
 *
 * @return Bluetooth Device Name
 */
const char *ncp_bt_get_name()
{
    printf("ncp_log: ncp_bt_get_name \n");

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *get_name_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)get_name_command, 0, NCP_COMMAND_LEN);

	total_len += NCP_CMD_HEADER_LEN;

    get_name_command->header.cmd      = NCP_CMD_BLE_MATTER_GET_DEVICE_NAME;
    get_name_command->header.size     = total_len;
    get_name_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    get_name_command->header.result   = NCP_CMD_RES_OK;
    get_name_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send get name TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
            
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}


/** @brief Get array index of a connection
 *
 *  @param conn id Connection ID.
 *
 *  @return Index of the connection object.
 *          The range of the returned value is 0..CONFIG_BT_MAX_CONN-1
 */
int ncp_bt_conn_index(uint16_t conn_id)
{
    printf("ncp_log: ncp_bt_conn_index \n");

    /**
     * Note: '#define BLE_CONNECTION_OBJECT uint16_t'
     * For NCP mode, ble stack locate in device side, host can't provide
     * struct bt_conn parameter, matter platform implementation should
     * define BLE_CONNECTION_OBJECT as uint16_t.
     */

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *get_conn_index_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)get_conn_index_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_GET_CONN_INDEX *get_conn_index = (MCP_CMD_GET_CONN_INDEX *)&get_conn_index_command->params.get_conn_index;
    get_conn_index->conn_id = conn_id;
    total_len += sizeof(uint16_t);

	total_len += NCP_CMD_HEADER_LEN;

    get_conn_index_command->header.cmd      = NCP_CMD_BLE_MATTER_GET_CONN_INDEX;
    get_conn_index_command->header.size     = total_len;
    get_conn_index_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    get_conn_index_command->header.result   = NCP_CMD_RES_OK;
    get_conn_index_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send conn index TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/** @brief Increment a connection's reference count.
 *
 *  Increment the reference count of a connection object.
 *
 *  @param conn_id Connection ID.
 *
 *  @return Connection id with incremented reference count, or NULL if the
 *          reference count is zero.
 */
int ncp_bt_conn_ref(uint16_t conn_id)
{
    printf("ncp_log: ncp_bt_conn_ref \n");

    /**
     * Note: '#define BLE_CONNECTION_OBJECT uint16_t'
     * For NCP mode, ble stack locate in device side, host can't provide
     * struct bt_conn parameter, matter platform implementation should
     * define BLE_CONNECTION_OBJECT as uint16_t.
     */
    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *conn_ref_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)conn_ref_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_CONN_REF *conn_ref = (MCP_CMD_CONN_REF *)&conn_ref_command->params.conn_ref;
    conn_ref->conn_id = conn_id;
    total_len += sizeof(uint16_t);

	total_len += NCP_CMD_HEADER_LEN;

    conn_ref_command->header.cmd      = NCP_CMD_BLE_MATTER_CONN_REF;
    conn_ref_command->header.size     = total_len;
    conn_ref_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    conn_ref_command->header.result   = NCP_CMD_RES_OK;
    conn_ref_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send conn ref TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                    
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/** @brief Decrement a connection's reference count.
 *
 *  Decrement the reference count of a connection object.
 *
 *  @param conn_id Connection ID.
 */
int ncp_bt_conn_unref(uint16_t conn_id)
{
    printf("ncp_log: ncp_bt_conn_unref \n");

    /**
     * Note: '#define BLE_CONNECTION_OBJECT uint16_t'
     * For NCP mode, ble stack locate in device side, host can't provide
     * struct bt_conn parameter, matter platform implementation should
     * define BLE_CONNECTION_OBJECT as uint16_t.
     */

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *conn_unref_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)conn_unref_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_CONN_UNREF *conn_unref = (MCP_CMD_CONN_UNREF *)&conn_unref_command->params.conn_unref;
    conn_unref->conn_id = conn_id;
    total_len += sizeof(uint16_t);

	total_len += NCP_CMD_HEADER_LEN;

    conn_unref_command->header.cmd      = NCP_CMD_BLE_MATTER_CONN_UNREF;
    conn_unref_command->header.size     = total_len;
    conn_unref_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    conn_unref_command->header.result   = NCP_CMD_RES_OK;
    conn_unref_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send conn unref TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                        
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/** @brief Register connection callbacks.
 *
 *  Register callbacks to monitor the state of connections.
 */
int ncp_bt_conn_cb_register(struct bt_conn_cb *cb)
{
    printf("ncp_log: ncp_bt_conn_cb_register \n");

    /** 
     * For connection, host should handle NCP_EVENT_DEVICE_CONNECTED event.
     * For disconnection, host should handle NCP_EVENT_DEVICE_DISCONNECT event.
     */

    matter_conn_cb = cb;

    return NCP_STATUS_SUCCESS;
}

/** @brief Disconnect from a remote device or cancel pending connection.
 *
 *  @param conn_id Connection id to disconnect.
 *  @param reason Reason code for the disconnection.
 *
 *  @return Zero on success or (negative) error code on failure.
 */
int ncp_bt_conn_disconnect(uint16_t conn_id, uint8_t reason)
{
    printf("ncp_log: ncp_bt_conn_disconnect \n");

    /**
     * Note: '#define BLE_CONNECTION_OBJECT uint16_t'
     * For NCP mode, ble stack locate in device side, host can't provide
     * struct bt_conn parameter, matter platform implementation should
     * define BLE_CONNECTION_OBJECT as uint16_t.
     */

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *disconn_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)disconn_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_DISCONN *disconn = (MCP_CMD_DISCONN *)&disconn_command->params.disconn;
    disconn->conn_id = conn_id;
    disconn->reason  = reason;
    total_len += sizeof(uint16_t);
    total_len += sizeof(uint8_t);

	total_len += NCP_CMD_HEADER_LEN;

    disconn_command->header.cmd      = NCP_CMD_BLE_MATTER_DISCONN;
    disconn_command->header.size     = total_len;
    disconn_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    disconn_command->header.result   = NCP_CMD_RES_OK;
    disconn_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send disconnect TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                            
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/** @brief Register Matter ble service.
 *
 *  @return 0 in case of success or negative value in case of error.
 */
int ncp_bt_gatt_service_register()
{
    printf("ncp_log: ncp_bt_gatt_service_register \n");

    uint32_t total_len = 0;

    uint8_t service_len = 1;
    uint8_t service_id = 7; //PERIPHERAL_MATTER_SERVICE_ID

    NCPCmd_DS_COMMAND *register_service_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)register_service_command, 0, NCP_COMMAND_LEN);

    MCP_REGISTER_SERVICE *register_service = (MCP_REGISTER_SERVICE *)&register_service_command->params.register_service;

    register_service->svc_length = service_len;
    total_len += sizeof(uint8_t);
    memcpy(register_service->service, &service_id, service_len);
    total_len += service_len;

    total_len += NCP_CMD_HEADER_LEN;

    register_service_command->header.cmd      = NCP_CMD_BLE_GATT_REGISTER_SERVICE;
    register_service_command->header.size     = total_len;
    register_service_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    register_service_command->header.result   = NCP_CMD_RES_OK;
    register_service_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send svc register TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                                
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/** @brief Register matter service rx write callback function.
 *
 *  Register callbacks to receive rx write data.
 */
int ncp_bt_matter_svc_cb_register(struct bt_svc_cb *cb)
{
    printf("ncp_log: ncp_bt_matter_svc_cb_register \n");

    /**
     * Register matter service callback function.
     */

    matter_svc_cb = cb;

    return NCP_STATUS_SUCCESS;
}


/** @brief Unregister Matter ble service.
 *
 *  @return 0 in case of success or negative value in case of error.
 */
int ncp_bt_gatt_service_unregister()
{
    printf("ncp_log: ncp_bt_gatt_service_unregister \n");

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *unregister_service_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)unregister_service_command, 0, NCP_COMMAND_LEN);

    total_len += NCP_CMD_HEADER_LEN;

    unregister_service_command->header.cmd      = NCP_CMD_BLE_MATTER_UNREGISTER;
    unregister_service_command->header.size     = total_len;
    unregister_service_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    unregister_service_command->header.result   = NCP_CMD_RES_OK;
    unregister_service_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send svc unregister TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                                
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}

/** @brief Get ATT MTU for a connection
 *
 *  Get negotiated ATT connection MTU, note that this does not equal the largest
 *  amount of attribute data that can be transferred within a single packet.
 *
 *  @param conn_id Connection ID.
 *
 *  @return MTU in bytes
 */
int ncp_bt_gatt_get_mtu(uint16_t conn_id)
{
    printf("ncp_log: ncp_bt_gatt_get_mtu \n");

    /**
     * Note: '#define BLE_CONNECTION_OBJECT uint16_t'
     * For NCP mode, ble stack locate in device side, host can't provide
     * struct bt_conn parameter, matter platform implementation should
     * define BLE_CONNECTION_OBJECT as uint16_t.
     */

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *get_mtu_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)get_mtu_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_GET_MTU *get_mtu = (MCP_CMD_GET_MTU *)&get_mtu_command->params.get_mtu;
    get_mtu->conn_id = conn_id;
    total_len += sizeof(uint16_t);

	total_len += NCP_CMD_HEADER_LEN;

    get_mtu_command->header.cmd      = NCP_CMD_BLE_MATTER_GET_MTU;
    get_mtu_command->header.size     = total_len;
    get_mtu_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    get_mtu_command->header.result   = NCP_CMD_RES_OK;
    get_mtu_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send get mtu TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                                    
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return matter_mtu_size;
}

/** @brief Indicate attribute value change.
 *
 *  @param conn_id Connection id.
 *  @param value Attribute value.
 *  @param value_len Length of the attribute value.
 *
 *  @return 0 in case of success or negative value in case of error.
 */
int ncp_bt_gatt_indicate(uint16_t conn_id, void *value, uint16_t value_len)
{
    printf("ncp_log: ncp_bt_gatt_indicate \n");

    /**
     * Note: '#define BLE_CONNECTION_OBJECT uint16_t'
     * For NCP mode, ble stack locate in device side, host can't provide
     * struct bt_conn parameter, matter platform implementation should
     * define BLE_CONNECTION_OBJECT as uint16_t.
     */

    uint32_t total_len = 0;

    NCPCmd_DS_COMMAND *get_mtu_command = ncp_get_ble_command_buffer();
    (void)memset((uint8_t *)get_mtu_command, 0, NCP_COMMAND_LEN);

    MCP_CMD_MATTER_INDICATE *indicate = (MCP_CMD_MATTER_INDICATE *)&get_mtu_command->params.indicate;
    indicate->conn_id = conn_id;
    total_len += sizeof(uint16_t);
    indicate->len = value_len;
    total_len += sizeof(uint16_t);
    memcpy(indicate->data, value, value_len);
    total_len += value_len;

	total_len += NCP_CMD_HEADER_LEN;

    get_mtu_command->header.cmd      = NCP_CMD_BLE_MATTER_INDICATE;
    get_mtu_command->header.size     = total_len;
    get_mtu_command->header.seqnum   = NCP_CMD_SEQ_ZERO;
    get_mtu_command->header.result   = NCP_CMD_RES_OK;
    get_mtu_command->header.rsvd     = NCP_CMD_RSVD;

#if NCP_DEBUG
    printf("P1) send gatt indicate TLV \n");
#endif

    ncp_tlv_send(tlv_cmd_buf, total_len);
    wait_for_rx();
                                        
#if NCP_DEBUG
    printf("P3) ble API return \n");
#endif

    return NCP_STATUS_SUCCESS;
}
