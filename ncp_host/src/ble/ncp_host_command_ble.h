/** @file ncp_host_command_ble.h
 *
 * Copyright (c) 2015-2016 Intel Corporation
 * Copyright (c) 2022 Codecoup
 * Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NCP_HOST_COMMAND_BLE_H__
#define __NCP_HOST_COMMAND_BLE_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/times.h>
#include "ncp_host_command.h"

/*BLE NCP subclass*/
#define NCP_CMD_BLE_CORE         0x00000000
#define NCP_CMD_BLE_GAP          0x00100000
#define NCP_CMD_BLE_GATT         0x00200000
#define NCP_CMD_BLE_L2CAP        0x00300000
#define NCP_CMD_BLE_POWERMGMT    0x00400000
#define NCP_CMD_BLE_VENDOR       0x00500000
#define NCP_CMD_BLE_OTHER        0x00600000
#define NCP_CMD_BLE_EVENT        0x00f00000

/*NCP MPU Command definitions*/
/*BLE Core command*/
#define NCP_CMD_BLE_CORE_SUPPORT_CMD    (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_CMD | 0x00000001) /* Read supported commands*/
#define NCP_RSP_BLE_CORE_SUPPORT_CMD    (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_BLE_CORE_SUPPORT_SER    (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_CMD | 0x00000002) /* Read supported services*/
#define NCP_RSP_BLE_CORE_SUPPORT_SER    (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_BLE_CORE_REGISTER       (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_CMD | 0x00000003) /* register services */
#define NCP_RSP_BLE_CORE_REGISTER       (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_BLE_CORE_UNREGISTER     (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_CMD | 0x00000004) /* unregister services*/
#define NCP_RSP_BLE_CORE_UNREGISTER     (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_BLE_CORE_RESET          (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_CMD | 0x00000006) /* reset board */
#define NCP_RSP_BLE_CORE_RESET          (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_RESP | 0x00000006)

/*BLE Gap command*/
#define NCP_CMD_BLE_GAP_SET_DATA_LEN         (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x00000020) /* Set data len */
#define NCP_RSP_BLE_GAP_SET_DATA_LEN         (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x00000020)
#define NCP_CMD_BLE_GAP_SET_PHY              (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000001f) /* Set phy */
#define NCP_RSP_BLE_GAP_SET_PHY              (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000001f)
#define NCP_CMD_BLE_GAP_SET_ADV_DATA         (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000001e) /* Set adv data */
#define NCP_RSP_BLE_GAP_SET_ADV_DATA         (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000001e)
#define NCP_CMD_BLE_GAP_SET_SCAN_PARAM       (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000001d) /* Set scan parameter */
#define NCP_RSP_BLE_GAP_SET_SCAN_PARAM       (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000001d)
#define NCP_CMD_BLE_GAP_START_ADV            (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000000a) /* Start advertising */
#define NCP_RSP_BLE_GAP_START_ADV            (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000000a)
#define NCP_CMD_BLE_GAP_STOP_ADV             (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000000b) /* Stop advertising */
#define NCP_RSP_BLE_GAP_STOP_ADV             (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000000b)
#define NCP_CMD_BLE_GAP_START_SCAN           (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000000c) /* Start discovery */
#define NCP_RSP_BLE_GAP_START_SCAN           (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000000c)
#define NCP_CMD_BLE_GAP_STOP_SCAN            (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000000d) /* Stop discovery */
#define NCP_RSP_BLE_GAP_STOP_SCAN            (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000000d)
#define NCP_CMD_BLE_GAP_CONNECT              (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000000e) /* Create a connection */
#define NCP_RSP_BLE_GAP_CONNECT              (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000000e)
#define NCP_CMD_BLE_GAP_DISCONNECT           (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000000f) /* Terminate a connection */
#define NCP_RSP_BLE_GAP_DISCONNECT           (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000000f)
#define NCP_CMD_BLE_GAP_CONN_PARAM_UPDATE    (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x00000016) /* Connection parameters update */
#define NCP_RSP_BLE_GAP_CONN_PARAM_UPDATE    (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x00000016)
#define NCP_CMD_BLE_GAP_SET_FILTER_LIST      (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x0000001c) /* Set filter accept list */
#define NCP_RSP_BLE_GAP_SET_FILTER_LIST      (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x0000001c)
#define NCP_CMD_BLE_GAP_PAIR                 (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_CMD | 0x00000011) /* Enable encryption with peer or start pair process */
#define NCP_RSP_BLE_GAP_PAIR                 (NCP_CMD_BLE | NCP_CMD_BLE_GAP | NCP_MSG_TYPE_RESP | 0x00000011)

/*BLE Gatt command*/
#define NCP_CMD_BLE_HOST_SERVICE_ADD         (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000002) /* Add Host Attribute to Device Gatt datebase and start, ble-host-service-start */
#define NCP_RSP_BLE_HOST_SERVICE_ADD         (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_BLE_HOST_SERVICE_DISC        (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000003) /* Discover Primary Service/Characteristics/Descriptors */
#define NCP_RSP_BLE_HOST_SERVICE_DISC        (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_BLE_GATT_SET_VALUE           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000006) /* Set Characteristic/Descriptor Value */
#define NCP_RSP_BLE_GATT_SET_VALUE           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_BLE_GATT_DISC_PRIM           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x0000000c) /* Discover Primary Service */
#define NCP_RSP_BLE_GATT_DISC_PRIM           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x0000000c)
#define NCP_CMD_BLE_GATT_DISC_CHRC           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x0000000f) /* Discover Characteristics */
#define NCP_RSP_BLE_GATT_DISC_CHRC           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x0000000f)
#define NCP_CMD_BLE_GATT_START_SERVICE       (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000007) /* Start server with previously prepared attributes database. */
#define NCP_RSP_BLE_GATT_START_SERVICE       (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_BLE_GATT_CFG_NOTIFY          (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x0000001a) /* Configure service to notify characteristic value to clinet */
#define NCP_RSP_BLE_GATT_CFG_NOTIFY          (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x0000001a)
#define NCP_CMD_BLE_GATT_CFG_INDICATE        (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x0000001b) /* Configure service to indicate characteristic value to clinet */
#define NCP_RSP_BLE_GATT_CFG_INDICATE        (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x0000001b)
#define NCP_CMD_BLE_GATT_READ                (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000011) /* Read Characteristic/Descriptor */
#define NCP_RSP_BLE_GATT_READ                (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000011)
#define NCP_CMD_BLE_GATT_REGISTER_SERVICE    (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000020)  /* register a profile service */
#define NCP_RSP_BLE_GATT_REGISTER_SERVICE    (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000020)
#define NCP_CMD_BLE_GATT_DESC_CHRC           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_CMD | 0x00000021) /* Discover Descriptors */
#define NCP_RSP_BLE_GATT_DESC_CHRC           (NCP_CMD_BLE | NCP_CMD_BLE_GATT | NCP_MSG_TYPE_RESP | 0x00000021)

/*BLE L2CAP command*/
#define NCP_CMD_BLE_L2CAP_CONNECT            (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_CMD | 0x00000002) /* L2CAP connect */
#define NCP_RSP_BLE_L2CAP_CONNECT            (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_BLE_L2CAP_DISCONNECT         (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_CMD | 0x00000003) /* L2CAP disconnect */
#define NCP_RSP_BLE_L2CAP_DISCONNECT         (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_BLE_L2CAP_SEND               (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_CMD | 0x00000004) /* L2CAP send */
#define NCP_RSP_BLE_L2CAP_SEND               (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_BLE_L2CAP_REGISTER           (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_CMD | 0x0000000a) /* L2CAP register*/
#define NCP_RSP_BLE_L2CAP_REGISTER           (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_RESP | 0x0000000a)
#define NCP_CMD_BLE_L2CAP_METRICS            (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_CMD | 0x0000000b) /* L2CAP metrics */
#define NCP_RSP_BLE_L2CAP_METRICS            (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_RESP | 0x0000000b)
#define NCP_CMD_BLE_L2CAP_RECEIVE            (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_CMD | 0x0000000c) /* L2CAP receive */
#define NCP_RSP_BLE_L2CAP_RECEIVE            (NCP_CMD_BLE | NCP_CMD_BLE_L2CAP | NCP_MSG_TYPE_RESP | 0x0000000c)

/*BLE Vendor command*/
#define NCP_CMD_BLE_VENDOR_POWER_MODE        (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_CMD | 0x00000001) /* Enable/Disable power save mode */
#define NCP_RSP_BLE_VENDOR_POWER_MODE        (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_BLE_VENDOR_SET_UART_BR       (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_CMD | 0x00000002) /* Set Uart baud rate */
#define NCP_RSP_BLE_VENDOR_SET_UART_BR       (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_BLE_VENDOR_SET_DEVICE_ADDR   (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_CMD | 0x00000003) /* Set Uart LE device address */
#define NCP_RSP_BLE_VENDOR_SET_DEVICE_ADDR   (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_BLE_VENDOR_SET_DEVICE_NAME   (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_CMD | 0x00000004) /* Set Uart LE device name */
#define NCP_RSP_BLE_VENDOR_SET_DEVICE_NAME   (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_BLE_VENDOR_CFG_MULTI_ADV     (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_CMD | 0x00000005) /* Config Multi-advertising */
#define NCP_RSP_BLE_VENDOR_CFG_MULTI_ADV     (NCP_CMD_BLE | NCP_CMD_BLE_VENDOR | NCP_MSG_TYPE_RESP | 0x00000005)

/*BLE events*/
#define NCP_EVENT_IUT_READY                  (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x80) /* IUT Ready event */
#define NCP_EVENT_ADV_REPORT                 (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x81) /* LE Advertising Report event */
#define NCP_EVENT_DEVICE_CONNECTED           (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x82) /* Connection Complete event */
#define NCP_EVENT_DEVICE_DISCONNECT          (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x83) /* Disconnection Complete event */
#define NCP_EVENT_PASSKEY_DISPLAY            (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x84) /* Passkey Display event */
#define NCP_EVENT_IDENITY_RESOLVED           (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x87) /* Remote Identity Address Resolved event */
#define NCP_EVENT_CONN_PARAM_UPDATE          (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x88) /* Connection param update event */
#define NCP_EVENT_SEC_LEVEL_CHANGED          (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x89) /* Security Level Changed event */
#define NCP_EVENT_PHY_UPDATED                (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x91) /* GAP phy updated */
#define NCP_EVENT_DATA_LEN_UPDATED           (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x92) /* GAP data len updated */

#define NCP_EVENT_GATT_NOTIFICATION          (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x80 | 0x200) /* GATT notification Receive event */
#define NCP_EVENT_ATTR_VALUE_CHANGED         (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x81 | 0x200) /* GATT Attribute Value Changed event */
#define NCP_EVENT_GATT_CCC_CFG_CHANGED       (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x82 | 0x200) /* GATT Client Characteristic Configuration Changed event */
#define NCP_EVENT_GATT_SUBSCRIPTIONED        (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x85 | 0x200) /* GATT Subcription status event */
#define NCP_EVENT_GATT_DISC_PRIM             (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x19 | 0x200) /* Discover Primary Service event */
#define NCP_EVENT_GATT_DISC_CHRC             (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x20 | 0x200) /* Discover Characteristics event */
#define NCP_EVENT_GATT_DISC_DESC             (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x21 | 0x200) /* Discover Descriptors event */

#define NCP_EVENT_L2CAP_CONNECT              (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x81 | 0x300) /* L2CAP Connect event */
#define NCP_EVENT_L2CAP_DISCONNECT           (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x82 | 0x300) /* L2CAP Disconnect event */
#define NCP_EVENT_L2CAP_RECEIVE              (NCP_CMD_BLE | NCP_CMD_BLE_EVENT | NCP_MSG_TYPE_EVENT | 0x83 | 0x300) /* L2CAP Receive event */


/*NCP BLE GATT TLV*/
#define NCP_CMD_GATT_ADD_SERVICE_TLV       0x0001
#define NCP_CMD_GATT_ADD_CHRC_TLV          0x0002
#define NCP_CMD_GATT_ADD_DESC_TLV          0x0003
#define NCP_CMD_GATT_START_SVC_TLV         0x0004

#define NCP_CMD_BLE_INVALID_CMD         (NCP_CMD_BLE | NCP_CMD_BLE_CORE | NCP_MSG_TYPE_CMD | 0x0000000a) /* invalid command recieve */


/* Bluetooth defines */
#define NCP_BLE_ADDR_LENGTH 6
#define NCP_BLE_DEVICE_NAME_MAX  32
#define MAX_MONIT_MAC_FILTER_NUM 3
#define MAX_SUPPORT_SERVICE 10
#define SERVER_MAX_UUID_LEN 16

typedef struct _MCP_CMD_ADV_START
{
    uint8_t data[256];
} MCP_CMD_ADV_START;

typedef struct _MCP_CMD_SET_ADV_DATA
{
  uint8_t adv_length;
  uint8_t adv_data[];
} MCP_CMD_SET_ADV_DATA;

typedef struct _MCP_CMD_SET_SCAN_PARAM
{
  /** Bit-field of scanning options. */
  uint32_t options;
  /** Scan interval (N * 0.625 ms) */
  uint16_t interval;
  /** Scan window (N * 0.625 ms) */
  uint16_t window;
} MCP_CMD_SET_SCAN_PARAM;

typedef struct _MCP_CMD_SCAN_START
{
    uint8_t type;
} MCP_CMD_SCAN_START;

typedef struct _MCP_CMD_CONNECT
{
    uint8_t type;
    uint8_t addr[6];
} MCP_CMD_CONNECT;

typedef struct _MCP_CMD_SET_DATA_LEN
{
   uint8_t  address_type;
   uint8_t  address[6];
   uint8_t  time_flag;
   uint16_t tx_max_len;
   uint16_t tx_max_time;
} MCP_CMD_SET_DATA_LEN;

typedef struct _MCP_CMD_SET_PHY
{
   uint8_t  address_type;
   uint8_t  address[6];
   uint16_t options;
   uint8_t  pref_tx_phy;
   uint8_t  pref_rx_phy;
} MCP_CMD_SET_PHY;

typedef struct _MCP_CMD_CONN_PARA_UPDATE
{
    uint8_t type;
    uint8_t addr[6];
    uint16_t interval_min;
    uint16_t interval_max;
    uint16_t latency;
    uint16_t timeout;
} MCP_CMD_CONN_PARA_UPDATE;

typedef struct _MCP_CMD_CONN_PARA_UPDATE_EV
{
    uint8_t type;
    uint8_t addr[6];
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout;
} MCP_CMD_CONN_PARA_UPDATE_EV;

typedef struct _MCP_CMD_PHY_UPDATE_EV
{
    uint8_t address_type;
    uint8_t address[6];
    uint8_t tx_phy;
    uint8_t rx_phy;
} MCP_CMD_PHY_UPDATE_EV;

typedef struct _MCP_CMD_DATA_LEN_UPDATE_EV
{
    uint8_t address_type;
    uint8_t address[6];
    uint16_t tx_max_len;
    uint16_t tx_max_time;
    uint16_t rx_max_len;
    uint16_t rx_max_time;
} MCP_CMD_DATA_LEN_UPDATE_EV;

typedef struct _MCP_CMD_ENCRIPTION
{
    uint8_t type;
    uint8_t addr[6];
} MCP_CMD_ENCRYPTION;

typedef struct _MCP_CMD_SET_ADDR
{
    uint8_t addr[6];
} MCP_CMD_SET_ADDR;

typedef struct _MCP_CMD_SET_NAME
{
    uint8_t name[33];
} MCP_CMD_SET_NAME;

typedef struct _MCP_CMD_SET_POWER_MODE
{
    uint8_t mode;
} MCP_CMD_SET_POWER_MODE;

typedef struct _MCP_SET_VALUE_CMD {
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
    uint16_t len;
    uint8_t value[512];
} MCP_SET_VALUE_CMD;

typedef struct _MCP_GATT_READ_CMD {
    uint8_t type;
    uint8_t addr[6];
    uint16_t handle;
} MCP_GATT_READ_CMD;

typedef struct gatt_add_service_cmd
{
    TypeHeader_t header;
    uint8_t type;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} gatt_add_service_cmd_t;

typedef struct gatt_add_characteristic_cmd
{
    TypeHeader_t header;
    uint16_t svc_id;
    uint8_t properties;
    uint16_t permissions;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} gatt_add_characteristic_cmd_t;

typedef struct gatt_add_descriptor_cmd
{
    TypeHeader_t header;
    uint16_t char_id;
    uint16_t permissions;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} gatt_add_descriptor_cmd_t;

typedef struct gatt_add_included_service_cmd
{
    TypeHeader_t header;
    uint16_t svc_id;
} gatt_add_included_service_cmd_t;

typedef struct gatt_start_service_cmd {
    TypeHeader_t header;
    uint8_t started;
} gatt_start_service_cmd_t;

typedef struct _MCP_CMD_SERVICE_ADD
{
  uint32_t tlv_buf_len;
  /**
   * add service TLV, gatt_add_service_cmd_t
   * add characteristic TLV, gatt_add_characteristic_cmd_t
   * add descriptor TLV, gatt_add_descriptor_cmd_t
   * add include service TLV, gatt_add_included_service_cmd_t (to be added in the future)
   * start host servuce TLV, gatt_start_service_cmd_t
  */
  uint8_t tlv_buf[1];
} MCP_CMD_SERVICE_ADD;

typedef struct _MCP_CMD_START_SERVICE
{
  uint8_t form_host;
  uint8_t svc_id;
} MCP_CMD_START_SERVICE;
typedef struct _MCP_DISC_PRIM_UUID_CMD {
    uint8_t address_type;
    uint8_t address[NCP_BLE_ADDR_LENGTH];
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} MCP_DISC_PRIM_UUID_CMD;

typedef struct _MCP_DISC_CHRC_UUID_CMD {
    uint8_t address_type;
    uint8_t address[NCP_BLE_ADDR_LENGTH];
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} MCP_DISC_CHRC_UUID_CMD;

typedef struct _MCP_CFG_SUBCRIBE_CMD {
    uint8_t address_type;
    uint8_t address[NCP_BLE_ADDR_LENGTH];
    uint8_t enable;
    uint16_t ccc_handle;
} MCP_CFG_SUBCRIBE_CMD;

typedef struct _MCP_REGISTER_SERVICE
{
    uint8_t svc_length;
    uint8_t service[MAX_SUPPORT_SERVICE];
} MCP_REGISTER_SERVICE;

//L2CAP
typedef struct _MCP_L2CAP_CONNECT_CMD {
    uint8_t address_type;
    uint8_t address[NCP_BLE_ADDR_LENGTH];
    uint16_t psm;
    uint8_t sec;
    uint8_t sec_flag;
} MCP_L2CAP_CONNECT_CMD;

typedef struct _MCP_L2CAP_DISCONNECT_CMD {
    uint8_t address_type;
    uint8_t address[NCP_BLE_ADDR_LENGTH];
} MCP_L2CAP_DISCONNECT_CMD;

typedef struct _MCP_L2CAP_SEND_CMD {
    uint8_t address_type;
    uint8_t address[NCP_BLE_ADDR_LENGTH];
    uint16_t times;
} MCP_L2CAP_SEND_CMD;

typedef struct _MCP_L2CAP_REGISTER_CMD {
    uint16_t psm;
    uint8_t sec_level;
    uint8_t sec_flag;
    uint8_t policy;
    uint8_t policy_flag;
} MCP_L2CAP_REGISTER_CMD;

typedef struct _MCP_L2CAP_METRICS_CMD {
    uint8_t metrics_flag;
} MCP_L2CAP_METRICS_CMD;

typedef struct _MCP_L2CAP_RECEIVE_CMD {
    uint32_t l2cap_recv_delay_ms;
} MCP_L2CAP_RECEIVE_CMD;
//L2CAP

typedef struct _MCP_START_ADV_RP {
    uint32_t adv_setting;
} MCP_START_ADV_RP;

typedef struct _MCP_ADD_SERVICE_RP {
    uint16_t attr_handle;
} MCP_ADD_SERVICE_RP;

typedef struct GATT_SERVICE {
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} GATT_SERVICE_T;

typedef struct GATT_CHARACTERISTIC {
    uint16_t characteristic_handle;
    uint16_t value_handle;
    uint8_t properties;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} GATT_CHARACTERISTIC_T;

typedef struct GATT_DESCRIPTOR {
    uint16_t descriptor_handle;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} GATT_DESCRIPTOR_T;

typedef struct _MCP_DISC_PRIM_RP {
    uint8_t services_count;
    GATT_SERVICE_T services[MAX_SUPPORT_SERVICE];
} MCP_DISC_PRIM_RP, MCP_DISC_PRIM_EV;

typedef struct  _MCP_DISC_CHRC_RP {
    uint8_t characteristics_count;
    GATT_CHARACTERISTIC_T characteristics[MAX_SUPPORT_SERVICE];
}  MCP_DISC_CHRC_RP,  MCP_DISC_CHRC_EV;

typedef struct  _MCP_DISC_ALL_DESC_RP {
    uint8_t descriptors_count;
    GATT_DESCRIPTOR_T descriptors[MAX_SUPPORT_SERVICE];
}  MCP_DISC_ALL_DESC_RP, MCP_DISC_ALL_DESC_EV;

typedef struct _MCP_DEVICE_ADV_REPORT_EV {
    uint8_t  address_type;
    uint8_t  address[6];
    int8_t   rssi;
    uint8_t  flags;
    uint16_t eir_data_len;
    uint8_t  eir_data[];
} MCP_DEVICE_ADV_REPORT_EV;

typedef struct _MCP_DEVICE_CONNECTED_EV {
    uint8_t address_type;
    uint8_t address[6];
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout;
} MCP_DEVICE_CONNECTED_EV;

typedef struct _MCP_DEVICE_DISCONNECTED_EV {
    uint8_t address_type;
    uint8_t address[6];
} MCP_DEVICE_DISCONNECTED_EV;

typedef struct _MCP_PASSKEY_DISPLAY_EV {
  uint8_t  address_type;
  uint8_t  address[6];
  uint32_t passkey;
} MCP_PASSKEY_DISPLAY_EV;

typedef struct _MCP_IDENTITY_RESOLVED_EV {
  uint8_t address_type;
  uint8_t address[6];
  uint8_t identity_address_type;
  uint8_t identity_address[6];
} MCP_IDENTITY_RESOLVED_EV;

typedef struct _MCP_SEC_LEVEL_CHANGED_EV {
  uint8_t address_type;
  uint8_t address[6];
  uint8_t sec_level;
} MCP_SEC_LEVEL_CHANGED_EV;

#define MAX_ATTRIBUTE_VALUE_LEN 256

typedef struct  _MCP_NOTIFICATION_EV {
    uint8_t svc_id;
    uint8_t address_type;
    uint8_t address[6];
    uint8_t type;
    uint16_t handle;
    uint16_t data_length;
    uint8_t data[MAX_ATTRIBUTE_VALUE_LEN];
} MCP_NOTIFICATION_EV;

typedef struct  _MCP_ATTR_VALUE_CHANGED_EV {
    uint16_t handle;
    uint16_t data_length;
    uint8_t data[MAX_ATTRIBUTE_VALUE_LEN];
} MCP_ATTR_VALUE_CHANGED_EV;

typedef struct  _MCP_CCC_CFG_CHANGED_EV {
    uint16_t ccc_value;
    uint8_t uuid_length;
    uint8_t uuid[SERVER_MAX_UUID_LEN];
} MCP_CCC_CFG_CHANGED_EV;

typedef struct  _MCP_SUBSCRIPTIONED_EV {
    uint8_t svc_id;
    uint8_t status;
} MCP_SUBSCRIPTIONED_EV;

//L2CAP event
typedef struct  _MCP_L2CAP_CONNECT_EV {
    uint8_t address_type;
    uint8_t address[6];
    uint16_t psm;
} MCP_L2CAP_CONNECT_EV;

typedef struct  _MCP_L2CAP_DISCONNECT_EV {
    uint8_t address_type;
    uint8_t address[6];
    uint16_t psm;
} MCP_L2CAP_DISCONNECT_EV;

typedef struct  _MCP_L2CAP_RECEIVE_EV {
    uint8_t address_type;
    uint8_t address[6];
    uint16_t psm;
    uint8_t len;
    uint8_t data[256];
} MCP_L2CAP_RECEIVE_EV;

typedef struct _NCPCmd_DS_COMMAND
{
    /** Command Header : Command */
    NCP_COMMAND header;
    /** Command Body */
    union
    {
        /** Adv */
        MCP_CMD_ADV_START adv_start;
        /** Ble Scan */
        MCP_CMD_SCAN_START scan_start;
        /** Set Ble Adv Data */
        MCP_CMD_SET_ADV_DATA set_adv_data;
        /** Set BLE Scan Parameter */
        MCP_CMD_SET_SCAN_PARAM set_scan_parameter;
        /** Ble Connect/Disconnect */
        MCP_CMD_CONNECT connect;
        /** Set Ble Data Len */
        MCP_CMD_SET_DATA_LEN set_data_len;
        /** Set Ble PHY */
        MCP_CMD_SET_PHY set_phy;
        /** Ble Connect Parameter Update */
        MCP_CMD_CONN_PARA_UPDATE conn_param_update;
        /** Ble Connect Encryption */
        MCP_CMD_ENCRYPTION conn_encryption;
        /** Ble Set Power Mode */
        MCP_CMD_SET_POWER_MODE set_pw_mode;
        /** Ble Set Device Address */
        MCP_CMD_SET_ADDR set_dev_addr;
        /** Ble Read characteristic */
        MCP_GATT_READ_CMD gatt_read_char;
        /** Ble Set Device Name */
        MCP_CMD_SET_NAME set_dev_name;
        /** Ble GATT Add Service Attribute */
        MCP_CMD_SERVICE_ADD host_svc_add;
        /** Ble Start Service at Host side */
        MCP_CMD_START_SERVICE host_start_svc;
        /** Ble GATT Register Service*/
        MCP_REGISTER_SERVICE register_service;
        /** Ble GATT Set Characteristic/Descriptor Service*/
        MCP_SET_VALUE_CMD gatt_set_value;
        /** Ble GATT Discover Primary Service*/
        MCP_DISC_PRIM_UUID_CMD discover_prim;
        /** Ble GATT Discover Characteristics*/
        MCP_DISC_CHRC_UUID_CMD discover_chrc;
        /** Ble GATT Configure service to indicate/notify characteristic value to clinet*/
        MCP_CFG_SUBCRIBE_CMD cfg_subcribe;
        /** L2CAP connect */
        MCP_L2CAP_CONNECT_CMD l2cap_connect;
        /** L2CAP disconnect */
        MCP_L2CAP_DISCONNECT_CMD l2cap_disconnect;
        /** L2CAP send */
        MCP_L2CAP_SEND_CMD l2cap_send;
        /** L2CAP register*/
        MCP_L2CAP_REGISTER_CMD l2cap_register;
        /** L2CAP metrics */
        MCP_L2CAP_METRICS_CMD l2cap_metrics;
        /** L2CAP receive */
        MCP_L2CAP_RECEIVE_CMD l2cap_receive;

        /** Ble Adv reported event */
        MCP_DEVICE_ADV_REPORT_EV adv_reported;
        /** Ble Connected event */
        MCP_DEVICE_CONNECTED_EV device_connected;
        /** Ble Disonnected event */
        MCP_DEVICE_DISCONNECTED_EV device_disconnected;
        /** Passkey Display event */
        MCP_PASSKEY_DISPLAY_EV passkey_display;
        /** Remote Identity Address Resolved event */
        MCP_IDENTITY_RESOLVED_EV idenitiy_resolved;
        /** Ble Connect Parameter Update event */
        MCP_CMD_CONN_PARA_UPDATE_EV conn_param_update_ev;
        /** Ble Phy Update event */
        MCP_CMD_PHY_UPDATE_EV phy_updated_ev;
        /** Ble Data Len Update event */
        MCP_CMD_DATA_LEN_UPDATE_EV data_len_updated_ev;
        /** Security Level Changed event */
        MCP_SEC_LEVEL_CHANGED_EV sec_level_changed;

        /** GATT notification Receive even */
        MCP_NOTIFICATION_EV gatt_notification;
        /** GATT Attribute Value Changed event */
        MCP_ATTR_VALUE_CHANGED_EV attr_value_changed;
        /** GATT Client Characteristic Configuration Changed event */
        MCP_CCC_CFG_CHANGED_EV gatt_ccc_cfg_changed_ev;
        /** GATT Client Subscription event */
        MCP_SUBSCRIPTIONED_EV gatt_subscription_ev;
        /** GATT Discover Primary Service event */
        MCP_DISC_PRIM_EV gatt_disc_prim_ev;
        /** GATT Discover Primary Service event */
        MCP_DISC_CHRC_EV gatt_disc_chrc_ev;
        /** GATT Discover Primary Service event */
        MCP_DISC_ALL_DESC_EV gatt_disc_desc_ev;

        /** Ble l2cap connect event */
        MCP_L2CAP_CONNECT_EV l2cap_connect_ev;
        /** Ble l2cap disconnect event */
        MCP_L2CAP_DISCONNECT_EV l2cap_disconnect_ev;
        /** Ble l2cap receive event */
        MCP_L2CAP_RECEIVE_EV l2cap_receive_ev;

        /** Ble Adv start response */
        MCP_START_ADV_RP start_adv_rp;
        /** Ble GATT Add Service Attribute Response */
        MCP_ADD_SERVICE_RP add_service_rp;
        /** Ble GATT Discover Primary Service Response */
        MCP_DISC_PRIM_RP discover_prim_rp;
        /** Ble GATT Discover Characteristics Response*/
        MCP_DISC_CHRC_RP discover_chrc_rp;
        /** Ble GATT Discover Descriptors Response*/
        MCP_DISC_ALL_DESC_RP discover_desc_rp ;
    } params;
} NCPCmd_DS_COMMAND;

#pragma pack()

#define NCP_HOST_MUTEX_INHERIT 1

int ble_set_adv_data_command(int argc, char **argv);

int ble_start_adv_command(int argc, char **argv);

int ble_stop_adv_command(int argc, char **argv);

int ble_set_scan_param_command(int argc, char **argv);

int ble_start_scan_command(int argc, char **argv);

int ble_stop_scan_command(int argc, char **argv);

void ble_connect_command_local(MCP_CMD_CONNECT *param);

int ble_connect_command(int argc, char **argv);

int ble_disconnect_command(int argc, char **argv);

int ble_set_data_len_command(int argc, char **argv);

int ble_set_phy_command(int argc, char **argv);

int ble_connect_paramter_update_command(int argc, char **argv);

int ble_set_filter_list_command(int argc, char **argv);

int ble_process_ble_gap_pair_response(uint8_t *res);

int ble_process_ble_gatt_read_char_response(uint8_t *res);

int ble_process_set_dev_addr_response(uint8_t *res);

int ble_process_set_dev_name_response(uint8_t *res);

int ble_process_set_power_mode_response(uint8_t *res);

int ble_start_encryption_command(int argc, char **argv);

void write_charateristic_command_local(MCP_SET_VALUE_CMD *param);

int ble_write_characteristic_command(int argc, char **argv);

int ble_read_characteristic_command(int argc, char **argv);

int ble_register_service_command(int argc, char **argv);

int ble_set_power_mode_command(int argc, char **argv);

int ble_set_device_address_command(int argc, char **argv);

int ble_set_device_name_command(int argc, char **argv);

int ble_host_service_add_command(int argc, char **argv);

int ble_start_service_command(int argc, char **argv);

void ble_disc_prim_command_local(MCP_DISC_PRIM_UUID_CMD *param);

int ble_disc_prim_command(int argc, char **argv);

void ble_disc_chrc_command_local(MCP_DISC_CHRC_UUID_CMD *param);

int ble_disc_chrc_command(int argc, char **argv);

void ble_disc_desc_command_local(MCP_DISC_CHRC_UUID_CMD *param);

int ble_disc_desc_command(int argc, char **argv);

int ble_cfg_subscribe_command(int argc, char **argv);

int ble_l2cap_connection_command(int argc, char **argv);

int ble_l2cap_disconnect_command(int argc, char **argv);

int ble_l2cap_send_command(int argc, char **argv);

int ble_l2cap_register_command(int argc, char **argv);

int ble_l2cap_metrics_command(int argc, char **argv);

int ble_l2cap_receive_command(int argc, char **argv);

int ble_process_ncp_event(uint8_t *res);

int ble_process_adv_report(uint8_t *res);

int ble_process_device_connected(uint8_t *res);

int ble_process_device_disconnected(uint8_t *res);

int ble_process_passkey_display(uint8_t *res);

int ble_process_conn_param_update(uint8_t *res);

int ble_process_phy_update(uint8_t *res);

int ble_process_data_len_update(uint8_t *res);

int ble_process_idenity_resolved(uint8_t *res);

int ble_process_security_level_changed(uint8_t *res);

int ble_process_gatt_notification(uint8_t *res);

int ble_process_attr_value_changed(uint8_t *res);

int ble_process_gatt_ccc_cfg_changed(uint8_t *res);

int ble_process_gatt_subscriptioned(uint8_t *res);

int ble_process_l2cap_connected(uint8_t *res);

int ble_process_l2cap_disconnected(uint8_t *res);

int ble_process_l2cap_received(uint8_t *res);

int ble_process_response(uint8_t *res);

int ble_process_start_adv_response(uint8_t *res);

int ble_process_stop_adv_response(uint8_t *res);

int ble_process_set_adv_data_response(uint8_t *res);

int ble_process_set_scan_param_response(uint8_t *res);

int ble_process_start_scan_response(uint8_t *res);

int ble_process_stop_scan_response(uint8_t *res);

int ble_process_connect_response(uint8_t *res);

int ble_process_disconnect_response(uint8_t *res);

int ble_process_set_data_len_response(uint8_t *res);

int ble_process_set_phy_response(uint8_t *res);

int ble_process_conn_update_response(uint8_t *res);

int ble_process_set_filter_list_response(uint8_t *res);

int ble_process_host_service_add_response(uint8_t *res);

int ble_process_start_service_response(uint8_t *res);

int ble_process_write_charateristic_response(uint8_t *res);

int ble_process_disc_prim_response(uint8_t *res);

int ble_process_disc_chrc_response(uint8_t *res);

int ble_process_disc_desc_response(uint8_t *res);

int ble_process_cfg_notify_response(uint8_t *res);

int ble_process_cfg_indicate_response(uint8_t *res);

int ble_process_register_service_response(uint8_t *res);

int ble_process_l2cap_connect_response(uint8_t *res);

int ble_process_l2cap_disconnect_response(uint8_t *res);

int ble_process_l2cap_send_response(uint8_t *res);

int ble_process_l2cap_register_response(uint8_t *res);

int ble_process_l2cap_metrics_response(uint8_t *res);

int ble_process_l2cap_receive_response(uint8_t *res);

int ble_process_gatt_prim_discovered(uint8_t *res);

int ble_process_gatt_chrc_discovered(uint8_t *res);

int ble_process_gatt_desc_discovered(uint8_t *res);

NCPCmd_DS_COMMAND *mpu_host_get_ble_command_buffer();

#endif /*__NCP_HOST_COMMAND_BLE_H__*/