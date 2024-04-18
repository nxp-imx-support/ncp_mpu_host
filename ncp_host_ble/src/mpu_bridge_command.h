/*
 * Copyright (c) 2015-2016 Intel Corporation
 * Copyright (c) 2022 Codecoup
 * Copyright 2022-2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __MPU_BRIDGE_COMMAND_H__
#define __MPU_BRIDGE_COMMAND_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/times.h>
#include "mpu_bridge_ble_config.h"

#define NCP_BRIDGE_CMD_HEADER_LEN sizeof(NCP_BRIDGE_COMMAND)
#define NCP_BRIDGE_TLV_HEADER_LEN sizeof(NCP_BRIDGE_TLV_HEADER)


#define MAC2STR(a)                a[0], a[1], a[2], a[3], a[4], a[5]
#define MCU_BRIDGE_IP_LENGTH      4
#define MCU_BRIDGE_IP_VALID       255
#define MCU_BRIDGE_MAX_AP_ENTRIES 30

/*NCP MCU Bridge command class*/
#define NCP_BRIDGE_CMD_WLAN   0x00000000
#define NCP_BRIDGE_CMD_BLE    0x01000000
#define NCP_BRIDGE_CMD_15D4   0x02000000
#define NCP_BRIDGE_CMD_MATTER 0x03000000
#define NCP_BRIDGE_CMD_SYSTEM 0x04000000

/*BLE NCP Bridge subclass*/
#define NCP_BRIDGE_CMD_BLE_CORE         0x00000000
#define NCP_BRIDGE_CMD_BLE_GAP          0x00010000
#define NCP_BRIDGE_CMD_BLE_GATT         0x00020000
#define NCP_BRIDGE_CMD_BLE_L2CAP        0x00030000
#define NCP_BRIDGE_CMD_BLE_POWERMGMT    0x00040000
#define NCP_BRIDGE_CMD_BLE_VENDOR       0x00050000
#define NCP_BRIDGE_CMD_BLE_OTHER        0x00060000
#define NCP_BRIDGE_CMD_BLE_EVENT        0x000f0000

/*WLAN NCP MCU Bridge subclass*/
#define NCP_BRIDGE_CMD_WLAN_STA         0x00000000
#define NCP_BRIDGE_CMD_WLAN_BASIC       0x00010000
#define NCP_BRIDGE_CMD_WLAN_REGULATORY  0x00020000
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT   0x00030000
#define NCP_BRIDGE_CMD_WLAN_DEBUG       0x00040000
#define NCP_BRIDGE_CMD_WLAN_OTHER       0x00050000
#define NCP_BRIDGE_CMD_WLAN_MEMORY      0x00060000
#define NCP_BRIDGE_CMD_WLAN_NETWORK     0x00070000
#define NCP_BRIDGE_CMD_WLAN_OFFLOAD     0x00080000
#define NCP_BRIDGE_CMD_WLAN_SOCKET      0x00090000
#define NCP_BRIDGE_CMD_WLAN_UAP         0x000a0000
#define NCP_BRIDGE_CMD_WLAN_HTTP        0x000b0000
#define NCP_BRIDGE_CMD_WLAN_COEX        0x000c0000
#define NCP_BRIDGE_CMD_WLAN_MATTER      0x000d0000
#define NCP_BRIDGE_CMD_WLAN_EDGE_LOCK   0x000e0000
#define NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT 0x000f0000

/* System NCP Bridge subclass */
#define NCP_BRIDGE_CMD_SYSTEM_CONFIG   0x00000000

/*NCP MCU Bridge Message Type*/
#define NCP_BRIDGE_MSG_TYPE_CMD   0x0000
#define NCP_BRIDGE_MSG_TYPE_RESP  0x0001
#define NCP_BRIDGE_MSG_TYPE_EVENT 0x0002

/*NCP MCU Bridge CMD response state*/
/*General result code ok*/
#define NCP_BRIDGE_CMD_RESULT_OK 0x0000
/*General error*/
#define NCP_BRIDGE_CMD_RESULT_ERROR 0x0001
/*NCP Bridge Command is not valid*/
#define NCP_BRIDGE_CMD_RESULT_NOT_SUPPORT 0x0002
/*NCP Bridge Command is pending*/
#define NCP_BRIDGE_CMD_RESULT_PENDING 0x0003
/*System is busy*/
#define NCP_BRIDGE_CMD_RESULT_BUSY 0x0004
/*Data buffer is not big enough*/
#define NCP_BRIDGE_CMD_RESULT_PARTIAL_DATA 0x0005
/*MCU device enter low power mode*/
#define NCP_BRIDGE_CMD_RESULT_ENTER_SLEEP 0x0006
/*MCU device exit low power mode*/
#define NCP_BRIDGE_CMD_RESULT_EXIT_SLEEP 0x0007

/* The max size of the network list*/
#define NCP_BRIDGE_WLAN_KNOWN_NETWORKS 5

/*NCP MCU Bridge Command definitions*/
/*BLE Core command*/
#define NCP_BRIDGE_CMD_BLE_CORE_SUPPORT_CMD    (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_CORE | 0x00000001) /* Read supported commands*/
#define NCP_BRIDGE_CMD_BLE_CORE_SUPPORT_SER    (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_CORE | 0x00000002) /* Read supported services*/
#define NCP_BRIDGE_CMD_BLE_CORE_REGISTER       (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_CORE | 0x00000003) /* register services */
#define NCP_BRIDGE_CMD_BLE_CORE_UNREGISTER     (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_CORE | 0x00000004) /* unregister services*/
#define NCP_BRIDGE_CMD_BLE_CORE_RESET          (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_CORE | 0x00000006) /* reset board */

/*BLE Gap command*/
#define NCP_BRIDGE_CMD_BLE_GAP_SET_DATA_LEN         (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x00000020) /* Set data len */
#define NCP_BRIDGE_CMD_BLE_GAP_SET_PHY              (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000001f) /* Set phy */
#define NCP_BRIDGE_CMD_BLE_GAP_SET_ADV_DATA         (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000001e) /* Set adv data */
#define NCP_BRIDGE_CMD_BLE_GAP_SET_SCAN_PARAM       (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000001d) /* Set scan parameter */
#define NCP_BRIDGE_CMD_BLE_GAP_START_ADV            (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000000a) /* Start advertising */
#define NCP_BRIDGE_CMD_BLE_GAP_STOP_ADV             (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000000b) /* Stop advertising */
#define NCP_BRIDGE_CMD_BLE_GAP_START_SCAN           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000000c) /* Start discovery */
#define NCP_BRIDGE_CMD_BLE_GAP_STOP_SCAN            (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000000d) /* Stop discovery */
#define NCP_BRIDGE_CMD_BLE_GAP_CONNECT              (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000000e) /* Create a connection */
#define NCP_BRIDGE_CMD_BLE_GAP_DISCONNECT           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000000f) /* Terminate a connection */
#define NCP_BRIDGE_CMD_BLE_GAP_CONN_PARAM_UPDATE    (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x00000016) /* Connection parameters update */
#define NCP_BRIDGE_CMD_BLE_GAP_SET_FILTER_LIST      (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x0000001c) /* Set filter accept list */
#define NCP_BRIDGE_CMD_BLE_GAP_PAIR                 (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GAP | 0x00000011) /* Enable encryption with peer or start pair process */

/*BLE Gatt command*/
#define NCP_BRIDGE_CMD_BLE_HOST_SERVICE_ADD         (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000002) /* Add Host Attribute to Device Gatt datebase and start, ble-host-service-start */
#define NCP_BRIDGE_CMD_BLE_HOST_SERVICE_DISC        (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000003) /* Discover Primary Service/Characteristics/Descriptors */
#define NCP_BRIDGE_CMD_BLE_GATT_SET_VALUE           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000006) /* Set Characteristic/Descriptor Value */
#define NCP_BRIDGE_CMD_BLE_GATT_DISC_PRIM           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x0000000c) /* Discover Primary Service */
#define NCP_BRIDGE_CMD_BLE_GATT_DISC_CHRC           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x0000000f) /* Discover Characteristics */
#define NCP_BRIDGE_CMD_BLE_GATT_START_SERVICE       (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000007) /* Start server with previously prepared attributes database. */
#define NCP_BRIDGE_CMD_BLE_GATT_CFG_NOTIFY          (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x0000001a) /* Configure service to notify characteristic value to clinet */
#define NCP_BRIDGE_CMD_BLE_GATT_CFG_INDICATE        (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x0000001b) /* Configure service to indicate characteristic value to clinet */
#define NCP_BRIDGE_CMD_BLE_GATT_READ                (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000011) /* Read Characteristic/Descriptor */
#define NCP_BRIDGE_CMD_BLE_GATT_REGISTER_SERVICE    (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000020)  /* register a profile service */
#define NCP_BRIDGE_CMD_BLE_GATT_DESC_CHRC           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_GATT | 0x00000021) /* Discover Descriptors */
/*BLE L2CAP command*/
#define NCP_BRIDGE_CMD_BLE_L2CAP_CONNECT            (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_L2CAP | 0x00000002) /* L2CAP connect */
#define NCP_BRIDGE_CMD_BLE_L2CAP_DISCONNECT         (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_L2CAP | 0x00000003) /* L2CAP disconnect */
#define NCP_BRIDGE_CMD_BLE_L2CAP_SEND               (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_L2CAP | 0x00000004) /* L2CAP send */
#define NCP_BRIDGE_CMD_BLE_L2CAP_REGISTER           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_L2CAP | 0x0000000a) /* L2CAP register*/
#define NCP_BRIDGE_CMD_BLE_L2CAP_METRICS            (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_L2CAP | 0x0000000b) /* L2CAP metrics */
#define NCP_BRIDGE_CMD_BLE_L2CAP_RECEIVE            (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_L2CAP | 0x0000000c) /* L2CAP receive */

/*BLE Vendor command*/
#define NCP_BRIDGE_CMD_BLE_VENDOR_POWER_MODE        (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_VENDOR | 0x00000001) /* Enable/Disable power save mode */
#define NCP_BRIDGE_CMD_BLE_VENDOR_SET_UART_BR       (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_VENDOR | 0x00000002) /* Set Uart baud rate */
#define NCP_BRIDGE_CMD_BLE_VENDOR_SET_DEVICE_ADDR   (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_VENDOR | 0x00000003) /* Set Uart LE device address */
#define NCP_BRIDGE_CMD_BLE_VENDOR_SET_DEVICE_NAME   (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_VENDOR | 0x00000004) /* Set Uart LE device name */
#define NCP_BRIDGE_CMD_BLE_VENDOR_CFG_MULTI_ADV     (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_VENDOR | 0x00000005) /* Config Multi-advertising */

/*BLE events*/
#define NCP_BRIDGE_EVENT_IUT_READY                  (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x80) /* IUT Ready event */
#define NCP_BRIDGE_EVENT_ADV_REPORT                 (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x81) /* LE Advertising Report event */
#define NCP_BRIDGE_EVENT_DEVICE_CONNECTED           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x82) /* Connection Complete event */
#define NCP_BRIDGE_EVENT_DEVICE_DISCONNECT          (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x83) /* Disconnection Complete event */
#define NCP_BRIDGE_EVENT_PASSKEY_DISPLAY            (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x84) /* Passkey Display event */
#define NCP_BRIDGE_EVENT_IDENITY_RESOLVED           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x87) /* Remote Identity Address Resolved event */
#define NCP_BRIDGE_EVENT_CONN_PARAM_UPDATE          (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x88) /* Connection param update event */
#define NCP_BRIDGE_EVENT_SEC_LEVEL_CHANGED          (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x89) /* Security Level Changed event */
#define NCP_BRIDGE_EVENT_PHY_UPDATED                (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x91) /* GAP phy updated */
#define NCP_BRIDGE_EVENT_DATA_LEN_UPDATED           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x92) /* GAP data len updated */

#define NCP_BRIDGE_EVENT_GATT_NOTIFICATION          (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x80 | 0x200) /* GATT notification Receive event */
#define NCP_BRIDGE_EVENT_ATTR_VALUE_CHANGED         (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x81 | 0x200) /* GATT Attribute Value Changed event */
#define NCP_BRIDGE_EVENT_GATT_CCC_CFG_CHANGED       (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x82 | 0x200) /* GATT Client Characteristic Configuration Changed event */
#define NCP_BRIDGE_EVENT_GATT_SUBSCRIPTIONED        (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x85 | 0x200) /* GATT Subcription status event */
#define NCP_BRIDGE_EVENT_GATT_DISC_PRIM             (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x19 | 0x200) /* Discover Primary Service event */
#define NCP_BRIDGE_EVENT_GATT_DISC_CHRC             (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x20 | 0x200) /* Discover Characteristics event */
#define NCP_BRIDGE_EVENT_GATT_DISC_DESC             (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x21 | 0x200) /* Discover Descriptors event */

#define NCP_BRIDGE_EVENT_L2CAP_CONNECT              (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x81 | 0x300) /* L2CAP Connect event */
#define NCP_BRIDGE_EVENT_L2CAP_DISCONNECT           (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x82 | 0x300) /* L2CAP Disconnect event */
#define NCP_BRIDGE_EVENT_L2CAP_RECEIVE              (NCP_BRIDGE_CMD_BLE | NCP_BRIDGE_CMD_BLE_EVENT | 0x83 | 0x300) /* L2CAP Receive event */


/*NCP Bridge BLE GATT TLV*/
#define NCP_BRIDGE_CMD_GATT_ADD_SERVICE_TLV       0x0001
#define NCP_BRIDGE_CMD_GATT_ADD_CHRC_TLV          0x0002
#define NCP_BRIDGE_CMD_GATT_ADD_DESC_TLV          0x0003
#define NCP_BRIDGE_CMD_GATT_START_SVC_TLV         0x0004

#define NCP_BRIDGE_CMD_INVALID_CMD    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x0000000a)


/* Bluetooth defines */
#define NCP_BLE_ADDR_LENGTH 6
#define NCP_BLE_DEVICE_NAME_MAX  32
#define MAX_MONIT_MAC_FILTER_NUM 3
#define MAX_SUPPORT_SERVICE 10
#define SERVER_MAX_UUID_LEN 16

#define MOD_ERROR_START(x) (x << 12 | 0)
/* Globally unique success code */
#define WM_SUCCESS 0

#define MPU_DEVICE_STATUS_ACTIVE 1
#define MPU_DEVICE_STATUS_SLEEP  2

/* Host wakes up MPU device through interface */
#define WAKE_MODE_INTF 0x1
#define WAKE_MODE_GPIO 0x2

typedef struct _power_cfg_t
{
    uint8_t enable;
    uint8_t wake_mode;
    uint8_t subscribe_evt;
    uint32_t wake_duration;
    uint8_t is_mef;
    uint32_t wake_up_conds;
    uint8_t is_manual;
    uint32_t rtc_timeout;
} power_cfg_t;

typedef struct _NCP_CMD_SYSTEM_SDIO_SET
{
    /* value */
    int val;
} NCP_CMD_SYSTEM_SDIO_SET;

enum wm_errno
{
    /* First Generic Error codes */
    WM_GEN_E_BASE = MOD_ERROR_START(0),
    WM_FAIL,     /* 1 */
    WM_E_PERM,   /* 2: Operation not permitted */
    WM_E_NOENT,  /* 3: No such file or directory */
    WM_E_SRCH,   /* 4: No such process */
    WM_E_INTR,   /* 5: Interrupted system call */
    WM_E_IO,     /* 6: I/O error */
    WM_E_NXIO,   /* 7: No such device or address */
    WM_E_2BIG,   /* 8: Argument list too long */
    WM_E_NOEXEC, /* 9: Exec format error */
    WM_E_BADF,   /* 10: Bad file number */
    WM_E_CHILD,  /* 11: No child processes */
    WM_E_AGAIN,  /* 12: Try again */
    WM_E_NOMEM,  /* 13: Out of memory */
    WM_E_ACCES,  /* 14: Permission denied */
    WM_E_FAULT,  /* 15: Bad address */
    WM_E_NOTBLK, /* 16: Block device required */
    WM_E_BUSY,   /* 17: Device or resource busy */
    WM_E_EXIST,  /* 18: File exists */
    WM_E_XDEV,   /* 19: Cross-device link */
    WM_E_NODEV,  /* 20: No such device */
    WM_E_NOTDIR, /* 21: Not a directory */
    WM_E_ISDIR,  /* 22: Is a directory */
    WM_E_INVAL,  /* 23: Invalid argument */
    WM_E_NFILE,  /* 24: File table overflow */
    WM_E_MFILE,  /* 25: Too many open files */
    WM_E_NOTTY,  /* 26: Not a typewriter */
    WM_E_TXTBSY, /* 27: Text file busy */
    WM_E_FBIG,   /* 28: File too large */
    WM_E_NOSPC,  /* 29: No space left on device */
    WM_E_SPIPE,  /* 30: Illegal seek */
    WM_E_ROFS,   /* 31: Read-only file system */
    WM_E_MLINK,  /* 32: Too many links */
    WM_E_PIPE,   /* 33: Broken pipe */
    WM_E_DOM,    /* 34: Math argument out of domain of func */
    WM_E_RANGE,  /* 35: Math result not representable */

    /* WMSDK generic error codes */
    WM_E_CRC,     /* 36: Error in CRC check */
    WM_E_UNINIT,  /* 37: Module is not yet initialized */
    WM_E_TIMEOUT, /* 38: Timeout occurred during operation */

    /* Defined for Hostcmd specific API*/
    WM_E_INBIG,   /* 39: Input buffer too big */
    WM_E_INSMALL, /* 40: A finer version for WM_E_INVAL, where it clearly specifies that input is much smaller than
                     minimum requirement */
    WM_E_OUTBIG,  /* 41: Data output exceeds the size provided */
};

#pragma pack(1) // unalign

/*NCP Bridge tlv header*/
typedef struct TLVTypeHeader_t
{
    uint16_t type;
    uint16_t size;
} TypeHeader_t, NCP_BRIDGE_TLV_HEADER, NCP_MCU_HOST_TLV_HEADER;

typedef struct _BRIDGE_COMMAND
{
    /*bit0 ~ bit15 cmd id  bit16 ~ bit23 cmd subclass bit24 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t msg_type;
} NCP_BRIDGE_COMMAND, NCP_BRIDGE_RESPONSE;

typedef struct _NCP_CMD_FW_VERSION
{
    /** Driver version string */
    char driver_ver_str[16];
    /** Firmware version string */
    char fw_ver_str[128];
} NCP_CMD_FW_VERSION;

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
    NCP_BRIDGE_COMMAND header;
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

#define BRIDGE_MUTEX_INHERIT 1

/*Convert IP Adderss to hexadecimal*/
int strip_to_hex(int *number, int len);

/*Convert IP Adderss to hexadecimal*/
int IP_to_hex(char *IPstr, uint8_t *hex);

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

int mcu_bridge_cli_command_init();

int mcu_bridge_send_tlv_command(void);
void clear_mpu_bridge_command_buffer();

NCPCmd_DS_COMMAND *ncp_mpu_bridge_get_command_buffer();

void clear_mpu_bridge_command_buffer();

int mpu_bridge_init_cli_commands();
#endif /*__MPU_BRIDGE_COMMAND_H__*/
