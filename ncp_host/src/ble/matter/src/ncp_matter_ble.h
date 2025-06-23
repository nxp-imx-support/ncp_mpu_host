/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NCP_MATTER_BLE_H__
#define __NCP_MATTER_BLE_H__
/* -------------------------------------------------------------------------- */
/*                           Includes                                         */
/* -------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>

#include "ncp_bluetooth.h"

/* -------------------------------------------------------------------------- */
/*                           Constants                                        */
/* -------------------------------------------------------------------------- */

#define NCP_CMD_SEQ_ZERO 0x0000
#define NCP_CMD_RES_OK   0x0000
#define NCP_CMD_RSVD     0x0000

#define NCP_COMMAND_LEN  4096
#define NCP_CMD_HEADER_LEN sizeof(NCP_COMMAND)


/* -------------------------------------------------------------------------- */
/*                           Function prototypes                              */
/* -------------------------------------------------------------------------- */

/*______________________________________________________________________
**
**            _   _  ____ ____        _    ____ ___
**           | \ | |/ ___|  _ \      / \  |  _ \_ _|
**           |  \| | |   | |_) |    / _ \ | |_) | |
**           | |\  | |___|  __/    / ___ \|  __/| |
**           |_| \_|\____|_|      /_/   \_\_|  |___|
**
**______________________________________________________________________
*/

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
int ncp_bt_set_adv_data(const struct bt_data *ad, uint8_t ad_len);

/**
 * @brief Start advertising
 * 
 * Start advertising.
 * 
 * @return Zero on success or (negative) error code otherwise.
 * @return -ENOMEM No free connection objects available for connectable advertiser.
 */
int ncp_bt_le_adv_start();

/**
 * @brief Stop advertising
 *
 * Stops ongoing advertising.
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int ncp_bt_le_adv_stop();

/**
 * @brief Enable Bluetooth
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int ncp_bt_enable();

/**
 * @brief Create a new identity.
 *
 * @param addr Address to use for the new identity.
 * @param irk  Identity Resolving Key (16 bytes) to be used with this identity.
 *
 * @return Identity identifier (>= 0) in case of success, or a negative
 *         error code on failure.
 */
int ncp_bt_id_create(bt_addr_le_t *addr, uint8_t *irk);

/**
 * @brief Set Bluetooth Device Name
 *
 * @param name New name
 *
 * @return Zero on success or (negative) error code otherwise.
 */
int ncp_bt_set_name(const char *name);

/**
 * @brief Get Bluetooth Device Name
 *
 * @return Bluetooth Device Name
 */
const char *ncp_bt_get_name();

/** @brief Get array index of a connection
 *
 *  @param conn_id Connection ID.
 *
 *  @return Index of the connection object.
 *          The range of the returned value is 0..CONFIG_BT_MAX_CONN-1
 */
int ncp_bt_conn_index(uint16_t conn_id);

/** @brief Increment a connection's reference count.
 *
 *  Increment the reference count of a connection object.
 *
 *  @param conn_id Connection ID.
 *
 *  @return Connection id with incremented reference count, or NULL if the
 *          reference count is zero.
 */
int ncp_bt_conn_ref(uint16_t conn_id);

/** @brief Decrement a connection's reference count.
 *
 *  Decrement the reference count of a connection object.
 *
 *  @param conn_id Connection ID.
 */
int ncp_bt_conn_unref(uint16_t conn_id);

/** @brief Register connection callbacks.
 *
 *  Register callbacks to monitor the state of connections.
 *
 *  @param cb Callback struct. Must point to memory that remains valid.
 */
int ncp_bt_conn_cb_register(struct bt_conn_cb *cb);

/** @brief Disconnect from a remote device or cancel pending connection.
 *
 *  @param conn_id Connection id to disconnect.
 *  @param reason Reason code for the disconnection.
 *
 *  @return Zero on success or (negative) error code on failure.
 */
int ncp_bt_conn_disconnect(uint16_t conn_id, uint8_t reason);

/** @brief Register Matter ble service.
 *
 *  @return 0 in case of success or negative value in case of error.
 */
int ncp_bt_gatt_service_register();

/** @brief Register matter service callback function.
 *
 *  @param cb Service callback function.
 */
int ncp_bt_matter_svc_cb_register(struct bt_svc_cb *cb);

/** @brief Unregister Matter ble service.
 *
 *  @return 0 in case of success or negative value in case of error.
 */
int ncp_bt_gatt_service_unregister();

/** @brief Get ATT MTU for a connection
 *
 *  Get negotiated ATT connection MTU, note that this does not equal the largest
 *  amount of attribute data that can be transferred within a single packet.
 *
 *  @param conn_id Connection ID.
 *
 *  @return MTU in bytes
 */
int ncp_bt_gatt_get_mtu(uint16_t conn_id);

#if CHIP_ENABLE_ADDITIONAL_DATA_ADVERTISING
/** @brief Generic Read Attribute value helper.
 *
 *  Read Additional commissioning related data.
 *
 *  @param conn_id Connection id.
 *  @param value Attribute value.
 *  @param value_len Length of the attribute value.
 *
 *  @return number of bytes read in case of success or negative values in case of error.
 */
int ncp_bt_gatt_attr_read(uint16_t conn_id, void *value, uint16_t value_len);
#endif

/** @brief Indicate attribute value change.
 *
 *  @param conn_id Connection id.
 *  @param value Attribute value.
 *  @param value_len Length of the attribute value.
 *
 *  @return 0 in case of success or negative value in case of error.
 */
int ncp_bt_gatt_indicate(uint16_t conn_id, void *value, uint16_t value_len);

#endif /* __NCP_MATTER_BLE_H__ */
