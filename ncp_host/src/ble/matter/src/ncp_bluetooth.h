/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NCP_BLUETOOTH_H__
#define __NCP_BLUETOOTH_H__
/* -------------------------------------------------------------------------- */
/*                           Includes                                         */
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
/*                           Constants                                        */
/* -------------------------------------------------------------------------- */

/** Bluetooth advertising type */
#define BT_DATA_SVC_DATA16                    0x16
#define BT_DATA_NAME_COMPLETE                 0x09

/** Bluetooth disconnection reason */
#define BT_HCI_ERR_REMOTE_USER_TERM_CONN      0x13
#define BT_HCI_ERR_LOCALHOST_TERM_CONN        0x16

/** Bluetooth GATT CCC value */
#define BT_GATT_CCC_INDICATE                  0x0002

/* -------------------------------------------------------------------------- */
/*                           Types                                            */
/* -------------------------------------------------------------------------- */

/** Bluetooth Device Address */
typedef struct {
	uint8_t  val[6];
} bt_addr_t;

/** Bluetooth LE Device Address */
typedef struct {
	uint8_t type;
	bt_addr_t a;
} bt_addr_le_t;

/** Bluetooth Adevertising Data */
struct bt_data {
	uint8_t type;
	uint8_t data_len;
	const uint8_t *data;
};

struct bt_conn_cb {
	/** A new connection has been established. */
	void (*connected)(uint16_t connId, uint8_t err);
	/** A connection has been disconnected. */
	void (*disconnected)(uint16_t connId, uint8_t reason);
};

struct bt_svc_cb {
	/** Receive rx write data. */
	void (*rx_write_cb)(uint16_t conId, void *buf, uint8_t len);
	/** Indication ccc changed. */
	void (*tx_ccc_write_cb)(uint16_t conId, uint16_t value);
    /** Receive indication confirm. */
	void (*tx_ind_confirm_cb)(uint16_t conId, uint8_t err);
};

#endif /* __NCP_BLUETOOTH_H__ */