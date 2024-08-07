/** @file ht.h
 *
 *  @brief  Health Thermometer Profile defineations.
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __HT_H_
#define __HT_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Definitions
******************************************************************************/

/**
 *  @brief GATT Primary Service UUID
 */
#define UUID_GATT_PRIMARY 0x2800

/**
 *  @brief Health Thermometer Service UUID
 */
#define UUID_HTS 0x1809

/**
 *  @brief HTS Characteristic Measurement Value UUID
 */
#define UUID_HTS_MEASUREMENT 0x2a1c

/**
 *  @brief GATT Client Characteristic Configuration UUID
 */
#define UUID_GATT_CCC 0x2902

/** Client Characteristic Configuration Values */

/**
 *  @brief Client Characteristic Configuration Notification.
 *
 *  If set, changes to Characteristic Value shall be notified.
 */
#define BT_GATT_CCC_NOTIFY			0x0001
/**
 *  @brief Client Characteristic Configuration Indication.
 *
 *  If set, changes to Characteristic Value shall be indicated.
 */
#define BT_GATT_CCC_INDICATE			0x0002

/* HTS flag values */
#define hts_unit_celsius_c        0x00U /* bit 0 unset */
#define hts_unit_fahrenheit_c     0x01U /* bit 0 set */

#define hts_include_temp_type     0x04U /* bit 2 set */


/* Temperature measurement format */
struct temp_measurement
{
    uint8_t flags;
    uint8_t temperature[4];
    uint8_t type;
};

/* Possible temperature sensor locations */
enum
{
    hts_no_temp_type = 0x00U,
    hts_armpit       = 0x01U,
    hts_body         = 0x02U,
    hts_ear          = 0x03U,
    hts_finger       = 0x04U,
    hts_gastroInt    = 0x05U,
    hts_mouth        = 0x06U,
    hts_rectum       = 0x07U,
    hts_toe          = 0x08U,
    hts_tympanum     = 0x09U,
};

/*******************************************************************************
* Prototypes
******************************************************************************/
void central_htc_task(void);
void central_htc_start(void);
#if 0
void central_htc_event_put(void);
void central_htc_found(MCP_DEVICE_ADV_REPORT_EV * data);
void central_htc_connect(void);
void central_htc_get_primary_service(MCP_DISC_PRIM_RP * param);
void central_htc_get_characteristics(MCP_DISC_CHRC_RP * param);
void central_htc_get_ccc(MCP_DISC_ALL_DESC_RP * param);
void central_notify(uint8_t *data);
#endif
void peripheral_hts_task(void);
void peripheral_hts_event_put(void);
void peripheral_hts_start(void);
void peripheral_hts_indicate(uint8_t value);



#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* __HT_H_ */
