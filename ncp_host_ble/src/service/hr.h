/** @file hr.h
 *
 *  @brief  Heart Rate Profile defineations.
 *
 *  Copyright 2024 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef __HR_H_
#define __HR_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Definitions
******************************************************************************/

/**
 *  @brief Heart Rate Service UUID value
 */
#define UUID_HRS 0x180d
/**
 *  @brief HRS Characteristic Measurement Interval UUID value
 */
#define UUID_HRS_MEASUREMENT 0x2a37
/**
 *  @brief HRS Characteristic Body Sensor Location
 */
#define UUID_HRS_BODY_SENSOR 0x2a38
/**
 *  @brief HRS Characteristic Control Point UUID value
 */
#define UUID_HRS_CONTROL_POINT 0x2a39


/* HTS flag values */
#define hrs_unit_celsius_c        0x00U /* bit 0 unset */
#define hrs_unit_fahrenheit_c     0x01U /* bit 0 set */

#define hrs_include_temp_type     0x04U /* bit 2 set */

/* Heart Rate format */
struct hr_measurement
{
    uint8_t sensor;
    uint8_t rate;
};

/*******************************************************************************
* Prototypes
******************************************************************************/


/*******************************************************************************
 * API
 ******************************************************************************/
void central_hrc_start(void);
void central_hrc_task(void *pvParameters);
#if 0
void central_hrc_event_put(void);
void central_hrc_found(NCP_DEVICE_ADV_REPORT_EV * data);
void central_hrc_get_primary_service(MCP_DISC_PRIM_RP * param);
void central_hrc_get_characteristics(MCP_DISC_CHRC_RP *param);
void central_hrc_get_ccc(MCP_DISC_ALL_DESC_RP * param);
void central_notify(uint8_t *data);
#endif
void peripheral_hrs_task(void);
void peripheral_hrs_event_put(void);
void peripheral_hrs_start(void);
void peripheral_hrs_indicate(uint8_t value);



#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* __HR_H_ */
