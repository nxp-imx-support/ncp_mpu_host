/** @file bas.h
 *
 *  @brief  Battery Service Profile defineations.
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __BAS_H_
#define __BAS_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Definitions
******************************************************************************/

/**
 *  @brief Battery Service UUID value
 */
#define UUID_BAS 0x180f
/**
 *  @brief BAS Characteristic Battery Level UUID value
 */
#define UUID_BAS_BATTERY_LEVEL 0x2a19


/*******************************************************************************
* Prototypes
******************************************************************************/


/*******************************************************************************
 * API
 ******************************************************************************/
void peripheral_bas_task(void);
void peripheral_bas_event_put(void);
void peripheral_bas_start(void);
void peripheral_bas_indicate(uint8_t value);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* __BAS_H_ */
