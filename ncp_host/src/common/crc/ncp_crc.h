/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _NCP_CRC_H_
#define _NCP_CRC_H_

#include <stdint.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/


#define CHECKSUM_LEN  4

/*******************************************************************************
 * API
 ******************************************************************************/

void     ncp_tlv_chksum_init(void);
uint32_t ncp_tlv_chksum(uint8_t *buf, uint16_t len);

#endif /* _NCP_CRC_H_ */
