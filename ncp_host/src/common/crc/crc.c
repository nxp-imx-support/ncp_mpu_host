/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "crc.h"
#include "ncp_adapter.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/
uint32_t crc32_table[256];

/*******************************************************************************
 * Public functions
 ******************************************************************************/
void ncp_tlv_chksum_init(void)
{
    int          i, j;
    unsigned int c;

    for (i = 0; i < 256; ++i)
    {
        for (c = i << 24, j = 8; j > 0; --j) c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
        crc32_table[i] = c;
    }
}

uint32_t ncp_tlv_chksum(uint8_t *buf, uint16_t len)
{
#if CONFIG_NCP_UART
    /*Wait for rt1060evkb ncp-host support HW crc*/
    uint8_t *    p;
    unsigned int crc;

    crc = 0xffffffff;
    for (p = buf; len > 0; ++p, --len) crc = (crc << 8) ^ (crc32_table[(crc >> 24) ^ *p]);
    return ~crc;
#else
    return 0;
#endif
}
