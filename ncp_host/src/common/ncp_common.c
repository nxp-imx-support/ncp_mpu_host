/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>

/** Dump buffer in hex format on console
 *
 * This function prints the received buffer in HEX format on the console
 *
 * \param[in] data Pointer to the data buffer
 * \param[in] len Length of the data
 */
#define DUMP_WRAPAROUND 16
void dump_hex(const void *data, unsigned len)
{
    (void)printf("**** Dump @ %p Len: %d ****\n\r", data, len);

    unsigned int i;
    const char *data8 = (const char *)data;
    for (i = 0; i < len;)
    {
        (void)printf("%02x ", data8[i++]);
        if (!(i % DUMP_WRAPAROUND))
            (void)printf("\n\r");
    }

    (void)printf("\n\r******** End Dump *******\n\r");
}

