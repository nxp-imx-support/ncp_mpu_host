/*
 * Copyright 2024 - 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _NCP_COMMON_H_
#define _NCP_COMMON_H_

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#ifdef __GNUC__
/** Structure packing begins */
#define NCP_TLV_PACK_START
/** Structure packeing end */
#define NCP_TLV_PACK_END __attribute__((aligned(8)))
#else /* !__GNUC__ */
#ifdef PRAGMA_PACK
/** Structure packing begins */
#define NCP_TLV_PACK_START
/** Structure packeing end */
#define NCP_TLV_PACK_END
#else /* !PRAGMA_PACK */
/** Structure packing begins */
#define NCP_TLV_PACK_START __packed
/** Structure packing end */
#define NCP_TLV_PACK_END
#endif /* PRAGMA_PACK */
#endif /* __GNUC__ */

#define NCP_ASSERT(x) assert(x)

#define NCP_SUCCESS 0
#define NCP_FAIL    1

/* NCP status */
typedef enum _ncp_status
{
    NCP_STATUS_ERROR      = -1,
    NCP_STATUS_CHKSUMERR  = -2,
    NCP_STATUS_NOMEM      = -3,
    NCP_STATUS_QUEUE_FULL = -4,
    NCP_STATUS_HANDLE_RSP = -5,
    NCP_STATUS_SUCCESS    = 0,
} ncp_status_t;

#endif /* _NCP_COMMON_H_ */