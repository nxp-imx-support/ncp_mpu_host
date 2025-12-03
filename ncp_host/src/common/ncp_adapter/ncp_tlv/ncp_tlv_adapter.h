/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NCP_TLV_ADAPTER_H__
#define __NCP_TLV_ADAPTER_H__

#include "fsl_common.h"
#include "ncp_pm.h"
#include "ncp_intf_pm.h"
#include "ncp_common.h"
#include "ncp_adapter.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#ifndef CONFIG_NCP_USE_ENCRYPT
#define CONFIG_NCP_USE_ENCRYPT              0
#endif
#ifndef CONFIG_NCP_HOST_AUTO_TRIG_ENCRYPT
#define CONFIG_NCP_HOST_AUTO_TRIG_ENCRYPT   0
#endif
#if CONFIG_NCP_USE_ENCRYPT
#define CONFIG_NCP_MBEDTLS_DBG_LEVEL        1   /* 0-4, higher means more log output */
#define CONFIG_NCP_IS_PVTKEY_ENCRYPTED      1
#endif

#define TLV_CMD_HEADER_LEN                  12
#define TLV_CMD_SIZE_LOW_BYTES              4
#define TLV_CMD_SIZE_HIGH_BYTES             5
#define TLV_CMD_BUF_SIZE                    4096
#define NCP_CHKSUM_LEN                      4
#define NCP_MAX_CLASS                       5

#define NCP_GET_PEER_CHKSUM(tlv, tlv_sz)    (*(uint32_t *)(tlv + tlv_sz))
#define NCP_GET_CLASS(tlv)                  (((tlv) & 0xf0000000) >> 28)

#define container_of(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })

#define ARG_UNUSED(x)                       (void)(x)

#if CONFIG_NCP_USE_ENCRYPT

#define NCP_ENDECRYPT_KEY_LEN               16
#define NCP_ENDECRYPT_IV_LEN                16

typedef struct _crypt_param_t {
    uint8_t  flag;
    uint8_t  rsv[3];
    void    *gcm_ctx_enc;
    void    *gcm_ctx_dec;
    uint8_t *dec_buf;
    uint32_t dec_buf_len;
    uint8_t  key_len;
    uint8_t  iv_len;
    uint8_t  key_enc[NCP_ENDECRYPT_KEY_LEN];
    uint8_t  key_dec[NCP_ENDECRYPT_KEY_LEN];
    uint8_t  iv_enc[NCP_ENDECRYPT_IV_LEN];
    uint8_t  iv_dec[NCP_ENDECRYPT_IV_LEN];
} crypt_param_t;

void dbg_print_hex(const uint8_t *buf, uint16_t len, const char *title);
int ncp_tlv_adapter_encrypt_init(const uint8_t *key_enc, const uint8_t *key_dec,
                                 const uint8_t *iv_enc, const uint8_t *iv_dec,
                                 uint16_t key_len, uint16_t iv_len);
int ncp_tlv_adapter_encrypt_deinit(void);
int ncp_tlv_adapter_encrypt_enable(void);
int ncp_tlv_adapter_encrypt_disable(void);
#endif /* CONFIG_NCP_USE_ENCRYPT */

int ncp_tlv_adapter_is_encrypt_mode(void);

/* NCP Debug options */
#if CONFIG_NCP_DEBUG
/* Interface related stats*/
typedef struct _stats_intf
{
    uint32_t tx;
    uint32_t tx0;
    uint32_t tx1;
    uint32_t tx2;
    uint32_t rx;
    uint32_t rx0;
    uint32_t rx1;
    uint32_t rx2;
    uint32_t err_tx;
    uint32_t err_rx;
    uint32_t chkerr;
    uint32_t drop;
    uint32_t lenerr;
    uint32_t ringerr;
} stats_inft_t;

/* NCP Interface stats container */
typedef struct _ncp_stats
{
    stats_inft_t tlvq;
    stats_inft_t intf;
} ncp_stats_t;

/* Global NCP statistics instance */
extern ncp_stats_t ncp_stats;

#define NCP_STATS_INC(x) ++ncp_stats.x
#define NCP_STATS_DEC(x) --ncp_stats.x
#else
#define NCP_STATS_INC(x)
#define NCP_STATS_DEC(x)
#endif /* CONFIG_NCP_DEBUG */
/* End of NCP debug options */

/* TX event sent before entering sleep mode */
#define NCP_TX_EVENT_CTRL_PRE   NCP_PM_NOTIFY_EVENT_PRE
/* TX event sent after waking up from sleep */
#define NCP_TX_EVENT_CTRL_POST  NCP_PM_NOTIFY_EVENT_POST
/* TX event indicating data is ready to send */
#define NCP_TX_EVENT_DATA_READY NCP_PM_NOTIFY_EVENT_DATA_READY
/* Mask for all TX events */
#define NCP_TX_EVENT_ALL        (NCP_TX_EVENT_CTRL_PRE | \
                                NCP_TX_EVENT_CTRL_POST | \
                                NCP_TX_EVENT_DATA_READY)

/* Maximum length of TX data queue */
#define NCP_TLV_DATA_QUEUE_LENGTH           80
/* Maximum length of TX control queue */
#define NCP_TLV_CTRL_QUEUE_LENGTH           2
/* Maximum message payload size in queue */
#define NCP_TLV_QUEUE_MSGPLD_SIZE           4096

/**
 * Message queue element size
 * Note: Queue element is a void* pointer to dynamically allocated buffer
 * Buffer size = sizeof(ncp_tlv_data_qelem_t) + tlv_sz
 */
#define NCP_TLV_QUEUE_MSG_SIZE              (sizeof(void *))

/**
 * @brief TX data queue element structure
 * 
 * Used for queuing data messages to be transmitted
 */
typedef NCP_TLV_PACK_START struct
{
    void *priv;
    size_t tlv_sz;        /**< TLV data size in bytes */
    uint8_t *tlv_buf;     /**< Pointer to TLV data buffer */
} NCP_TLV_PACK_END ncp_tlv_data_qelem_t;

/**
 * @brief TX control queue element structure
 * 
 * Used for queuing control messages to be transmitted
 */
typedef NCP_TLV_PACK_START struct
{
    uint32_t event;       /**< Event code (see TX Event Types) */
    uint32_t seqnum;      /**< Message sequence number */
    size_t ctrl_sz;       /**< Control data size in bytes */
    uint8_t *ctrl_buf;    /**< Pointer to control data buffer */
} NCP_TLV_PACK_END ncp_tlv_ctrl_qelem_t;

/**
 * @brief TLV message handler callback function
 * @param tlv Pointer to TLV message
 * @param tlv_sz TLV message size
 * @param status Processing status
 */
typedef void (*tlv_callback_t)(void *tlv, size_t tlv_sz, int status);

typedef void (*tlv_send_callback_t)(void *arg);

/**
 * @brief NCP interface operations structure
 * 
 * Defines the interface layer operations for different transport types
 */
typedef struct _ncp_intf_ops
{
    int (*init)(void *);
    int (*deinit)(void *);
    int (*send)(uint8_t *buf, size_t len, tlv_send_callback_t cb);
    int (*recv)(uint8_t *buf, size_t *len);
    ncp_intf_pm_ops_t *pm_ops;
} ncp_intf_ops_t;

/**
 * @brief NCP TLV adapter main structure
 *
 * Central structure containing all adapter components
 */
typedef struct _ncp_tlv_adapter
{
    const ncp_intf_ops_t *intf_ops;             /**< Interface operations */
    const ncp_pm_ops_t *pm_ops;                 /**< Power management operations */
    tlv_callback_t tlv_handler[NCP_MAX_CLASS];  /**< TLV handlers indexed by class */
#if CONFIG_NCP_USE_ENCRYPT
    crypt_param_t *crypt;                       /**< Encryption parameters */
#endif
} ncp_tlv_adapter_t;

/*******************************************************************************
 * API
 ******************************************************************************/

/**
 * @brief Dispatch received TLV message to appropriate handler
 * @param tlv Pointer to TLV message
 * @param tlv_sz TLV message size
 */
void ncp_tlv_dispatch(void *tlv, size_t tlv_sz);

/* --- TX API Functions --- */
/**
 * @brief Send TLV data message (copy mode)
 *
 * The TLV buffer will be copied to internal queue
 *
 * @param tlv_buf Pointer to TLV buffer
 * @param tlv_sz TLV buffer size in bytes
 * @return NCP_STATUS_SUCCESS on success, error code otherwise
 */
ncp_status_t ncp_tlv_send(void *tlv_buf, size_t tlv_sz);

/**
 * @brief Send control message
 *
 * @param event Event code (see TX Event Types)
 * @param ctrl_buf Pointer to control buffer
 * @param ctrl_sz Control buffer size in bytes
 * @return 0 on success, negative error code on failure
 */
int ncp_tlv_ctrl_send(uint32_t event, void *ctrl_buf, size_t ctrl_sz);

/**
 * @brief Set TX event for notification
 * @param event Event mask to set
 */
void ncp_tlv_tx_set_event(uint32_t event);

/**
 * @brief Get pointer to global TLV adapter instance
 * @return Pointer to ncp_tlv_adapter_t structure
 */
const ncp_tlv_adapter_t *ncp_tlv_adapter_get(void);

#endif /* __NCP_TLV_ADAPTER_H__ */
