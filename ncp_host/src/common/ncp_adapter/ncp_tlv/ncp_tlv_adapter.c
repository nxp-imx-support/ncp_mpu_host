/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_tlv_adapter.h"
#include "crc.h"
#include "ncp_adapter.h"
#include "lpm.h"
#if CONFIG_NCP_USE_ENCRYPT
#include "mbedtls/gcm.h"
#include "mbedtls_common.h"
#include "ncp_host_command.h"
#endif
#include <sys/syscall.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define NCP_TX_QUEUE_NAME "/ncp_tx_queue"

/*******************************************************************************
 * Variables
 ******************************************************************************/

#ifdef CONFIG_NCP_UART
extern ncp_intf_ops_t ncp_uart_ops;
#elif defined(CONFIG_NCP_SDIO)
extern ncp_intf_ops_t ncp_sdio_ops;
#elif defined(CONFIG_NCP_USB)
extern ncp_intf_ops_t ncp_usb_ops;
#elif defined(CONFIG_NCP_SPI)
extern ncp_intf_ops_t ncp_spi_ops;
#endif

/* Global variable containing NCP internal statistics */
#ifdef CONFIG_NCP_DEBUG
ncp_stats_t ncp_stats;
#endif

ncp_tlv_adapter_t ncp_tlv_adapter;

/* NCP adapter tx queue handler */
mqd_t ncp_tlv_tx_msgq_handle;

/* NCP adapter tx task */
static pthread_t       ncp_tlv_thread;
static pthread_mutex_t ncp_tlv_thread_mutex;
static void *          ncp_tlv_process(void *arg);

/*******************************************************************************
 * Private functions
 ******************************************************************************/

static void ncp_tlv_cb(void *arg)
{
#ifdef CONFIG_NCP_SDIO
    device_pm_enter(arg);
#endif
}

static void* ncp_tlv_process(void *arg)
{
    ssize_t         recv_sz = 0;
    ncp_tlv_qelem_t *qelem = NULL;

    ncp_adap_d("Start ncp_tlv_process thread");
    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));

    while (pthread_mutex_trylock(&ncp_tlv_thread_mutex) != 0)
    {
        qelem = NULL;
        recv_sz = mq_receive(ncp_tlv_tx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL);

        ncp_adap_d("%s: mq_receive qelem=%p recv_sz=%ld", __FUNCTION__, qelem, recv_sz);
        if (recv_sz == -1)
        {
            ncp_adap_e("%s: mq_receive failed", __FUNCTION__);
            NCP_TLV_STATS_INC(err_tx);
            continue;
        }

        if (qelem == NULL)
        {
            ncp_adap_e("%s: qelem=%p", __FUNCTION__, qelem);
            NCP_TLV_STATS_INC(err_tx);
            continue;
        }

        ncp_adap_d("%s: intf send qelem=%p: tlv_buf=%p tlv_sz=%lu",
                    __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
        mpu_dump_hex(qelem, sizeof(ncp_tlv_qelem_t) + qelem->tlv_sz);
#endif
        NCP_TLV_STATS_INC(tx1);
        /* sync send data */
        ncp_tlv_adapter.intf_ops->send(qelem->tlv_buf, qelem->tlv_sz, ncp_tlv_cb);
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
    }

    pthread_mutex_unlock(&ncp_tlv_thread_mutex);
    ncp_adap_d("Exit ncp_tlv_process thread");
    return NULL;
}

/*
 * Enqueue the qelement to ncp tx queue
 */
static ncp_status_t ncp_tlv_tx_enque(ncp_tlv_qelem_t *qelem)
{
    ncp_status_t status = NCP_STATUS_SUCCESS;

    ncp_adap_d("%s: mq_send qelem=%p: tlv_buf=%p tlv_sz=%lu", __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
    mpu_dump_hex(qelem, sizeof(ncp_tlv_qelem_t) + qelem->tlv_sz);
#endif
    if (mq_send(ncp_tlv_tx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, 0) != 0)
    {
        ncp_adap_e("ncp tlv enqueue failure");
        NCP_TLV_STATS_INC(err_tx);
        status = NCP_STATUS_ERROR;
        goto Fail;
    }
    NCP_TLV_STATS_INC(tx0);
    ncp_adap_d("enque tlv_buf success");

Fail:
    ncp_adap_d("Exit ncp_tlv_tx_enque");
    return status;
}

static ncp_status_t ncp_tlv_tx_init(void)
{
    int                status = NCP_STATUS_SUCCESS;
    struct mq_attr     qattr;
    pthread_attr_t     tattr;

    ncp_adap_d("Enter ncp_tlv_tx_init");
    mq_unlink(NCP_TX_QUEUE_NAME);
    qattr.mq_flags         = 0;
    qattr.mq_maxmsg        = NCP_TLV_QUEUE_LENGTH;
    qattr.mq_msgsize       = NCP_TLV_QUEUE_MSG_SIZE;
    qattr.mq_curmsgs       = 0;
    ncp_tlv_tx_msgq_handle = mq_open(NCP_TX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
    if ((int)ncp_tlv_tx_msgq_handle == -1)
    {
        ncp_adap_e("ERROR: ncp tx msg queue create fail");
        goto err_tlv_tx_msgq;
    }

    /* initialized with default attributes */
    status = pthread_attr_init(&tattr);
    if (status != 0)
    {
        ncp_adap_e("ERROR: pthread_attr_init");
        goto err_tlv_attr;
    }

    pthread_mutex_init(&ncp_tlv_thread_mutex, NULL);
    pthread_mutex_lock(&ncp_tlv_thread_mutex);

    status = pthread_create(&ncp_tlv_thread, &tattr, &ncp_tlv_process, NULL);
    if (status != 0)
    {
        ncp_adap_e("ERROR: pthread_create");
        goto err_tlv_thread;
    }

    ncp_adap_d("ncp tx init success");
    ncp_adap_d("Exit ncp_tlv_tx_init");
    return status;

err_tlv_thread:
    pthread_mutex_unlock(&ncp_tlv_thread_mutex);
    pthread_mutex_destroy(&ncp_tlv_thread_mutex);
err_tlv_attr:
    mq_close(ncp_tlv_tx_msgq_handle);
err_tlv_tx_msgq:
   return NCP_STATUS_ERROR;
}

static void ncp_tlv_tx_deinit(void)
{
    ssize_t         tlv_sz;
    ncp_tlv_qelem_t *qelem = NULL;

    pthread_mutex_unlock(&ncp_tlv_thread_mutex);
    pthread_join(ncp_tlv_thread, NULL);
    printf("-->\n");
    while (1)
    {
        qelem = NULL;
        if ((tlv_sz = mq_receive(ncp_tlv_tx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL)) != -1)
        {
            if (qelem == NULL)
            {
                ncp_adap_e("%s: qelem=%p", __FUNCTION__, qelem);
                continue;
            }
            ncp_adap_d("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                            __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
            ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
            free(qelem);
            qelem = NULL;
            continue;
        }
        else
        {
            ncp_adap_d("ncp adapter queue flush completed");
            break;
        }
    }

    if (mq_close(ncp_tlv_tx_msgq_handle) != 0)
    {
        ncp_adap_e("ncp adapter tx deint MsgQ fail");
    }
    mq_unlink(NCP_TX_QUEUE_NAME);

    if (pthread_mutex_destroy(&ncp_tlv_thread_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint thread mutex fail");
    }
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

#if CONFIG_NCP_USE_ENCRYPT

int ncp_tlv_adapter_encrypt_init(const uint8_t *key_enc, const uint8_t *key_dec, 
                                 const uint8_t *iv_enc, const uint8_t *iv_dec,
                                 uint16_t key_len, uint16_t iv_len)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;
    int ret = 0, ret2 = 0;
    NCP_ASSERT(key_enc && key_dec && iv_enc && iv_dec);

    if ((adapter->crypt) || (key_len > NCP_ENDECRYPT_KEY_LEN) 
                         || (iv_len > NCP_ENDECRYPT_IV_LEN))
    {
        return NCP_STATUS_ERROR;
    }

    adapter->crypt = (crypt_param_t*)calloc(1, sizeof(crypt_param_t));
    if (!adapter->crypt)
    {
        return NCP_STATUS_NOMEM;
    }

    adapter->crypt->gcm_ctx_enc = calloc(1, sizeof(mbedtls_gcm_context));
    if (!adapter->crypt->gcm_ctx_enc)
    {
        free(adapter->crypt);
        adapter->crypt = NULL;
        return NCP_STATUS_NOMEM;
    }

    adapter->crypt->gcm_ctx_dec = calloc(1, sizeof(mbedtls_gcm_context));
    if (!adapter->crypt->gcm_ctx_dec)
    {
        free(adapter->crypt->gcm_ctx_enc);
        free(adapter->crypt);
        adapter->crypt = NULL;
        return NCP_STATUS_NOMEM;
    }
    
    (void) memcpy(adapter->crypt->key_enc, key_enc, NCP_ENDECRYPT_KEY_LEN);
    (void) memcpy(adapter->crypt->key_dec, key_dec, NCP_ENDECRYPT_KEY_LEN);
    (void) memcpy(adapter->crypt->iv_enc, iv_enc, NCP_ENDECRYPT_IV_LEN);
    (void) memcpy(adapter->crypt->iv_dec, iv_dec, NCP_ENDECRYPT_IV_LEN);
    
    adapter->crypt->key_len = key_len;
    adapter->crypt->iv_len = iv_len;
    adapter->crypt->dec_buf = NULL;
    adapter->crypt->dec_buf_len = 0;
    
    (void) mbedtls_gcm_init((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_enc);
    (void) mbedtls_gcm_init((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_dec);
    
    ret = mbedtls_gcm_setkey((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_enc, 
                             MBEDTLS_CIPHER_ID_AES,
                             adapter->crypt->key_enc,
                             adapter->crypt->key_len * 8);
    ret2 = mbedtls_gcm_setkey((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_dec, 
                             MBEDTLS_CIPHER_ID_AES,
                             adapter->crypt->key_dec,
                             adapter->crypt->key_len * 8);
    if (ret != 0 || ret2 != 0)
    {
        (void) mbedtls_gcm_free((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_enc);
        (void) mbedtls_gcm_free((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_dec);
        free(adapter->crypt->gcm_ctx_enc);
        free(adapter->crypt->gcm_ctx_dec);
        free(adapter->crypt);
        adapter->crypt = NULL;
        return NCP_STATUS_ERROR;
    }
        
    return NCP_STATUS_SUCCESS;
}

int ncp_tlv_adapter_encrypt_deinit(void)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;

    if (!adapter->crypt)
    {
        return NCP_STATUS_ERROR;
    }
    
    (void) mbedtls_gcm_free((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_enc);
    (void) memset(adapter->crypt->gcm_ctx_enc, 0, sizeof(mbedtls_gcm_context));
    free(adapter->crypt->gcm_ctx_enc);
    
    (void) mbedtls_gcm_free((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_dec);
    (void) memset(adapter->crypt->gcm_ctx_dec, 0, sizeof(mbedtls_gcm_context));
    free(adapter->crypt->gcm_ctx_dec);
    
    free(adapter->crypt->dec_buf);
    
    (void) memset(adapter->crypt, 0, sizeof(crypt_param_t));
    free(adapter->crypt);
    adapter->crypt = NULL;

    return NCP_STATUS_SUCCESS;
}

int ncp_tlv_adapter_encrypt_enable(void)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;
    if (!adapter->crypt)
    {
        return NCP_STATUS_ERROR;
    }

    adapter->crypt->flag = 1;
    return NCP_STATUS_SUCCESS;
}

int ncp_tlv_adapter_encrypt_disable(void)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;
    if (adapter->crypt)
    {
        adapter->crypt->flag = 0;
    }
    return NCP_STATUS_SUCCESS;
}

int ncp_tlv_adapter_is_encrypt_mode(void)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;
    return adapter->crypt && adapter->crypt->flag;
}

static ncp_status_t ncp_tlv_encrypt(void *input, void *output, size_t input_len)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;
    int ret = 0;  
    uint8_t tag_buf[16];
    NCP_ASSERT(input && output);
    
    if ((!adapter->crypt) || (!adapter->crypt->flag))
    {
        return NCP_STATUS_ERROR;
    }

    ret = mbedtls_gcm_crypt_and_tag((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_enc, 
                        MBEDTLS_GCM_ENCRYPT, input_len,
                        adapter->crypt->iv_enc, adapter->crypt->iv_len,
                        NULL, 0, input, output, sizeof(tag_buf), tag_buf);
    if (ret != 0)
    {
        ncp_adap_e("mbedtls_gcm_crypt_and_tag err %d\r\n", ret);
        return NCP_STATUS_ERROR;
    }

    return NCP_STATUS_SUCCESS;
}

static ncp_status_t ncp_tlv_decrypt(void *input, size_t input_len)
{
    ncp_tlv_adapter_t *adapter = &ncp_tlv_adapter;
    int ret = 0;
    uint8_t tag_buf[16];

    if ((!adapter->crypt) || (!adapter->crypt->flag))
    {
        return NCP_STATUS_ERROR;
    }
    if (adapter->crypt->dec_buf_len < input_len)
    {
        adapter->crypt->dec_buf = (uint8_t*)realloc(adapter->crypt->dec_buf, input_len);
        if (!adapter->crypt->dec_buf)
        {
            adapter->crypt->dec_buf_len = 0;
            return NCP_STATUS_NOMEM;
        }
        
        adapter->crypt->dec_buf_len = input_len;
    }
    
    (void) memcpy(adapter->crypt->dec_buf, input, input_len);
    
    ret = mbedtls_gcm_crypt_and_tag((mbedtls_gcm_context*)adapter->crypt->gcm_ctx_dec, 
                        MBEDTLS_GCM_DECRYPT, input_len,
                        adapter->crypt->iv_dec, adapter->crypt->iv_len,
                        NULL, 0, adapter->crypt->dec_buf, 
                        input, sizeof(tag_buf), tag_buf);
    if (ret != 0)
    {
        return NCP_STATUS_ERROR;
    }

    return NCP_STATUS_SUCCESS;
}

#endif  /* CONFIG_NCP_USE_ENCRYPT */

ncp_status_t ncp_adapter_init(char * dev_name)
{
    ncp_status_t status = NCP_STATUS_SUCCESS;

#ifdef CONFIG_NCP_UART
    ncp_tlv_adapter.intf_ops = &ncp_uart_ops;
#elif defined(CONFIG_NCP_SDIO)
    ncp_tlv_adapter.intf_ops = &ncp_sdio_ops;
#elif defined(CONFIG_NCP_USB)
    ncp_tlv_adapter.intf_ops = &ncp_usb_ops;
#elif defined(CONFIG_NCP_SPI)
    ncp_tlv_adapter.intf_ops = &ncp_spi_ops;
#endif
    /* Init CRC32 */
    ncp_tlv_chksum_init();
    status = ncp_tlv_tx_init();
    if (status != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("ncp adapater init fail: ncp_tlv_tx_init");
        return status;
    }
    /* Init interface */
    status = (ncp_status_t)ncp_tlv_adapter.intf_ops->init((void *)dev_name);
    if (status != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("ncp adapater init fail: intf_ops->init");
        ncp_tlv_tx_deinit();
        return status;
    }

    ncp_lpm_gpio_init();
#if defined(CONFIG_NCP_USB) || defined(CONFIG_NCP_SDIO)
	status = device_notify_gpio_init();
    if (status != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("ERROR device_notify_gpio_init \r\n");
        ncp_tlv_adapter.intf_ops->deinit((void *)dev_name);
        ncp_tlv_tx_deinit();
        return NCP_STATUS_ERROR;
    }
#endif

    return status;
}

ncp_status_t ncp_adapter_deinit(void)
{
    ncp_status_t status = NCP_STATUS_SUCCESS;
#if defined(CONFIG_NCP_USB) || defined(CONFIG_NCP_SDIO)
    device_notify_gpio_deinit();
#endif
    /* Deinit interface */
    status                   = (ncp_status_t)ncp_tlv_adapter.intf_ops->deinit(NULL);
    ncp_tlv_adapter.intf_ops = NULL;

    ncp_tlv_tx_deinit();

    return status;
}

void ncp_tlv_install_handler(uint8_t class, void *func_cb)
{
    NCP_ASSERT((uint8_t)NCP_MAX_CLASS > class);
    NCP_ASSERT(NULL != func_cb);

    ncp_tlv_adapter.tlv_handler[class] = (tlv_callback_t)func_cb;
}

void ncp_tlv_uninstall_handler(uint8_t class)
{
    NCP_ASSERT((uint8_t)NCP_MAX_CLASS > class);

    ncp_tlv_adapter.tlv_handler[class] = NULL;
}

void ncp_tlv_dispatch(void *tlv, size_t tlv_sz)
{
    ncp_status_t status         = NCP_STATUS_SUCCESS;
    uint32_t     local_checksum = 0, remote_checksum = 0;
    uint8_t class = 0;

    ncp_adap_d("%s: tlv_sz=%lu", __FUNCTION__, tlv_sz);

    /* check CRC */
    remote_checksum = NCP_GET_PEER_CHKSUM((uint8_t *)tlv, tlv_sz);
    local_checksum  = ncp_tlv_chksum(tlv, tlv_sz);
    ncp_adap_d("%s: checksum: remote=0x%x local=0x%x", __FUNCTION__, remote_checksum, local_checksum);
    if (remote_checksum != local_checksum)
    {
        status = NCP_STATUS_CHKSUMERR;
        ncp_adap_e("Checksum validation failed: remote=0x%x local=0x%x", remote_checksum, local_checksum);
    }
    
#if CONFIG_NCP_USE_ENCRYPT
    if ((ncp_tlv_adapter.crypt) && (ncp_tlv_adapter.crypt->flag != 0)
                              && (tlv_sz > TLV_CMD_HEADER_LEN))
    {
        struct _NCP_COMMAND *cmd_hdr = (struct _NCP_COMMAND *)tlv;
        if (!ncp_cmd_is_data_cmd(cmd_hdr->cmd))
        {
            status = ncp_tlv_decrypt(tlv + TLV_CMD_HEADER_LEN, tlv_sz - TLV_CMD_HEADER_LEN);
            if (status != NCP_STATUS_SUCCESS)
            {
                ncp_adap_e("ncp tlv decrypt err %d", (int)status);
                return;
            }
        }
    }
#endif /* CONFIG_NCP_USE_ENCRYPT */

    /* TLV command class */
    class = NCP_GET_CLASS(tlv);

    if (ncp_tlv_adapter.tlv_handler[class])
    {
        ncp_adap_d("Call tlv_handler callback ");
        ncp_tlv_adapter.tlv_handler[class](tlv, tlv_sz, status);
    }

    ncp_adap_d("Exit tlv_handler callback ");
}

/*
    qbuf_len = sizeof(ncp_tlv_qelem_t) + sdio_intf_head + tlv_sz + chksum_len
    qbuf_tlv = qbuf + sizeof(ncp_tlv_qelem_t)
    memcpy_buf = qbuf + sizeof(ncp_tlv_qelem_t) + sdio_intf_head
    chksum_buf = qbuf + sizeof(ncp_tlv_qelem_t) + sdio_intf_head + tlv_sz
    sdio_intf_head: reserved length for sdio interface header
*/
ncp_status_t ncp_tlv_send(void *tlv_buf, size_t tlv_sz)
{
    ncp_status_t     status   = NCP_STATUS_SUCCESS;
    ncp_tlv_qelem_t *qbuf     = NULL;
    uint8_t *        qbuf_tlv = NULL, *chksum_buf = NULL;
    uint32_t         qlen = 0;
    uint8_t          chksum_len = 4;
    uint32_t         chksum      = 0;
    uint32_t         header_size = sizeof(ncp_tlv_qelem_t);

    ncp_adap_d("Enter %s: input tlv_buf=%p tlv_sz=%lu", __FUNCTION__, tlv_buf, tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
    mpu_dump_hex(tlv_buf, tlv_sz);
#endif
    qlen = header_size + tlv_sz + chksum_len;
    qbuf = (ncp_tlv_qelem_t *)malloc(qlen);
    if (!qbuf)
    {
        ncp_adap_e("failed to allocate memory for tlv queue element");
        return NCP_STATUS_NOMEM;
    }
    ncp_adap_d("%s: malloc qelem %p %d", __FUNCTION__, qbuf, qlen);
    memset(qbuf, 0x00, qlen);
    qbuf->tlv_sz = tlv_sz + chksum_len;
    qbuf->priv   = NULL;

    qbuf_tlv = (uint8_t *)qbuf + header_size;
    
#if !CONFIG_NCP_USE_ENCRYPT
    (void) memcpy(qbuf_tlv, tlv_buf, tlv_sz);
#else
    if ((!ncp_tlv_adapter.crypt) || (!ncp_tlv_adapter.crypt->flag))
    {
        (void) memcpy(qbuf_tlv, tlv_buf, tlv_sz);
    }
    else
    {
        struct _NCP_COMMAND *cmd_hdr = (struct _NCP_COMMAND *)tlv_buf;
        if (ncp_cmd_is_data_cmd(cmd_hdr->cmd))
        {
            (void) memcpy(qbuf_tlv, tlv_buf, tlv_sz);
        }
        else
        {
            (void) memcpy(qbuf_tlv, tlv_buf, TLV_CMD_HEADER_LEN);
            if (tlv_sz > TLV_CMD_HEADER_LEN)
            {
                status = ncp_tlv_encrypt(tlv_buf + TLV_CMD_HEADER_LEN,
                                qbuf_tlv + TLV_CMD_HEADER_LEN, 
                                tlv_sz - TLV_CMD_HEADER_LEN);
                if (status != NCP_STATUS_SUCCESS)
                {
                    NCP_TLV_STATS_INC(drop);
                    ncp_adap_e("ncp tlv encrypt err %d", (int)status);
                    return NCP_STATUS_ERROR;
                }
            }
        }
    }
#endif /* CONFIG_NCP_USE_ENCRYPT */

    qbuf->tlv_buf = qbuf_tlv;
    chksum        = ncp_tlv_chksum(qbuf_tlv, (uint16_t)tlv_sz);
    chksum_buf    = qbuf_tlv + tlv_sz;
    chksum_buf[0] = chksum & 0xff;
    chksum_buf[1] = (chksum & 0xff00) >> 8;
    chksum_buf[2] = (chksum & 0xff0000) >> 16;
    chksum_buf[3] = (chksum & 0xff000000) >> 24;

    status = ncp_tlv_tx_enque(qbuf);
    if (status != NCP_STATUS_SUCCESS)
    {
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qbuf);
        free(qbuf);
        ncp_adap_e("ncp tlv enque element fail");
    }
    ncp_adap_d("Exit ncp_tlv_send");
    return status;
}

void ncp_dump_hex(const void *data, unsigned int len)
{
    printf("********** Dump @ %p   Length:  %d **********\r\n", data, len);

    const uint8_t *Data = (const uint8_t *)data;
    for (int i = 0; i < len;)
    {
        printf("%02x ", Data[i++]);
        if (i % NCP_DUMP_WRAPAROUND == 0)
            printf("\r\n");
    }

    printf("\r\n**********  End Dump **********\r\n");
}

