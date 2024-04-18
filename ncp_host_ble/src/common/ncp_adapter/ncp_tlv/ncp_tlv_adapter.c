/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_tlv_adapter.h"
#include "crc.h"
#include "ncp_adapter.h"

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

static ncp_tlv_adapter_t ncp_tlv_adapter;

/* NCP adapter tx queue handler */
mqd_t ncp_tlv_tx_msgq_handle;

/* NCP adapter tx mutex for queue counter*/
static pthread_mutex_t ncp_tlv_queue_mutex;

/* NCP adapter tx task */
static pthread_t       ncp_tlv_thread;
static pthread_mutex_t ncp_tlv_thread_mutex;
static void *          ncp_tlv_process(void *arg);

/* NCP adapter tx queue counter */
static int ncp_tlv_queue_len = 0;

/*******************************************************************************
 * Private functions
 ******************************************************************************/

static void ncp_tlv_cb(void *arg)
{
    /* todo */
}

static void* ncp_tlv_process(void *arg)
{
    ssize_t         recv_sz = 0;
    ncp_tlv_qelem_t *qelem = NULL;

    ncp_adap_d("Start ncp_tlv_process thread");

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

        pthread_mutex_lock(&ncp_tlv_queue_mutex);
        ncp_tlv_queue_len--;
        pthread_mutex_unlock(&ncp_tlv_queue_mutex);

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

    pthread_mutex_lock(&ncp_tlv_queue_mutex);

    if (ncp_tlv_queue_len == NCP_TLV_QUEUE_LENGTH)
    {
        ncp_adap_e("ncp tlv queue is full max queue length: %d", NCP_TLV_QUEUE_LENGTH);
        status = NCP_STATUS_QUEUE_FULL;
        goto Fail;
    }

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
    ncp_tlv_queue_len++;
    NCP_TLV_STATS_INC(tx0);
    ncp_adap_d("enque tlv_buf success");

Fail:
    pthread_mutex_unlock(&ncp_tlv_queue_mutex);
    ncp_adap_d("Exit ncp_tlv_tx_enque");
    return status;
}

static ncp_status_t ncp_tlv_tx_init(void)
{
    int                status = NCP_STATUS_SUCCESS;
    struct mq_attr     qattr;
    pthread_attr_t     tattr;

    ncp_adap_d("Enter ncp_tlv_tx_init");
    status = pthread_mutex_init(&ncp_tlv_queue_mutex, NULL);
    if (status != 0)
    {
        ncp_adap_e("ERROR: pthread_mutex_init");
        return NCP_STATUS_ERROR;
    }

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
   pthread_mutex_destroy(&ncp_tlv_queue_mutex);
   return NCP_STATUS_ERROR;
}

static void ncp_tlv_tx_deinit(void)
{
    ssize_t         tlv_sz;
    ncp_tlv_qelem_t *qelem = NULL;

    pthread_mutex_unlock(&ncp_tlv_thread_mutex);
    pthread_join(ncp_tlv_thread, NULL);
    printf("-->\n");
    pthread_mutex_lock(&ncp_tlv_queue_mutex);
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
    ncp_tlv_queue_len = 0;
    pthread_mutex_unlock(&ncp_tlv_queue_mutex);

    if (pthread_mutex_destroy(&ncp_tlv_queue_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint queue mutex fail");
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
        return status;
    }

    return status;
}

ncp_status_t ncp_adapter_deinit(void)
{
    ncp_status_t status = NCP_STATUS_SUCCESS;

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
    memcpy(qbuf_tlv, tlv_buf, tlv_sz);
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

