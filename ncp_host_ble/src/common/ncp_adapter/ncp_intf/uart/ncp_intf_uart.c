/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_intf_uart.h"
#include "ncp_tlv_adapter.h"
#include "uart.h"
#include <pthread.h>

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define NCP_UART_BAUDRATE       B115200
#define NCP_UART_BUFFER_SIZE    256

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* UART ringbuffer */
static uint8_t ncp_uart_bgbuf[NCP_UART_BUFFER_SIZE];

static uint8_t ncp_uart_tlvbuf[TLV_CMD_BUF_SIZE];

static pthread_t       ncp_uart_intf_thread;
static pthread_mutex_t ncp_uart_intf_thread_mutex;

static uart_device_t uart_device;

ncp_intf_ops_t ncp_uart_ops = {
    .init   = ncp_uart_init,
    .deinit = ncp_uart_deinit,
    .send   = ncp_uart_send,
    .recv   = ncp_uart_receive,
};

/*******************************************************************************
 * Private functions
 ******************************************************************************/

static void* ncp_uart_intf_task(void *argv)
{
    int    ret;
    size_t tlv_size = 0;

    ARG_UNUSED(argv);

    while (pthread_mutex_trylock(&ncp_uart_intf_thread_mutex) != 0)
    {
        ret = ncp_uart_receive(ncp_uart_tlvbuf, &tlv_size);
        if (ret == 0)
        {
            ncp_tlv_dispatch(ncp_uart_tlvbuf, tlv_size);
        }
        else
        {
            ncp_adap_e("Failed to receive TLV command!");
        }
    }
    pthread_exit(NULL);
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/
ncp_status_t ncp_uart_init(void *argv)
{
    int ret;

    ncp_adap_d("Enter ncp_uart_init");

    ARG_UNUSED(argv);

    uart_device.instance = (uint8_t *)argv;

    uart_device.rate = NCP_UART_BAUDRATE;

    if (uart_init(&uart_device) != 0)
    {
        ncp_adap_e("ERROR ncp_uart_init \n");
        return NCP_STATUS_ERROR;
    }

    pthread_mutex_init(&ncp_uart_intf_thread_mutex, NULL);
    pthread_mutex_lock(&ncp_uart_intf_thread_mutex);

    ret = pthread_create(&ncp_uart_intf_thread, NULL, &ncp_uart_intf_task, NULL);
    if (ret != 0)
    {
        pthread_mutex_unlock(&ncp_uart_intf_thread_mutex);
        pthread_mutex_destroy(&ncp_uart_intf_thread_mutex);
        ncp_adap_e("ERROR pthread_create \n");
        return NCP_STATUS_ERROR;
    }

    ncp_adap_d("Exit ncp_uart_init");
    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_uart_deinit(void *argv)
{
    ARG_UNUSED(argv);

    pthread_mutex_unlock(&ncp_uart_intf_thread_mutex);
    pthread_join(ncp_uart_intf_thread, NULL);
    pthread_mutex_destroy(&ncp_uart_intf_thread_mutex);
    uart_deinit(&uart_device);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_uart_receive(uint8_t *tlv_buf, size_t *tlv_sz)
{
    int    ret;
    size_t rx_len = 0, cmd_len = 0;
    int    tmp_len = 0, total = 0;

    NCP_ASSERT(NULL != tlv_buf);
    NCP_ASSERT(NULL != tlv_sz);

    while (tmp_len < TLV_CMD_HEADER_LEN)
    {
        ret = uart_receive(&uart_device, tlv_buf + tmp_len, (TLV_CMD_HEADER_LEN - tmp_len), &rx_len);
        if (ret != 0)
        {
            return NCP_STATUS_ERROR;
        }

        if (rx_len != 0)
        {
            tmp_len += rx_len;
            total += rx_len;
        }
    }

    cmd_len = (tlv_buf[TLV_CMD_SIZE_HIGH_BYTES] << 8) | tlv_buf[TLV_CMD_SIZE_LOW_BYTES];
    tmp_len = 0;
    rx_len  = 0;

    if (cmd_len < TLV_CMD_HEADER_LEN || cmd_len > TLV_CMD_BUF_SIZE)
    {
        NCP_UART_STATS_INC(lenerr);
        NCP_UART_STATS_INC(drop);

        (void)memset(ncp_uart_bgbuf, 0, NCP_UART_BUFFER_SIZE);
        (void)memset(tlv_buf, 0, TLV_CMD_BUF_SIZE);
        total = 0;

        ncp_adap_e("Failed to receive TLV Header!");
        NCP_ASSERT(0);

        return NCP_STATUS_ERROR;
    }

    while (tmp_len != (cmd_len - TLV_CMD_HEADER_LEN + NCP_CHKSUM_LEN))
    {
        ret = uart_receive(&uart_device, tlv_buf + TLV_CMD_HEADER_LEN + tmp_len,
                           cmd_len - TLV_CMD_HEADER_LEN + NCP_CHKSUM_LEN - tmp_len, &rx_len);
        if (ret != 0)
        {
            return NCP_STATUS_ERROR;
        }

        tmp_len += rx_len;
        total += rx_len;
        if ((ret != 0) || total >= TLV_CMD_BUF_SIZE)
        {
            NCP_UART_STATS_INC(ringerr);
            NCP_UART_STATS_INC(lenerr);
            NCP_UART_STATS_INC(drop);

            (void)memset(ncp_uart_bgbuf, 0, NCP_UART_BUFFER_SIZE);
            (void)memset(tlv_buf, 0, TLV_CMD_BUF_SIZE);
            total = 0;

            ncp_adap_e("NCP UART interface ring buffer overflow!");
            NCP_ASSERT(0);

            return NCP_STATUS_ERROR;
        }
    }

    *tlv_sz = cmd_len;

    NCP_UART_STATS_INC(rx);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_uart_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb)
{
    int ret;

    ARG_UNUSED(cb);

    NCP_ASSERT(NULL != tlv_buf);

    ret = uart_send(&uart_device, tlv_buf, tlv_sz);
    if (ret != 0)
    {
        return NCP_STATUS_ERROR;
    }

    NCP_UART_STATS_INC(tx);

    return NCP_STATUS_SUCCESS;
}
