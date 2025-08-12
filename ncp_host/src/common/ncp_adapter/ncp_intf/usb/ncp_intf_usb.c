/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_intf_usb.h"
#include "ncp_tlv_adapter.h"
#include "usb.h"
#include "lpm.h"

#include <pthread.h>
#include <sys/types.h>


/*******************************************************************************
 * Defines
 ******************************************************************************/

#define NCP_USB_BUFFER_SIZE    256
#define HS_HID_GENERIC_INTERRUPT_OUT_PACKET_SIZE 4096

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* USB ringbuffer */
static uint8_t ncp_usb_bgbuf[NCP_USB_BUFFER_SIZE];

static uint8_t ncp_usb_tlvbuf[TLV_CMD_BUF_SIZE];

static pthread_t       ncp_usb_intf_thread;
static pthread_mutex_t ncp_usb_intf_thread_mutex;

static usb_device_t usb_device;

ncp_intf_ops_t ncp_usb_ops = {
    .init   = ncp_usb_init,
    .deinit = ncp_usb_deinit,
    .send   = ncp_usb_send,
    .recv   = ncp_usb_receive,
    .lpm_exit = NULL,
};

/*******************************************************************************
 * Private functions
 ******************************************************************************/
static void* ncp_usb_intf_task(void *argv)
{
    int    ret;
    size_t tlv_size = 0;

    ARG_UNUSED(argv);

    while (pthread_mutex_trylock(&ncp_usb_intf_thread_mutex) != 0)
    {
        ret = ncp_usb_receive(ncp_usb_tlvbuf, &tlv_size);
        if (ret == 0)
        {
            ncp_tlv_dispatch(ncp_usb_tlvbuf, tlv_size);
        }
        else
        {
            //ncp_adap_e("Failed to receive TLV command!");
        }
    }
    pthread_exit(NULL);
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/
ncp_status_t ncp_usb_init(void *argv)
{
    int ret;

    ncp_adap_d("Enter ncp_usb_init");

    ARG_UNUSED(argv);

    if (usb_init(&usb_device) != 0)
    {
        ncp_adap_e("ERROR ncp_usb_init \n");
        return NCP_STATUS_ERROR;
    }

    pthread_mutex_init(&ncp_usb_intf_thread_mutex, NULL);
    pthread_mutex_lock(&ncp_usb_intf_thread_mutex);

    ret = pthread_create(&ncp_usb_intf_thread, NULL, &ncp_usb_intf_task, NULL);
    if (ret != 0)
    {
        ncp_adap_e("ERROR pthread_create \n");
        pthread_mutex_unlock(&ncp_usb_intf_thread_mutex);
        pthread_mutex_destroy(&ncp_usb_intf_thread_mutex);
        usb_deinit(&usb_device);
        return NCP_STATUS_ERROR;
    }

    if(usb_lpm_init() != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("usb_lpm_init failed\r\n");
        goto err_usb_lpm_init;
    }
    
    ncp_adap_d("Exit ncp_usb_init");
    return NCP_STATUS_SUCCESS;
    
err_usb_lpm_init:   
    pthread_mutex_unlock(&ncp_usb_intf_thread_mutex);
    pthread_join(ncp_usb_intf_thread, NULL);
    pthread_mutex_destroy(&ncp_usb_intf_thread_mutex);
    usb_deinit(&usb_device);
    return NCP_STATUS_ERROR;
}

ncp_status_t ncp_usb_deinit(void *argv)
{
    ARG_UNUSED(argv);

    pthread_mutex_unlock(&ncp_usb_intf_thread_mutex);
    pthread_join(ncp_usb_intf_thread, NULL);
    pthread_mutex_destroy(&ncp_usb_intf_thread_mutex);
    usb_deinit(&usb_device);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_usb_receive(uint8_t *tlv_buf, size_t *tlv_sz)
{
    int    ret;
    size_t rx_len = 0, cmd_len = 0;
    int    tmp_len = 0, total = 0;

    NCP_ASSERT(NULL != tlv_buf);
    NCP_ASSERT(NULL != tlv_sz);

    while (tmp_len < TLV_CMD_HEADER_LEN)
    {
        ret = usb_receive(&usb_device, tlv_buf+ tmp_len, HS_HID_GENERIC_INTERRUPT_OUT_PACKET_SIZE - 1, &rx_len);

        if (ret == 0 || (ret == LIBUSB_ERROR_TIMEOUT && rx_len))
        {
            tmp_len += rx_len;
            total   += rx_len;
        }
        else
           return NCP_STATUS_ERROR;
    }

    cmd_len = (tlv_buf[TLV_CMD_SIZE_HIGH_BYTES] << 8) | tlv_buf[TLV_CMD_SIZE_LOW_BYTES];
    rx_len  = 0;

    if (cmd_len < TLV_CMD_HEADER_LEN || cmd_len > TLV_CMD_BUF_SIZE)
    {
        NCP_USB_STATS_INC(lenerr);
        NCP_USB_STATS_INC(drop);

        (void)memset(ncp_usb_bgbuf, 0, NCP_USB_BUFFER_SIZE);
        (void)memset(tlv_buf, 0, TLV_CMD_BUF_SIZE);
        total = 0;

        ncp_adap_e("Failed to receive TLV Header!");
        NCP_ASSERT(0);

        return NCP_STATUS_ERROR;
    }

    while (total < cmd_len)
    {
        ret = usb_receive(&usb_device, tlv_buf + total , HS_HID_GENERIC_INTERRUPT_OUT_PACKET_SIZE - 1, &rx_len);

        if(ret == 0 || (ret == LIBUSB_ERROR_TIMEOUT && rx_len))
        {
            total += rx_len;
            if ((ret != 0) || total >= TLV_CMD_BUF_SIZE)
            {
                NCP_USB_STATS_INC(ringerr);
                NCP_USB_STATS_INC(lenerr);
                NCP_USB_STATS_INC(drop);

                (void)memset(ncp_usb_bgbuf, 0, NCP_USB_BUFFER_SIZE);
                (void)memset(tlv_buf, 0, TLV_CMD_BUF_SIZE);
                total = 0;

                ncp_adap_e("NCP usb interface ring buffer overflow!");
                NCP_ASSERT(0);

                return NCP_STATUS_ERROR;
            }
        }
        else
        {
            continue;
        }
    }

    *tlv_sz = cmd_len;

    NCP_USB_STATS_INC(rx);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_usb_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb)
{
    int ret;

    ARG_UNUSED(cb);

    NCP_ASSERT(NULL != tlv_buf);

    ret = usb_send(&usb_device, tlv_buf, tlv_sz);
    if (ret != 0)
    {
        return NCP_STATUS_ERROR;
    }

    NCP_USB_STATS_INC(tx);

    return NCP_STATUS_SUCCESS;
}

