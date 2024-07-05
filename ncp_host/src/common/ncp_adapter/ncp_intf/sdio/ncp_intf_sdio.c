/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_intf_sdio.h"
#include "ncp_tlv_adapter.h"
#include "ncp_host_command.h"
#include "ncp_system_command.h"

#include "ncp_host_command_wifi.h"
#include "sdio.h"
#include "lpm.h"

#include <pthread.h>

/*******************************************************************************
 * Defines
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

#define SDIO_DEV_NAME_LEN 64
static uint8_t ncp_sdio_tlvbuf[TLV_CMD_BUF_SIZE];

static pthread_t       ncp_sdio_intf_thread;
static pthread_mutex_t ncp_sdio_intf_thread_mutex;

char user_sdio_device[SDIO_DEV_NAME_LEN];
static sdio_device_t sdio_device;

ncp_intf_ops_t ncp_sdio_ops = {
    .init   = ncp_sdio_init,
    .deinit = ncp_sdio_deinit,
    .send   = ncp_sdio_send,
    .recv   = ncp_sdio_receive,
    .lpm_exit = ncp_sdio_lpm_exit,
};

/*******************************************************************************
 * Private functions
 ******************************************************************************/

static void* ncp_sdio_intf_task(void *argv)
{
    ncp_status_t    ret = NCP_STATUS_SUCCESS;
    size_t tlv_size = 0;

    ARG_UNUSED(argv);

    while (pthread_mutex_trylock(&ncp_sdio_intf_thread_mutex) != 0)
    {
        ret = ncp_sdio_receive(ncp_sdio_tlvbuf, &tlv_size);
        if (ret == NCP_STATUS_SUCCESS)
        {
            ncp_adap_d("%s: receive len = %lu", __FUNCTION__, tlv_size);
#ifdef CONFIG_MPU_IO_DUMP
            ncp_dump_hex(ncp_sdio_tlvbuf, tlv_size);
#endif
            ncp_tlv_dispatch(ncp_sdio_tlvbuf, tlv_size - NCP_CHKSUM_LEN);
        }
    }
    pthread_exit(NULL);
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/
ncp_status_t ncp_sdio_init(void *argv)
{
    int ret;

    ncp_adap_d("Enter ncp_sdio_init");

    ARG_UNUSED(argv);

    memset(user_sdio_device, 0x00, sizeof(user_sdio_device));
    if (argv && (strlen(argv) > 0) && (strlen(argv) < SDIO_DEV_NAME_LEN - 1))
    {
        strcpy(user_sdio_device, argv);
    }
    else
    {
        strcpy(user_sdio_device, "/dev/mcu-sdio");
    }
    sdio_device.instance = (uint8_t *)user_sdio_device;

    if (sdio_init(&sdio_device) != 0)
    {
        ncp_adap_e("ERROR ncp_sdio_init \n");
        return NCP_STATUS_ERROR;
    }

    pthread_mutex_init(&ncp_sdio_intf_thread_mutex, NULL);
    pthread_mutex_lock(&ncp_sdio_intf_thread_mutex);

    ret = pthread_create(&ncp_sdio_intf_thread, NULL, &ncp_sdio_intf_task, NULL);
    if (ret != 0)
    {
        ncp_adap_e("ERROR pthread_create \n");
        pthread_mutex_unlock(&ncp_sdio_intf_thread_mutex);
        pthread_mutex_destroy(&ncp_sdio_intf_thread_mutex);
        sdio_deinit(&sdio_device);
        return NCP_STATUS_ERROR;
    }

    ncp_adap_d("Exit ncp_sdio_init");

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_sdio_deinit(void *argv)
{
    ARG_UNUSED(argv);

    pthread_mutex_unlock(&ncp_sdio_intf_thread_mutex);
    pthread_join(ncp_sdio_intf_thread, NULL);
    pthread_mutex_destroy(&ncp_sdio_intf_thread_mutex);
    sdio_deinit(&sdio_device);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_sdio_receive(uint8_t *tlv_buf, size_t *tlv_sz)
{
    ncp_status_t ret = NCP_STATUS_SUCCESS;
    size_t rx_len = 0;

    NCP_ASSERT(NULL != tlv_buf);
    NCP_ASSERT(NULL != tlv_sz);

    ret = sdio_receive(&sdio_device, tlv_buf, TLV_CMD_BUF_SIZE, &rx_len);
    if ((ret != NCP_STATUS_SUCCESS) || (rx_len <= 0))
    {
        return NCP_STATUS_ERROR;
    }

    *tlv_sz = rx_len;

    NCP_SDIO_STATS_INC(rx0);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_sdio_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb)
{
    ncp_status_t ret = NCP_STATUS_SUCCESS;

    ARG_UNUSED(cb);

    NCP_ASSERT(NULL != tlv_buf);

    ncp_adap_d("%s: tlv_buf=%p tlv_sz=%lu", __FUNCTION__, tlv_buf, tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
    ncp_dump_hex(tlv_buf, tlv_sz);
#endif
    ret = sdio_send(&sdio_device, tlv_buf, tlv_sz);
    if (ret != NCP_STATUS_SUCCESS)
    {
        return NCP_STATUS_ERROR;
    }

    NCP_SDIO_STATS_INC(tx2);

    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_sdio_lpm_exit(int32_t pm_state)
{
    uint8_t sdio_cmd_buf[sizeof(NCP_COMMAND) + sizeof(NCP_CMD_SYSTEM_SDIO_SET)] = {0};

    if(NCP_PM_STATE_PM3 == pm_state)
    {
        memset(sdio_cmd_buf, 0x00, sizeof(sdio_cmd_buf));
        ncp_set_sdio(sdio_cmd_buf, sizeof(sdio_cmd_buf), 1);
        ncp_sdio_send(sdio_cmd_buf, sizeof(sdio_cmd_buf), NULL);
    }
    return NCP_STATUS_SUCCESS;
}

