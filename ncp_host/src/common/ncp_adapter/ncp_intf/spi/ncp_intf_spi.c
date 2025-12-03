/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if CONFIG_NCP_SPI
#include "ncp_intf_spi.h"
#include "ncp_tlv_adapter.h"
#include "spi_master.h"
#include <pthread.h>
#include <sys/syscall.h>

#include "ncp_log.h"
#include "ncp_pm.h"

NCP_LOG_MODULE_DEFINE(ncp_spi, CONFIG_LOG_NCP_INTF_LEVEL);
NCP_LOG_MODULE_REGISTER(ncp_spi, CONFIG_LOG_NCP_INTF_LEVEL);
#if CONFIG_NCP_DEBUG
#define NCP_SPI_STATS_INC(x) NCP_STATS_INC(uart.x)
#else
#define NCP_SPI_STATS_INC(x)
#endif


/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint8_t ncp_spi_tlvbuf[TLV_CMD_BUF_SIZE];
static pthread_t       ncp_spi_intf_thread;

/*******************************************************************************
 * Private functions
 ******************************************************************************/

static void* ncp_spi_intf_task(void *argv)
{
    int    ret;
    size_t tlv_size = 0;

    ARG_UNUSED(argv);
    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));
    while(1)
    {
        ret = ncp_spi_receive(ncp_spi_tlvbuf, &tlv_size);
        if (ret == 0)
        {
            ncp_tlv_dispatch(ncp_spi_tlvbuf, tlv_size);
        }
        else
        {
            NCP_LOG_ERR("Failed to receive TLV command!");
        }
    }
    pthread_exit(NULL);
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/
ncp_status_t ncp_spi_init(void *argv)
{
    int ret = 0;
	ret = ncp_host_spi_init();
	if (ret < 0)
    {
        return NCP_STATUS_ERROR;
    }
    ret = pthread_create(&ncp_spi_intf_thread, NULL, &ncp_spi_intf_task, NULL);
    if (ret != 0)
    {
        NCP_LOG_ERR("ERROR pthread_create \n");
		ncp_host_spi_deinit();
        return NCP_STATUS_ERROR;
    }
	return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_spi_deinit(void *argv)
{
	ncp_host_spi_deinit();
	pthread_cancel(ncp_spi_intf_thread);
	pthread_join(ncp_spi_intf_thread, NULL);
	return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_spi_receive(uint8_t *tlv_buf, size_t *tlv_sz)
{
    int ret = 0;
    NCP_ASSERT(NULL != tlv_buf);
    NCP_ASSERT(NULL != tlv_sz);

    ret = ncp_host_spi_master_rx(tlv_buf, tlv_sz);
    if (ret < 0)
    {
        NCP_SPI_STATS_INC(err_rx);
		return NCP_STATUS_ERROR;
    }
    NCP_SPI_STATS_INC(rx);
    return NCP_STATUS_SUCCESS;
}

ncp_status_t ncp_spi_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb)
{
    int ret;

    ARG_UNUSED(cb);

    NCP_ASSERT(NULL != tlv_buf);

    ret = ncp_host_spi_master_tx(tlv_buf, tlv_sz);
    if (ret != 0)
    {
        NCP_SPI_STATS_INC(err_tx);
        return NCP_STATUS_ERROR;
    }

    NCP_SPI_STATS_INC(tx);

    return NCP_STATUS_SUCCESS;
}

static int ncp_spi_pm_enter(unsigned char pm_state)
{
    /* TODO: NCP uart pm */
	ARG_UNUSED(pm_state);
    return 0;
}

static int ncp_spi_pm_exit(unsigned char pm_state)
{
    /* TODO: NCP uart pm */
	ARG_UNUSED(pm_state);
    return 0;
}

static ncp_intf_pm_ops_t ncp_spi_pm_ops =
{
    .init  = NULL,
    .prep  = NULL,
    .enter = ncp_spi_pm_enter,
    .exit  = ncp_spi_pm_exit,
};


ncp_intf_ops_t ncp_intf_ops = {
    .init   = ncp_spi_init,
    .deinit = ncp_spi_deinit,
    .send   = ncp_spi_send,
    .recv   = ncp_spi_receive,
    .pm_ops = &ncp_spi_pm_ops,
};

const ncp_intf_ops_t *ncp_intf_get_ops(void)
{
    return &ncp_intf_ops;
}

#endif /* CONFIG_NCP_SPI */
