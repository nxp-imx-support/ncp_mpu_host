/*
 * Copyright 2024 - 2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if CONFIG_NCP_UART
#include <string.h>
#include "fsl_os_abstraction.h"
#include "uart.h"
#include "ncp_intf_uart.h"
#include "ncp_log.h"
#include "ncp_pm.h"
#include "ncp_tlv_adapter.h"

NCP_LOG_MODULE_DEFINE(ncp_uart, CONFIG_LOG_NCP_INTF_LEVEL);
NCP_LOG_MODULE_REGISTER(ncp_uart, CONFIG_LOG_NCP_INTF_LEVEL);

/*******************************************************************************
 * Defines
 ******************************************************************************/

#define NCP_UART_BAUDRATE       B115200
#define NCP_UART_BUFFER_SIZE    256
#define NCP_UART_RX_STACK_SIZE  2048
#define NCP_UART_RX_PRIORITY    OSA_PRIORITY_NORMAL

#if CONFIG_NCP_DEBUG
#define NCP_UART_STATS_INC(x) NCP_STATS_INC(uart.x)
#else
#define NCP_UART_STATS_INC(x)
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void ncp_uart_rx_task(osa_task_param_t argv);
static int ncp_uart_recv(uint8_t *tlv_buf, size_t *tlv_sz);

/*******************************************************************************
 * Variables
 ******************************************************************************/

static uart_device_t uart_device;

static uint8_t ncp_uart_tlvbuf[TLV_CMD_BUF_SIZE];

OSA_MUTEX_HANDLE_DEFINE(ncp_uart_tx_mutex);
OSA_TASK_HANDLE_DEFINE(ncp_uart_rx_task_handle);
OSA_TASK_DEFINE(ncp_uart_rx_task, NCP_UART_RX_PRIORITY, 1, NCP_UART_RX_STACK_SIZE, 0);

/*******************************************************************************
 * Code
 ******************************************************************************/

static void ncp_uart_rx_task(osa_task_param_t argv)
{
    int    ret;
    size_t tlv_size = 0;

    ARG_UNUSED(argv);

    while (1)
    {
        ret = ncp_uart_recv(ncp_uart_tlvbuf, &tlv_size);
        if (ret == NCP_SUCCESS)
        {
            ncp_tlv_dispatch(ncp_uart_tlvbuf, tlv_size);
        }
        else
        {
            NCP_LOG_ERR("Failed to receive TLV command!");
        }
    }
}

static int ncp_uart_init(void *argv)
{
    osa_status_t status;

    NCP_LOG_DBG("Enter %s", __FUNCTION__);

    ARG_UNUSED(argv);

    uart_device.instance = (const char *)argv;
    uart_device.rate = NCP_UART_BAUDRATE;
    uart_device.flow_control = 1;

    status = OSA_MutexCreate(&ncp_uart_tx_mutex);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to create TX mutex");
        return -NCP_FAIL;
    }

    if (uart_init(&uart_device) != 0)
    {
        NCP_LOG_ERR("Failed to initialize UART");
        OSA_MutexDestroy(&ncp_uart_tx_mutex);
        return -NCP_FAIL;
    }

    status = OSA_TaskCreate(ncp_uart_rx_task_handle,
                           OSA_TASK(ncp_uart_rx_task),
                           NULL);
    if (status != KOSA_StatusSuccess)
    {
        uart_deinit(&uart_device);
        OSA_MutexDestroy(&ncp_uart_tx_mutex);
        NCP_LOG_ERR("Failed to create NCP UART RX task");
        return -NCP_FAIL;
    }

    NCP_LOG_DBG("Exit %s", __FUNCTION__);
    return NCP_SUCCESS;
}

static int ncp_uart_deinit(void *argv)
{
    osa_status_t status;

    ARG_UNUSED(argv);

    status = OSA_TaskDestroy(ncp_uart_rx_task_handle);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to destroy NCP UART RX task");
    }

    OSA_MutexDestroy(&ncp_uart_tx_mutex);
    uart_deinit(&uart_device);

    return NCP_SUCCESS;
}

static int ncp_uart_recv(uint8_t *tlv_buf, size_t *tlv_sz)
{
    int    ret;
    size_t rx_len = 0, cmd_len = 0;
    int    tmp_len = 0, total = 0;

    NCP_ASSERT(NULL != tlv_buf);
    NCP_ASSERT(NULL != tlv_sz);

    while (1)
    {
        ret = uart_receive(&uart_device, tlv_buf, 1, &rx_len);
        if (ret != 0)
        {
            NCP_LOG_ERR("UART receive error");
            return -NCP_FAIL;
        }

        if (rx_len == 1)
        {
            if (tlv_buf[0] == 0x0)
            {
                continue;
            }
            tmp_len = 1;
            total = 1;
            break;
        }
    }

    while (tmp_len < TLV_CMD_HEADER_LEN)
    {
        ret = uart_receive(&uart_device, 
                          tlv_buf + tmp_len, 
                          TLV_CMD_HEADER_LEN - tmp_len, 
                          &rx_len);
        if (ret != 0)
        {
            NCP_LOG_ERR("Failed to receive TLV header");
            return -NCP_FAIL;
        }

        if (rx_len > 0)
        {
            tmp_len += rx_len;
            total += rx_len;
        }
    }

    cmd_len = (tlv_buf[TLV_CMD_SIZE_HIGH_BYTES] << 8) | 
              tlv_buf[TLV_CMD_SIZE_LOW_BYTES];

    if (cmd_len < TLV_CMD_HEADER_LEN || cmd_len > TLV_CMD_BUF_SIZE)
    {
        NCP_UART_STATS_INC(lenerr);
        NCP_UART_STATS_INC(drop);

        NCP_LOG_ERR("Invalid TLV command length: %zu (valid range: %d-%d)", 
                cmd_len, TLV_CMD_HEADER_LEN, TLV_CMD_BUF_SIZE);

        (void)memset(tlv_buf, 0, TLV_CMD_BUF_SIZE);

        uint8_t discard_buf[256];
        size_t discard_len;
        uart_receive(&uart_device, discard_buf, sizeof(discard_buf), &discard_len);

        return -NCP_FAIL;
    }

    tmp_len = 0;
    size_t remaining = cmd_len - TLV_CMD_HEADER_LEN + NCP_CHKSUM_LEN;

    while (tmp_len < remaining)
    {
        ret = uart_receive(&uart_device, 
                          tlv_buf + TLV_CMD_HEADER_LEN + tmp_len,
                          remaining - tmp_len, 
                          &rx_len);
        if (ret != 0)
        {
            NCP_LOG_ERR("Failed to receive TLV data");
            return -NCP_FAIL;
        }

        if (rx_len > 0)
        {
            tmp_len += rx_len;
            total += rx_len;
        }
    }

    if (total != (cmd_len + NCP_CHKSUM_LEN))
    {
        NCP_LOG_ERR("Received data length mismatch: expected %zu, got %d", 
                cmd_len + NCP_CHKSUM_LEN, total);
        return -NCP_FAIL;
    }

    *tlv_sz = cmd_len;
    NCP_UART_STATS_INC(rx);

    NCP_LOG_DBG("Successfully received TLV command, size: %zu", cmd_len);
    return NCP_SUCCESS;
}

static int ncp_uart_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb)
{
    int ret;
    osa_status_t status;

    ARG_UNUSED(cb);
    NCP_ASSERT(NULL != tlv_buf);

    status = OSA_MutexLock(&ncp_uart_tx_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to lock TX mutex");
        return -NCP_FAIL;
    }

    NCP_LOG_DBG("Sending data over UART, size: %zu", tlv_sz);
    ret = uart_send(&uart_device, tlv_buf, tlv_sz);
    OSA_MutexUnlock(&ncp_uart_tx_mutex);
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to send data over UART!");
        return -NCP_FAIL;
    }

    NCP_UART_STATS_INC(tx);
    NCP_LOG_DBG("Data sent over UART successfully");

    return NCP_SUCCESS;
}

uint8_t magic_pattern[12] = {0xBA, 0xDC, 0xFE, 0x87, 0x89, 0xEF, 0xCD, 0xAB, 0xB9, 0x3E, 0x7A, 0x67};
static int ncp_uart_pm_exit(uint8_t pm_state)
{
    ARG_UNUSED(pm_state);

    ncp_uart_send(magic_pattern, sizeof(magic_pattern), NULL);

    return NCP_PM_STATUS_SUCCESS;
}

static ncp_intf_pm_ops_t ncp_uart_pm_ops =
{
    .init  = NULL,
    .prep  = NULL,
    .enter = NULL,
    .exit  = ncp_uart_pm_exit,
};

static ncp_intf_ops_t ncp_intf_ops = {
    .init   = ncp_uart_init,
    .deinit = ncp_uart_deinit,
    .send   = ncp_uart_send,
    .recv   = ncp_uart_recv,
    .pm_ops = &ncp_uart_pm_ops,
};

const ncp_intf_ops_t *ncp_intf_get_ops(void)
{
    return &ncp_intf_ops;
}
#endif /* CONFIG_NCP_UART */