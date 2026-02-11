/*
 * Copyright 2024 - 2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if CONFIG_NCP_SDIO
#include <string.h>
#include "sdio.h"
#include "ncp_intf_sdio.h"
#include "ncp_tlv_adapter.h"
#include "ncp_log.h"
#include "ncp_pm.h"
#include "gpio_ncp_adapter.h"
#include "fsl_os_abstraction.h"

NCP_LOG_MODULE_DEFINE(ncp_sdio, CONFIG_LOG_NCP_INTF_LEVEL);
NCP_LOG_MODULE_REGISTER(ncp_sdio, CONFIG_LOG_NCP_INTF_LEVEL);

/*******************************************************************************
 * Defines
 ******************************************************************************/

#define SDIO_SET_RE_ENUM          1
#define SDIO_SET_DIS_INT_IRQ      2
#define SDIO_SET_DIS_INT_IRQ_TEST 3
#define SDIO_DEV_NAME_LEN         64
#define NCP_SDIO_RX_STACK_SIZE    2048
#define NCP_SDIO_RX_PRIORITY      OSA_PRIORITY_NORMAL

#define NCP_SDIO_GPIO_CHIP_NUM           4    /* /dev/gpiochip4 */
#define NCP_SDIO_GPIO_DEVICE_NOTIFY_PIN  8    /* Input - Device notification */

#if CONFIG_NCP_DEBUG
#define NCP_SDIO_STATS_INC(x) NCP_STATS_INC(sdio.x)
#else
#define NCP_SDIO_STATS_INC(x)
#endif

#define NCP_SDIO_CMD_SDIO_SET 0x40010000
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void ncp_sdio_rx_task(osa_task_param_t argv);
static int ncp_sdio_recv(uint8_t *tlv_buf, size_t *tlv_sz);

/*******************************************************************************
 * Variables
 ******************************************************************************/

static sdio_device_t sdio_device;
static uint8_t ncp_sdio_tlvbuf[TLV_CMD_BUF_SIZE];
char user_sdio_device[SDIO_DEV_NAME_LEN];

OSA_MUTEX_HANDLE_DEFINE(ncp_sdio_tx_mutex);
OSA_TASK_HANDLE_DEFINE(ncp_sdio_rx_task_handle);
OSA_TASK_DEFINE(ncp_sdio_rx_task, NCP_SDIO_RX_PRIORITY, 1, NCP_SDIO_RX_STACK_SIZE, 0);

gpio_handle_t sdio_gpio_handle;
int sdio_gpio_event_id = -1;
static const ncp_gpio_config_t sdio_gpio_cfg = {
    .chip_num = NCP_SDIO_GPIO_CHIP_NUM,
    .pin_num = NCP_SDIO_GPIO_DEVICE_NOTIFY_PIN,
    .direction = GPIO_DIR_INPUT,
    .pull = GPIO_PULL_UP,
    .interrupt_edge = GPIO_EDGE_FALLING,
    .enable_interrupt = true,
    .label = "ncp_sdio_device_notify",
};

/*******************************************************************************
 * Code
 ******************************************************************************/

static void ncp_sdio_rx_task(osa_task_param_t argv)
{
    int ret = NCP_SUCCESS;
    size_t tlv_size = 0;

    ARG_UNUSED(argv);

    while (1)
    {
        ret = ncp_sdio_recv(ncp_sdio_tlvbuf, &tlv_size);
        if (ret == NCP_SUCCESS)
        {
            NCP_LOG_DBG("%s: receive len = %lu", __FUNCTION__, tlv_size);
#ifdef CONFIG_MPU_IO_DUMP
            ncp_dump_hex(ncp_sdio_tlvbuf, tlv_size);
#endif
            ncp_tlv_dispatch(ncp_sdio_tlvbuf, tlv_size - NCP_CHKSUM_LEN);
        }
    }
    pthread_exit(NULL);
}

static int ncp_sdio_recv(uint8_t *tlv_buf, size_t *tlv_sz)
{
    int ret = NCP_SUCCESS;
    size_t rx_len    = 0;

    NCP_ASSERT(NULL != tlv_buf);
    NCP_ASSERT(NULL != tlv_sz);

    ret = sdio_receive(&sdio_device, tlv_buf, TLV_CMD_BUF_SIZE, &rx_len);
    if ((ret != NCP_SUCCESS) || (rx_len <= 0))
    {
        NCP_LOG_DBG("SDIO receive error");
        return -NCP_FAIL;
    }

    *tlv_sz = rx_len;

    NCP_SDIO_STATS_INC(rx0);

    return NCP_SUCCESS;
}

static int ncp_sdio_send(uint8_t *tlv_buf, size_t tlv_sz, tlv_send_callback_t cb)
{
    int ret = NCP_SUCCESS;
    osa_status_t status;

    ARG_UNUSED(cb);

    NCP_ASSERT(NULL != tlv_buf);

    NCP_LOG_DBG("%s: tlv_buf=%p tlv_sz=%lu", __FUNCTION__, tlv_buf, tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
    ncp_dump_hex(tlv_buf, tlv_sz);
#endif

    status = OSA_MutexLock(&ncp_sdio_tx_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to lock TX mutex");
        return -NCP_FAIL;
    }
    NCP_LOG_DBG("Sending data over SDIO, size: %zu", tlv_sz);
    ret = sdio_send(&sdio_device, tlv_buf, tlv_sz);
    OSA_MutexUnlock(&ncp_sdio_tx_mutex);
    if (ret != NCP_STATUS_SUCCESS)
    {
        return -NCP_FAIL;
    }

    NCP_SDIO_STATS_INC(tx2);

    NCP_LOG_DBG("Data sent over SDIO successfully");

    return NCP_SUCCESS;
}

static void ncp_set_sdio(uint8_t *buf, uint32_t buf_len, uint32_t val)
{
    NCP_CMD_SDIO_SET *sys_cfg_command = (NCP_CMD_SDIO_SET *)buf;

    if (!buf || buf_len < (sizeof(NCP_CMD_SDIO_SET)))
    {
        NCP_LOG_DBG("Error: Invalid buf %p or buf_len %u!\r\n", buf, buf_len);
        return;
    }

    sys_cfg_command->header.cmd      = NCP_SDIO_CMD_SDIO_SET;
    sys_cfg_command->header.result   = NCP_SUCCESS;
    sys_cfg_command->val = val;
    sys_cfg_command->header.size = sizeof(NCP_CMD_SDIO_SET);
}

static void ncp_sdio_gpio_callback(gpio_handle_t *handle, gpio_edge_t edge, void *data)
{
    uint8_t sdio_cmd_buf[sizeof(NCP_CMD_SDIO_SET)] = {0};

    memset(sdio_cmd_buf, 0x00, sizeof(sdio_cmd_buf));
    ncp_set_sdio(sdio_cmd_buf, sizeof(sdio_cmd_buf), SDIO_SET_RE_ENUM);
    ncp_sdio_send(sdio_cmd_buf, sizeof(sdio_cmd_buf), NULL);
}

static int ncp_sdio_gpio_init(void)
{
    const ncp_gpio_config_t *cfg = &sdio_gpio_cfg;
    int ret = 0;

    ret = gpio_init();
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to initialize GPIO subsystem");
        return ret;
    }

    memset(&sdio_gpio_handle, 0, sizeof(sdio_gpio_handle));
    ret = gpio_open(&sdio_gpio_handle, cfg->chip_num, cfg->pin_num);
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to open GPIO %d_%d", cfg->chip_num, cfg->pin_num);
        return ret;
    }

    /* Register interrupt event (handled by single epoll task in driver) */
    sdio_gpio_event_id = gpio_register_event(&sdio_gpio_handle, cfg->interrupt_edge,
                                             ncp_sdio_gpio_callback, NULL);

    if (sdio_gpio_event_id < 0)
    {
        NCP_LOG_ERR("Failed to register event for GPIO %d_%d", cfg->chip_num, cfg->pin_num);
        gpio_close(&sdio_gpio_handle);
        return -NCP_FAIL;
    }

    NCP_LOG_DBG("Registered event %d for GPIO %d_%d", sdio_gpio_event_id, cfg->chip_num, cfg->pin_num);

    return NCP_SUCCESS;
}

static int ncp_sdio_gpio_deinit(void)
{
    if (sdio_gpio_event_id >= 0)
    {
        gpio_unregister_event(sdio_gpio_event_id);
        sdio_gpio_event_id = -1;
    }

    if (sdio_gpio_handle.is_open)
    {
        gpio_close(&sdio_gpio_handle);
    }

    gpio_deinit();

    NCP_LOG_DBG("NCP GPIO adapter deinitialized");

    return NCP_SUCCESS;
}

static int ncp_sdio_init(void *argv)
{
    osa_status_t status;

    NCP_LOG_DBG("Enter %s", __FUNCTION__);

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
        NCP_LOG_ERR("Failed to initialize SDIO");
        return -NCP_FAIL;
    }

    status = OSA_MutexCreate(&ncp_sdio_tx_mutex);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to create TX mutex");
        return -NCP_FAIL;
    }

    status = OSA_TaskCreate(ncp_sdio_rx_task_handle,
                           OSA_TASK(ncp_sdio_rx_task),
                           NULL);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("ERROR pthread_create");
        OSA_MutexDestroy(&ncp_sdio_tx_mutex);
        sdio_deinit(&sdio_device);
        return -NCP_FAIL;
    }

    if (ncp_sdio_gpio_init())
    {
        OSA_MutexDestroy(&ncp_sdio_tx_mutex);
        sdio_deinit(&sdio_device);
        NCP_LOG_ERR("Failed to init NCP SDIO GPIO pin");
        return -NCP_FAIL;
    }

    NCP_LOG_DBG("Exit %s", __FUNCTION__);
    return NCP_SUCCESS;
}

static int ncp_sdio_deinit(void *argv)
{
    osa_status_t status;

    ARG_UNUSED(argv);

    status = OSA_TaskDestroy(ncp_sdio_rx_task_handle);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to destroy NCP SDIO RX task");
    }

    OSA_MutexDestroy(&ncp_sdio_tx_mutex);
    sdio_deinit(&sdio_device);

    if (ncp_sdio_gpio_deinit())
    {
       NCP_LOG_ERR("Failed to deinit NCP SDIO GPIO");
    }

    return NCP_SUCCESS;
}

static int ncp_sdio_pm_init(void)
{
    return NCP_SUCCESS;
}

static int ncp_sdio_pm_prep(uint8_t pm_state, uint8_t event_type, void *data)
{
    ARG_UNUSED(pm_state);
    ARG_UNUSED(event_type);
    ARG_UNUSED(data);

    return NCP_SUCCESS;
}

static int ncp_sdio_pm_exit(uint8_t pm_state)
{
    NCP_COMMAND wakeup_buf;

    if (NCP_PM_STATE_PM2 == pm_state)
    {
        memset(&wakeup_buf, 0x0, sizeof(NCP_COMMAND));
        wakeup_buf.size = NCP_CMD_HEADER_LEN - 1;
        //write(S_D->serial_fd, &wakeup_buf, NCP_CMD_HEADER_LEN);
        NCP_LOG_DBG("%s: send wakeup_buf", __FUNCTION__);
        ncp_sdio_send((uint8_t *)&wakeup_buf, NCP_CMD_HEADER_LEN, NULL);
    }

    return NCP_SUCCESS;
}

static int ncp_sdio_pm_enter(uint8_t pm_state)
{
#if 0
    uint8_t sdio_cmd_buf[sizeof(NCP_CMD_SDIO_SET)] = {0};

    if (NCP_PM_STATE_PM3 == pm_state)
    {
        memset(sdio_cmd_buf, 0x00, sizeof(sdio_cmd_buf));
        /* Send cmd to SDIO driver to release irq. */
        ncp_set_sdio(sdio_cmd_buf, sizeof(sdio_cmd_buf), SDIO_SET_DIS_INT_IRQ);
        ncp_sdio_send(sdio_cmd_buf, sizeof(sdio_cmd_buf), NULL);
    }
#endif
    return NCP_SUCCESS;
}

static ncp_intf_pm_ops_t ncp_sdio_pm_ops =
{
    .init  = ncp_sdio_pm_init,
    .prep  = ncp_sdio_pm_prep,
    .enter = ncp_sdio_pm_enter,
    .exit  = ncp_sdio_pm_exit,
};

ncp_intf_ops_t ncp_intf_ops  = {
    .init     = ncp_sdio_init,
    .deinit   = ncp_sdio_deinit,
    .send     = ncp_sdio_send,
    .recv     = ncp_sdio_recv,
    .pm_ops   = &ncp_sdio_pm_ops,
};

const ncp_intf_ops_t *ncp_intf_get_ops(void)
{
    return &ncp_intf_ops;
}
#endif /* CONFIG_NCP_SDIO */
