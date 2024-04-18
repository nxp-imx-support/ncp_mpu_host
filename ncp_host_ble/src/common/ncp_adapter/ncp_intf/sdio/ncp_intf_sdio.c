/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_intf_sdio.h"
#include "ncp_tlv_adapter.h"
#include "mpu_bridge_command.h"
#include "sdio.h"
#include <pthread.h>
#include <poll.h>
#include <linux/gpio.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define GPIO_DEV_PATH          "/dev/gpiochip4"

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
};

#define GPIO_POLL_BUF_LEN 32
static int sdio_gpio_fd = 0;
static int sdio_gpio_rx_fd = 0;
static pthread_t sdio_gpio_thread;
static pthread_mutex_t sdio_gpio_thread_mutex;

/*******************************************************************************
 * Private functions
 ******************************************************************************/
static ncp_status_t ncp_sdio_gpio_init_fd();
static ncp_status_t ncp_sdio_gpio_deinit_fd();

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

static void *ncp_sdio_gpio_input_task(void *pvParameters)
{
    struct pollfd fds[1];
    int timeout_ms = 10000;
    int ret = 0;

    while (pthread_mutex_trylock(&sdio_gpio_thread_mutex) != 0)
    {
        fds[0].fd = sdio_gpio_rx_fd;
        fds[0].events = POLLIN;
        ret = poll(fds, 1, timeout_ms);
        ncp_adap_d("%s: poll fds[0].fd=%d ret=%d revents=0x%x\n", __FUNCTION__, fds[0].fd, ret, fds[0].revents);
        if ((ret == 1) && (fds[0].revents & POLLIN))
        {
            ssize_t rd_size = 0;
            char buf[GPIO_POLL_BUF_LEN] = {0};
            uint8_t sdio_cmd_buf[sizeof(NCP_BRIDGE_COMMAND) + sizeof(NCP_CMD_SYSTEM_SDIO_SET)] = {0};
            memset(buf, 0x00, sizeof(buf));

            ARG_UNUSED(rd_size);
            rd_size = read(fds[0].fd, buf, sizeof(buf));
            ncp_adap_d("%s: get rd_size : %ld\n", __FUNCTION__, rd_size);
#ifdef CONFIG_MPU_IO_DUMP
            ncp_dump_hex(buf, rd_size);
#endif

            memset(sdio_cmd_buf, 0x00, sizeof(sdio_cmd_buf));
            //ncp_set_sdio(sdio_cmd_buf, sizeof(sdio_cmd_buf), 1);
            ncp_sdio_send(sdio_cmd_buf, sizeof(sdio_cmd_buf), NULL);
        }
    }

    pthread_mutex_unlock(&sdio_gpio_thread_mutex);
    return NULL;
}

static ncp_status_t ncp_sdio_gpio_init_fd()
{
    struct gpioevent_request req;
    uint8_t gpiopin = 8; /* GPIO PIN Slot 7 */
    int ret = 0;

    ncp_adap_d("%s Enter: sdio_gpio_fd=%d sdio_gpio_rx_fd=%d", __FUNCTION__, sdio_gpio_fd, sdio_gpio_rx_fd);
    sdio_gpio_fd = open(GPIO_DEV_PATH, O_RDWR);
    if (sdio_gpio_fd < 0)
    {
        ncp_adap_e("%s: open %s fail sdio_gpio_fd=%d", __FUNCTION__, GPIO_DEV_PATH, sdio_gpio_fd);
        goto err;
    }
    ncp_adap_d("%s: sdio_gpio_fd=%d", __FUNCTION__, sdio_gpio_fd);

    req.lineoffset  = gpiopin;
    req.handleflags = GPIOHANDLE_REQUEST_INPUT;
    req.eventflags  = GPIOEVENT_REQUEST_FALLING_EDGE;
    snprintf(req.consumer_label, sizeof(req.consumer_label), "%s", "sdio_gpio_rx");

    ret = ioctl(sdio_gpio_fd, GPIO_GET_LINEEVENT_IOCTL, &req);
    if ((ret != 0) || (req.fd < 0))
    {
        ncp_adap_e("%s: ioctl fail for ret=%d req.fd=%d", __FUNCTION__, ret, req.fd);
        goto err_ioctl;
    }
    sdio_gpio_rx_fd = req.fd;
    ncp_adap_d("%s: sdio_gpio_rx_fd=%d", __FUNCTION__, sdio_gpio_rx_fd);

    return NCP_STATUS_SUCCESS;

err_ioctl:
    close(sdio_gpio_fd);
err:
    return NCP_STATUS_ERROR;
}

static ncp_status_t ncp_sdio_gpio_deinit_fd()
{
    ncp_adap_d("%s Enter: sdio_gpio_fd=%d sdio_gpio_rx_fd=%d", __FUNCTION__, sdio_gpio_fd, sdio_gpio_rx_fd);
    close(sdio_gpio_rx_fd);
    close(sdio_gpio_fd);
    sdio_gpio_rx_fd = 0;
    sdio_gpio_fd = 0;

    return NCP_STATUS_SUCCESS;
}

/*******************************************************************************
 * Init gpio line
 * The gpio input signal when device PM3 then wakeup to inform host
 ******************************************************************************/
static ncp_status_t ncp_sdio_gpio_init()
{
    pthread_attr_t tattr;
    int ret = 0;

    if (ncp_sdio_gpio_init_fd() != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("%s: ncp_sdio_gpio_init_fd fail", __FUNCTION__);
        goto err;
    }

    ret = pthread_attr_init(&tattr);
    if (ret != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_attr_init", __FUNCTION__);
        goto err_tlv_attr;
    }

    pthread_mutex_init(&sdio_gpio_thread_mutex, NULL);
    pthread_mutex_lock(&sdio_gpio_thread_mutex);

    ret = pthread_create(&sdio_gpio_thread, &tattr, &ncp_sdio_gpio_input_task, NULL);
    if (ret != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_create", __FUNCTION__);
        goto err_tlv_thread;
    }

    return NCP_STATUS_SUCCESS;

err_tlv_thread:
    pthread_mutex_unlock(&sdio_gpio_thread_mutex);
    pthread_mutex_destroy(&sdio_gpio_thread_mutex);
err_tlv_attr:
    ncp_sdio_gpio_deinit_fd();
err:
    return NCP_STATUS_ERROR;
}

static ncp_status_t ncp_sdio_gpio_deinit()
{
    pthread_mutex_unlock(&sdio_gpio_thread_mutex);
    pthread_join(sdio_gpio_thread, NULL);
    pthread_mutex_destroy(&sdio_gpio_thread_mutex);

    ncp_sdio_gpio_deinit_fd();

    return NCP_STATUS_SUCCESS;
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

    if (ncp_sdio_gpio_init() != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("ERROR sdio_gpio_init \n");
        goto err_gpio_init;
    }

    ncp_adap_d("Exit ncp_sdio_init");

    return NCP_STATUS_SUCCESS;

err_gpio_init:
    pthread_mutex_unlock(&ncp_sdio_intf_thread_mutex);
    pthread_join(ncp_sdio_intf_thread, NULL);
    pthread_mutex_destroy(&ncp_sdio_intf_thread_mutex);
    sdio_deinit(&sdio_device);
    return NCP_STATUS_ERROR;
}

ncp_status_t ncp_sdio_deinit(void *argv)
{
    ARG_UNUSED(argv);

    ncp_sdio_gpio_deinit();

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
