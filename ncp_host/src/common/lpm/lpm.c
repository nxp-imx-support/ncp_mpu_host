/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <poll.h>
#include <linux/gpio.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <pthread.h>

#include "ncp_host_command.h"
#include "ncp_system_command.h"
#include "lpm.h"
#include "ncp_tlv_adapter.h"
#include <sys/syscall.h>

extern ncp_tlv_adapter_t ncp_tlv_adapter;

static int device_notify_gpio_fd = 0;
static int device_notify_gpio_rx_fd = 0;
static pthread_t device_notify_gpio_thread;
static pthread_mutex_t device_notify_gpio_thread_mutex;

static ncp_status_t device_notify_gpio_init_fd();
static ncp_status_t ncp_device_notify_gpio_deinit_fd();

extern power_cfg_t global_power_config;
extern uint8_t ncp_device_status;

#define GPIO_DEV_PATH          "/dev/gpiochip4"
static int lpm_gpio_fd = 0;
static int lpm_gpio_wakeup_fd = 0;

int SetGpioValue(int aFd, uint8_t aValue)
{
    struct gpiohandle_data data;

    data.values[0] = aValue;
    if (ioctl(aFd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data) != 0)
    {
        ncp_adap_e("ioctl GPIOHANDLE_SET_LINE_VALUES_IOCTL fail\n");
        return -1;
    }
    return 0;
}

void set_lpm_gpio_value(uint8_t aValue)
{
    SetGpioValue(lpm_gpio_wakeup_fd, aValue);
}

void ncp_lpm_gpio_init(void)
{
    struct gpiohandle_request req;
    int ret;
    uint8_t     lpm_gpio_pin = 9;

    lpm_gpio_fd = open(GPIO_DEV_PATH, O_RDWR);
    if (lpm_gpio_fd < 0)
    {
        ncp_adap_e("%s: open %s fail lpm_gpio_fd=%d", __FUNCTION__, GPIO_DEV_PATH, lpm_gpio_fd);
        return;
    }

    req.flags  = GPIOHANDLE_REQUEST_OUTPUT;
    req.lines = 1;
    req.lineoffsets[0]  = lpm_gpio_pin;
    req.default_values[0] = 1;
    snprintf(req.consumer_label, sizeof(req.consumer_label), "%s", "lpm_gpio_pin");

    ret = ioctl(lpm_gpio_fd, GPIO_GET_LINEHANDLE_IOCTL, &req);
    if (ret != 0)
    {
        ncp_adap_e("%s: ioctl fail for ret=%d req.fd=%d", __FUNCTION__, ret, req.fd);
        close(lpm_gpio_fd);
        return;
    }
    lpm_gpio_wakeup_fd = req.fd;
    return;
}

static void *device_notify_gpio_input_task(void *pvParameters)
{
    struct pollfd fds[1];
    int timeout_ms = 10000;
    int ret = 0;

    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));

    while (pthread_mutex_trylock(&device_notify_gpio_thread_mutex) != 0)
    {
        fds[0].fd = device_notify_gpio_rx_fd;
        fds[0].events = POLLIN;
        ret = poll(fds, 1, timeout_ms);
        ncp_adap_d("%s: poll fds[0].fd=%d ret=%d revents=0x%x\n", __FUNCTION__, fds[0].fd, ret, fds[0].revents);
        if ((ret == 1) && (fds[0].revents & POLLIN))
        {
            ssize_t rd_size = 0;
            char buf[GPIO_POLL_BUF_LEN] = {0};

            memset(buf, 0x00, sizeof(buf));

            rd_size = read(fds[0].fd, buf, sizeof(buf));
            ncp_adap_d("%s: get rd_size : %ld\n", __FUNCTION__, rd_size);
#ifdef CONFIG_MPU_IO_DUMP
            ncp_dump_hex(buf, rd_size);
#endif
            if (ncp_device_status == NCP_DEVICE_STATUS_PRE_SLEEP)
            {
                while (ncp_device_status != NCP_DEVICE_STATUS_SLEEP)
                {
                     usleep(1);
                     ncp_adap_d("%s: usleep(1) ncp_device_status=%u", __FUNCTION__, ncp_device_status);
                }
            }
            ncp_adap_d("%s: ncp_device_status=%u wake_mode=%u\n", __FUNCTION__,
                    ncp_device_status, global_power_config.wake_mode);
            if (ncp_device_status == NCP_DEVICE_STATUS_SLEEP)
            {
                if(global_power_config.wake_mode == WAKE_MODE_GPIO)
                {
                    if (NULL != ncp_tlv_adapter.intf_ops->lpm_exit)
                    {
                        ncp_tlv_adapter.intf_ops->lpm_exit(NCP_PM_STATE_PM3);
                        ncp_adap_d("%s: lpm_exit PM3 done", __FUNCTION__);
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&device_notify_gpio_thread_mutex);
    return NULL;
}

static ncp_status_t device_notify_gpio_init_fd()
{
    struct gpioevent_request req;
    uint8_t gpiopin = 8; /* GPIO PIN Slot 7 */
    int ret = 0;

    ncp_adap_d("%s Enter: sdio_gpio_fd=%d sdio_gpio_rx_fd=%d", __FUNCTION__, device_notify_gpio_fd, device_notify_gpio_rx_fd);
    device_notify_gpio_fd = open(GPIO_DEV_PATH, O_RDWR);
    if (device_notify_gpio_fd < 0)
    {
        ncp_adap_e("%s: open %s fail sdio_gpio_fd=%d", __FUNCTION__, GPIO_DEV_PATH, device_notify_gpio_fd);
        goto err;
    }
    ncp_adap_d("%s: sdio_gpio_fd=%d", __FUNCTION__, device_notify_gpio_fd);

    req.lineoffset  = gpiopin;
    req.handleflags = GPIOHANDLE_REQUEST_INPUT;
    req.eventflags  = GPIOEVENT_REQUEST_FALLING_EDGE;
    snprintf(req.consumer_label, sizeof(req.consumer_label), "%s", "device_notify_gpio_rx");

    ret = ioctl(device_notify_gpio_fd, GPIO_GET_LINEEVENT_IOCTL, &req);
    if ((ret != 0) || (req.fd < 0))
    {
        ncp_adap_e("%s: ioctl fail for ret=%d req.fd=%d", __FUNCTION__, ret, req.fd);
        goto err_ioctl;
    }
    device_notify_gpio_rx_fd = req.fd;
    ncp_adap_d("%s: sdio_gpio_rx_fd=%d", __FUNCTION__, device_notify_gpio_rx_fd);

    return NCP_STATUS_SUCCESS;

err_ioctl:
    close(device_notify_gpio_fd);
err:
    return NCP_STATUS_ERROR;
}

static ncp_status_t device_notify_gpio_deinit_fd()
{
    ncp_adap_d("%s Enter: device_notify_gpio_fd=%d sdio_gpio_rx_fd=%d", __FUNCTION__, device_notify_gpio_fd, device_notify_gpio_rx_fd);
    close(device_notify_gpio_rx_fd);
    close(device_notify_gpio_fd);
    device_notify_gpio_rx_fd = 0;
    device_notify_gpio_fd = 0;

    return NCP_STATUS_SUCCESS;
}

/*******************************************************************************
 * Init gpio line
 * The gpio input signal when device PM3 then wakeup to inform host
 ******************************************************************************/
ncp_status_t device_notify_gpio_init()
{
    pthread_attr_t tattr;
    int ret = 0;

    if (device_notify_gpio_init_fd() != NCP_STATUS_SUCCESS)
    {
        ncp_adap_e("%s: device_notify_gpio_init_fd fail", __FUNCTION__);
        goto err;
    }

    ret = pthread_attr_init(&tattr);
    if (ret != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_attr_init", __FUNCTION__);
        goto err_tlv_attr;
    }

    pthread_mutex_init(&device_notify_gpio_thread_mutex, NULL);
    pthread_mutex_lock(&device_notify_gpio_thread_mutex);

    ret = pthread_create(&device_notify_gpio_thread, &tattr, &device_notify_gpio_input_task, NULL);
    if (ret != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_create", __FUNCTION__);
        goto err_tlv_thread;
    }

    return NCP_STATUS_SUCCESS;

err_tlv_thread:
    pthread_mutex_unlock(&device_notify_gpio_thread_mutex);
    pthread_mutex_destroy(&device_notify_gpio_thread_mutex);
err_tlv_attr:
    device_notify_gpio_deinit_fd();
err:
    return NCP_STATUS_ERROR;
}

ncp_status_t device_notify_gpio_deinit()
{
    pthread_mutex_unlock(&device_notify_gpio_thread_mutex);
    pthread_join(device_notify_gpio_thread, NULL);
    pthread_mutex_destroy(&device_notify_gpio_thread_mutex);

    device_notify_gpio_deinit_fd();

    return NCP_STATUS_SUCCESS;
}

ncp_status_t device_pm_enter(void *arg)
{
    NCP_COMMAND *cmd = (NCP_COMMAND *)arg;
    if (!cmd)
    {
        ncp_adap_d("%s: cmd is NULL", __FUNCTION__);
        return NCP_STATUS_SUCCESS;
    }

    ncp_adap_d("%s: cmd=0x%x wake_mode=%u", __FUNCTION__,
        NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM, global_power_config.wake_mode);
    if (cmd->cmd == NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM)
    {
        if (global_power_config.wake_mode == WAKE_MODE_GPIO)
        {
            if (NULL != ncp_tlv_adapter.intf_ops->lpm_enter)
            {
                ncp_tlv_adapter.intf_ops->lpm_enter(NCP_PM_STATE_PM3);
                ncp_adap_d("%s: lpm_enter PM3 done", __FUNCTION__);
            }
        }
    }

    return NCP_STATUS_SUCCESS;
}

