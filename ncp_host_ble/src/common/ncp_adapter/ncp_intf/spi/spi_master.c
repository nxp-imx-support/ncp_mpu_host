/** @file spi_master.c
 *
 *  @brief This file provides  mpu bridge interfaces
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */


#define _GNU_SOURCE
#include <sched.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <linux/gpio.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include "spi_master.h"
#include <mpu_bridge_app.h>
#include <mpu_bridge_command.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/eventfd.h>
#include <mqueue.h>

#ifdef CONFIG_SPI_DEBUG
#define SPI_DEBUG_PRINT(fmt, ...) \
    do { \
        printf(fmt, ##__VA_ARGS__); \
    } while (0)
 
#else
#define SPI_DEBUG_PRINT(fmt, ...) do {} while (0)
#endif


static int spi_dev_fd;
static const char *spi_dev_path = SPI_DEV_PATH;
static uint32_t spi_mode = 0;
static uint8_t spi_bits = 8;
static uint32_t spi_speed = NCP_SPI_MASTER_CLOCK;
static uint16_t spi_delay = 1;
static pthread_mutex_t *spi_slave_rx_ready_mutex = 0;
static pthread_mutex_t *spi_slave_rtx_sync_mutex = 0;
static pthread_mutex_t *ncp_machine_state_mutex = 0;


int gpio_fd;
int ncp_host_gpio_rx_fd;
int ncp_host_gpio_rx_ready_fd;
int ncp_host_gpio_rd_sig_msgq = 0;
int ncp_host_gpio_sig_msgq = 0;
static spi_gpio_signal_msg_t gpio_signal;

int ncp_host_efd;
pthread_t spi_select_loop_thread;
pthread_t spi_state_machine_thread;

static int spi_master_tx(int fd, const uint8_t *tx, size_t len)
{
    int ret = 0;
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = 0,
        .len = len,
        .delay_usecs = spi_delay,
        .speed_hz = spi_speed,
        .bits_per_word = spi_bits,
    };
    
    ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 0)
	{
		perror("can't ioctrl spi device: ");
		return -1;
	}

	return 0;
}

static int spi_master_rx(int fd, uint8_t const *rx, size_t len)
{
    int ret = 0;
    struct spi_ioc_transfer tr = {
        .tx_buf = 0,
        .rx_buf = (unsigned long)rx,
        .len = len,
        .delay_usecs = spi_delay,
        .speed_hz = spi_speed,
        .bits_per_word = spi_bits,
    };
    
    ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 0)
	{
		perror("can't ioctrl spi device: ");
		return -1;
	}
	return 0;
}

static int spi_dev_init(void)
{
    int ret = 0;
    
    uint32_t request = spi_mode;
    
    spi_dev_fd = open(spi_dev_path, O_RDWR);
    if (spi_dev_fd < 0)
    {
        perror("can't open device: ");
        goto open_fail;
    }
    ret = ioctl(spi_dev_fd, SPI_IOC_WR_MODE32, &spi_mode);
    if (ret < 0)
	{
        perror("can't ioctrl spi device: ");
        goto ioctl_fail;
	}

    /* RD is read what mode the device actually is in */
    ret = ioctl(spi_dev_fd, SPI_IOC_RD_MODE32, &spi_mode);
    if (ret < 0)
	{
        perror("can't ioctrl spi device: ");
        goto ioctl_fail;
	}

    /* Drivers can reject some mode bits without returning an error.
     * Read the current value to identify what mode it is in, and if it
     * differs from the requested mode, warn the user.
     */
    if (request != spi_mode)
        printf("WARNING device does not support requested mode 0x%x\n", request);
    
    /*
     * bits per word
     */
    ret = ioctl(spi_dev_fd, SPI_IOC_WR_BITS_PER_WORD, &spi_bits);
    if (ret < 0)
	{
        perror("can't ioctrl spi device: ");
        goto ioctl_fail;
	}

    ret = ioctl(spi_dev_fd, SPI_IOC_RD_BITS_PER_WORD, &spi_bits);
    if (ret < 0)
	{
        perror("can't ioctrl spi device: ");
        goto ioctl_fail;
	}

    /*
     * max speed hz
     */
    ret = ioctl(spi_dev_fd, SPI_IOC_WR_MAX_SPEED_HZ, &spi_speed);
    if (ret < 0)
	{
        perror("can't ioctrl spi device: ");
        goto ioctl_fail;
	}

    ret = ioctl(spi_dev_fd, SPI_IOC_RD_MAX_SPEED_HZ, &spi_speed);
    if (ret < 0)
	{
        perror("can't ioctrl spi device: ");
        goto ioctl_fail;
	}

    SPI_DEBUG_PRINT("spi mode: 0x%x\n", spi_mode);
    SPI_DEBUG_PRINT("bits per word: %u\n", spi_bits);
    SPI_DEBUG_PRINT("max speed: %u Hz (%u kHz)\n", spi_speed, spi_speed/1000);
    return 0;

ioctl_fail:
    close(spi_dev_fd);
    spi_dev_fd = 0;
open_fail:
    return ret;
}

static void spi_dev_deinit(void)
{
    SPI_DEBUG_PRINT("Spi master device\r\n");
    close(spi_dev_fd);
}

static int SetupGpioHandle(int aFd, uint8_t aLine, uint32_t aHandleFlags, const char *aLabel)
{
    struct gpiohandle_request req;
    int                       ret;

    req.flags             = aHandleFlags;
    req.lines             = 1;
    req.lineoffsets[0]    = aLine;
    req.default_values[0] = 1;

    snprintf(req.consumer_label, sizeof(req.consumer_label), "%s", aLabel);

    ret = ioctl(aFd, GPIO_GET_LINEHANDLE_IOCTL, &req);
	if (ret != 0)
	{
		printf("ioctl GPIO_GET_LINEHANDLE_IOCTL fail\n");
		return -1;
	}

    return req.fd;
}

static int SetupGpioEvent(int aFd, uint8_t aLine, uint32_t aHandleFlags, uint32_t aEventFlags, const char *aLabel)
{
    struct gpioevent_request req;
    int                      ret;

    req.lineoffset  = aLine;
    req.handleflags = aHandleFlags;
    req.eventflags  = aEventFlags;
    snprintf(req.consumer_label, sizeof(req.consumer_label), "%s", aLabel);

    ret = ioctl(aFd, GPIO_GET_LINEEVENT_IOCTL, &req);
	if (ret != 0)
	{
		printf("ioctl GPIO_GET_LINEHANDLE_IOCTL fail\n");
		return -1;
	}
    return req.fd;
}

/*
static int SetGpioValue(int aFd, uint8_t aValue)
{
    struct gpiohandle_data data;

    data.values[0] = aValue;
    if (ioctl(aFd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data) != 0)
	{
		printf("ioctl GPIOHANDLE_SET_LINE_VALUES_IOCTL fail\n");
		return -1;
	}
    return 0;
}

static int GetGpioValue(int aFd)
{
    struct gpiohandle_data data;

    if (ioctl(aFd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, &data) != 0)
	{
		printf("ioctl GPIOHANDLE_GET_LINE_VALUES_IOCTL fail\n");
		return -1;
	}
    return data.values[0];
}

static void ToggleGpio(int gpio_fd)
{
    SetGpioValue(gpio_fd, 1);
    SetGpioValue(gpio_fd, 0);
}
*/

static int spi_master_gpio_init(void)
{
    int msgq_key = 5678;
    const char *ncp_host_gpio_dev = GPIO_DEV_PATH;
    uint8_t     spiGpioIntLine_rx = 6;   /* GPIO PIN Slot 10 */
    uint8_t     spiGpioIntLine_rx_ready = 8; /* GPIO PIN Slot 7 */

    gpio_fd = open(ncp_host_gpio_dev, O_RDWR);
    if (gpio_fd < 0)
    {
        printf("open %s fail\n", ncp_host_gpio_dev);
        goto spi_fd_fail;
    }
    ncp_host_gpio_rx_fd = SetupGpioEvent(gpio_fd, spiGpioIntLine_rx, GPIOHANDLE_REQUEST_INPUT, GPIOEVENT_REQUEST_FALLING_EDGE, "ncp_host_gpio_rx");
    if (ncp_host_gpio_rx_fd < 0)
    {
        printf("SetupGpioEvent GPIOHANDLE_REQUEST_INPUT fail\n");
        goto gpio_rx_fail;
    }
    ncp_host_gpio_rx_ready_fd = SetupGpioEvent(gpio_fd, spiGpioIntLine_rx_ready, GPIOHANDLE_REQUEST_INPUT, GPIOEVENT_REQUEST_FALLING_EDGE, "ncp_host_gpio_rx_ready");
    if (ncp_host_gpio_rx_ready_fd < 0)
    {
        printf("SetupGpioEvent GPIOHANDLE_REQUEST_INPUT fail\n");
        goto gpio_rx_ready_fail;
    }

    /* Create message queue */
    if ((ncp_host_gpio_rd_sig_msgq = msgget((key_t)msgq_key, IPC_CREAT | 0666)) < 0)
    {
        printf("msgget failed\r\n");
        goto msgq_fail;
    }
    /* Create message queue */
    if ((ncp_host_gpio_sig_msgq = msgget((key_t)(msgq_key+1), IPC_CREAT | 0666)) < 0)
    {
        printf("msgget failed\r\n");
        goto msgq_fail;
    }

    /*create eventfd*/
    ncp_host_efd= eventfd(0, 0);
    if (ncp_host_efd == -1) {
        perror("eventfd: ");
        goto eventfd_fail;
    }
    return 0;

eventfd_fail:
    msgctl(ncp_host_gpio_rd_sig_msgq, IPC_RMID, 0);
	msgctl(ncp_host_gpio_sig_msgq, IPC_RMID, 0);
msgq_fail:
    close(ncp_host_gpio_rx_ready_fd);
gpio_rx_ready_fail:
    close(ncp_host_gpio_rx_fd);
gpio_rx_fail:
    close(gpio_fd);
spi_fd_fail:

    return -1;
}

static void spi_master_gpio_deinit(void)
{
	SPI_DEBUG_PRINT("Spi master gpio deinit\r\n");
	msgctl(ncp_host_gpio_rd_sig_msgq, IPC_RMID, 0);
	msgctl(ncp_host_gpio_sig_msgq, IPC_RMID, 0);
	close(ncp_host_gpio_rx_ready_fd);
	close(ncp_host_gpio_rx_fd);
	close(gpio_fd);
	close(ncp_host_efd);
	ncp_host_gpio_rx_ready_fd = 0;
	ncp_host_gpio_rx_fd = 0;
	gpio_fd = 0;
	ncp_host_efd = 0;
}

static void *spi_select_loop_func(void *arg)
{
    int ret = 0;
    int mMaxFd = 0;
    fd_set		   mReadFdSet;	///< The read file descriptors.
    fd_set		   mWriteFdSet; ///< The write file descriptors.
    
    while (1)
    {
        mMaxFd = ncp_host_gpio_rx_fd > ncp_host_gpio_rx_ready_fd? ncp_host_gpio_rx_fd : ncp_host_gpio_rx_ready_fd;
        FD_ZERO(&mReadFdSet);
        FD_ZERO(&mWriteFdSet);
        FD_SET(ncp_host_gpio_rx_fd, &mReadFdSet);
        FD_SET(ncp_host_gpio_rx_ready_fd, &mReadFdSet);
        
        ret = select(mMaxFd + 1, &mReadFdSet, &mWriteFdSet, NULL, NULL);
        if (ret < 0)
        {
        perror("select fail: \n");
        continue;
        }
        if (FD_ISSET(ncp_host_gpio_rx_fd, &mReadFdSet))
        {
            struct gpioevent_data event;
            // Read event data to clear interrupt.
            read(ncp_host_gpio_rx_fd, &event, sizeof(event));
            gpio_signal.msg_type = GPIO_RX_SIGNAL;
			SPI_DEBUG_PRINT("send gpio rx signal\n");
            if ((msgsnd(ncp_host_gpio_sig_msgq, &gpio_signal, sizeof(spi_gpio_signal_msg_t), 0)) < 0)
            {
                perror("send gpio rx signal fail: ");
                continue;
            }
        
        }
        if (FD_ISSET(ncp_host_gpio_rx_ready_fd, &mReadFdSet))
        {
            struct gpioevent_data event;
            // Read event data to clear interrupt.
            read(ncp_host_gpio_rx_ready_fd, &event, sizeof(event));
            gpio_signal.msg_type = GPIO_RX_READY_SIGNAL;
			SPI_DEBUG_PRINT("send gpio rx ready signal\n");
            if ((msgsnd(ncp_host_gpio_rd_sig_msgq, &gpio_signal, sizeof(spi_gpio_signal_msg_t), 0)) < 0)
            {
                perror("send gpio rx ready signal fail: ");
                continue;
            }
        }
    }
    return NULL;
}

static void *spi_master_sm_func(void *arg)
{
    while(1)
    {
        if (msgrcv(ncp_host_gpio_rd_sig_msgq, (void *)&gpio_signal, sizeof(spi_gpio_signal_msg_t), 0, 0) < 0)
        {
            perror("msgrcv failed: ");
            continue;
        }
		pthread_mutex_unlock(spi_slave_rx_ready_mutex);
    }
    return NULL;
}

/*
static void spi_master_send_signal(void)
{
    ToggleGpio(ncp_host_gpio_tx_fd);
}
*/

int ncp_host_spi_master_tx(uint8_t *buff, uint16_t data_size)
{
    int ret = 0;
    uint16_t trans_len = 0, len = 0;
    uint8_t *p   = NULL;
    static uint8_t hs_tx[4] = {'s', 'e', 'n', 'd'};
resend:
	pthread_mutex_lock(spi_slave_rtx_sync_mutex);
	SPI_DEBUG_PRINT("start master tx\n");
	/* spi slave and master handshake */
	ret = spi_master_tx(spi_dev_fd, hs_tx, 4);
    if (ret < 0)
    {
        printf("spi slave tx fail");
        goto done;
    }

    /* spi stransfer valid data */
	pthread_mutex_lock(spi_slave_rx_ready_mutex);
	SPI_DEBUG_PRINT("spi transfer complete-tx-%d\n", __LINE__);
    len = data_size;
    p   = buff;
    trans_len = NCP_BRIDGE_CMD_HEADER_LEN;
	ret = spi_master_tx(spi_dev_fd, p, trans_len);
    if (ret < 0)
    {
        printf("spi slave tx fail");
        goto done;
    }
    len -= NCP_BRIDGE_CMD_HEADER_LEN;
    p += NCP_BRIDGE_CMD_HEADER_LEN;
    while (len)
    {
		pthread_mutex_lock(spi_slave_rx_ready_mutex);
		SPI_DEBUG_PRINT("spi transfer complete-tx-%d\n", __LINE__);
        if (len <= MAX_TRANSFER_COUNT)
            trans_len = len;
        else
            trans_len = MAX_TRANSFER_COUNT;
		ret = spi_master_tx(spi_dev_fd, p, trans_len);
        if (ret)
        {
            printf("read spi slave rx fail\n");
            goto done;
        }
        len -= trans_len;
        p += trans_len;
    }
done:
    /*wait slave prepare handshake dma*/
    pthread_mutex_lock(spi_slave_rx_ready_mutex);
    pthread_mutex_unlock(spi_slave_rtx_sync_mutex);
    return ret;
}

int ncp_host_spi_master_rx(uint8_t *buff, size_t *tlv_sz)
{
    int ret = 0;
    uint16_t total_len = 0, resp_len = 0, trans_len = 0, len = 0;
    uint8_t *p   = buff;
	static uint8_t hs_rx[4] = {'r', 'e', 'c', 'v'};

    if (msgrcv(ncp_host_gpio_sig_msgq, (void *)&gpio_signal, sizeof(spi_gpio_signal_msg_t), 0, 0) < 0)
    {
        perror("msgrcv failed: ");
        return -1;
    }
	pthread_mutex_lock(spi_slave_rtx_sync_mutex);
    SPI_DEBUG_PRINT("start to master rx\n");
    /* spi handshake */
	ret = spi_master_tx(spi_dev_fd, hs_rx, 4);

    /* spi transfer valid data */	
	pthread_mutex_lock(spi_slave_rx_ready_mutex);
	SPI_DEBUG_PRINT("spi transfer complete-rx-%d\n", __LINE__);
    trans_len = NCP_BRIDGE_CMD_HEADER_LEN;
	ret = spi_master_rx(spi_dev_fd, p, trans_len);
    if (ret)
    {
        printf("read spi slave rx ready fail\n");
        goto done;
    }

    /* Length of the packet is indicated by byte[4] & byte[5] of
     * the packet excluding checksum [4 bytes]*/
    resp_len = (p[NCP_BRIDGE_CMD_SIZE_HIGH_BYTES] << 8) | p[NCP_BRIDGE_CMD_SIZE_LOW_BYTES];
    total_len = resp_len + CHECKSUM_LEN;

    if (resp_len < NCP_BRIDGE_CMD_HEADER_LEN || total_len >= NCP_BRIDGE_COMMAND_LEN)
    {
        printf("Invalid tlv reponse length from ncp bridge\n");
        goto done;
    }
    len = total_len - NCP_BRIDGE_CMD_HEADER_LEN;
    p += NCP_BRIDGE_CMD_HEADER_LEN;
    while (len)
    {
		pthread_mutex_lock(spi_slave_rx_ready_mutex);
		SPI_DEBUG_PRINT("spi transfer complete-rx-%d\n", __LINE__);
        if (len <= MAX_TRANSFER_COUNT)
            trans_len = len;
        else
            trans_len = MAX_TRANSFER_COUNT;
		ret = spi_master_rx(spi_dev_fd, p, trans_len);
		if (ret)
        {
            printf("read spi slave rx ready fail\n");
            goto done;
        }
        len -= trans_len;
        p += trans_len;
    }
done:
    /*wait slave prepare handshake dma*/
    pthread_mutex_lock(spi_slave_rx_ready_mutex);
    pthread_mutex_unlock(spi_slave_rtx_sync_mutex);
    *tlv_sz             = resp_len;
    return ret;
}

int ncp_host_spi_init(void)
{
    int ret = 0;
    ret = spi_dev_init();
    if (ret < 0)
	{
		printf("Failed to init spi device!\r\n");
		goto spi_dev_init_fail;
	}

    ret = spi_master_gpio_init();
    if (ret < 0)
	{
		printf("Failed to init spi device!\r\n");
		goto ncp_gpio_init_fail;
	}

    spi_slave_rx_ready_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!spi_slave_rx_ready_mutex)
    {
        printf("Failed to creat spi slave rx ready mutex!\r\n");
        goto create_rx_ready_mutex_fail;
    }
    
    if (pthread_mutex_init(spi_slave_rx_ready_mutex, NULL) != 0)
    {
        printf("Failed to init spi_slave rx ready mutex!\r\n");
        goto init_rx_ready_mutex_fail;
    }
    pthread_mutex_lock(spi_slave_rx_ready_mutex);
    
    spi_slave_rtx_sync_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!spi_slave_rtx_sync_mutex)
    {
        printf("Failed to create spi slave tx complete mutex!\r\n");
        goto malloc_rx_ready_mutex_fail;
    }
    
    if (pthread_mutex_init(spi_slave_rtx_sync_mutex, NULL) != 0)
    {
        printf("Failed to init spi_slave_rtx_sync_mutex!\r\n");
        goto init_rtx_sync_mutex_fail;
    }
    
    ncp_machine_state_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!ncp_machine_state_mutex)
    {
        printf("Failed to create ncp_machine_state_mutex!\n");
        goto malloc_ms_mutex_fail;
    }
    
    if (pthread_mutex_init(ncp_machine_state_mutex, NULL) != 0)
    {
        printf("Failed to init ncp_machine_state_mutex!\n");
        goto init_ms_mutex_fail;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
    pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
    
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    ret = pthread_create(&spi_select_loop_thread, &attr, (void *)spi_select_loop_func, NULL);
    if (ret)
    {
        printf("Failed to create spi_select_loop_thread!\r\n");
        goto create_sl_thread_fail;
    }
    
    ret = pthread_create(&spi_state_machine_thread, &attr, (void *)spi_master_sm_func, NULL);
    if (ret)
    {
        printf("Failed to create spi_select_loop_thread!\r\n");
        goto create_ms_thread_fail;
    
    }
	signal(SIGINT, stop_spi);
    return 0;
    
create_ms_thread_fail:
    pthread_cancel(spi_select_loop_thread);
    pthread_join(spi_select_loop_thread, NULL);
create_sl_thread_fail:
init_ms_mutex_fail:
    free(ncp_machine_state_mutex);
    ncp_machine_state_mutex = 0;
malloc_ms_mutex_fail:
init_rtx_sync_mutex_fail:
    free(spi_slave_rtx_sync_mutex);
    spi_slave_rtx_sync_mutex = 0;
malloc_rx_ready_mutex_fail:
init_rx_ready_mutex_fail:
    free(spi_slave_rx_ready_mutex);
    spi_slave_rx_ready_mutex = 0;
create_rx_ready_mutex_fail:
    spi_master_gpio_deinit();
ncp_gpio_init_fail:
    spi_dev_deinit();
spi_dev_init_fail:
    
    return -1;
}

void ncp_host_spi_deinit(void)
{
    int ret = 0;
    SPI_DEBUG_PRINT("Ncp mpu spi deinit\r\n");

    ret = pthread_cancel(spi_select_loop_thread);
    if (ret < 0)
    {
        printf("Failed to join spi_select_loop_thread!\r\n");
    }

    ret = pthread_cancel(spi_state_machine_thread);
    if (ret < 0)
    {
        printf("Failed to join spi_state_machine_thread!\r\n");
    }

    ret = pthread_join(spi_select_loop_thread, NULL);
    if (ret < 0)
    {
        printf("Failed to join spi_select_loop_thread!\r\n");
    }

    ret = pthread_join(spi_state_machine_thread, NULL);
    if (ret < 0)
    {
        printf("Failed to join spi_state_machine_thread!\r\n");
    }

    pthread_mutex_destroy(spi_slave_rx_ready_mutex);
    if (spi_slave_rx_ready_mutex)
    {
        free(spi_slave_rx_ready_mutex);
        spi_slave_rx_ready_mutex = 0;
    }

    pthread_mutex_destroy(spi_slave_rtx_sync_mutex);
    if (spi_slave_rtx_sync_mutex)
    {
        free(spi_slave_rtx_sync_mutex);
        spi_slave_rtx_sync_mutex = 0;
    }

    pthread_mutex_destroy(ncp_machine_state_mutex);
    if (ncp_machine_state_mutex)
    {
        free(ncp_machine_state_mutex);
        ncp_machine_state_mutex = 0;
    }
	spi_master_gpio_deinit();
    spi_dev_deinit();
}


void stop_spi(int signo)
{
	ncp_host_spi_deinit();
    _exit(0);
}