/** @file ncp_host_app_ble.c
 *
 *  @brief This file provides ble init and rx handle function
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/times.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <mqueue.h>
#include <ctype.h>
#include <pthread.h>
#include <semaphore.h>
#include <ncp_host_command_ble.h>
#include <ncp_host_app.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "ncp_tlv_adapter.h"

#if defined(CONFIG_NCP_HTS) || defined(CONFIG_NCP_HTC)
#include <service/ht.h>
#endif
#if defined(CONFIG_NCP_HRS) || defined(CONFIG_NCP_HRC)
#include <service/hr.h>
#endif
#if defined(CONFIG_NCP_BAS)
#include <service/bas.h>
#endif

/** command semaphore*/
extern sem_t cmd_sem;
extern uint32_t last_resp_rcvd, last_cmd_sent;

/* ble service variables */
#if defined(CONFIG_NCP_HTS) || defined(CONFIG_NCP_HTC) || defined(CONFIG_NCP_HRS) || defined(CONFIG_NCP_HRC) || defined(CONFIG_NCP_BAS)
sem_t htc_sem;
sem_t hts_sem;
sem_t hrc_sem;
sem_t hrs_sem;
sem_t bas_sem;
#endif

#ifdef CONFIG_NCP_HTS
pthread_t hts_service_thread;
#endif
#ifdef CONFIG_NCP_HRS
pthread_t hrs_service_thread;
#endif
#ifdef CONFIG_NCP_BAS
pthread_t bas_service_thread;
#endif
#ifdef CONFIG_NCP_HTC
    pthread_t htc_client_thread;
#endif
#ifdef CONFIG_NCP_HRC
    pthread_t hrc_client_thread;
#endif

#define NCP_BLE_RX_QUEUE_NAME "/ncp_ble_rx_queue"
static pthread_t ble_ncp_tlv_rx_thread;
static mqd_t ble_ncp_tlv_rx_msgq_handle;
static pthread_mutex_t ble_ncp_tlv_rx_queue_mutex;
static pthread_mutex_t ble_ncp_tlv_rx_thread_mutex;
static int ble_ncp_tlv_rx_queue_len = 0;

uint8_t uuid_str_valid(const char *uuid)
{
	int i, valid;

	if (uuid == NULL)
		return 0;

	for (i = 0, valid = 1; uuid[i] && valid; i++) {
		switch (i) {
		case 8: case 13: case 18: case 23:
			valid = (uuid[i] == '-');
			break;
		default:
			valid = isxdigit(uuid[i]);
			break;
		}
	}

	if (i != 16 || !valid)
		return 0;

	return 1;
}

uint8_t uuid2arry(const char *uuid, uint8_t *arry, uint8_t type)
{
    if(type == 2)//UUID16
    {
        arry[1] = (CHAR2INT(uuid[0]) << 4) + CHAR2INT(uuid[1]);
        arry[0] = (CHAR2INT(uuid[2]) << 4) + CHAR2INT(uuid[3]);
    }
    else
    {
        if(!uuid_str_valid(uuid))
            return 1;
        arry[15] = (CHAR2INT(uuid[0]) << 4) + CHAR2INT(uuid[1]);
        arry[14] = (CHAR2INT(uuid[2]) << 4) + CHAR2INT(uuid[3]);
        arry[13] = (CHAR2INT(uuid[4]) << 4) + CHAR2INT(uuid[5]);
        arry[12] = (CHAR2INT(uuid[6]) << 4) + CHAR2INT(uuid[7]);

        arry[11] = (CHAR2INT(uuid[9]) << 4) + CHAR2INT(uuid[10]);
        arry[10] = (CHAR2INT(uuid[11]) << 4) + CHAR2INT(uuid[12]);

        arry[9] = (CHAR2INT(uuid[14]) << 4) + CHAR2INT(uuid[15]);
        arry[8] = (CHAR2INT(uuid[16]) << 4) + CHAR2INT(uuid[17]);

        arry[7] = (CHAR2INT(uuid[19]) << 4) + CHAR2INT(uuid[20]);
        arry[6] = (CHAR2INT(uuid[21]) << 4) + CHAR2INT(uuid[22]);

        arry[5] = (CHAR2INT(uuid[24]) << 4) + CHAR2INT(uuid[25]);
        arry[4] = (CHAR2INT(uuid[26]) << 4) + CHAR2INT(uuid[27]);
        arry[3] = (CHAR2INT(uuid[28]) << 4) + CHAR2INT(uuid[29]);
        arry[2] = (CHAR2INT(uuid[30]) << 4) + CHAR2INT(uuid[31]);
        arry[1] = (CHAR2INT(uuid[32]) << 4) + CHAR2INT(uuid[33]);
        arry[0] = (CHAR2INT(uuid[34]) << 4) + CHAR2INT(uuid[35]);
    }

    return 0;
}

static void ble_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
    //ncp_status_t ret = NCP_STATUS_SUCCESS;
    ncp_tlv_qelem_t *qelem = NULL;
    uint8_t *qelem_pld = NULL;

    pthread_mutex_lock(&ble_ncp_tlv_rx_queue_mutex);
    if (tlv_sz > NCP_TLV_QUEUE_MSGPLD_SIZE)
    {
        ncp_adap_e("%s: tlv_sz=%lu > %d", __FUNCTION__, tlv_sz, NCP_TLV_QUEUE_MSGPLD_SIZE);
        NCP_TLV_STATS_INC(err_rx);
        goto Fail;
    }

    if (ble_ncp_tlv_rx_queue_len == NCP_TLV_QUEUE_LENGTH)
    {
        ncp_adap_e("%s: ncp tlv queue is full max queue length: %d", __FUNCTION__, NCP_TLV_QUEUE_LENGTH);
        //ret = NCP_STATUS_QUEUE_FULL;
        NCP_TLV_STATS_INC(err_rx);
        goto Fail;
    }

    qelem = (ncp_tlv_qelem_t *)malloc(sizeof(ncp_tlv_qelem_t) + tlv_sz);
    if (!qelem)
    {
        ncp_adap_e("%s: failed to allocate qelem memory", __FUNCTION__);
        //return NCP_STATUS_NOMEM;
        goto Fail;
    }
    ncp_adap_d("%s: malloc qelem %p %lu", __FUNCTION__, qelem, sizeof(ncp_tlv_qelem_t) + tlv_sz);
    qelem->tlv_sz = tlv_sz;
    qelem->priv   = NULL;
    qelem_pld = (uint8_t *)qelem + sizeof(ncp_tlv_qelem_t);
    memcpy(qelem_pld, tlv, tlv_sz);
    qelem->tlv_buf = qelem_pld;

    ncp_adap_d("%s: mq_send qelem=%p: tlv_buf=%p tlv_sz=%lu", __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
    mpu_dump_hex((uint8_t *)qelem, sizeof(ncp_tlv_qelem_t) + qelem->tlv_sz);
#endif
    if (mq_send(ble_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, 0) != 0)
    {
        ncp_adap_e("%s: ncp tlv enqueue failure", __FUNCTION__);
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
        NCP_TLV_STATS_INC(err_rx);
        //ret = NCP_STATUS_ERROR;
        goto Fail;
    }
    ble_ncp_tlv_rx_queue_len++;
    NCP_TLV_STATS_INC(rx1);
    ncp_adap_d("%s: enque tlv_buf success", __FUNCTION__);

Fail:
    pthread_mutex_unlock(&ble_ncp_tlv_rx_queue_mutex);
    return;
}

static int ble_ncp_handle_rx_cmd_event(uint8_t *cmd)
{
    uint32_t msg_type = 0;

#ifdef CONFIG_MPU_IO_DUMP
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)cmd;
    int recv_resp_length = cmd_res->header.size;
    printf("%s: recv_resp_length = %d\r\n", __FUNCTION__, recv_resp_length);
    mpu_dump_hex((uint8_t *)cmd_res, recv_resp_length);
#endif

    msg_type = GET_MSG_TYPE(((NCP_COMMAND *)cmd)->cmd);
    if (msg_type == NCP_MSG_TYPE_EVENT)
        ble_process_ncp_event(cmd);
    else
    {
        ble_process_response(cmd);

        last_resp_rcvd = ((NCPCmd_DS_COMMAND *)cmd)->header.cmd;
        if (last_resp_rcvd == (last_cmd_sent | NCP_MSG_TYPE_RESP))
        {
            sem_post(&cmd_sem);
#ifdef CONFIG_MPU_IO_DUMP
            printf("put command semaphore\r\n");
#endif
        }
        if (last_resp_rcvd == NCP_CMD_BLE_INVALID_CMD)
        {
            printf("Previous command is invalid\r\n");
            sem_post(&cmd_sem);
            last_resp_rcvd = 0;
        }
#ifdef CONFIG_MPU_IO_DUMP
        printf("last_resp_rcvd = 0x%08x, last_cmd_sent = 0x%08x \r\n", last_resp_rcvd, last_cmd_sent);
#endif
    }
    return 0;
}

void ble_ncp_rx_task(void *pvParameters)
{
    ssize_t         tlv_sz = 0;
    ncp_tlv_qelem_t *qelem = NULL;

    while (pthread_mutex_trylock(&ble_ncp_tlv_rx_thread_mutex) != 0)
    {
        qelem = NULL;
        tlv_sz = mq_receive(ble_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL);
        ncp_adap_d("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                    __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
        if (tlv_sz == -1)
        {
            ncp_adap_e("%s: mq_receive failed", __FUNCTION__);
            NCP_TLV_STATS_INC(err_rx);
            continue;
        }

        pthread_mutex_lock(&ble_ncp_tlv_rx_queue_mutex);
        ble_ncp_tlv_rx_queue_len--;
        pthread_mutex_unlock(&ble_ncp_tlv_rx_queue_mutex);

        if (qelem == NULL)
        {
            ncp_adap_e("%s: qelem=%p", __FUNCTION__, qelem);
            NCP_TLV_STATS_INC(err_rx);
            continue;
        }
        NCP_TLV_STATS_INC(rx2);
        ble_ncp_handle_rx_cmd_event(qelem->tlv_buf);
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
    }
    pthread_mutex_unlock(&ble_ncp_tlv_rx_thread_mutex);
}

int ble_ncp_init(void)
{
    int status = NCP_STATUS_SUCCESS;
    struct mq_attr     qattr;
    pthread_attr_t     tattr;

    ncp_adap_d("Enter ble_ncp_init");

    status = pthread_mutex_init(&ble_ncp_tlv_rx_queue_mutex, NULL);
    if (status != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_mutex_init", __FUNCTION__);
        return NCP_STATUS_ERROR;
    }

    qattr.mq_flags         = 0;
    qattr.mq_maxmsg        = NCP_TLV_QUEUE_LENGTH;
    qattr.mq_msgsize       = NCP_TLV_QUEUE_MSG_SIZE;
    qattr.mq_curmsgs       = 0;
    ble_ncp_tlv_rx_msgq_handle = mq_open(NCP_BLE_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
    if ((int)ble_ncp_tlv_rx_msgq_handle == -1)
    {
        ncp_adap_e("ERROR: ble_ncp_tlv_rx_msgq_handle create fail");
        goto err_msgq;
    }

    /* initialized with default attributes */
    status = pthread_attr_init(&tattr);
    if (status != 0)
    {
        ncp_adap_e("ERROR: %s pthread_attr_init", __FUNCTION__);
        goto err_arrt_init;
    }

    pthread_mutex_init(&ble_ncp_tlv_rx_thread_mutex, NULL);
    pthread_mutex_lock(&ble_ncp_tlv_rx_thread_mutex);

    status = pthread_create(&ble_ncp_tlv_rx_thread, &tattr, (void *)ble_ncp_rx_task, NULL);
    if (status != 0)
    {
        ncp_adap_e("ERROR: %s pthread_create", __FUNCTION__);
        goto err_rx_mutex;
    }

    ncp_tlv_install_handler(GET_CMD_CLASS(NCP_CMD_BLE), (void *)ble_ncp_callback);
    ncp_adap_d("Exit ble_ncp_init");
    return NCP_STATUS_SUCCESS;

err_rx_mutex:
    pthread_mutex_unlock(&ble_ncp_tlv_rx_thread_mutex);
    pthread_mutex_destroy(&ble_ncp_tlv_rx_thread_mutex);
err_arrt_init:
    mq_close(ble_ncp_tlv_rx_msgq_handle);
err_msgq:
    pthread_mutex_unlock(&ble_ncp_tlv_rx_queue_mutex);
    pthread_mutex_destroy(&ble_ncp_tlv_rx_queue_mutex);

    return NCP_STATUS_ERROR;
}

int ble_ncp_deinit(void)
{
    ssize_t		 tlv_sz;
    ncp_tlv_qelem_t *qelem = NULL;

    pthread_mutex_unlock(&ble_ncp_tlv_rx_thread_mutex);
    pthread_join(ble_ncp_tlv_rx_thread, NULL);
    printf("-->\n");
    pthread_mutex_lock(&ble_ncp_tlv_rx_queue_mutex);
    while (1)
    {
        qelem = NULL;
        if ((tlv_sz = mq_receive(ble_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL)) != -1)
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
    ble_ncp_tlv_rx_queue_len = 0;
    pthread_mutex_unlock(&ble_ncp_tlv_rx_queue_mutex);

    if (pthread_mutex_destroy(&ble_ncp_tlv_rx_queue_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint queue mutex fail");
    }

    if (mq_close(ble_ncp_tlv_rx_msgq_handle) != 0)
    {
        ncp_adap_e("ncp adapter tx deint MsgQ fail");
    }
    mq_unlink(NCP_BLE_RX_QUEUE_NAME);

    if (pthread_mutex_destroy(&ble_ncp_tlv_rx_thread_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint thread mutex fail");
    }
    return NCP_STATUS_SUCCESS;
}

/**
 * @brief        ble_ncp_app_init function
 *
 * @param argc   void
 * @return       NCP_STATUS_SUCCESS
 */
int ble_ncp_app_init(void)
{
#if defined(CONFIG_NCP_HTC)
    if (sem_init(&htc_sem, 0, 1) == -1)
    {
        printf("Failed to init service semaphore!\r\n");
        return NCP_STATUS_ERROR;
    }
    sem_wait(&htc_sem);
#endif
#if defined(CONFIG_NCP_HRC)
    if (sem_init(&hrc_sem, 0, 1) == -1)
    {
        printf("Failed to init service semaphore!\r\n");
#if defined(CONFIG_NCP_HTC)
        sem_destroy(&htc_sem);
#endif
        return NCP_STATUS_ERROR;
    }
    sem_wait(&hrc_sem);
#endif

#ifdef CONFIG_NCP_HTC
    htc_client_thread = pthread_create(&htc_client_thread, NULL, (void *)central_htc_task, NULL);
    if (htc_client_thread != 0)
    {
        printf("Failed to creat  htc clinet Thread!\r\n");
#if defined(CONFIG_NCP_HTC) && defined(CONFIG_NCP_HRC)
        sem_destroy(&htc_sem);
        sem_destroy(&hrc_sem);
#endif
        return NCP_STATUS_ERROR;
    }
    else
        printf("Success to creat htc clinet Thread!\r\n");
#endif

#ifdef CONFIG_NCP_HRC
    hrc_client_thread = pthread_create(&hrc_client_thread, NULL, (void *)central_hrc_task, NULL);
    if (hrc_client_thread != 0)
    {
        printf("Failed to create  hrc client Thread!\r\n");
#if defined(CONFIG_NCP_HTC) && defined(CONFIG_NCP_HRC)
        sem_destroy(&htc_sem);
        sem_destroy(&hrc_sem);
        pthread_join(htc_client_thread, NULL);
#endif
        return NCP_STATUS_ERROR;
    }
    else
        printf("Success to create hrc client Thread!\r\n");
#endif
    return NCP_STATUS_SUCCESS;
}

/**
 * @brief        ble_ncp_app_deinit function
 *
 * @param argc   void
 * @return       NCP_STATUS_SUCCESS
 */
int ble_ncp_app_deinit(void)
{
#if defined(CONFIG_NCP_HTS)
    pthread_join(hts_service_thread, NULL);
    sem_destroy(&hts_sem);
#endif
#if defined(CONFIG_NCP_HTC)
    pthread_join(htc_client_thread, NULL);
    sem_destroy(&htc_sem);
#endif
#if defined(CONFIG_NCP_HRS)
    pthread_join(hrs_service_thread, NULL);
    sem_destroy(&hrs_sem);
#endif
#if defined(CONFIG_NCP_HRC)
    pthread_join(hrc_client_thread, NULL);
    sem_destroy(&hrc_sem);
#endif
#if defined(CONFIG_NCP_BAS)
    pthread_join(bas_service_thread, NULL);
    sem_destroy(&bas_sem);
#endif
    return NCP_STATUS_SUCCESS;
}