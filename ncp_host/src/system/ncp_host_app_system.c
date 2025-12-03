/** @file ncp_host_app_system.c
 *
 *  @brief  This file provides interface for receiving tlv responses and processing tlv responses.
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "ncp_host_command.h"
#include "ncp_system_command.h"
#include "pthread.h"
#include "mqueue.h"
#include "ncp_tlv_adapter.h"
#include "ncp_adapter.h"
#include <sys/syscall.h>
#include "ncp_log.h"
#include <string.h>

NCP_LOG_MODULE_DEFINE(ncp_system, CONFIG_LOG_NCP_SYSTEM_LEVEL);
NCP_LOG_MODULE_REGISTER(ncp_system, CONFIG_LOG_NCP_SYSTEM_LEVEL);

/*SYSTEM NCP COMMAND TASK*/
static mqd_t system_ncp_tlv_rx_msgq_handle;
#define NCP_SYSTEM_TX_QUEUE_NAME "/ncp_system_tx_queue"
static pthread_mutex_t system_ncp_tlv_rx_queue_mutex;
static pthread_mutex_t system_ncp_tlv_rx_thread_mutex;
static int system_ncp_tlv_rx_queue_len = 0;

typedef ncp_tlv_data_qelem_t system_ncp_tlv_qelem_t;
extern uint32_t last_resp_rcvd, last_cmd_sent;
extern uint16_t last_seqno_rcvd, last_seqno_sent;

int system_process_response(uint8_t *res);
int system_process_event(uint8_t *res);

static void system_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
	//ncp_status_t ret = NCP_STATUS_SUCCESS;
	system_ncp_tlv_qelem_t *qelem = NULL;
	uint8_t *qelem_pld = NULL;

	pthread_mutex_lock(&system_ncp_tlv_rx_queue_mutex);
	if (tlv_sz > NCP_TLV_QUEUE_MSGPLD_SIZE)
	{
		NCP_LOG_ERR("%s: tlv_sz=%lu > %d", __FUNCTION__, tlv_sz, NCP_TLV_QUEUE_MSGPLD_SIZE);
		goto Fail;
	}

	if (system_ncp_tlv_rx_queue_len == NCP_TLV_DATA_QUEUE_LENGTH)
	{
		NCP_LOG_ERR("%s: ncp tlv queue is full max queue length: %d", __FUNCTION__, NCP_TLV_DATA_QUEUE_LENGTH);
		//ret = NCP_STATUS_QUEUE_FULL;
		goto Fail;
	}

	qelem = (ncp_tlv_data_qelem_t *)malloc(sizeof(ncp_tlv_data_qelem_t) + tlv_sz);
	if (!qelem)
	{
		NCP_LOG_ERR("%s: failed to allocate qelem memory", __FUNCTION__);
		//return NCP_STATUS_NOMEM;
		goto Fail;
	}
	NCP_LOG_DBG("%s: malloc qelem %p %lu", __FUNCTION__, qelem, sizeof(ncp_tlv_data_qelem_t) + tlv_sz);
	qelem->tlv_sz = tlv_sz;
	qelem->priv   = NULL;
	qelem_pld = (uint8_t *)qelem + sizeof(ncp_tlv_data_qelem_t);
	memcpy(qelem_pld, tlv, tlv_sz);
	qelem->tlv_buf = qelem_pld;

	NCP_LOG_DBG("%s: mq_send qelem=%p: tlv_buf=%p tlv_sz=%lu", __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
#ifdef CONFIG_MPU_IO_DUMP
	NCP_LOG_HEXDUMP_DBG((uint8_t *)qelem, sizeof(ncp_tlv_data_qelem_t) + qelem->tlv_sz);
#endif
	if (mq_send(system_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, 0) != 0)
	{
		NCP_LOG_ERR("%s: ncp tlv enqueue failure", __FUNCTION__);
		NCP_LOG_DBG("%s: free qelem %p", __FUNCTION__, qelem);
		free(qelem);
		goto Fail;
	}
	system_ncp_tlv_rx_queue_len++;
	NCP_LOG_DBG("%s: enque tlv_buf success", __FUNCTION__);

Fail:
	pthread_mutex_unlock(&system_ncp_tlv_rx_queue_mutex);
	return;

}

static int system_ncp_handle_cmd_input(uint8_t *cmd)
{
	uint32_t msg_type = 0;

	msg_type = GET_MSG_TYPE(((NCP_COMMAND *)cmd)->cmd);
	if (msg_type == NCP_MSG_TYPE_EVENT)
		system_process_event(cmd);
	else
	{
		system_process_response(cmd);

		last_resp_rcvd = ((NCP_COMMAND *)cmd)->cmd;
		last_seqno_rcvd = ((NCP_COMMAND *)cmd)->seqnum;
		if (last_resp_rcvd == (last_cmd_sent | NCP_MSG_TYPE_RESP))
		{
			sem_post(&cmd_sem);
#ifdef CONFIG_MPU_IO_DUMP
			printf("put command semaphore\r\n");
#endif
		}
		if (last_resp_rcvd == NCP_RSP_SYSTEM_INVALID_CMD)
		{
			printf("Previous command is invalid\r\n");
			sem_post(&cmd_sem);
			last_resp_rcvd = 0;
			last_seqno_rcvd = 0;
		}
#ifdef CONFIG_MPU_IO_DUMP
		printf("last_resp_rcvd = 0x%08x, last_cmd_sent = 0x%08x, last_seqno_rcvd = 0x%08x, last_seqno_sent = 0x%08x\r\n",
		    last_resp_rcvd, last_cmd_sent, last_seqno_rcvd, last_seqno_sent);
#endif
	}
	return 0;
}

static void system_ncp_task(void *arg)
{
    ssize_t         tlv_sz = 0;
    system_ncp_tlv_qelem_t *qelem = NULL;

    while (pthread_mutex_trylock(&system_ncp_tlv_rx_thread_mutex) != 0)
    {
        qelem = NULL;
        tlv_sz = mq_receive(system_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL);
        NCP_LOG_DBG("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                    __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
        if (tlv_sz == -1)
        {
            NCP_LOG_ERR("%s: mq_receive failed", __FUNCTION__);
            continue;
        }

        pthread_mutex_lock(&system_ncp_tlv_rx_queue_mutex);
        system_ncp_tlv_rx_queue_len--;
        pthread_mutex_unlock(&system_ncp_tlv_rx_queue_mutex);

        if (qelem == NULL)
        {
            NCP_LOG_ERR("%s: qelem=%p", __FUNCTION__, qelem);
            continue;
        }
        system_ncp_handle_cmd_input(qelem->tlv_buf);
        NCP_LOG_DBG("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
    }
    pthread_mutex_unlock(&system_ncp_tlv_rx_thread_mutex);

}

int ncp_system_app_init()
{
    int ret;
    struct mq_attr     qattr;
    pthread_t ncp_system_thread;
	
    pthread_mutex_init(&system_ncp_tlv_rx_thread_mutex, NULL);
    pthread_mutex_lock(&system_ncp_tlv_rx_thread_mutex);

    ret = pthread_mutex_init(&system_ncp_tlv_rx_queue_mutex, NULL);
    if (ret != 0)
    {
        NCP_LOG_ERR("%s: ERROR: pthread_mutex_init", __FUNCTION__);
        return NCP_STATUS_ERROR;
    }
    qattr.mq_flags         = 0;
    qattr.mq_maxmsg        = NCP_TLV_DATA_QUEUE_LENGTH;
    qattr.mq_msgsize       = NCP_TLV_QUEUE_MSG_SIZE;
    qattr.mq_curmsgs       = 0;

    system_ncp_tlv_rx_msgq_handle = mq_open(NCP_SYSTEM_TX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
    if (system_ncp_tlv_rx_msgq_handle == -1)
    {
        NCP_LOG_ERR("ERROR: ncp system tx msg queue create fail");
        goto err_mq_open;
    }

    if (ret != NCP_STATUS_SUCCESS)
    {
        NCP_LOG_ERR("failed to create system ncp command queue: %d", ret);
        return -NCP_STATUS_ERROR;
    }
    ncp_tlv_install_handler(GET_CMD_CLASS(NCP_CMD_SYSTEM), (void *)system_ncp_callback);

    ncp_system_thread = pthread_create(&ncp_system_thread, NULL, (void *)system_ncp_task, NULL);
    if (ncp_system_thread != 0)
    {
        NCP_LOG_ERR("Failed to create Send Thread!");
        goto err_tlv_thread;
    }
    else
        printf("Success to creat Send Thread!\r\n");

    return 0;

err_tlv_thread:
    pthread_mutex_unlock(&system_ncp_tlv_rx_queue_mutex);
    pthread_mutex_destroy(&system_ncp_tlv_rx_queue_mutex);
err_mq_open:
    mq_close(system_ncp_tlv_rx_msgq_handle);
    return ret;
}



void ncp_system_app_deinit(void)
{
    ssize_t         tlv_sz;
    system_ncp_tlv_qelem_t *qelem = NULL;

    pthread_mutex_unlock(&system_ncp_tlv_rx_thread_mutex);
    while (1)
    {
        qelem = NULL;
        if ((tlv_sz = mq_receive(system_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL)) != -1)
        {
            if (qelem == NULL)
            {
                NCP_LOG_ERR("%s: qelem=%p", __FUNCTION__, qelem);
                continue;
            }
            NCP_LOG_DBG("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                            __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
            NCP_LOG_DBG("%s: free qelem %p", __FUNCTION__, qelem);
            free(qelem);
            qelem = NULL;
            continue;
        }
        else
        {
            NCP_LOG_DBG("ncp system queue flush completed");
            break;
        }
    }
    system_ncp_tlv_rx_queue_len = 0;

    if (pthread_mutex_destroy(&system_ncp_tlv_rx_thread_mutex) != 0)
    {
        NCP_LOG_ERR("ncp system tx deint queue mutex fail");
    }

    if (mq_close(system_ncp_tlv_rx_msgq_handle) != 0)
    {
        NCP_LOG_ERR("ncp system tx deint MsgQ fail");
    }
    mq_unlink(NCP_SYSTEM_TX_QUEUE_NAME);

    if (pthread_mutex_destroy(&system_ncp_tlv_rx_thread_mutex) != 0)
    {
        NCP_LOG_ERR("ncp system tx deint thread mutex fail");
    }
}

