/** @file ncp_host_app_ot.c
 *
 *  @brief This file provides ot functions to handle ot commands input/output
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>

#include <ncp_host_command_ble.h>
#include <ncp_host_app.h>
#include <ncp_tlv_adapter.h>
#include "ncp_host_app_ot.h"
#include "otopcode.h"
#include "otopcode_private.h"

#define NCP_OT_RX_QUEUE_NAME "/ncp_ot_rx_queue"
static pthread_t ot_ncp_tlv_rx_thread;
static mqd_t ot_ncp_tlv_rx_msgq_handle;
static pthread_mutex_t ot_ncp_tlv_rx_queue_mutex;
static pthread_mutex_t ot_ncp_tlv_rx_thread_mutex;
static int ot_ncp_tlv_rx_queue_len = 0;

extern uint8_t cmd_buf[NCP_COMMAND_LEN];

/* -------------------------------------------------------------------------- */
/*                              Private Functions                             */
/* -------------------------------------------------------------------------- */

static int ot_ncp_handle_rx_cmd_event(uint8_t *tlv_buf, int tlv_sz)
{
    uint8_t *recv_buf;
    recv_buf    = (uint8_t *)malloc(tlv_sz + 1);

    if (recv_buf == NULL)
    {
        ncp_adap_e("failed to allocate memory for the received response");
        return -1;
    }

    memcpy(recv_buf, tlv_buf, tlv_sz);
    *(recv_buf + tlv_sz) = '\0';
    printf("%s", (recv_buf + NCP_CMD_HEADER_LEN));

    sem_post(&cmd_sem);
    return 0;
}
static void ot_ncp_rx_task(void *pvParameters)
{
    printf("here in rx task  ot_ncp_rx_task \n");
    ssize_t         tlv_sz = 0;
    ncp_tlv_qelem_t *qelem = NULL;

    while (pthread_mutex_trylock(&ot_ncp_tlv_rx_thread_mutex) != 0)
    {
        qelem = NULL;
        tlv_sz = mq_receive(ot_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL);
        ncp_adap_d("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                    __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
        if (tlv_sz == -1)
        {
            ncp_adap_e("%s: mq_receive failed", __FUNCTION__);
            NCP_TLV_STATS_INC(err_rx);
            continue;
        }

        pthread_mutex_lock(&ot_ncp_tlv_rx_queue_mutex);
        ot_ncp_tlv_rx_queue_len--;
        pthread_mutex_unlock(&ot_ncp_tlv_rx_queue_mutex);

        if (qelem == NULL)
        {
            ncp_adap_e("%s: qelem=%p", __FUNCTION__, qelem);
            NCP_TLV_STATS_INC(err_rx);
            continue;
        }
        NCP_TLV_STATS_INC(rx2);
        ot_ncp_handle_rx_cmd_event(qelem->tlv_buf,qelem->tlv_sz );
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
    }
    pthread_mutex_unlock(&ot_ncp_tlv_rx_thread_mutex);
}

static void ot_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
    ncp_tlv_qelem_t *qelem = NULL;
    uint8_t *qelem_pld = NULL;

    pthread_mutex_lock(&ot_ncp_tlv_rx_queue_mutex);
    if (tlv_sz > NCP_TLV_QUEUE_MSGPLD_SIZE)
    {
        ncp_adap_e("%s: tlv_sz=%lu > %d", __FUNCTION__, tlv_sz, NCP_TLV_QUEUE_MSGPLD_SIZE);
        NCP_TLV_STATS_INC(err_rx);
        goto Fail;
    }

    if (ot_ncp_tlv_rx_queue_len == NCP_TLV_QUEUE_LENGTH)
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
    if (mq_send(ot_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, 0) != 0)
    {
        ncp_adap_e("%s: ncp tlv enqueue failure", __FUNCTION__);
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
        NCP_TLV_STATS_INC(err_rx);
        //ret = NCP_STATUS_ERROR;
        goto Fail;
    }
    ot_ncp_tlv_rx_queue_len++;
    NCP_TLV_STATS_INC(rx1);
    ncp_adap_d("%s: enque tlv_buf success", __FUNCTION__);

Fail:
    pthread_mutex_unlock(&ot_ncp_tlv_rx_queue_mutex);
    return;
}

static NCPCmd_DS_COMMAND *mpu_host_get_ot_command_buffer()
{
    return (NCPCmd_DS_COMMAND *)(cmd_buf);
}

static int ot_command_handler(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *ot_command = mpu_host_get_ot_command_buffer();
    uint8_t *ncp_header_address=(uint8_t *)&ot_command->header;
    (void)memset((uint8_t *)ot_command, 0, NCP_COMMAND_LEN);
    uint8_t *input_buff=malloc(OT_CMD_INPUT_BUFF_LEN*sizeof(uint8_t));
    uint8_t user_cmd[OT_CMD_INPUT_BUFF_LEN];

    for (int i = 2; i < argc; i++)
    {
        strcat(input_buff, argv[i]); //store all OT command arguments in the input_buff
        strcat(input_buff, " ");
    }

    ot_command->header.cmd      = (NCP_TLV_CMD_CLASS << 28) | (NCP_TLV_CMD_SUBCLASS << 20) | (NCP_TLV_CMD_MSGTYPE << 16) | NCP_TLV_CMD_TYPE;
    ot_command->header.size     = NCP_CMD_HEADER_LEN;
    ot_command->header.result   = NCP_CMD_RESULT_OK;

    memcpy(user_cmd , argv[1], strlen(argv[1]));
    *(ncp_header_address + sizeof(ot_command->header)) = ot_get_opcode(user_cmd, strlen(argv[1])); //get opcode
    *(ncp_header_address + OT_OPCODE_SIZE + sizeof(ot_command->header)) = ASCII_FOR_SPACE; //adding space between opcode and received ot command arguments
    memcpy(ncp_header_address + OT_OPCODE_SIZE + SPACE_CHAR_SIZE + sizeof(ot_command->header), input_buff, strlen(input_buff)); // store all ot arguments after ot command
    *(ncp_header_address + OT_OPCODE_SIZE + SPACE_CHAR_SIZE + sizeof(ot_command->header) + strlen(input_buff))='\r'; //NCP device will check this to start processing command
    ot_command->header.size += OT_OPCODE_SIZE + SPACE_CHAR_SIZE + CARRIAGE_RETURN_CHAR_SIZE +  strlen(input_buff);

    return 0;
}

static struct mpu_host_cli_command mpu_host_app_ot_cli_commands[] = {

    {"ot", "<command name> <command argument>", ot_command_handler},
};

/* -------------------------------------------------------------------------- */
/*                              Public Functions                              */
/* -------------------------------------------------------------------------- */

int ot_ncp_init(void)
{
    int status = NCP_STATUS_SUCCESS;
    struct mq_attr     qattr;
    pthread_attr_t     tattr;

    ncp_adap_d("Enter ot_ncp_init");

    status = pthread_mutex_init(&ot_ncp_tlv_rx_queue_mutex, NULL);
    if (status != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_mutex_init", __FUNCTION__);
        return NCP_STATUS_ERROR;
    }

    qattr.mq_flags         = 0;
    qattr.mq_maxmsg        = NCP_TLV_QUEUE_LENGTH;
    qattr.mq_msgsize       = NCP_TLV_QUEUE_MSG_SIZE;
    qattr.mq_curmsgs       = 0;
    ot_ncp_tlv_rx_msgq_handle = mq_open(NCP_OT_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
    if ((int)ot_ncp_tlv_rx_msgq_handle == -1)
    {
        ncp_adap_e("ERROR: ot_ncp_tlv_rx_msgq_handle create fail");
        goto err_msgq;
    }

    /* initialized with default attributes */
    status = pthread_attr_init(&tattr);
    if (status != 0)
    {
        ncp_adap_e("ERROR: %s pthread_attr_init", __FUNCTION__);
        goto err_arrt_init;
    }

    pthread_mutex_init(&ot_ncp_tlv_rx_thread_mutex, NULL);
    pthread_mutex_lock(&ot_ncp_tlv_rx_thread_mutex);

    status = pthread_create(&ot_ncp_tlv_rx_thread, &tattr, (void *)ot_ncp_rx_task, NULL);
    if (status != 0)
    {
        ncp_adap_e("ERROR: %s pthread_create", __FUNCTION__);
        goto err_rx_mutex;
    }

    ncp_tlv_install_handler(GET_CMD_CLASS(NCP_CMD_15D4), (void *)ot_ncp_callback);
    ncp_adap_d("Exit ot_ncp_init");
    return NCP_STATUS_SUCCESS;

err_rx_mutex:
    pthread_mutex_unlock(&ot_ncp_tlv_rx_thread_mutex);
    pthread_mutex_destroy(&ot_ncp_tlv_rx_thread_mutex);
err_arrt_init:
    mq_close(ot_ncp_tlv_rx_msgq_handle);
err_msgq:
    pthread_mutex_unlock(&ot_ncp_tlv_rx_queue_mutex);
    pthread_mutex_destroy(&ot_ncp_tlv_rx_queue_mutex);

    return NCP_STATUS_ERROR;
}

int ot_ncp_deinit(void)
{
    ssize_t		 tlv_sz;
    ncp_tlv_qelem_t *qelem = NULL;

    pthread_mutex_unlock(&ot_ncp_tlv_rx_thread_mutex);
    pthread_join(ot_ncp_tlv_rx_thread, NULL);
    printf("-->\n");
    pthread_mutex_lock(&ot_ncp_tlv_rx_queue_mutex);
    while (1)
    {
        qelem = NULL;
        if ((tlv_sz = mq_receive(ot_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL)) != -1)
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
    ot_ncp_tlv_rx_queue_len = 0;
    pthread_mutex_unlock(&ot_ncp_tlv_rx_queue_mutex);

    if (pthread_mutex_destroy(&ot_ncp_tlv_rx_queue_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint queue mutex fail");
    }

    if (mq_close(ot_ncp_tlv_rx_msgq_handle) != 0)
    {
        ncp_adap_e("ncp adapter tx deint MsgQ fail");
    }
    mq_unlink(NCP_OT_RX_QUEUE_NAME);

    if (pthread_mutex_destroy(&ot_ncp_tlv_rx_thread_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint thread mutex fail");
    }
    return NCP_STATUS_SUCCESS;
}

int mpu_host_init_cli_commands_ot(void)
{
    if (mpu_host_register_commands(mpu_host_app_ot_cli_commands,
                                     sizeof(mpu_host_app_ot_cli_commands) / sizeof(struct mpu_host_cli_command)) != 0)
    {
        return FALSE;
    }

    return TRUE;
}

int mpu_host_deinit_cli_commands_ot(void)
{
    if (mpu_host_unregister_commands(mpu_host_app_ot_cli_commands,
                                     sizeof(mpu_host_app_ot_cli_commands) / sizeof(struct mpu_host_cli_command)) != 0)
    {
        return FALSE;
    }

    return TRUE;
}
