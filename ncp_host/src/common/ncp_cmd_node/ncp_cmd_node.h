/** @file ncp_host_command.h
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_CMD_NODE__
#define __NCP_CMD_NODE__


#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define NCP_COMMAND_LEN 4096
#define NCP_CMD_NODE_SEM_TIMEOUT 20
#define SEM_NAME "/cmd_node_sem"

/** Get command cmd_id */
#define GET_CMD_ID(cmd)       ((cmd)&0x0000ffff)

typedef struct ncp_cmd_node_t ncp_cmd_node_t;

typedef void (*Handle_respFunc)(void * cmd_resp_buf, ncp_cmd_node_t * cmd_node);

typedef struct ncp_cmd_node_t
{
    void * resp_buf;
    char sem_name[32];
    uint32_t ncp_cmd_id;
    uint16_t seqnum;
    void * send_tlv_buf;
    Handle_respFunc handle_resp_cb;
    struct ncp_cmd_node_t * next;
} ncp_cmd_node_t;

typedef struct {
    ncp_cmd_node_t *head;
    ncp_cmd_node_t *tail;
    pthread_mutex_t cmd_node_list_lock;
    pthread_mutex_t cmd_node_seqno_lock;
    size_t size;
} ncp_cmd_node_list_t;

int ncp_cmd_node_list_init();
void ncp_cmd_node_list_deinit();
uint8_t ncp_tlv_send_wait_resp(void * cmd, void * cmd_resp_buf, Handle_respFunc cb);
uint8_t ncp_tlv_send_no_resp(void * cmd);
void ncp_cmd_node_wakeup_pending_tasks(uint8_t *cmd_res);

#endif
