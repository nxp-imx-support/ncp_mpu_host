/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "ncp_host_command.h"
#include "ncp_cmd_node.h"
#include "ncp_adapter.h"

ncp_cmd_node_list_t g_cmd_node_list;
uint16_t g_cmd_node_seqno = 0;
uint32_t last_cmd_node_sent,last_cmd_node_rcvd;
uint16_t last_cmd_node_seqno_rcvd, last_cmd_node_seqno_sent;

static void add_cmd_node(ncp_cmd_node_t * cmd_node)
{
    if(cmd_node == NULL)
    {
        printf("cmd_node is NULL, can't be added to the cmd node list!\r\n");
        return;
    }
    
    pthread_mutex_lock(&g_cmd_node_list.cmd_node_list_lock);

    /** Insert at the head of the list */    
    cmd_node->next = g_cmd_node_list.head;
    g_cmd_node_list.head  = cmd_node;

    pthread_mutex_unlock(&g_cmd_node_list.cmd_node_list_lock);
}

static ncp_cmd_node_t * find_cmd_node(ncp_cmd_node_t * target)
{
    if(target == NULL)
    {
        return NULL;
    }

    pthread_mutex_lock(&g_cmd_node_list.cmd_node_list_lock);

    ncp_cmd_node_t * current  = g_cmd_node_list.head;
    
    while(current != NULL)
    {
        if(current == target)
        {
            pthread_mutex_unlock(&g_cmd_node_list.cmd_node_list_lock);
            return current;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&g_cmd_node_list.cmd_node_list_lock);
    return NULL;
}

static ncp_cmd_node_t * match_cmd_node(uint32_t target_cmd_id, uint16_t target_cmd_seqnum)
{
    pthread_mutex_lock(&g_cmd_node_list.cmd_node_list_lock);

    ncp_cmd_node_t * current  = g_cmd_node_list.head;
    ncp_cmd_node_t * previous = NULL;

    while (current != NULL)
    {
        if ((GET_CMD_ID(target_cmd_id) == GET_CMD_ID(current->ncp_cmd_id)) && (target_cmd_seqnum == current->seqnum))
        {
            if (previous == NULL)
            {
                g_cmd_node_list.head = current->next;
            }
            else
            {
                previous->next = current->next;
            }
            pthread_mutex_unlock(&g_cmd_node_list.cmd_node_list_lock);
            return current;
        }

        previous = current;
        current  = current->next;
    }

    pthread_mutex_unlock(&g_cmd_node_list.cmd_node_list_lock);
    return NULL;
}

uint8_t ncp_tlv_send_wait_resp(void * cmd, void * cmd_resp_buf, Handle_respFunc cb)
{
    NCP_COMMAND * ncp_cmd = (NCP_COMMAND *) cmd;
    uint8_t ret = NCP_STATUS_SUCCESS;

    struct timespec ts;

    ncp_cmd_node_t * cmd_node = malloc(sizeof(ncp_cmd_node_t));
    if(cmd_node == NULL)
    {
        printf("failed to malloc cmd_node!\r\n");
        return NCP_STATUS_ERROR;
    }
    (void) memset((uint8_t *) cmd_node, 0, sizeof(ncp_cmd_node_t));

    cmd_node->resp_buf        = cmd_resp_buf;
    cmd_node->ncp_cmd_id      = ncp_cmd->cmd;
    cmd_node->send_tlv_buf    = &ncp_cmd;
    cmd_node->handle_resp_cb  = cb;
    cmd_node->next            = NULL;

    /* set cmd seqno */
    ncp_cmd->seqnum  = g_cmd_node_seqno;
    cmd_node->seqnum = g_cmd_node_seqno;
   
    /** add cmd id and seqnum in the sem name to distinguish different cmd and multiple calls of the same cmd*/
    snprintf(cmd_node->sem_name, sizeof(cmd_node->sem_name), "%s_%d_%d", SEM_NAME, cmd_node->ncp_cmd_id, ncp_cmd->seqnum);
    sem_t *sem = sem_open(cmd_node->sem_name, O_CREAT, 0644, 0);

    if (sem == SEM_FAILED)
    {
        perror("sem_open");
        ret = NCP_STATUS_ERROR;
        goto out_clear;
    }

    add_cmd_node(cmd_node);

    if (ncp_tlv_send(cmd, ncp_cmd->size) != NCP_STATUS_SUCCESS)
    {
        printf("ncp_tlv_send failed!\r\n");
        ret = NCP_STATUS_ERROR;
        goto out_clear;
    }

    /** resv for future use */
    //last_cmd_node_sent = ncp_cmd->cmd;
    //last_cmd_node_seqno_sent = ncp_cmd->seqnum;

    pthread_mutex_lock(&g_cmd_node_list.cmd_node_seqno_lock);
    g_cmd_node_seqno++;
    pthread_mutex_unlock(&g_cmd_node_list.cmd_node_seqno_lock);
    //ncp_adap_d("%s: last_cmd_node_sent=0x%x last_cmd_node_seqno_sent=0x%x\r\n", __FUNCTION__, last_cmd_node_sent, last_cmd_node_seqno_sent);

    /* wait notify */
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += NCP_CMD_NODE_SEM_TIMEOUT;
    sem_timedwait(sem, &ts);
    if (errno == ETIMEDOUT)
    {
        printf("xinyu sem_timedwait timeout\r\n");
        ret = NCP_STATUS_ERROR;
        goto out_clear;
    }

out_clear:
    sem_close(sem);
    sem_unlink(cmd_node->sem_name);
    if(find_cmd_node(cmd_node) != NULL)
    {
        match_cmd_node(cmd_node->ncp_cmd_id, cmd_node->seqnum);
    }
    free(cmd_node);
    return ret;
}

void ncp_cmd_node_wakeup_pending_tasks(uint8_t *res)
{
    NCP_COMMAND *cmd_res = (NCP_COMMAND *)res;
    ncp_cmd_node_t * cmd_node  = NULL;

    cmd_node = match_cmd_node(cmd_res->cmd, cmd_res->seqnum);

    if (cmd_node != NULL)
    {
        cmd_node->handle_resp_cb(cmd_res, cmd_node);
        sem_t *sem = sem_open(cmd_node->sem_name, 0);
        sem_post(sem);
        sem_close(sem); 
    }
}

int ncp_cmd_node_list_init()
{
    int ret = 0;
    
    g_cmd_node_list.head = NULL;
    g_cmd_node_list.tail = NULL;
    g_cmd_node_list.size = 0;
    ret = pthread_mutex_init(&g_cmd_node_list.cmd_node_list_lock, NULL);
    ret |= pthread_mutex_init(&g_cmd_node_list.cmd_node_seqno_lock, NULL);

    return ret;
}

void ncp_cmd_node_list_deinit()
{
    pthread_mutex_lock(&g_cmd_node_list.cmd_node_list_lock);

    ncp_cmd_node_t * current  = g_cmd_node_list.head;
    ncp_cmd_node_t * cmd_node_for_free = NULL;

    while(current != NULL)
    {
        cmd_node_for_free = current;
        current = current->next;
        if(cmd_node_for_free->resp_buf != NULL)
        {
            free(cmd_node_for_free->resp_buf);
        }
        
        sem_t *temp_sem = sem_open(cmd_node_for_free->sem_name, 0);
        if(temp_sem != SEM_FAILED)
        {
            sem_close(temp_sem);
            sem_unlink(cmd_node_for_free->sem_name);
        }
        
        free(cmd_node_for_free);
    }

    pthread_mutex_unlock(&g_cmd_node_list.cmd_node_list_lock);

    if (pthread_mutex_destroy(&g_cmd_node_list.cmd_node_list_lock) !=0)
    {
        perror("Failed to destroy mutex");
    }
    if (pthread_mutex_destroy(&g_cmd_node_list.cmd_node_seqno_lock) !=0)
    {
        perror("Failed to destroy mutex");
    }
}
