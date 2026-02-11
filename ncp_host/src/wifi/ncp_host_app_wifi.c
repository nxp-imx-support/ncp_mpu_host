/** @file ncp_host_app_wifi.c
 *
 *  @brief This file provides  mpu ncp host wifi APIs
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
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
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "ncp_host_app.h"
#include "ncp_host_app_wifi.h"
#include "ncp_host_command.h"
#include "ncp_host_command_wifi.h"
#include "ncp_tlv_adapter.h"
#include "ncp_inet.h"
#include <sys/syscall.h>
#include "ncp_log.h"

NCP_LOG_MODULE_DEFINE(ncp_wifi, CONFIG_LOG_NCP_WIFI_LEVEL);
NCP_LOG_MODULE_REGISTER(ncp_wifi, CONFIG_LOG_NCP_WIFI_LEVEL);

/* ping variables */
int ping_qid;
sem_t ping_res_sem;
ping_msg_t ping_msg;
ping_res_t ping_res;
int ping_sock_handle = -1;

sem_t iperf_tx_sem;
sem_t iperf_rx_sem;
int iperf_tx_cnt       = 0;
int iperf_rx_cnt       = 0;
int iperf_rx_recv_size = 0;

#define NCP_RX_QUEUE_NAME "/ncp_rx_queue"
static pthread_t wifi_ncp_tlv_rx_thread;
static mqd_t wifi_ncp_tlv_rx_msgq_handle;
static pthread_mutex_t wifi_ncp_tlv_rx_queue_mutex;
static pthread_mutex_t wifi_ncp_tlv_rx_thread_mutex;
static int wifi_ncp_tlv_rx_queue_len = 0;

pthread_t ping_sock_thread, iperf_tx_thread, iperf_rx_thread;

extern uint32_t last_resp_rcvd, last_cmd_sent;
extern uint16_t last_seqno_rcvd, last_seqno_sent;

int cpu_latancy_fd = 0;

void bzero(void *s, size_t n);
int usleep();

/* Display the final result of ping */
static void display_ping_result(int total, int recvd)
{
    int dropped = total - recvd;
    printf("\r\n--- ping statistics ---\r\n");
    printf("%d packets transmitted, %d received,", total, recvd);
    if (dropped != 0)
        printf(" +%d errors,", dropped);
    printf(" %d%% packet loss\r\n", (dropped * 100) / total);
}

/** Prepare a echo ICMP request */
static void ping_prepare_echo(struct icmp_echo_hdr *iecho, uint16_t len, uint16_t seq_no)
{
    size_t i;
    size_t data_len = len - sizeof(struct icmp_echo_hdr);

    iecho->type   = ICMP_ECHO;
    iecho->code   = 0;
    iecho->chksum = 0;
    iecho->id     = PING_ID;
    iecho->seqno  = htons(seq_no);

    /* fill the additional data buffer with some data */
    for (i = 0; i < data_len; i++)
    {
        ((char *)iecho)[sizeof(struct icmp_echo_hdr) + i] = (char)i;
    }

    iecho->chksum = inet_chksum(iecho, len);
}

/* Display the statistics of the current iteration of ping */
static void display_ping_stats(int status, uint32_t size, const char *ip_str, uint16_t seqno, int ttl, uint64_t time)
{
    if (status == WM_SUCCESS)
    {
        printf("%u bytes from %s: icmp_req=%u ttl=%u time=%lu ms\r\n", size, ip_str, seqno, ttl, time);
    }
    else
    {
        printf("icmp_seq=%u Destination Host Unreachable\r\n", seqno);
    }
}

/* Send an ICMP echo request by NCP_CMD_WLAN_SOCKET_SENDTO command and get ICMP echo reply by
 * NCP_CMD_WLAN_SOCKET_RECVFROM command. Print ping statistics in NCP_CMD_WLAN_SOCKET_RECVFROM
 * command response, and print ping result in ping_sock_task.
 */
#if CONFIG_INET_SOCKET
#define PING_RECV_TIMEOUT_MS 5000
static void ping_sock_task(void *arg)
{
    struct ip_hdr *iphdr;
    struct icmp_echo_hdr *iecho;
    struct icmp_echo_hdr *iecho_resp;
    uint8_t *recv_buf;
    uint64_t ping_time;
    ping_time_t ping_stop, temp_time;
    struct timeval tv;

    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));

    while (1)
    {   
        ping_res.recvd  = 0;
        ping_res.seq_no = -1;
        /* demo ping task wait for user input ping command from console */
        (void)memset(&ping_msg, 0, sizeof(ping_msg_t));
        if (msgrcv(ping_qid, (void *)&ping_msg, sizeof(ping_msg_t), 0, 0) < 0)
        {
            printf("msgrcv failed!\r\n");
            continue;
        }

        printf("PING %s (%s) %u(%lu) bytes of data\r\n", ping_msg.ip_addr, ping_msg.ip_addr, ping_msg.size,
        ping_msg.size + sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr));

        int i = 1;
        /* Ping size is: size of ICMP header + size of payload */
        uint16_t ping_size = sizeof(struct icmp_echo_hdr) + ping_msg.size;

        iecho = (struct icmp_echo_hdr *)malloc(ping_size);
        if (!iecho)
        {
            printf("failed to allocate memory for ping packet!\r\n");
            continue;
        }

        recv_buf = (uint8_t *)malloc(ping_size + sizeof(struct ip_hdr));
        if (!recv_buf)
        {
            printf("failed to allocate memory for ping response packet!\r\n");
            free(iecho);
            continue;
        }

        struct sockaddr_in server_addr = {0};
        struct in_addr dest_addr;
        inet_pton(AF_INET, ping_msg.ip_addr, &dest_addr);
        server_addr.sin_family		= PF_INET;
        server_addr.sin_addr.s_addr     = dest_addr.s_addr;
        int sockfd = ncp_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        tv.tv_sec = PING_RECV_TIMEOUT_MS / 1000;
        tv.tv_usec = (PING_RECV_TIMEOUT_MS % 1000) * 1000;
        ncp_setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        while (i <= ping_msg.count)
        {
            ping_res.echo_resp = FALSE;
            (void)memset(iecho, 0, ping_size);
            (void)memset(recv_buf, 0, ping_size + IP_HEADER_LEN);

            /* Prepare ping command */
            ping_prepare_echo(iecho, (uint16_t)ping_size, i);

            NCP_LOG_DBG("%s: SOCKET_SENDTO ping count=%u", __FUNCTION__, ping_msg.count);
            ping_time_now(&ping_res.time);
            ping_res.seq_no = i;
            ncp_sendto(sockfd, iecho, ping_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

            socklen_t len = sizeof(server_addr);
            /* Function raw_input may put multiple pieces of data in conn->recvmbox,
             * waiting to select the data we want */
            while (ping_res.echo_resp != TRUE)
            {
                int ret = ncp_recvfrom(sockfd, recv_buf, ping_size + sizeof(struct ip_hdr), 0, (struct sockaddr *)&server_addr, &len);
                if (ret > (int)(sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr)))
                {
                    /* Handle the ICMP echo response and extract required parameters */
                    iphdr = (struct ip_hdr *)recv_buf;
                    /* Calculate the offset of ICMP header */
                    iecho_resp = (struct icmp_echo_hdr *)(recv_buf + ((iphdr->_v_hl & 0x0f) * 4));
                    /* Verify that the echo response is for the echo request
                    * we sent by checking PING_ID and sequence number */
                    if ((iecho_resp->id == PING_ID) && (iecho_resp->seqno == htons(ping_res.seq_no)))
                    {
                        /* Increment the receive counter */
                        ping_res.recvd++;
                        /* Extract TTL and send back so that it can be
                         * displayed in ping statistics */
                        ping_res.ttl = iphdr->_ttl;
                        ping_res.size = ret - sizeof(struct ip_hdr);
                        ping_res.echo_resp = TRUE;
                        break;
                    }
                    else
                    {
                        (void)memset(recv_buf, 0, ping_size + IP_HEADER_LEN);
                    }
                }
                else
                {
                    /* ncp_recvfrom timeout and break */
                    break;
                }
            }

            ping_time_now(&ping_stop);
            ping_time_diff(&ping_stop, &ping_res.time, &temp_time);
            ping_res.time = temp_time;
            ping_time = ping_time_in_msecs(&ping_res.time);
            inet_ntop(AF_INET, &(server_addr.sin_addr), ping_res.ip_addr, IP_ADDR_LEN);
            display_ping_stats(ping_res.echo_resp, ping_res.size, ping_res.ip_addr, ping_res.seq_no, ping_res.ttl, ping_time);

            usleep(1000000);
            i++;
        }
        display_ping_result((int)ping_msg.count, ping_res.recvd);
        free((void *)iecho);
        free((void *)recv_buf);
        ncp_close(sockfd);
    }

    pthread_exit(NULL);
}
#else
static void ping_sock_task(void *arg)
{
    struct icmp_echo_hdr *iecho;
    send_data_t *S_D = (send_data_t *)arg;
    uint64_t ping_time;
    int retry;
    ping_time_t ping_stop, temp_time;
    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));

    while (1)
    {
        ping_res.recvd  = 0;
        ping_res.seq_no = -1;
        /* demo ping task wait for user input ping command from console */
        (void)memset(&ping_msg, 0, sizeof(ping_msg_t));
        if (msgrcv(ping_qid, (void *)&ping_msg, sizeof(ping_msg_t), 0, 0) < 0)
        {
            printf("msgrcv failed!\r\n");
            continue;
        }

        printf("PING %s (%s) %u(%lu) bytes of data\r\n", ping_msg.ip_addr, ping_msg.ip_addr, ping_msg.size,
        ping_msg.size + sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr));

        int i = 1;
        /* Ping size is: size of ICMP header + size of payload */
        uint16_t ping_size = sizeof(struct icmp_echo_hdr) + ping_msg.size;

        iecho = (struct icmp_echo_hdr *)malloc(ping_size);
        if (!iecho)
        {
            printf("failed to allocate memory for ping packet!\r\n");
            continue;
        }

        /* Wait for command response semaphore. */
        sem_wait(&cmd_sem);
        /* Open socket before ping */
        NCPCmd_DS_COMMAND *ping_sock_open_command = mpu_host_get_wifi_command_buffer();
        ping_sock_open_command->header.cmd        = NCP_CMD_WLAN_SOCKET_OPEN;
        ping_sock_open_command->header.size       = NCP_CMD_HEADER_LEN;
        ping_sock_open_command->header.result     = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_OPEN_CFG *ping_sock_open_tlv = (NCP_CMD_SOCKET_OPEN_CFG *)&ping_sock_open_command->params.wlan_socket_open;
        strcpy(ping_sock_open_tlv->socket_type, "raw");
        strcpy(ping_sock_open_tlv->domain_type, "ipv4");
        strcpy(ping_sock_open_tlv->protocol, "icmp");
        ping_sock_open_command->header.size += sizeof(NCP_CMD_SOCKET_OPEN_CFG);
        NCP_LOG_DBG("%s: SOCKET_OPEN before ping", __FUNCTION__);
        /* Send socket open command */
        send_tlv_command(S_D);

        sem_wait(&ping_res_sem);
        while (i <= ping_msg.count)
        {
            ping_res.echo_resp = FALSE;
            retry = 10;

            /* Wait for command response semaphore. */
            sem_wait(&cmd_sem);

            /* Prepare ping command */
            ping_prepare_echo(iecho, (uint16_t)ping_size, i);

            NCPCmd_DS_COMMAND *ping_sock_command = mpu_host_get_wifi_command_buffer();
            ping_sock_command->header.cmd        = NCP_CMD_WLAN_SOCKET_SENDTO;
            ping_sock_command->header.size       = NCP_CMD_HEADER_LEN;
            ping_sock_command->header.result     = NCP_CMD_RESULT_OK;

            NCP_CMD_SOCKET_SENDTO_CFG *ping_sock_tlv =
                (NCP_CMD_SOCKET_SENDTO_CFG *)&ping_sock_command->params.wlan_socket_sendto;
            ping_sock_tlv->handle = ping_sock_handle;
            ping_sock_tlv->port   = ping_msg.port;
            memcpy(ping_sock_tlv->ip_addr, ping_msg.ip_addr, strlen(ping_msg.ip_addr) + 1);
            memcpy(ping_sock_tlv->send_data, iecho, ping_size);
            ping_sock_tlv->size = ping_size;

            /*cmd size*/
            ping_sock_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
            ping_sock_command->header.size += ping_size;

            NCP_LOG_DBG("%s: SOCKET_SENDTO ping count=%u", __FUNCTION__, ping_msg.count);
            /* Send ping TLV command */
            send_tlv_command(S_D);
            /* Get the current ticks as the start time */
            ping_time_now(&ping_res.time);

            /* sequence number */
            ping_res.seq_no = i;

            /* wait for NCP_CMD_WLAN_SOCKET_SENDTO command response */
            sem_wait(&ping_res_sem);

            NCP_LOG_DBG("%s: echo_resp=%d retry=%d", __FUNCTION__, ping_res.echo_resp, retry);
            /* Function raw_input may put multiple pieces of data in conn->recvmbox,
             * waiting to select the data we want */
            while (ping_res.echo_resp != TRUE && retry)
            {
                /* Wait for command response semaphore. */
                sem_wait(&cmd_sem);

                /* Prepare get-ping-result command */
                NCPCmd_DS_COMMAND *ping_res_command = mpu_host_get_wifi_command_buffer();
                ping_res_command->header.cmd        = NCP_CMD_WLAN_SOCKET_RECVFROM;
                ping_res_command->header.size       = NCP_CMD_HEADER_LEN;
                ping_res_command->header.result     = NCP_CMD_RESULT_OK;

                NCP_CMD_SOCKET_RECVFROM_CFG *ping_res_sock_tlv =
                    (NCP_CMD_SOCKET_RECVFROM_CFG *)&ping_res_command->params.wlan_socket_recvfrom;
                ping_res_sock_tlv->handle  = ping_sock_handle;
                ping_res_sock_tlv->size    = ping_msg.size + IP_HEADER_LEN;
                ping_res_sock_tlv->timeout = PING_RECVFROM_TIMEOUT;

                /* cmd size */
                ping_res_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);

                NCP_LOG_DBG("%s: SOCKET_RECVFROM echo_resp=%d retry=%d", __FUNCTION__, ping_res.echo_resp, retry);
                /* Send get-ping-result TLV command */
                send_tlv_command(S_D);
                /* wait for NCP_CMD_WLAN_SOCKET_RECVFROM command response */
                sem_wait(&ping_res_sem);

                retry--;
            }

            /* Calculate the round trip time */
            ping_time_now(&ping_stop);
            ping_time_diff(&ping_stop, &ping_res.time, &temp_time);
            ping_res.time = temp_time;

            ping_time = ping_time_in_msecs(&ping_res.time);
            display_ping_stats(ping_res.echo_resp, ping_res.size, ping_res.ip_addr, ping_res.seq_no, ping_res.ttl, ping_time);

            usleep(1000000);
            i++;
        }
        free((void *)iecho);
        sem_post(&ping_res_sem);
        display_ping_result((int)ping_msg.count, ping_res.recvd);

        sem_wait(&cmd_sem);
        NCPCmd_DS_COMMAND *ping_socket_close_command = mpu_host_get_wifi_command_buffer();
        ping_socket_close_command->header.cmd        = NCP_CMD_WLAN_SOCKET_CLOSE;
        ping_socket_close_command->header.size       = NCP_CMD_HEADER_LEN;
        ping_socket_close_command->header.result     = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_CLOSE_CFG *ping_socket_close_tlv =
            (NCP_CMD_SOCKET_CLOSE_CFG *)&ping_socket_close_command->params.wlan_socket_close;
        ping_socket_close_tlv->handle = ping_sock_handle;
        /*cmd size*/
        ping_socket_close_command->header.size += sizeof(NCP_CMD_SOCKET_CLOSE_CFG);
        NCP_LOG_DBG("%s: SOCKET_CLOSE ping handle=%u", __FUNCTION__, ping_sock_handle);
        send_tlv_command(S_D);
        ping_sock_handle = -1;
    }

    pthread_exit(NULL);
}
#endif


extern iperf_msg_t iperf_msg;

/** A const buffer to send from: we want to measure sending, not copying! */
static uint8_t lwiperf_txbuf_const[3000] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
};

char lwiperf_end_token[NCP_IPERF_END_TOKEN_SIZE] = {'N', 'C', 'P', 'I', 'P', 'E', 'R', 'P', 'E', 'N', 'D'};

int iperf_send_setting(void *arg)
{
    send_data_t *S_D = (send_data_t *)arg;
    NCP_LOG_DBG("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX || iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
    {
        NCPCmd_DS_COMMAND *iperf_command = mpu_host_get_wifi_command_buffer();
        iperf_command->header.cmd        = NCP_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size       = NCP_CMD_HEADER_LEN;
        iperf_command->header.result     = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_SEND_CFG *ncp_iperf_tlv = (NCP_CMD_SOCKET_SEND_CFG *)&iperf_command->params.wlan_socket_send;
        ncp_iperf_tlv->handle                  = iperf_msg.handle;
        ncp_iperf_tlv->size                    = sizeof(iperf_set_t);
        memcpy(ncp_iperf_tlv->send_data, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SEND_CFG);
        iperf_command->header.size += sizeof(iperf_set_t);
        memcpy(lwiperf_txbuf_const, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX || iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX)
    {
        NCPCmd_DS_COMMAND *iperf_command = mpu_host_get_wifi_command_buffer();
        iperf_command->header.cmd        = NCP_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size       = NCP_CMD_HEADER_LEN;
        iperf_command->header.result     = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_SENDTO_CFG *ncp_iperf_tlv =
            (NCP_CMD_SOCKET_SENDTO_CFG *)&iperf_command->params.wlan_socket_sendto;
        ncp_iperf_tlv->handle = iperf_msg.handle;
        ncp_iperf_tlv->size   = sizeof(iperf_set_t);
        ncp_iperf_tlv->port   = iperf_msg.port;
        memcpy(ncp_iperf_tlv->ip_addr, iperf_msg.ip_addr, strlen(iperf_msg.ip_addr) + 1);
        memcpy(ncp_iperf_tlv->send_data, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
        iperf_command->header.size += sizeof(iperf_set_t);
        memcpy(lwiperf_txbuf_const, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
    }
    else
    {
        (void)printf("iperf type is error\r\n");
        return FALSE;
    }
    /* Send ping TLV command */
    send_tlv_command(S_D);
    return TRUE;
}

void iperf_send_finish(void *arg)
{
    send_data_t *S_D                 = (send_data_t *)arg;
    NCPCmd_DS_COMMAND *iperf_command = mpu_host_get_wifi_command_buffer();
    NCP_LOG_DBG("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
    {    
        iperf_command->header.cmd        = NCP_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size       = NCP_CMD_HEADER_LEN;
        iperf_command->header.result     = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_SEND_CFG *ncp_iperf_tlv = (NCP_CMD_SOCKET_SEND_CFG *)&iperf_command->params.wlan_socket_send;
        ncp_iperf_tlv->handle                  = iperf_msg.handle;
        ncp_iperf_tlv->size                    = NCP_IPERF_END_TOKEN_SIZE;
        memcpy(ncp_iperf_tlv->send_data, lwiperf_end_token, NCP_IPERF_END_TOKEN_SIZE);

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SEND_CFG);
        iperf_command->header.size += NCP_IPERF_END_TOKEN_SIZE;
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
    {
        iperf_command->header.cmd            = NCP_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size           = NCP_CMD_HEADER_LEN;
        iperf_command->header.result         = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_SENDTO_CFG *ncp_iperf_tlv =
            (NCP_CMD_SOCKET_SENDTO_CFG *)&iperf_command->params.wlan_socket_sendto;
        ncp_iperf_tlv->handle = iperf_msg.handle;
        ncp_iperf_tlv->size   = NCP_IPERF_END_TOKEN_SIZE;
        ncp_iperf_tlv->port   = iperf_msg.port;
        memcpy(ncp_iperf_tlv->ip_addr, iperf_msg.ip_addr, strlen(iperf_msg.ip_addr) + 1);
        memcpy(ncp_iperf_tlv->send_data, (char *)&lwiperf_end_token[0], NCP_IPERF_END_TOKEN_SIZE);
        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
        iperf_command->header.size += NCP_IPERF_END_TOKEN_SIZE;
    }

    /* Send ping TLV command */
    send_tlv_command(S_D);
}

struct timeval iperf_timer_start;
struct timeval iperf_timer_end;
void ncp_iperf_report(long long total_size)
{
    long long rate          = 0;
    long long total_time_ms = 0;

    total_time_ms = (iperf_timer_end.tv_sec - iperf_timer_start.tv_sec) * 1000 +
                    (iperf_timer_end.tv_usec - iperf_timer_start.tv_usec) / 1000;

    rate = (total_size * 1000) / total_time_ms;
    rate = rate * 8 / 1024;

    (void)printf("total_time_ms :%lld , iperf rate = %lld kbit/s\r\n", total_time_ms, rate);
}

void iperf_tcp_tx(void *arg)
{
    send_data_t *S_D                 = (send_data_t *)arg;
    NCPCmd_DS_COMMAND *iperf_command = mpu_host_get_wifi_command_buffer();

    NCP_LOG_DBG("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
    {
        iperf_command->header.cmd      = NCP_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size     = NCP_CMD_HEADER_LEN;
        iperf_command->header.result   = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_SEND_CFG *ncp_iperf_tlv = (NCP_CMD_SOCKET_SEND_CFG *)&iperf_command->params.wlan_socket_send;
        ncp_iperf_tlv->handle                  = iperf_msg.handle;
        ncp_iperf_tlv->size                    = iperf_msg.per_size;
        memcpy(ncp_iperf_tlv->send_data, lwiperf_txbuf_const, iperf_msg.per_size);

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SEND_CFG);
        iperf_command->header.size += iperf_msg.per_size;
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
    {
        iperf_command->header.cmd      = NCP_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size     = NCP_CMD_HEADER_LEN;
        iperf_command->header.result   = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_SENDTO_CFG *ncp_iperf_tlv =
            (NCP_CMD_SOCKET_SENDTO_CFG *)&iperf_command->params.wlan_socket_sendto;
        ncp_iperf_tlv->handle = iperf_msg.handle;
        ncp_iperf_tlv->size   = iperf_msg.per_size;
        ncp_iperf_tlv->port   = iperf_msg.port;
        memcpy(ncp_iperf_tlv->send_data, lwiperf_txbuf_const, iperf_msg.per_size);
        memcpy(ncp_iperf_tlv->ip_addr, iperf_msg.ip_addr, strlen(iperf_msg.ip_addr) + 1);

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
        iperf_command->header.size += iperf_msg.per_size;
    }

    /* Send iperf TLV command */
    send_tlv_command(S_D);
}

void iperf_tcp_rx(void *arg)
{
    send_data_t *S_D                     = (send_data_t *)arg;
    NCPCmd_DS_COMMAND *ncp_iperf_command = mpu_host_get_wifi_command_buffer();

    NCP_LOG_DBG("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
    {
        ncp_iperf_command->header.cmd      = NCP_CMD_WLAN_SOCKET_RECV;
        ncp_iperf_command->header.size     = NCP_CMD_HEADER_LEN;
        ncp_iperf_command->header.result   = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_RECEIVE_CFG *ncp_iperf_res_sock_tlv =
            (NCP_CMD_SOCKET_RECEIVE_CFG *)&ncp_iperf_command->params.wlan_socket_receive;
        ncp_iperf_res_sock_tlv->handle  = iperf_msg.handle;
        ncp_iperf_res_sock_tlv->size    = iperf_msg.per_size;
        ncp_iperf_res_sock_tlv->timeout = IPERF_TCP_RECV_TIMEOUT;

        /*cmd size*/
        ncp_iperf_command->header.size += sizeof(NCP_CMD_SOCKET_RECEIVE_CFG);
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX)
    {
        NCPCmd_DS_COMMAND *ncp_iperf_command = mpu_host_get_wifi_command_buffer();
        ncp_iperf_command->header.cmd        = NCP_CMD_WLAN_SOCKET_RECVFROM;
        ncp_iperf_command->header.size       = NCP_CMD_HEADER_LEN;
        ncp_iperf_command->header.result     = NCP_CMD_RESULT_OK;

        NCP_CMD_SOCKET_RECVFROM_CFG *ncp_iperf_res_sock_tlv =
            (NCP_CMD_SOCKET_RECVFROM_CFG *)&ncp_iperf_command->params.wlan_socket_recvfrom;
        ncp_iperf_res_sock_tlv->handle  = iperf_msg.handle;
        ncp_iperf_res_sock_tlv->size    = iperf_msg.per_size;
        ncp_iperf_res_sock_tlv->timeout = g_udp_recv_timeout;

        /*cmd size*/
        ncp_iperf_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);
    }
    /* Send iperf TLV command */
    send_tlv_command(S_D);
}

#if CONFIG_INET_SOCKET
static void iperf_tx_task(void *arg)
{
    long long i               = 0;
    //long long total_time_ms   = 0;
    long long send_total_size = 0;
    long long udp_rate = 0;
    int per_pkt_size      = 1480;
    int pkt_num_per_xms            = 0;
    struct timeval prev_time, cur_time;
    long long prev_time_us = 0, cur_time_us = 0;
    long long delta = 0;
    int send_interval = 1;
    int ret = 0;
    int32_t latency_target = 0, latency_old = 0;

    int                client_sockfd;
    struct sockaddr_in server_addr = {0};
    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));


    while (1)
    {
        sem_wait(&iperf_tx_sem);

        if (cpu_latancy_fd > 0)
        {
            read(cpu_latancy_fd, &latency_old, sizeof(latency_old));
            write(cpu_latancy_fd, &latency_target, sizeof(latency_target));
        }

        {
            if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
            {
                struct in_addr dest_addr;
                inet_pton(AF_INET, iperf_msg.ip_addr, &dest_addr);
                server_addr.sin_family		= AF_INET;
                server_addr.sin_port		= htons(NCP_IPERF_TCP_SERVER_PORT_DEFAULT);
                server_addr.sin_addr.s_addr = dest_addr.s_addr;
                client_sockfd = ncp_socket(PF_INET, (SOCK_STREAM | SOCK_CLOEXEC), IPPROTO_TCP);
                if (ncp_connect(client_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
                {
                    NCP_LOG_ERR("connect to server failed!");
                    ncp_close(client_sockfd);
                    continue;
                }
                else
                    NCP_LOG_INF("[OK] Connected to Server");
            }
            else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
            {
                struct in_addr dest_addr; // argv[1]
                inet_pton(AF_INET, iperf_msg.ip_addr, &dest_addr);
                client_sockfd = ncp_socket(PF_INET, (SOCK_DGRAM | SOCK_CLOEXEC), IPPROTO_UDP);
                if (client_sockfd < 0)
                {
                    NCP_LOG_ERR("socket creation failed! -- errno=%d => '%s'", errno, strerror(errno));
                    continue;
                }
                else
                {
                    NCP_LOG_WRN("\t[OK] socket Created: client_sockfd=%d", client_sockfd);
                }
                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(NCP_IPERF_UDP_SERVER_PORT_DEFAULT);
                server_addr.sin_addr.s_addr = dest_addr.s_addr;
           }
        }
        udp_rate = iperf_msg.iperf_set.iperf_udp_rate;

        if (udp_rate <= 120)
            send_interval = 1000;
        if (udp_rate <= 2*1024)
           send_interval = 60;
        if (udp_rate <= 10*1024)
           send_interval = 12;
        if (udp_rate <= 20*1024)
           send_interval = 6;
        else if (udp_rate <= 30 * 1024)
            send_interval = 4;
        else if (udp_rate <= 60 * 1024)
            send_interval = 2;
        else
            send_interval = 1;
        pkt_num_per_xms = ((udp_rate * 1024 / 8) / per_pkt_size / (1000 / send_interval)); /*num pkt per send_interval(ms)*/
        gettimeofday(&prev_time, NULL);
        prev_time_us  = prev_time.tv_sec * 1000 * 1000 + prev_time.tv_usec;

        send_total_size = iperf_msg.iperf_set.iperf_count * iperf_msg.per_size;
        /*send setting*/
        memcpy(lwiperf_txbuf_const, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
#ifdef CONFIG_MPU_INET_DUMP
        NCP_LOG_ERR("%s: dump %u setting buffer %u", __FUNCTION__, iperf_msg.iperf_set.iperf_type, sizeof(iperf_set_t));
        NCP_LOG_HEXDUMP_DBG(lwiperf_txbuf_const, sizeof(iperf_set_t));
#endif
        if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
        {
            ret = ncp_send(client_sockfd, lwiperf_txbuf_const, sizeof(iperf_set_t), 0);
            if (ret < 0)
            {
                NCP_LOG_ERR("[send iperf setting fail]");
                continue;
            }
        }
        else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
        {
            ret = ncp_sendto(client_sockfd, lwiperf_txbuf_const, sizeof(iperf_set_t), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (ret < 0)
            {
                NCP_LOG_ERR("[send iperf setting fail]");
                continue;
            }
        }
        /* Get the current ticks as the start time */
        gettimeofday(&iperf_timer_start, NULL);

        i = 0; // Reset index
        while (i < iperf_msg.iperf_set.iperf_count)
        {
#ifdef CONFIG_MPU_INET_DUMP
            NCP_LOG_ERR("%s: [%llu] dump %u setting buffer %u", __FUNCTION__, i, iperf_msg.iperf_set.iperf_type, iperf_msg.per_size);
            NCP_LOG_HEXDUMP_DBG(lwiperf_txbuf_const, 64);
#endif
            if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
            {
                ret = ncp_send(client_sockfd, lwiperf_txbuf_const, iperf_msg.per_size, 0);
                if (ret < 0)
                    NCP_LOG_ERR("[send iperf data fail");
            }
            else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
            {
                ret = ncp_sendto(client_sockfd, lwiperf_txbuf_const, iperf_msg.per_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
                if (ret < 0)
                    NCP_LOG_ERR("[send iperf data fail");
            }

            if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
            {
                gettimeofday(&cur_time, NULL);
                cur_time_us = cur_time.tv_sec * 1000 * 1000 + cur_time.tv_usec;
                if ((i > 0) && (!(i % pkt_num_per_xms)))
                {
                    delta = prev_time_us + (1000 * send_interval) - cur_time_us;
                    if (delta > 0)
                        usleep(delta);
                    prev_time_us += (1000 * send_interval);
                }
            }

            i++;
            iperf_tx_cnt = i;
        }

        gettimeofday(&iperf_timer_end, NULL);
        ncp_iperf_report(send_total_size);
        sleep(1);
        /*End token*/
        if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
        {
            ret = ncp_send(client_sockfd, lwiperf_end_token, NCP_IPERF_END_TOKEN_SIZE, 0);
            if (ret < 0)
                NCP_LOG_ERR("[send iperf finish fail]");
            else
                NCP_LOG_INF("[send iperf finish]");
        }
        else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
        {
            ret = ncp_sendto(client_sockfd, lwiperf_end_token, NCP_IPERF_END_TOKEN_SIZE, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (ret < 0)
                NCP_LOG_ERR("[send iperf finish fail]");
            else
                NCP_LOG_INF("[send iperf finish]");

        }
        sleep(1);
        ncp_close(client_sockfd);
        if (cpu_latancy_fd > 0)
            write(cpu_latancy_fd, &latency_old, sizeof(latency_old));
    }

    pthread_exit(NULL);
}

static void iperf_rx_task(void *arg)
{
    long long pkg_num   = 0;
    long long recv_size = 0, left_size = 0;
    int ret = 0;
    int32_t latency_target = 0, latency_old = 0;
    int                client_sockfd;
    struct sockaddr_in server_addr = {0};
    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));

    while (1)
    {
        sem_wait(&iperf_rx_sem);
        if (cpu_latancy_fd > 0) {
            read(cpu_latancy_fd, &latency_old, sizeof(latency_old));
            write(cpu_latancy_fd, &latency_target, sizeof(latency_target));
        }

        printf("ncp iperf rx start\r\n");
        /* connect server */
        {
            if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
            {
                struct in_addr dest_addr;
                inet_pton(AF_INET, iperf_msg.ip_addr, &dest_addr);
                server_addr.sin_family		= AF_INET;
                server_addr.sin_port		= htons(NCP_IPERF_TCP_SERVER_PORT_DEFAULT);
                server_addr.sin_addr.s_addr = dest_addr.s_addr;
                client_sockfd = ncp_socket(PF_INET, (SOCK_STREAM | SOCK_CLOEXEC), IPPROTO_TCP);
                if (ncp_connect(client_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
                {
                    NCP_LOG_ERR("connect to server failed!");
                    ncp_close(client_sockfd);
                    continue;
                }
                else
                    NCP_LOG_INF("[OK] Connected to Server");
            }
            else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX)
            {
                struct in_addr dest_addr; // argv[1]
                inet_pton(AF_INET, iperf_msg.ip_addr, &dest_addr);
                client_sockfd = ncp_socket(PF_INET, (SOCK_DGRAM | SOCK_CLOEXEC), IPPROTO_UDP);
                if (client_sockfd < 0)
                {
                    NCP_LOG_ERR("socket creation failed! -- errno=%d => '%s'", errno, strerror(errno));
                    continue;
                }
                else
                {
                    NCP_LOG_WRN("\t[OK] socket Created: client_sockfd=%d", client_sockfd);
				}
                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(5003);
                server_addr.sin_addr.s_addr = dest_addr.s_addr;
            }
        }

        /*send setting*/
        memcpy(lwiperf_txbuf_const, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
#ifdef CONFIG_MPU_INET_DUMP
        NCP_LOG_ERR("%s: dump %u setting buffer %u", __FUNCTION__, iperf_msg.iperf_set.iperf_type, sizeof(iperf_set_t));
        NCP_LOG_HEXDUMP_DBG(lwiperf_txbuf_const, sizeof(iperf_set_t));
#endif
        if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
        {
            ret = ncp_send(client_sockfd, lwiperf_txbuf_const, sizeof(iperf_set_t), 0);
            if (ret < 0)
            {
                NCP_LOG_ERR("[send iperf setting fail");
                continue;
            }
        }
        else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX)
        {
            ret = ncp_sendto(client_sockfd, lwiperf_txbuf_const, sizeof(iperf_set_t), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (ret < 0)
            {
                NCP_LOG_ERR("[send iperf setting fail");
                continue;
            }
        }

        pkg_num             = 0;
        iperf_msg.status[1] = 0;
        recv_size           = 0;
        left_size           = iperf_msg.per_size * iperf_msg.iperf_set.iperf_count;
        /* Get the current ticks as the start time */
        gettimeofday(&iperf_timer_start, NULL);
        while (left_size > 0)
        {
            char buffer[3000];
            ret = ncp_recv(client_sockfd, buffer, iperf_msg.per_size, 0);
            if (ret < 0)
            {
                NCP_LOG_ERR("%s: ncp_recv fail ret=%d", __FUNCTION__, ret);
                continue;
            }
            if (iperf_msg.per_size > sizeof(buffer))
            {
                NCP_LOG_ERR("%s: invalid recv size %u", __FUNCTION__, iperf_msg.per_size);
                continue;
            }
#ifdef CONFIG_MPU_INET_DUMP
            NCP_LOG_ERR("%s: dump ncp_recv buffer %u ret=%d", __FUNCTION__, iperf_msg.per_size, ret);
            NCP_LOG_HEXDUMP_DBG(buffer, ret);
#endif
            recv_size += ret;
            left_size -= ret;
            pkg_num++;
            iperf_rx_cnt       = pkg_num;
            iperf_rx_recv_size = recv_size;
            if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX && ret == 11)
                break;
        }
        recv_size += ret;
        left_size -= ret;
        gettimeofday(&iperf_timer_end, NULL);
        (void)printf("RX IPERF END\r\n");
        ncp_iperf_report(recv_size);
        sleep(1);
        ncp_close(client_sockfd);
        if (cpu_latancy_fd > 0)
            write(cpu_latancy_fd, &latency_old, sizeof(latency_old));

    }

    pthread_exit(NULL);
}
#else
static void iperf_tx_task(void *arg)
{
    long long i               = 0;
    //long long total_time_ms   = 0;
    long long send_total_size = 0;
    long long udp_rate = 0;
    int per_pkt_size      = 1480;
    int pkt_num_per_xms            = 0;
    struct timeval prev_time, cur_time;
    long long prev_time_us = 0, cur_time_us = 0;
    long long delta = 0;
    int send_interval = 1;

    send_data_t *S_D = (send_data_t *)arg;
    while (1)
    {
        sem_wait(&iperf_tx_sem);
        
        udp_rate = iperf_msg.iperf_set.iperf_udp_rate;

        if (udp_rate <= 120)
            send_interval = 1000;
        if (udp_rate <= 2*1024)
           send_interval = 60;
        if (udp_rate <= 10*1024)
           send_interval = 12; 
        if (udp_rate <= 20*1024)
           send_interval = 6; 
        else if (udp_rate <= 30 * 1024)
            send_interval = 4;
        else if (udp_rate <= 60 * 1024)
            send_interval = 2;
        else
            send_interval = 1;
        pkt_num_per_xms = ((udp_rate * 1024 / 8) / per_pkt_size / (1000 / send_interval)); /*num pkt per send_interval(ms)*/
        
        //(void)printf("udp_rate %lld send_interval %d pkt_num_per_xms %d \r\n",udp_rate, send_interval, pkt_num_per_xms);
        
        gettimeofday(&prev_time, NULL);
        prev_time_us  = prev_time.tv_sec * 1000 * 1000 + prev_time.tv_usec;
        
        send_total_size = iperf_msg.iperf_set.iperf_count * iperf_msg.per_size;

        /*first, tell the server the direction and size*/
        sem_wait(&cmd_sem);

        if (FALSE == iperf_send_setting(S_D))
            continue;
        /* Get the current ticks as the start time */
        gettimeofday(&iperf_timer_start, NULL);

        i = 0; // Reset index

        while (i < iperf_msg.iperf_set.iperf_count)
        {
            /* Wait for command response semaphore. */
            sem_wait(&cmd_sem);
            /*
            if (iperf_msg.status[0] == (char)-WM_FAIL)
            {
                (void)printf("send command run failr\n");
                gettimeofday(&iperf_timer_end, NULL);
                total_time_ms = (long long)(iperf_timer_end.tv_sec - iperf_timer_start.tv_sec) * 1000 +
                                (long long)(iperf_timer_end.tv_usec - iperf_timer_start.tv_usec) / 1000;
                ncp_iperf_report(send_total_size);
                sem_post(&cmd_sem);
            }
            */
            
            iperf_tcp_tx(arg);

            if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
            {
                gettimeofday(&cur_time, NULL);
                cur_time_us = cur_time.tv_sec * 1000 * 1000 + cur_time.tv_usec;
                if ((i > 0) && (!(i % pkt_num_per_xms)))
                {
                    delta = prev_time_us + (1000 * send_interval) - cur_time_us;
                    //printf("prev_time_us = %lld, cur_time_us = %lld, delta = %lld, pkt_num_per1ms = %d, i = %d\n",
                    // prev_time_us, cur_time_us, delta, pkt_num_per_xms, i);
                    if (delta > 0)
                        usleep(delta);
                    prev_time_us += (1000 * send_interval);
                }
            }

            i++;
            iperf_tx_cnt = i;
        }

        gettimeofday(&iperf_timer_end, NULL);
        ncp_iperf_report(send_total_size);
        sleep(1);
        /* Wait for command response semaphore. */
        sem_wait(&cmd_sem);
        /*End token*/
        iperf_send_finish(S_D);
    }

    pthread_exit(NULL);

}

static void iperf_rx_task(void *arg)
{
    long long pkg_num   = 0;
    long long recv_size = 0, left_size = 0;
    send_data_t *S_D = (send_data_t *)arg;

    while (1)
    {
        sem_wait(&iperf_rx_sem);
        printf("ncp iperf rx start\r\n");
        /*first, tell the server the direction and size*/
        sem_wait(&cmd_sem);
        if (FALSE == iperf_send_setting(S_D))
            continue;

        pkg_num             = 0;
        iperf_msg.status[1] = 0;
        recv_size           = 0;
        left_size           = iperf_msg.per_size * iperf_msg.iperf_set.iperf_count;
        /* Get the current ticks as the start time */
        gettimeofday(&iperf_timer_start, NULL);
        while (left_size > 0)
        {
            /* Wait for command response semaphore. */
            sem_wait(&cmd_sem);
            
            if (iperf_msg.status[1] < 0)
            {
                sem_post(&cmd_sem);
                break;
            }
            
            recv_size += iperf_msg.status[1];
            left_size -= iperf_msg.status[1];
            iperf_tcp_rx(arg);
            pkg_num++;
            iperf_rx_cnt       = pkg_num;
            iperf_rx_recv_size = recv_size;
        }
        recv_size += iperf_msg.status[1];
        left_size -= iperf_msg.status[1];
        gettimeofday(&iperf_timer_end, NULL);
        (void)printf("RX IPERF END\r\n");
        ncp_iperf_report(recv_size);
    }

    pthread_exit(NULL);
}
#endif

static void wifi_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
    //ncp_status_t ret = NCP_STATUS_SUCCESS;
    ncp_tlv_data_qelem_t *qelem = NULL;
    uint8_t *qelem_pld = NULL;

    pthread_mutex_lock(&wifi_ncp_tlv_rx_queue_mutex);
    if (tlv_sz > NCP_TLV_QUEUE_MSGPLD_SIZE)
    {
        NCP_LOG_ERR("%s: tlv_sz=%lu > %d", __FUNCTION__, tlv_sz, NCP_TLV_QUEUE_MSGPLD_SIZE);
        // NCP_TLV_STATS_INC(err_rx);
        goto Fail;
    }

    if (wifi_ncp_tlv_rx_queue_len == NCP_TLV_DATA_QUEUE_LENGTH)
    {
        NCP_LOG_ERR("%s: ncp tlv queue is full max queue length: %d", __FUNCTION__, NCP_TLV_DATA_QUEUE_LENGTH);
        //ret = NCP_STATUS_QUEUE_FULL;
        // NCP_TLV_STATS_INC(err_rx);
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
    if (mq_send(wifi_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, 0) != 0)
    {
        NCP_LOG_ERR("%s: ncp tlv enqueue failure", __FUNCTION__);
        NCP_LOG_DBG("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
        // NCP_TLV_STATS_INC(err_rx);
        //ret = NCP_STATUS_ERROR;
        goto Fail;
    }
    wifi_ncp_tlv_rx_queue_len++;
    // NCP_TLV_STATS_INC(rx1);
    NCP_LOG_DBG("%s: enque tlv_buf success", __FUNCTION__);

Fail:
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);
    return;
}

static int wifi_ncp_handle_rx_cmd_event(uint8_t *cmd)
{
    uint32_t msg_type = 0;
    int ret;

#ifdef CONFIG_MPU_IO_DUMP
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)cmd;
    int recv_resp_length = cmd_res->header.size;
    printf("%s: recv_resp_length = %d\r\n", __FUNCTION__, recv_resp_length);
    NCP_LOG_HEXDUMP_DBG((uint8_t *)cmd_res, recv_resp_length);
#endif

    msg_type = GET_MSG_TYPE(((NCP_COMMAND *)cmd)->cmd);
    if (msg_type == NCP_MSG_TYPE_EVENT)
        wlan_process_ncp_event(cmd);
    else
    {
        ret = wlan_process_response(cmd);

        if(ret != -NCP_STATUS_HANDLE_RSP)
        {
            last_resp_rcvd = ((NCP_COMMAND *)cmd)->cmd;
            last_seqno_rcvd = ((NCP_COMMAND *)cmd)->seqnum;
            if (last_resp_rcvd == (last_cmd_sent | NCP_MSG_TYPE_RESP))
            {
                sem_post(&cmd_sem);
#ifdef CONFIG_MPU_IO_DUMP
                printf("put command semaphore\r\n");
#endif
            }
            if (last_resp_rcvd == NCP_RSP_INVALID_CMD)
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

    }
    return 0;
}

void wifi_ncp_rx_task(void *pvParameters)
{
    ssize_t         tlv_sz = 0;
    ncp_tlv_data_qelem_t *qelem = NULL;
    printf("[%s-%d], %ld\n", __func__, __LINE__, syscall(SYS_gettid));

    while (pthread_mutex_trylock(&wifi_ncp_tlv_rx_thread_mutex) != 0)
    {
        qelem = NULL;
        tlv_sz = mq_receive(wifi_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL);
        NCP_LOG_DBG("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                    __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
        if (tlv_sz == -1)
        {
            NCP_LOG_ERR("%s: mq_receive failed", __FUNCTION__);
            // NCP_TLV_STATS_INC(err_rx);
            continue;
        }

        pthread_mutex_lock(&wifi_ncp_tlv_rx_queue_mutex);
        wifi_ncp_tlv_rx_queue_len--;
        pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);

        if (qelem == NULL)
        {
            NCP_LOG_ERR("%s: qelem=%p", __FUNCTION__, qelem);
            // NCP_TLV_STATS_INC(err_rx);
            continue;
        }
        // NCP_TLV_STATS_INC(rx2);
        wifi_ncp_handle_rx_cmd_event(qelem->tlv_buf);
        NCP_LOG_DBG("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
    }
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_thread_mutex);
}

int wifi_ncp_init()
{
    int status = NCP_STATUS_SUCCESS;
    struct mq_attr     qattr;
    pthread_attr_t     tattr;

    NCP_LOG_DBG("Enter wifi_ncp_init");

    status = pthread_mutex_init(&wifi_ncp_tlv_rx_queue_mutex, NULL);
    if (status != 0)
    {
        NCP_LOG_ERR("%s: ERROR: pthread_mutex_init", __FUNCTION__);
        return NCP_STATUS_ERROR;
    }
    mq_unlink(NCP_RX_QUEUE_NAME);
    qattr.mq_flags         = 0;
    qattr.mq_maxmsg        = NCP_TLV_DATA_QUEUE_LENGTH;
    qattr.mq_msgsize       = NCP_TLV_QUEUE_MSG_SIZE;
    qattr.mq_curmsgs       = 0;
    wifi_ncp_tlv_rx_msgq_handle = mq_open(NCP_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
    if ((int)wifi_ncp_tlv_rx_msgq_handle == -1)
    {
        NCP_LOG_ERR("ERROR: wifi_ncp_tlv_rx_msgq_handle create fail");
        goto err_msgq;
    }

    /* initialized with default attributes */
    status = pthread_attr_init(&tattr);
    if (status != 0)
    {
        NCP_LOG_ERR("ERROR: %s pthread_attr_init", __FUNCTION__);
        goto err_arrt_init;
    }

    pthread_mutex_init(&wifi_ncp_tlv_rx_thread_mutex, NULL);
    pthread_mutex_lock(&wifi_ncp_tlv_rx_thread_mutex);

    status = pthread_create(&wifi_ncp_tlv_rx_thread, &tattr, (void *)wifi_ncp_rx_task, NULL);
    if (status != 0)
    {
        NCP_LOG_ERR("ERROR: %s pthread_create", __FUNCTION__);
        goto err_rx_mutex;
    }

    ncp_tlv_install_handler(GET_CMD_CLASS(NCP_CMD_WLAN), (void *)wifi_ncp_callback);
    ncp_inet_init();
    NCP_LOG_DBG("Exit wifi_ncp_init");
    return NCP_STATUS_SUCCESS;

err_rx_mutex:
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_thread_mutex);
    pthread_mutex_destroy(&wifi_ncp_tlv_rx_thread_mutex);
err_arrt_init:
    mq_close(wifi_ncp_tlv_rx_msgq_handle);
err_msgq:
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);
    pthread_mutex_destroy(&wifi_ncp_tlv_rx_queue_mutex);

    return NCP_STATUS_ERROR;
}

int wifi_ncp_deinit()
{
    ssize_t		 tlv_sz;
    ncp_tlv_data_qelem_t *qelem = NULL;

    pthread_mutex_unlock(&wifi_ncp_tlv_rx_thread_mutex);
    pthread_join(wifi_ncp_tlv_rx_thread, NULL);
    printf("-->\n");
    pthread_mutex_lock(&wifi_ncp_tlv_rx_queue_mutex);
    while (1)
    {
        qelem = NULL;
        if ((tlv_sz = mq_receive(wifi_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL)) != -1)
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
            NCP_LOG_DBG("ncp adapter queue flush completed");
            break;
        }
    }
    wifi_ncp_tlv_rx_queue_len = 0;
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);

    if (pthread_mutex_destroy(&wifi_ncp_tlv_rx_queue_mutex) != 0)
    {
        NCP_LOG_ERR("ncp adapter tx deint queue mutex fail");
    }

    if (mq_close(wifi_ncp_tlv_rx_msgq_handle) != 0)
    {
        NCP_LOG_ERR("ncp adapter tx deint MsgQ fail");
    }
    mq_unlink(NCP_RX_QUEUE_NAME);

    if (pthread_mutex_destroy(&wifi_ncp_tlv_rx_thread_mutex) != 0)
    {
        NCP_LOG_ERR("ncp adapter tx deint thread mutex fail");
    }
    return NCP_STATUS_SUCCESS;
}

int wifi_ncp_app_init()
{
    if (sem_init(&ping_res_sem, 0, 1) == -1 ||sem_init(&iperf_tx_sem, 0, 1) == -1 ||
        sem_init(&iperf_rx_sem, 0, 1) == -1)
    {
        printf("Failed to init semaphore!\r\n");
        goto err_sem_init;
    }
    sem_wait(&iperf_tx_sem);
    sem_wait(&iperf_rx_sem);

    /* Create message queue */
    if ((ping_qid = msgget((key_t)1234, IPC_CREAT | 0666)) == -1)
    {
        printf("msgget failed\r\n");
        goto err_get_ping_qid;
    }

    return NCP_STATUS_SUCCESS;

err_get_ping_qid:
    sem_destroy(&iperf_tx_sem);
    sem_destroy(&iperf_rx_sem);
    sem_destroy(&ping_res_sem);
err_sem_init:
    return NCP_STATUS_ERROR;
}

int wifi_ncp_app_deinit()
{
    msgctl(ping_qid, IPC_RMID, NULL);
    sem_destroy(&iperf_tx_sem);
    sem_destroy(&iperf_rx_sem);
    sem_destroy(&ping_res_sem);

    return NCP_STATUS_SUCCESS;
}

int wifi_ncp_app_task_init(void *send_data, void *recv_data)
{
    ping_sock_thread = pthread_create(&ping_sock_thread, NULL, (void *)ping_sock_task, (void *)send_data);
    if (ping_sock_thread != 0)
    {
        printf("Failed to creat Ping Socket Thread!\r\n");
        goto err_ping_sock_thread;
    }
    else
        printf("Success to creat Ping Socket Thread!\r\n");

    iperf_tx_thread = pthread_create(&iperf_tx_thread, NULL, (void *)iperf_tx_task, (void *)send_data);
    if (iperf_tx_thread != 0)
    {
        printf("Failed to creat iperf_tx_thread!\r\n");
        goto err_iperf_tx_thread;
    }
    else
        printf("Success to creat iperf_tx_thread!\r\n");

    iperf_rx_thread = pthread_create(&iperf_rx_thread, NULL, (void *)iperf_rx_task, (void *)recv_data);
    if (iperf_rx_thread != 0)
    {
        printf("Failed to creat iperf_rx_thread!\r\n");
        goto err_iperf_rx_thread;
    }
    else
        printf("Success to creat iperf_rx_thread!\r\n");

    cpu_latancy_fd = open("/dev/cpu_dma_latency", O_RDWR);
    if (cpu_latancy_fd < 0)
        perror("open: ");

    return NCP_STATUS_SUCCESS;

err_iperf_rx_thread:
    pthread_join(iperf_tx_thread, NULL);
err_iperf_tx_thread:
    pthread_join(ping_sock_thread, NULL);
err_ping_sock_thread:
    return NCP_STATUS_ERROR;
}

int wifi_ncp_app_task_deinit()
{
    pthread_join(iperf_rx_thread, NULL);
    pthread_join(iperf_tx_thread, NULL);
    pthread_join(ping_sock_thread, NULL);

    return NCP_STATUS_SUCCESS;
}

