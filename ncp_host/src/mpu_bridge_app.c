/** @file mpu_bridge_app.c
 *
 *  @brief This file provides  mpu bridge interfaces
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
#include <mpu_bridge_app.h>
#include <mpu_bridge_command.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "ncp_tlv_adapter.h"
#include "lpm.h"

uint8_t input_buf[NCP_BRIDGE_COMMAND_LEN];
uint8_t recv_buf[NCP_BRIDGE_RING_BUFFER_SIZE_ALIGN];
uint8_t resp_buf[NCP_BRIDGE_RESPONSE_LEN];
uint8_t cmd_buf[NCP_BRIDGE_COMMAND_LEN];
uint8_t temp_buf[NCP_BRIDGE_RESPONSE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
uint16_t sequence_number = 1;
/** command semaphore*/
sem_t cmd_sem;
uint32_t last_resp_rcvd, last_cmd_sent;

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

pthread_mutex_t gpio_wakeup_mutex = PTHREAD_MUTEX_INITIALIZER;
extern power_cfg_t global_power_config;
extern uint8_t mpu_device_status;

#define NCP_RX_QUEUE_NAME "/ncp_rx_queue"
static pthread_t wifi_ncp_tlv_rx_thread;
static mqd_t wifi_ncp_tlv_rx_msgq_handle;
static pthread_mutex_t wifi_ncp_tlv_rx_queue_mutex;
static pthread_mutex_t wifi_ncp_tlv_rx_thread_mutex;
static int wifi_ncp_tlv_rx_queue_len = 0;

void bzero(void *s, size_t n);
int usleep();
void send_tlv_command(send_data_t *S_D);

static struct mpu_bridge_commands
{
    const struct mpu_bridge_cli_command *commands[MPU_BRIDGE_MAX_COMMANDS];
    unsigned int num_commands;
} mpu_bridge_app_cmd;


/* Initialize a ring buffer structure*/
static ring_buffer_t *ring_buf_init(void *buffer, uint32_t size, pthread_mutex_t *f_lock)
{
    assert(buffer);
    ring_buffer_t *ring_buf = NULL;

    ring_buf = (ring_buffer_t *)malloc(sizeof(ring_buffer_t));
    if (!ring_buf)
    {
        printf("Failed to malloc memory for ring_buffer_t\r\n");
        return ring_buf;
    }
    memset(ring_buf, 0, sizeof(ring_buffer_t));
    ring_buf->buffer = buffer;
    ring_buf->size   = size;
    ring_buf->head   = 0;
    ring_buf->tail   = 0;
    ring_buf->f_lock = f_lock;

    return ring_buf;
}
/* Free ring buffer structure */
static void ring_buf_free(ring_buffer_t *ring_buf)
{
    if (ring_buf)
    {
        /* In the mpu bridge app, the ring buffer uses a static array,
         * so there is no need to release ring_buf->buffer,
         * otherwise it needs to be released.
         */
        free(ring_buf);
        ring_buf = NULL;
    }
}

#if 0
/* Read data from ring buffer */
static uint32_t ring_buf_read(ring_buffer_t *ring_buf, void *buffer, uint32_t size)
{
    uint32_t len = 0;
    assert(ring_buf || buffer);

    pthread_mutex_lock(ring_buf->f_lock);

    size = min(size, ring_buf->head - ring_buf->tail);
    /* first get the data from ring_buf->tail until the end of the buffer */
    len = min(size, ring_buf->size - (ring_buf->tail & (ring_buf->size - 1)));
    memcpy(buffer, ring_buf->buffer + (ring_buf->tail & (ring_buf->size - 1)), len);
    /* then get the rest (if any) from the beginning of the buffer */
    memcpy(buffer + len, ring_buf->buffer, size - len);
    ring_buf->tail += size;

    /* No data */
    if (ring_buf->head == ring_buf->tail)
        ring_buf->head = ring_buf->tail = 0;

    pthread_mutex_unlock(ring_buf->f_lock);
    return size;
}

/* Write data to ring buffer */
static uint32_t ring_buf_write(ring_buffer_t *ring_buf, void *buffer, uint32_t size)
{
    uint32_t len = 0;
    assert(ring_buf || buffer);
    pthread_mutex_lock(ring_buf->f_lock);

    size = min(size, ring_buf->size - ring_buf->head + ring_buf->tail);
    /* first put the data starting from ring_buf->head to buffer end */
    len = min(size, ring_buf->size - (ring_buf->head & (ring_buf->size - 1)));
    memcpy(ring_buf->buffer + (ring_buf->head & (ring_buf->size - 1)), buffer, len);
    /* then put the rest (if any) at the beginning of the buffer */
    memcpy(ring_buf->buffer, buffer + len, size - len);
    ring_buf->head += size;

    pthread_mutex_unlock(ring_buf->f_lock);
    return size;
}

int check_command_complete(uint8_t *buf)
{
    NCP_BRIDGE_COMMAND *new_cmd;
    uint16_t msglen;
    uint32_t local_checksum = 0, remote_checksum = 0;

    new_cmd = (NCP_BRIDGE_COMMAND *)buf;
    /* check crc */
    msglen = new_cmd->size;

    remote_checksum = *(uint32_t *)(buf + msglen);
    local_checksum  = uart_get_crc32(msglen, buf);
    if (remote_checksum == local_checksum)
    {
#ifdef CONFIG_MPU_IO_DUMP
        printf("local checksum == remote checksum: 0x%02x \r\n", local_checksum);
#endif
        return 0;
    }
    else
    {
        printf("[ERROR] local checksum: %02x != remote checksum: 0x%02x \r\n", local_checksum, remote_checksum);
        return -1;
    }
}
#endif

int mpu_bridge_register_command(const struct mpu_bridge_cli_command *command)
{
    int i;
    if (!command->name || !command->function)
        return FALSE;

    if (mpu_bridge_app_cmd.num_commands < MPU_BRIDGE_MAX_COMMANDS)
    {
        /* Check if the command has already been registered.
         * Return TURE, if it has been registered.
         */
        for (i = 0; i < mpu_bridge_app_cmd.num_commands; i++)
        {
            if (mpu_bridge_app_cmd.commands[i] == command)
                return TRUE;
        }
        mpu_bridge_app_cmd.commands[mpu_bridge_app_cmd.num_commands++] = command;
        return TRUE;
    }

    return FALSE;
}

int mpu_bridge_unregister_command(const struct mpu_bridge_cli_command *command)
{
    int i;
    if (!command->name || !command->function)
        return FALSE;

    for (i = 0; i < mpu_bridge_app_cmd.num_commands; i++)
    {
        if (mpu_bridge_app_cmd.commands[i] == command)
        {
            mpu_bridge_app_cmd.num_commands--;
            int remaining_cmds = mpu_bridge_app_cmd.num_commands - i;
            if (remaining_cmds > 0)
            {
                (void)memmove(&mpu_bridge_app_cmd.commands[i], &mpu_bridge_app_cmd.commands[i + 1],
                              (remaining_cmds * sizeof(struct mpu_bridge_cli_command *)));
            }
            mpu_bridge_app_cmd.commands[mpu_bridge_app_cmd.num_commands] = NULL;
            return TRUE;
        }
    }

    return FALSE;
}

int mpu_bridge_register_commands(const struct mpu_bridge_cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
        if (mpu_bridge_register_command(commands++) != 0)
            return FALSE;
    return TRUE;
}

int mpu_bridge_unregister_commands(const struct mpu_bridge_cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
        if (mpu_bridge_unregister_command(commands++) != 0)
            return FALSE;

    return TRUE;
}

int help_command(int argc, char **argv)
{
    int i, n;

    (void)printf("\r\n");
    for (i = 0, n = 0; i < MPU_BRIDGE_MAX_COMMANDS && n < mpu_bridge_app_cmd.num_commands; i++)
    {
        if (mpu_bridge_app_cmd.commands[i]->name != NULL)
        {
            printf("%s %s\r\n", mpu_bridge_app_cmd.commands[i]->name,
                   mpu_bridge_app_cmd.commands[i]->help ? mpu_bridge_app_cmd.commands[i]->help : "");
            n++;
        }
    }

    return TRUE;
}

void mpu_dump_hex(const void *data, unsigned int len)
{
    printf("********** Dump @ %p   Length:  %d **********\r\n", data, len);

    const uint8_t *Data = (const uint8_t *)data;
    for (int i = 0; i < len;)
    {
        printf("%02x ", Data[i++]);
        if (i % MPU_DUMP_WRAPAROUND == 0)
            printf("\r\n");
    }

    printf("\r\n**********  End Dump **********\r\n");
}

#if 0
int processs_cmdresp(void *arg)
{
    ring_buffer_t *ring_buf = (ring_buffer_t *)arg;
    int recv_resp_length    = 0;
    int cmd_size            = 0;
    int len                 = 0;
    uint16_t msg_type       = 0;

    while (1)
    {
        while (len < NCP_BRIDGE_CMD_HEADER_LEN)
        {
            recv_resp_length = ring_buf_read(ring_buf, resp_buf + len, NCP_BRIDGE_CMD_HEADER_LEN);
            len += recv_resp_length;
        }

        cmd_size         = (resp_buf[NCP_BRIDGE_CMD_SIZE_HIGH_BYTES] << 8) | resp_buf[NCP_BRIDGE_CMD_SIZE_LOW_BYTES];
        recv_resp_length = 0;

        while (len < (cmd_size + CHECKSUM_LEN))
        {
            recv_resp_length = ring_buf_read(ring_buf, resp_buf + len, cmd_size + CHECKSUM_LEN - len);
            len += recv_resp_length;
        }

#ifdef CONFIG_MPU_IO_DUMP
        printf("processs_cmdresp Response cmd:\r\n");
        mpu_dump_hex(resp_buf, recv_resp_length);
#endif
        msg_type = ((NCP_BRIDGE_COMMAND *)resp_buf)->msg_type;
        if (check_command_complete(resp_buf) == 0)
        {
            if (msg_type == NCP_BRIDGE_MSG_TYPE_EVENT)
                wlan_process_ncp_event(resp_buf);
            else
            {
                wlan_process_response(resp_buf);

                last_resp_rcvd = ((NCPCmd_DS_COMMAND *)resp_buf)->header.cmd;
                if (last_cmd_sent == last_resp_rcvd)
                {
                    sem_post(&cmd_sem);
#ifdef CONFIG_MPU_IO_DUMP
                    printf("put command semaphore\r\n");
#endif
                }
                if (last_resp_rcvd == NCP_BRIDGE_CMD_INVALID_CMD)
                {
                    printf("Previous command is invalid\r\n");
                    sem_post(&cmd_sem);
                    last_resp_rcvd = 0;
                }
#ifdef CONFIG_MPU_IO_DUMP
                printf("last_resp_rcvd = 0x%08x, last_cmd_sent = 0x%08x \r\n", last_resp_rcvd, last_cmd_sent);
#endif
            }
        }
        /** Reset command response buffer */
        memset(resp_buf, 0, sizeof(resp_buf));
        recv_resp_length = 0;
        len              = 0;
        usleep(1000);
    }
    return TRUE;
}
#endif

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

/* Send an ICMP echo request by NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO command and get ICMP echo reply by
 * NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM command. Print ping statistics in NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM
 * command response, and print ping result in ping_sock_task.
 */
static void ping_sock_task(void *arg)
{
    struct icmp_echo_hdr *iecho;
    send_data_t *S_D = (send_data_t *)arg;
    uint64_t ping_time;
    int retry;
    ping_time_t ping_stop, temp_time;

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
        NCPCmd_DS_COMMAND *ping_sock_open_command = ncp_mpu_bridge_get_command_buffer();
        ping_sock_open_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_OPEN;
        ping_sock_open_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
        ping_sock_open_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
        ping_sock_open_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_OPEN_CFG *ping_sock_open_tlv = (NCP_CMD_SOCKET_OPEN_CFG *)&ping_sock_open_command->params.wlan_socket_open;
        strcpy(ping_sock_open_tlv->socket_type, "raw");
        strcpy(ping_sock_open_tlv->domain_type, "ipv4");
        strcpy(ping_sock_open_tlv->protocol, "icmp");
        ping_sock_open_command->header.size += sizeof(NCP_CMD_SOCKET_OPEN_CFG);
        ncp_adap_d("%s: SOCKET_OPEN before ping", __FUNCTION__);
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

            NCPCmd_DS_COMMAND *ping_sock_command = ncp_mpu_bridge_get_command_buffer();
            ping_sock_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
            ping_sock_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
            ping_sock_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
            ping_sock_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

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

            ncp_adap_d("%s: SOCKET_SENDTO ping count=%u", __FUNCTION__, ping_msg.count);
            /* Send ping TLV command */
            send_tlv_command(S_D);
            /* Get the current ticks as the start time */
            ping_time_now(&ping_res.time);

            /* sequence number */
            ping_res.seq_no = i;

            /* wait for NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO command response */
            sem_wait(&ping_res_sem);

            ncp_adap_d("%s: echo_resp=%d retry=%d", __FUNCTION__, ping_res.echo_resp, retry);
            /* Function raw_input may put multiple pieces of data in conn->recvmbox,
             * waiting to select the data we want */
            while (ping_res.echo_resp != TRUE && retry)
            {
                /* Wait for command response semaphore. */
                sem_wait(&cmd_sem);

                /* Prepare get-ping-result command */
                NCPCmd_DS_COMMAND *ping_res_command = ncp_mpu_bridge_get_command_buffer();
                ping_res_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM;
                ping_res_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
                ping_res_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
                ping_res_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

                NCP_CMD_SOCKET_RECVFROM_CFG *ping_res_sock_tlv =
                    (NCP_CMD_SOCKET_RECVFROM_CFG *)&ping_res_command->params.wlan_socket_recvfrom;
                ping_res_sock_tlv->handle  = ping_sock_handle;
                ping_res_sock_tlv->size    = ping_msg.size + IP_HEADER_LEN;
                ping_res_sock_tlv->timeout = PING_RECVFROM_TIMEOUT;

                /* cmd size */
                ping_res_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);

                ncp_adap_d("%s: SOCKET_RECVFROM echo_resp=%d retry=%d", __FUNCTION__, ping_res.echo_resp, retry);
                /* Send get-ping-result TLV command */
                send_tlv_command(S_D);
                /* wait for NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM command response */
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
        NCPCmd_DS_COMMAND *ping_socket_close_command = ncp_mpu_bridge_get_command_buffer();
        ping_socket_close_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_CLOSE;
        ping_socket_close_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
        ping_socket_close_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
        ping_socket_close_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_CLOSE_CFG *ping_socket_close_tlv =
            (NCP_CMD_SOCKET_CLOSE_CFG *)&ping_socket_close_command->params.wlan_socket_close;
        ping_socket_close_tlv->handle = ping_sock_handle;
        /*cmd size*/
        ping_socket_close_command->header.size += sizeof(NCP_CMD_SOCKET_CLOSE_CFG);
        ncp_adap_d("%s: SOCKET_CLOSE ping handle=%u", __FUNCTION__, ping_sock_handle);
        send_tlv_command(S_D);
        ping_sock_handle = -1;
    }
}

extern iperf_msg_t iperf_msg;
#if 0
/** A const buffer to send from: we want to measure sending, not copying! */
static char lwiperf_txbuf_const[NCP_IPERF_PER_UDP_PKG_SIZE] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
};
#endif

/** A const buffer to send from: we want to measure sending, not copying! */
static uint8_t lwiperf_txbuf_const[1600] = {
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
    ncp_adap_d("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX || iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
    {
        NCPCmd_DS_COMMAND *iperf_command = ncp_mpu_bridge_get_command_buffer();
        iperf_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

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
        NCPCmd_DS_COMMAND *iperf_command = ncp_mpu_bridge_get_command_buffer();
        iperf_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

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
    NCPCmd_DS_COMMAND *iperf_command = ncp_mpu_bridge_get_command_buffer();
    ncp_adap_d("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
    {    
        iperf_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

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
        iperf_command->header.cmd            = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size           = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result         = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type       = NCP_BRIDGE_MSG_TYPE_CMD;

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
    NCPCmd_DS_COMMAND *iperf_command = ncp_mpu_bridge_get_command_buffer();

    ncp_adap_d("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
    {
        iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

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
        iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

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
    NCPCmd_DS_COMMAND *ncp_iperf_command = ncp_mpu_bridge_get_command_buffer();

    ncp_adap_d("%s: iperf_type=%u", __FUNCTION__, iperf_msg.iperf_set.iperf_type);
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
    {
        ncp_iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_RECV;
        ncp_iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        ncp_iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        ncp_iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

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
        NCPCmd_DS_COMMAND *ncp_iperf_command = ncp_mpu_bridge_get_command_buffer();
        ncp_iperf_command->header.cmd        = NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM;
        ncp_iperf_command->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
        ncp_iperf_command->header.result     = NCP_BRIDGE_CMD_RESULT_OK;
        ncp_iperf_command->header.msg_type   = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_RECVFROM_CFG *ncp_iperf_res_sock_tlv =
            (NCP_CMD_SOCKET_RECVFROM_CFG *)&ncp_iperf_command->params.wlan_socket_recvfrom;
        ncp_iperf_res_sock_tlv->handle  = iperf_msg.handle;
        ncp_iperf_res_sock_tlv->size    = iperf_msg.per_size;
        ncp_iperf_res_sock_tlv->timeout = IPERF_UDP_RECV_TIMEOUT;

        /*cmd size*/
        ncp_iperf_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);
    }
    /* Send iperf TLV command */
    send_tlv_command(S_D);
}

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
        else if (udp_rate <= 2*1024)
            send_interval = 60;
        else if (udp_rate <= 10*1024)
            send_interval = 12;
        else if (udp_rate <= 20*1024)
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
        
        send_total_size = (long long)iperf_msg.iperf_set.iperf_count * (long long)iperf_msg.per_size;

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
                    prev_time_us += (long long)(1000 * send_interval);
                }
            }

            i++;
            iperf_tx_cnt = i;
        }

        gettimeofday(&iperf_timer_end, NULL);
        ncp_iperf_report(send_total_size);
        sleep(1);
        /*End token*/
        iperf_send_finish(S_D);
    }
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
        left_size           = (long long)iperf_msg.per_size * (long long)iperf_msg.iperf_set.iperf_count;
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
}

/* Find the command 'name' in the mpu bridge app commands table.
 * If len is 0 then full match will be performed else upto len bytes.
 * Returns: a pointer to the corresponding bridge_cli_command struct or NULL.
 */
const struct mpu_bridge_cli_command *lookup_command(char *name, int len)
{
    int i = 0;
    int n = 0;

    while (i < MPU_BRIDGE_MAX_COMMANDS && n < mpu_bridge_app_cmd.num_commands)
    {
        if (mpu_bridge_app_cmd.commands[i]->name == NULL)
        {
            i++;
            continue;
        }
        /* See if partial or full match is expected */
        if (len != 0)
        {
            if (!strncmp(mpu_bridge_app_cmd.commands[i]->name, name, len))
                return mpu_bridge_app_cmd.commands[i];
        }
        else
        {
            if (!strcmp(mpu_bridge_app_cmd.commands[i]->name, name))
                return mpu_bridge_app_cmd.commands[i];
        }

        i++;
        n++;
    }

    return NULL;
}

static int handle_input(uint8_t *inbuf)
{
    struct
    {
        unsigned inArg : 1;
        unsigned inQuote : 1;
        unsigned done : 1;
    } stat;
    static char *argv[32];
    int argc                                     = 0;
    int i                                        = 0;
    int j                                        = 0;
    const struct mpu_bridge_cli_command *command = NULL;
    const char *p;
    int ret = FALSE;

    (void)memset((void *)&argv, 0, sizeof(argv));
    (void)memset(&stat, 0, sizeof(stat));

    /*
     * Some terminals add CRLF to the input buffer.
     * Sometimes the CR and LF characters maybe misplaced (it maybe added at the
     * start or at the end of the buffer). Therefore, strip all CRLF (0x0d, 0x0a).
     */
    for (j = 0; j < MPU_BRIDGE_INBUF_SIZE; j++)
    {
        if (inbuf[j] == 0x0D || inbuf[j] == 0x0A)
        {
            if (j < (MPU_BRIDGE_INBUF_SIZE - 1))
                (void)memmove((inbuf + j), inbuf + j + 1, (MPU_BRIDGE_INBUF_SIZE - j));
            inbuf[MPU_BRIDGE_INBUF_SIZE] = 0x00;
        }
    }

    do
    {
        switch (inbuf[i])
        {
            case '\0':
                if (stat.inQuote != 0U)
                    return FALSE;
                stat.done = 1;
                break;

            case '"':
                if (i > 0 && inbuf[i - 1] == '\\' && stat.inArg)
                {
                    (void)memcpy(&inbuf[i - 1], &inbuf[i], strlen((char *)&inbuf[i]) + 1);
                    --i;
                    break;
                }
                if (!stat.inQuote && stat.inArg)
                    break;
                if (stat.inQuote && !stat.inArg)
                    return FALSE;

                if (!stat.inQuote && !stat.inArg)
                {
                    stat.inArg   = 1;
                    stat.inQuote = 1;
                    argc++;
                    argv[argc - 1] = (char *)&inbuf[i + 1];
                }
                else if (stat.inQuote && stat.inArg)
                {
                    stat.inArg   = 0;
                    stat.inQuote = 0;
                    inbuf[i]     = '\0';
                }
                else
                { /* Do Nothing */
                }
                break;

            case ' ':
                if (i > 0 && inbuf[i - 1] == '\\' && stat.inArg)
                {
                    (void)memcpy(&inbuf[i - 1], &inbuf[i], strlen((char *)&inbuf[i]) + 1);
                    --i;
                    break;
                }
                if (!stat.inQuote && stat.inArg)
                {
                    stat.inArg = 0;
                    inbuf[i]   = '\0';
                }
                break;

            default:
                if (!stat.inArg)
                {
                    stat.inArg = 1;
                    argc++;
                    argv[argc - 1] = (char *)&inbuf[i];
                }
                break;
        }
    } while (!stat.done && ++i < MPU_BRIDGE_INBUF_SIZE);

    if (argc < 1)
        return FALSE;

    /*
     * Some commands can allow extensions like foo.a, foo.b and hence
     * compare commands before first dot.
     */
    i = ((p = strchr(argv[0], '.')) == NULL) ? 0 : (p - argv[0]);

    command = lookup_command(argv[0], i);
    if (command == NULL)
        return FALSE;
    if (string_equal("help", argv[0]))
    {
        ret = help_command(0, NULL);
    }
    else
    {
        ret = command->function(argc, argv);
    }

    return ret;
}

/**
 * @brief       This function judges if s1 and s2 are equal.
 *
 * @param s1   A pointer to string s1.
 * @param s2   A pointer to string s2.
 *
 * @return     Return 1 if s1 is equal to s2.
 */
int string_equal(const char *s1, const char *s2)
{
    size_t len = strlen(s1);

    if (len == strlen(s2) && !strncmp(s1, s2, len))
        return 1;
    return 0;
}

/**
 * @brief       This function convters string to decimal number.
 *
 * @param arg   A pointer to string.
 * @param dest  A pointer to number.
 * @param len   Length of string arg.
 *
 * @return      return 0 if string arg can be convert to decimal number.
 */
int get_uint(const char *arg, unsigned int *dest, unsigned int len)
{
    int i;
    unsigned int val = 0;

    for (i = 0; i < len; i++)
    {
        if (arg[i] < '0' || arg[i] > '9')
            return FALSE;
        val *= 10;
        val += arg[i] - '0';
    }

    *dest = val;
    return TRUE;
}

uint32_t a2hex_or_atoi(char *value)
{
    if (value[0] == '0' && (value[1] == 'X' || value[1] == 'x'))
    {
        return a2hex(value + 2);
    }
    else if (mpu_isdigit((unsigned char)*value) != 0)
    {
        return atoi(value);
    }
    else
    {
        return *value;
    }
}

uint32_t a2hex(const char *s)
{
    uint32_t val = 0;

    if (!strncasecmp("0x", s, 2))
    {
        s += 2;
    }

    while (*s && (mpu_isdigit((unsigned char)*s) || mpu_islower((unsigned char)*s) || mpu_isupper((unsigned char)*s)))
    {
        val = (val << 4) + hexc2bin(*s++);
    }
    return val;
}

uint8_t hexc2bin(char chr)
{
    if (chr >= '0' && chr <= '9')
        chr -= '0';
    else if (chr >= 'A' && chr <= 'F')
        chr -= ('A' - 10);
    else if (chr >= 'a' && chr <= 'f')
        chr -= ('a' - 10);
    else
    { /* Do Nothing */
    }
    return chr;
}

void send_tlv_command(send_data_t *S_D)
{
#if 0
    int index;
    uint32_t bridge_checksum = 0;
#endif
    uint8_t *temp_cmd        = cmd_buf;
    int Datalen, ret = TRUE;

    Datalen = (temp_cmd[NCP_BRIDGE_CMD_SIZE_HIGH_BYTES] << 8) | temp_cmd[NCP_BRIDGE_CMD_SIZE_LOW_BYTES];
    ncp_adap_d("%s Enter: cmd_buf=%p Datalen=%d", __FUNCTION__, cmd_buf, Datalen);
    if ((0 == Datalen) || (Datalen > NCP_BRIDGE_COMMAND_LEN))
    {
        printf("%s: Invalid Datalen=%d!\r\n", __FUNCTION__, Datalen);
#ifdef CONFIG_MPU_IO_DUMP
        mpu_dump_hex(cmd_buf, 64);
#endif
        ret = FALSE;
        goto out_clear;
    }

    temp_cmd[NCP_BRIDGE_CMD_SEQUENCE_LOW_BYTES]  = (sequence_number & 0xFF);
    temp_cmd[NCP_BRIDGE_CMD_SEQUENCE_HIGH_BYTES] = (sequence_number >> 8) & 0xFF;

#ifdef CONFIG_MPU_IO_DUMP
    printf("Send command:\r\n");
    mpu_dump_hex(cmd_buf, Datalen);
#endif
    if (ncp_tlv_send(temp_cmd, Datalen) != NCP_STATUS_SUCCESS)
    {
        printf("ncp_tlv_send failed!\r\n");
        ret = FALSE;
        goto out_clear;
    }

    last_cmd_sent = ((NCPCmd_DS_COMMAND *)temp_cmd)->header.cmd;
    sequence_number++;
    ncp_adap_d("%s: last_cmd_sent=0x%x sequence_number=0x%x", __FUNCTION__, last_cmd_sent, sequence_number);

out_clear:
    clear_mpu_bridge_command_buffer();
#if 0
    if (NCP_BRIDGE_CMD_SYSTEM_CONFIG_SDIO_SET == last_cmd_sent)
    {
        sem_post(&cmd_sem);
    }
#endif
    if (ret == FALSE)
    {
        sem_post(&cmd_sem);

#ifdef CONFIG_NCP_MPU_HOST_DEBUG
        printf("send_tlv_command, put command semaphore\r\n");
#endif
    }
    ncp_adap_d("%s Exit", __FUNCTION__);
}

/**
 * @brief      Waiting for input
 *
 * @return     Set successfully: TRUE  else: FALSE
 */
int keyboard_hit()
{
    struct termios oldt, newt;
    int ch, oldf;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_cflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, F_GETFL, 0);
    oldf = fcntl(STDIN_FILENO, F_SETFL, 0);
	if (oldf < 0)
        return FALSE;
    if (fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK) < 0)
        return FALSE;
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    if (fcntl(STDIN_FILENO, F_SETFL, oldf) < 0)
        return FALSE;
    if (ch != EOF)
    {
        ungetc(ch, stdin);
        return TRUE;
    }

    return FALSE;
}


/**
 * @brief        Send command to bridge_app
 *
 * @param arg    arg
 * @return       TRUE
 */
static void wifi_ncp_handle_input_task(void *arg)
{
    send_data_t *S_D = (send_data_t *)arg;
    int ret;
    char nul[2];
    nul[0] = '\n'; // only input enter
#ifdef CONFIG_NCP_SDIO
    NCP_BRIDGE_COMMAND wakeup_buf;
#endif

    while (1)
    {
        if (pthread_mutex_lock(&mutex) == 0)
        {
            while (keyboard_hit() == TRUE)
            {
                fgets((char *)S_D->data_buf, MAX_SEND_RECV_LEN, stdin);
                if (!strncmp((char *)S_D->data_buf, nul, 1))
                    continue;
                S_D->data_buf[strlen((char *)S_D->data_buf) - 1] = '\0';

                if (sem_trywait(&cmd_sem) == -1)
                {
                    printf("Please wait for the previous command to complete!\r\n");
                    break;
                }
#ifdef CONFIG_MPU_IO_DUMP
                printf("got command semaphore\r\n");
#endif
                ret = handle_input(S_D->data_buf);
                if (ret != TRUE)
                {
                    printf("Failed to send command. Please input command again.\r\n");
                    clear_mpu_bridge_command_buffer();
                    sem_post(&cmd_sem);
                    printf("put command semaphore\r\n");
                }
                else
                {
                    if (mpu_device_status == MPU_DEVICE_STATUS_SLEEP)
                    {
#ifdef CONFIG_NCP_SDIO
                        if(global_power_config.wake_mode == WAKE_MODE_INTF)
                        {
                            memset(&wakeup_buf, 0x0, sizeof(NCP_BRIDGE_COMMAND));
                            wakeup_buf.size = NCP_BRIDGE_CMD_HEADER_LEN - 1;
                            //write(S_D->serial_fd, &wakeup_buf, NCP_BRIDGE_CMD_HEADER_LEN);
                            ncp_adap_d("%s: send wakeup_buf", __FUNCTION__);
                            ncp_tlv_send(&wakeup_buf, NCP_BRIDGE_CMD_HEADER_LEN);
                        }
                        else
#endif
                        if(global_power_config.wake_mode == WAKE_MODE_GPIO)
                        {
                            set_lpm_gpio_value(0);
                            pthread_mutex_unlock(&mutex);
                            pthread_mutex_lock(&gpio_wakeup_mutex);
                            set_lpm_gpio_value(1);
                            pthread_mutex_unlock(&gpio_wakeup_mutex);
                            pthread_mutex_lock(&mutex);
                        }
                    }
                    ncp_adap_d("%s: input cmd send", __FUNCTION__);
                    send_tlv_command(S_D);
                }
            }
            pthread_mutex_unlock(&mutex);
        }
        usleep(10);
    }
}

static void wifi_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
    //ncp_status_t ret = NCP_STATUS_SUCCESS;
    ncp_tlv_qelem_t *qelem = NULL;
    uint8_t *qelem_pld = NULL;

    pthread_mutex_lock(&wifi_ncp_tlv_rx_queue_mutex);
    if (tlv_sz > NCP_TLV_QUEUE_MSGPLD_SIZE)
    {
        ncp_adap_e("%s: tlv_sz=%lu > %d", __FUNCTION__, tlv_sz, NCP_TLV_QUEUE_MSGPLD_SIZE);
        NCP_TLV_STATS_INC(err_rx);
        goto Fail;
    }

    if (wifi_ncp_tlv_rx_queue_len == NCP_TLV_QUEUE_LENGTH)
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
    if (mq_send(wifi_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, 0) != 0)
    {
        ncp_adap_e("%s: ncp tlv enqueue failure", __FUNCTION__);
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
        NCP_TLV_STATS_INC(err_rx);
        //ret = NCP_STATUS_ERROR;
        goto Fail;
    }
    wifi_ncp_tlv_rx_queue_len++;
    NCP_TLV_STATS_INC(rx1);
    ncp_adap_d("%s: enque tlv_buf success", __FUNCTION__);

Fail:
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);
    return;
}

static int wifi_ncp_handle_rx_cmd_event(uint8_t *cmd)
{
    uint16_t msg_type = 0;

#ifdef CONFIG_MPU_IO_DUMP
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)cmd;
    int recv_resp_length = cmd_res->header.size;
    printf("%s: recv_resp_length = %d\r\n", __FUNCTION__, recv_resp_length);
    mpu_dump_hex((uint8_t *)cmd_res, recv_resp_length);
#endif

    msg_type = ((NCP_BRIDGE_COMMAND *)cmd)->msg_type;
    if (msg_type == NCP_BRIDGE_MSG_TYPE_EVENT)
        wlan_process_ncp_event(cmd);
    else
    {
        wlan_process_response(cmd);

        last_resp_rcvd = ((NCPCmd_DS_COMMAND *)cmd)->header.cmd;
        if (last_cmd_sent == last_resp_rcvd)
        {
            sem_post(&cmd_sem);
#ifdef CONFIG_MPU_IO_DUMP
            printf("put command semaphore\r\n");
#endif
        }
        if (last_resp_rcvd == NCP_BRIDGE_CMD_INVALID_CMD)
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

void wifi_ncp_rx_task(void *pvParameters)
{
    ssize_t         tlv_sz = 0;
    ncp_tlv_qelem_t *qelem = NULL;

    while (pthread_mutex_trylock(&wifi_ncp_tlv_rx_thread_mutex) != 0)
    {
        qelem = NULL;
        tlv_sz = mq_receive(wifi_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE, NULL);
        ncp_adap_d("%s: mq_receive qelem=%p: tlv_buf=%p tlv_sz=%lu",
                    __FUNCTION__, qelem, qelem->tlv_buf, qelem->tlv_sz);
        if (tlv_sz == -1)
        {
            ncp_adap_e("%s: mq_receive failed", __FUNCTION__);
            NCP_TLV_STATS_INC(err_rx);
            continue;
        }

        pthread_mutex_lock(&wifi_ncp_tlv_rx_queue_mutex);
        wifi_ncp_tlv_rx_queue_len--;
        pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);

        if (qelem == NULL)
        {
            ncp_adap_e("%s: qelem=%p", __FUNCTION__, qelem);
            NCP_TLV_STATS_INC(err_rx);
            continue;
        }
        NCP_TLV_STATS_INC(rx2);
        wifi_ncp_handle_rx_cmd_event(qelem->tlv_buf);
        ncp_adap_d("%s: free qelem %p", __FUNCTION__, qelem);
        free(qelem);
    }
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_thread_mutex);
}

int wifi_ncp_init()
{
    int status = NCP_STATUS_SUCCESS;
    struct mq_attr     qattr;
    pthread_attr_t     tattr;

    ncp_adap_d("Enter wifi_ncp_init");

    status = pthread_mutex_init(&wifi_ncp_tlv_rx_queue_mutex, NULL);
    if (status != 0)
    {
        ncp_adap_e("%s: ERROR: pthread_mutex_init", __FUNCTION__);
        return NCP_STATUS_ERROR;
    }

    qattr.mq_flags         = 0;
    qattr.mq_maxmsg        = NCP_TLV_QUEUE_LENGTH;
    qattr.mq_msgsize       = NCP_TLV_QUEUE_MSG_SIZE;
    qattr.mq_curmsgs       = 0;
    wifi_ncp_tlv_rx_msgq_handle = mq_open(NCP_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
    if ((int)wifi_ncp_tlv_rx_msgq_handle == -1)
    {
        ncp_adap_e("ERROR: wifi_ncp_tlv_rx_msgq_handle create fail");
        goto err_msgq;
    }

    /* initialized with default attributes */
    status = pthread_attr_init(&tattr);
    if (status != 0)
    {
        ncp_adap_e("ERROR: %s pthread_attr_init", __FUNCTION__);
        goto err_arrt_init;
    }

    pthread_mutex_init(&wifi_ncp_tlv_rx_thread_mutex, NULL);
    pthread_mutex_lock(&wifi_ncp_tlv_rx_thread_mutex);

    status = pthread_create(&wifi_ncp_tlv_rx_thread, &tattr, (void *)wifi_ncp_rx_task, NULL);
    if (status != 0)
    {
        ncp_adap_e("ERROR: %s pthread_create", __FUNCTION__);
        goto err_rx_mutex;
    }

    ncp_tlv_install_handler(NCP_BRIDGE_CMD_WLAN >> 6, (void *)wifi_ncp_callback);

    ncp_adap_d("Exit wifi_ncp_init");
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
    ncp_tlv_qelem_t *qelem = NULL;

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
    wifi_ncp_tlv_rx_queue_len = 0;
    pthread_mutex_unlock(&wifi_ncp_tlv_rx_queue_mutex);

    if (pthread_mutex_destroy(&wifi_ncp_tlv_rx_queue_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint queue mutex fail");
    }

    if (mq_close(wifi_ncp_tlv_rx_msgq_handle) != 0)
    {
        ncp_adap_e("ncp adapter tx deint MsgQ fail");
    }
    mq_unlink(NCP_RX_QUEUE_NAME);

    if (pthread_mutex_destroy(&wifi_ncp_tlv_rx_thread_mutex) != 0)
    {
        ncp_adap_e("ncp adapter tx deint thread mutex fail");
    }
    return NCP_STATUS_SUCCESS;
}

/**
 * @brief        Main function
 *
 * @param argc   argc
 * @param argv   argv
 * @return       TRUE
 */
#ifndef NCP_OT_CLI
int main(int argc, char **argv)
{
    pthread_t send_thread, ping_sock_thread, iperf_tx_thread, iperf_rx_thread;
    recv_data_t recv_data;
    send_data_t send_data;
    send_data.data_buf      = input_buf;
    ring_buffer_t *ring_buf = NULL;

#if 0
    uart_init_crc32();
#endif
    if (ncp_adapter_init(argv[1]) != NCP_STATUS_SUCCESS)
    {
        printf("ncp_adapter_init failed!\r\n");
        goto err_adapter_init;
    }

    if (wifi_ncp_init() != NCP_STATUS_SUCCESS)
    {
        printf("wifi_ncp_init failed!\r\n");
        goto err_ncp_init;
    }

    if (sem_init(&cmd_sem, 0, 1) == -1 || sem_init(&ping_res_sem, 0, 1) == -1 || sem_init(&iperf_tx_sem, 0, 1) == -1 ||
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

    pthread_mutex_t *ring_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (pthread_mutex_init(ring_lock, NULL) != 0)
    {
        printf("Failed to init mutex!\r\n");
        goto err_ring_lock;
    }

    ring_buf = ring_buf_init(recv_buf, NCP_BRIDGE_RING_BUFFER_SIZE_ALIGN, ring_lock);
    if (!ring_buf)
    {
        printf("Failed to init ring buffer!\r\n");
        goto err_ring_buf_init;
    }

    recv_data.data_buf = ring_buf;

    send_thread = pthread_create(&send_thread, NULL, (void *)wifi_ncp_handle_input_task, (void *)&send_data);
    if (send_thread != 0)
    {
        printf("Failed to creat Send Thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to creat Send Thread!\r\n");

    ping_sock_thread = pthread_create(&ping_sock_thread, NULL, (void *)ping_sock_task, (void *)&send_data);
    if (ping_sock_thread != 0)
    {
        printf("Failed to creat Ping Socket Thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to creat Ping Socket Thread!\r\n");

    iperf_tx_thread = pthread_create(&iperf_tx_thread, NULL, (void *)iperf_tx_task, (void *)&send_data);
    if (iperf_tx_thread != 0)
    {
        printf("Failed to creat iperf_tx_thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to creat iperf_tx_thread!\r\n");

    iperf_rx_thread = pthread_create(&iperf_rx_thread, NULL, (void *)iperf_rx_task, (void *)&recv_data);
    if (iperf_rx_thread != 0)
    {
        printf("Failed to creat iperf_rx_thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to creat iperf_rx_thread!\r\n");

    if (mpu_bridge_init_cli_commands() != TRUE)
    {
        printf("Failed to register MPU Bridge app cli commands!\r\n");
        goto err_init;
    }

    printf("You can input these commands:\r\n");
    printf("================================\r\n");
    help_command(0, NULL);
    printf("================================\r\n");
    while (1)
    {
        usleep(100000);
    }
#if 0
    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);
    pthread_join(process_thread, NULL);
    pthread_join(ping_sock_thread, NULL);
#endif
err_init:
    ring_buf_free(ring_buf);
err_ring_buf_init:
    free(ring_lock);
err_ring_lock:
    msgctl(ping_qid, IPC_RMID, NULL);
err_get_ping_qid:
    sem_destroy(&cmd_sem);
    sem_destroy(&iperf_tx_sem);
    sem_destroy(&iperf_rx_sem);
    sem_destroy(&ping_res_sem);
err_sem_init:
    wifi_ncp_deinit();
err_ncp_init:
    ncp_adapter_deinit();
err_adapter_init:
    exit(EXIT_FAILURE);

    return TRUE;
}
#endif
