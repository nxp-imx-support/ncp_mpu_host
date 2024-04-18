/** @file mpu_bridge_app.c
 *
 *  @brief This file provides  mpu bridge interfaces
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
#include <mpu_bridge_app.h>
#include <mpu_bridge_command.h>
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

ring_buffer_t *ring_buf = NULL;

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

/* service variables */
#if defined(CONFIG_NCP_HTS) || defined(CONFIG_NCP_HTC) || defined(CONFIG_NCP_HRS) || defined(CONFIG_NCP_HRC) || defined(CONFIG_NCP_BAS)
send_data_t *service_S_D = NULL;
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

pthread_mutex_t gpio_wakeup_mutex = PTHREAD_MUTEX_INITIALIZER;
extern power_cfg_t global_power_config;
extern uint8_t mpu_device_status;

#define NCP_RX_QUEUE_NAME "/ncp_rx_queue"
static pthread_t ble_ncp_tlv_rx_thread;
static mqd_t ble_ncp_tlv_rx_msgq_handle;
static pthread_mutex_t ble_ncp_tlv_rx_queue_mutex;
static pthread_mutex_t ble_ncp_tlv_rx_thread_mutex;
static int ble_ncp_tlv_rx_queue_len = 0;

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
                ble_process_ncp_event(resp_buf);
            else
            {
                ble_process_response(resp_buf);

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
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);
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
static void ble_ncp_handle_input_task(void *arg)
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
#if defined(CONFIG_NCP_HTS) || defined(CONFIG_NCP_HTC) || defined(CONFIG_NCP_HRS) || defined(CONFIG_NCP_HRC) || defined(CONFIG_NCP_BAS)
                if (service_S_D == NULL)
                {
                    service_S_D = (send_data_t *)arg;
                }
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
                            //TODO: Toggle output GPIO to wakeup NCP device
                            pthread_mutex_unlock(&mutex);
                            pthread_mutex_lock(&gpio_wakeup_mutex);
							//TODO: Reset output GPIO level
                            pthread_mutex_unlock(&gpio_wakeup_mutex);
                            pthread_mutex_lock(&mutex);
                        }
                    }
                    send_tlv_command(S_D);
                }
            }
            pthread_mutex_unlock(&mutex);
        }
        usleep(10);
    }

    pthread_exit(NULL);
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
    uint16_t msg_type = 0;

#ifdef CONFIG_MPU_IO_DUMP
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)cmd;
    int recv_resp_length = cmd_res->header.size;
    printf("%s: recv_resp_length = %d\r\n", __FUNCTION__, recv_resp_length);
    mpu_dump_hex((uint8_t *)cmd_res, recv_resp_length);
#endif

    msg_type = ((NCP_BRIDGE_COMMAND *)cmd)->msg_type;
    if (msg_type == NCP_BRIDGE_MSG_TYPE_EVENT)
        ble_process_ncp_event(cmd);
    else
    {
        ble_process_response(cmd);

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

int ble_ncp_init()
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
    ble_ncp_tlv_rx_msgq_handle = mq_open(NCP_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);
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

    ncp_tlv_install_handler(NCP_BRIDGE_CMD_BLE >> 24, (void *)ble_ncp_callback);
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

int ble_ncp_deinit()
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
    mq_unlink(NCP_RX_QUEUE_NAME);

    if (pthread_mutex_destroy(&ble_ncp_tlv_rx_thread_mutex) != 0)
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
int main(int argc, char **argv)
{
    pthread_t send_thread;
#ifdef CONFIG_NCP_HTC
    pthread_t htc_client_thread;
#endif
#ifdef CONFIG_NCP_HRC
    pthread_t hrc_client_thread;
#endif
    //recv_data_t recv_data;
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

    if (ble_ncp_init() != NCP_STATUS_SUCCESS)
    {
        printf("ble_ncp_init failed!\r\n");
        goto err_ncp_init;
    }

    if (sem_init(&cmd_sem, 0, 1) == -1)
    {
        printf("Failed to init semaphore!\r\n");
		goto err_sem_init;
    }
#if defined(CONFIG_NCP_HTC)
    if (sem_init(&htc_sem, 0, 1) == -1)
    {
        printf("Failed to init service semaphore!\r\n");
        goto err_sem_init;
    }
    sem_wait(&htc_sem);
#endif
#if defined(CONFIG_NCP_HRC)
    if (sem_init(&hrc_sem, 0, 1) == -1)
    {
        printf("Failed to init service semaphore!\r\n");
        goto err_sem_init;
    }
    sem_wait(&hrc_sem);
#endif
    pthread_mutex_t *ring_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (pthread_mutex_init(ring_lock, NULL) != 0)
    {
        printf("Failed to init mutex!\r\n");
        //goto err_ring_lock;
		exit(EXIT_FAILURE);
    }

    ring_buf = ring_buf_init(recv_buf, NCP_BRIDGE_RING_BUFFER_SIZE_ALIGN, ring_lock);
    if (!ring_buf)
    {
        printf("Failed to init ring buffer!\r\n");
        goto err_ring_buf_init;
    }

    //recv_data.data_buf = ring_buf;

    send_thread = pthread_create(&send_thread, NULL, (void *)ble_ncp_handle_input_task, (void *)&send_data);
    if (send_thread != 0)
    {
        printf("Failed to create Send Thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to create Send Thread!\r\n");

#ifdef CONFIG_NCP_HTC
    htc_client_thread = pthread_create(&htc_client_thread, NULL, (void *)central_htc_task, (void *)&send_data);
    if (htc_client_thread != 0)
    {
        printf("Failed to creat  htc clinet Thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to creat htc clinet Thread!\r\n");
#endif

#ifdef CONFIG_NCP_HRC
    hrc_client_thread = pthread_create(&hrc_client_thread, NULL, (void *)central_hrc_task, (void *)&send_data);
    if (hrc_client_thread != 0)
    {
        printf("Failed to create  hrc client Thread!\r\n");
        goto err_init;
    }
    else
        printf("Success to create hrc client Thread!\r\n");
#endif

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

    pthread_join(send_thread, NULL);
#if 0
    pthread_join(recv_thread, NULL);
    pthread_join(process_thread, NULL);
#endif

    sem_destroy(&cmd_sem);
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
err_init:
    ring_buf_free(ring_buf);
err_ring_buf_init:
    free(ring_lock);
err_sem_init:
    ble_ncp_deinit();
err_ncp_init:
    ncp_adapter_deinit();
err_adapter_init:
    exit(EXIT_FAILURE);

    return TRUE;
}
