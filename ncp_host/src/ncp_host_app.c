/** @file ncp_host_app.c
 *
 *  @brief This file provides  mpu ncp host interfaces
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
#include "ncp_host_app_ble.h"
#include "ncp_host_app_ot.h"
#include "ncp_host_command.h"
#include "ncp_host_command_wifi.h"
#include "ncp_tlv_adapter.h"
#include "lpm.h"

uint8_t input_buf[NCP_COMMAND_LEN];
uint8_t recv_buf[NCP_RING_BUFFER_SIZE_ALIGN];
uint8_t resp_buf[NCP_RESPONSE_LEN];
uint8_t cmd_buf[NCP_COMMAND_LEN];
uint8_t temp_buf[NCP_RESPONSE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
uint16_t sequence_number = 1;
/** command semaphore*/
sem_t cmd_sem;
uint32_t last_resp_rcvd, last_cmd_sent;

/* ble service variables */
#if defined(CONFIG_NCP_HTS) || defined(CONFIG_NCP_HTC) || defined(CONFIG_NCP_HRS) || defined(CONFIG_NCP_HRC) || defined(CONFIG_NCP_BAS)
send_data_t *service_S_D = NULL;
#endif

pthread_mutex_t gpio_wakeup_mutex = PTHREAD_MUTEX_INITIALIZER;
extern power_cfg_t global_power_config;
extern uint8_t mpu_device_status;

#if defined(CONFIG_NCP_BLE)
extern int mpu_host_init_cli_commands_ble();
extern int mpu_host_deinit_cli_commands_ble();
#endif

void bzero(void *s, size_t n);
int usleep();


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
        /* In the mpu ncp host app, the ring buffer uses a static array,
         * so there is no need to release ring_buf->buffer,
         * otherwise it needs to be released.
         */
        free(ring_buf);
        ring_buf = NULL;
    }
}

/* Parse string 'arg' formatted "AA:BB:CC:DD:EE:FF" (assuming 'sep' is ':')
 * into a 6-byte array 'dest' such that dest = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}
 * set 'sep' accordingly. */
int get_mac(const char *arg, char *dest, char sep)
{
    unsigned char n;
    int i, j, k;

    if (strlen(arg) < 17)
        return 1;

    (void)memset(dest, 0, 6);

    for (i = 0, k = 0; i < 17; i += 3, k++)
    {
        for (j = 0; j < 2; j++)
        {
            if (arg[i + j] >= '0' && arg[i + j] <= '9')
                n = arg[i + j] - '0';
            else if (arg[i + j] >= 'A' && arg[i + j] <= 'F')
                n = arg[i + j] - 'A' + 10;
            else if (arg[i + j] >= 'a' && arg[i + j] <= 'f')
                n = arg[i + j] - 'a' + 10;
            else
                return 1;

            n <<= 4 * (1 - j);
            dest[k] += n;
        }
        if (i < 15 && arg[i + 2] != sep)
            return 1;
    }

    return 0;
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
    const struct mpu_host_cli_command *command = NULL;
    const char *p;
    int ret = FALSE;

    (void)memset((void *)&argv, 0, sizeof(argv));
    (void)memset(&stat, 0, sizeof(stat));

    /*
     * Some terminals add CRLF to the input buffer.
     * Sometimes the CR and LF characters maybe misplaced (it maybe added at the
     * start or at the end of the buffer). Therefore, strip all CRLF (0x0d, 0x0a).
     */
    for (j = 0; j < MPU_HOST_INBUF_SIZE; j++)
    {
        if (inbuf[j] == 0x0D || inbuf[j] == 0x0A)
        {
            if (j < (MPU_HOST_INBUF_SIZE - 1))
                (void)memmove((inbuf + j), inbuf + j + 1, (MPU_HOST_INBUF_SIZE - j));
            inbuf[MPU_HOST_INBUF_SIZE] = 0x00;
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
    } while (!stat.done && ++i < MPU_HOST_INBUF_SIZE);

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

    Datalen = (temp_cmd[NCP_CMD_SIZE_HIGH_BYTES] << 8) | temp_cmd[NCP_CMD_SIZE_LOW_BYTES];
    ncp_adap_d("%s Enter: cmd_buf=%p Datalen=%d", __FUNCTION__, cmd_buf, Datalen);
    if ((0 == Datalen) || (Datalen > NCP_COMMAND_LEN))
    {
        printf("%s: Invalid Datalen=%d!\r\n", __FUNCTION__, Datalen);
#ifdef CONFIG_MPU_IO_DUMP
        mpu_dump_hex(cmd_buf, 64);
#endif
        ret = FALSE;
        goto out_clear;
    }

    temp_cmd[NCP_CMD_SEQUENCE_LOW_BYTES]  = (sequence_number & 0xFF);
    temp_cmd[NCP_CMD_SEQUENCE_HIGH_BYTES] = (sequence_number >> 8) & 0xFF;

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
    clear_mpu_host_command_buffer();
#if 0
    if (NCP_CMD_SYSTEM_CONFIG_SDIO_SET == last_cmd_sent)
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
 * @brief        Handle cli commands and send tlv commands to ncp device.
 *
 * @param arg    arg
 * @return       TRUE
 */
static void ncp_handle_input_task(void *arg)
{
    send_data_t *S_D = (send_data_t *)arg;
    int ret;
    char nul[2];
    nul[0] = '\n'; // only input enter
#ifdef CONFIG_NCP_SDIO
    NCP_COMMAND wakeup_buf;
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
                if(string_equal("help", S_D->data_buf))
                {
                    sem_post(&cmd_sem);
                    continue;
                }
                if (ret != TRUE)
                {
                    printf("Failed to send command. Please input command again.\r\n");
                    clear_mpu_host_command_buffer();
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
                            memset(&wakeup_buf, 0x0, sizeof(NCP_COMMAND));
                            wakeup_buf.size = NCP_CMD_HEADER_LEN - 1;
                            //write(S_D->serial_fd, &wakeup_buf, NCP_CMD_HEADER_LEN);
                            ncp_adap_d("%s: send wakeup_buf", __FUNCTION__);
                            ncp_tlv_send(&wakeup_buf, NCP_CMD_HEADER_LEN);
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

    pthread_exit(NULL);
}


/**
 * @brief        Main function
 *
 * @param argc   argc
 * @param argv   argv
 * @return       TRUE
 */

extern int ncp_system_app_init();
extern int ncp_host_system_command_init();
extern void ncp_system_app_deinit(void);
int main(int argc, char **argv)
{
    pthread_t send_thread;
    recv_data_t recv_data;
    send_data_t send_data;
    send_data.data_buf      = input_buf;
    ring_buffer_t *ring_buf = NULL;

    if (ncp_adapter_init(argv[1]) != NCP_STATUS_SUCCESS)
    {
        printf("ncp_adapter_init failed!\r\n");
        goto err_adapter_init;
    }
	if (ncp_system_app_init() != NCP_STATUS_SUCCESS)
    {
        printf("ncp_adapter_init failed!\r\n");
        goto err_system_init;
    }


#ifdef CONFIG_NCP_WIFI
    if (wifi_ncp_init() != NCP_STATUS_SUCCESS)
    {
        printf("wifi_ncp_init failed!\r\n");
        goto err_wifi_ncp_init;
    }
#endif

#ifdef CONFIG_NCP_BLE
    if (ble_ncp_init() != NCP_STATUS_SUCCESS)
    {
        printf("ble_ncp_init failed!\r\n");
        goto err_ble_ncp_init;
    }
#endif

#ifdef CONFIG_NCP_OT
    if (ot_ncp_init() != NCP_STATUS_SUCCESS)
    {
        printf("ot_ncp_init failed!\r\n");
        goto err_ot_ncp_init;
    }
#endif

    if (sem_init(&cmd_sem, 0, 1) == -1)
    {
        printf("Failed to init semaphore!\r\n");
        goto err_sem_init;
    }

#ifdef CONFIG_NCP_WIFI
    if (wifi_ncp_app_init() != NCP_STATUS_SUCCESS)
    {
        printf("wifi_ncp_app_init failed!\r\n");
        goto err_wifi_ncp_app_init;
    }
#endif

#ifdef CONFIG_NCP_BLE
    if (ble_ncp_app_init() != NCP_STATUS_SUCCESS)
    {
        printf("ble_ncp_app_init failed!\r\n");
        goto err_ble_ncp_app_init;
    }
#endif

    pthread_mutex_t *ring_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (ring_lock == NULL)
    {
        printf("Failed to init mutex!\r\n");
        goto err_malloc_ring_lock;
    }
    if (pthread_mutex_init(ring_lock, NULL) != 0)
    {
        printf("Failed to init mutex!\r\n");
        goto err_ring_lock;
    }

    ring_buf = ring_buf_init(recv_buf, NCP_RING_BUFFER_SIZE_ALIGN, ring_lock);
    if (!ring_buf)
    {
        printf("Failed to init ring buffer!\r\n");
        goto err_ring_buf_init;
    }

    recv_data.data_buf = ring_buf;

    send_thread = pthread_create(&send_thread, NULL, (void *)ncp_handle_input_task, (void *)&send_data);
    if (send_thread != 0)
    {
        printf("Failed to creat Send Thread!\r\n");
        goto err_send_thread;
    }
    else
        printf("Success to creat Send Thread!\r\n");

#ifdef CONFIG_NCP_WIFI
    if (wifi_ncp_app_task_init((void *)&send_data, (void *)&recv_data) != NCP_STATUS_SUCCESS)
    {
        printf("wifi_ncp_init failed!\r\n");
        goto err_wifi_ncp_app_task_init;
    }
#endif

    if (mpu_host_init_cli_commands() != TRUE)
    {
        printf("Failed to register MPU ncp host cli commands!\r\n");
        goto err_init_cli;
    }

    ncp_host_system_command_init();

#ifdef CONFIG_NCP_WIFI
    if (mpu_host_init_cli_commands_wifi() != TRUE)
    {
        printf("Failed to register MPU ncp host app cli commands!\r\n");
        goto err_init_cli_wifi;
    }
#endif

#ifdef CONFIG_NCP_BLE
    if (mpu_host_init_cli_commands_ble() != TRUE)
    {
        printf("Failed to register MPU ncp host app ble cli commands!\r\n");
        goto err_init_cli_ble;
    }
#endif

#ifdef CONFIG_NCP_OT
    if (mpu_host_init_cli_commands_ot() != TRUE)
    {
        printf("Failed to register MPU ncp host app ot cli commands!\r\n");
        goto err_init_cli_ot;
    }
#endif

    printf("You can input these commands:\r\n");
    printf("================================\r\n");
    help_command(0, NULL);
    printf("================================\r\n");
    while (1)
    {
        usleep(100000);
    }

#ifdef CONFIG_NCP_WIFI
err_init_cli_wifi:
    mpu_host_deinit_cli_commands_wifi();
#endif
#ifdef CONFIG_NCP_BLE
err_init_cli_ble:
    mpu_host_deinit_cli_commands_ble();
#endif
#ifdef CONFIG_NCP_OT
err_init_cli_ot:
    mpu_host_deinit_cli_commands_ot();
#endif
err_init_cli:
    mpu_host_deinit_cli_commands();
#ifdef CONFIG_NCP_WIFI
    wifi_ncp_app_task_deinit();
#endif
#ifdef CONFIG_NCP_WIFI
err_wifi_ncp_app_task_init:
#endif
    pthread_join(send_thread, NULL);
err_send_thread:
    ring_buf_free(ring_buf);
err_ring_buf_init:
err_ring_lock:
    free(ring_lock);
err_malloc_ring_lock:
#ifdef CONFIG_NCP_WIFI
    wifi_ncp_app_deinit();
#endif
#ifdef CONFIG_NCP_BLE
    ble_ncp_app_deinit();
#endif
#ifdef CONFIG_NCP_WIFI
err_wifi_ncp_app_init:
#endif
#ifdef CONFIG_NCP_BLE
err_ble_ncp_app_init:
#endif
    sem_destroy(&cmd_sem);
err_sem_init:
#ifdef CONFIG_NCP_WIFI
    wifi_ncp_deinit();
#endif
#ifdef CONFIG_NCP_BLE
    ble_ncp_deinit();
#endif
#ifdef CONFIG_NCP_OT
    ot_ncp_deinit();
#endif
#ifdef CONFIG_NCP_WIFI
err_wifi_ncp_init:
#endif
#ifdef CONFIG_NCP_BLE
err_ble_ncp_init:
#endif
#ifdef CONFIG_NCP_OT
err_ot_ncp_init:
#endif
    ncp_system_app_deinit();
err_system_init:
    ncp_adapter_deinit();
err_adapter_init:
    exit(EXIT_FAILURE);

    return TRUE;
}

