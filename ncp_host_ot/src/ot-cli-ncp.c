/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */
#include <semaphore.h>
#include "ncp_adapter.h"
#include "ncp_intf_uart.h"
#include "ncp_tlv_adapter.h"
#include "otopcode.h"
#include "uart.h"
#include "lpm.h"
#include "mbedtls_host.h"
#include "ncp_system_command.h"
#include "ot_redefined_cmds.h"

/* -------------------------------------------------------------------------- */
/*                              Constants                                     */
/* -------------------------------------------------------------------------- */

#define NCP_TLV_CMD_TYPE 0X01
#define NCP_TLV_CMD_CLASS 0X02
#define NCP_TLV_CMD_SUBCLASS 0X01
#define NCP_TLV_CMD_RESULT 0X00
#define NCP_TLV_CMD_MSGTYPE 0X00

#define NCP_TLV_HDR_LEN 12
#define SPACE_CHARACTER 32
#define OT_OPCODE_SIZE 1

#define INBAND_WAKEUP_PARAM  '0'
#define OUTBAND_WAKEUP_PARAM '1'

#if defined(CONFIG_NCP_UART)
#define UART_WAKEUP_MAGIC (0xABCDEF8987FEDCBAU)
uint64_t uart_wakeup_magic = UART_WAKEUP_MAGIC;
#endif

/* -------------------------------------------------------------------------- */
/*                               Types                                        */
/* -------------------------------------------------------------------------- */

/*NCP command header*/
typedef struct command_header
{
    /*bit0 ~ bit15 cmd id,  bit16 ~ bit19 message type, bit20 ~ bit27 cmd subclass, bit28 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t rsvd;
} NCP_TLV_COMMAND;

typedef struct
{
    uint32_t response_sz;
    uint8_t *recv_buf;
} ncp_response_t;
/* -------------------------------------------------------------------------- */
/*                               Variables                                    */
/* -------------------------------------------------------------------------- */

static volatile uint8_t g_rx = 0; /*will be used to indicate if we have received something to display*/
static ncp_response_t   recv_item;
static pthread_mutex_t  main_mutex;
static uint8_t          command_is_pending;

extern uint8_t ncp_device_status;
extern power_cfg_t global_power_config;
extern pthread_mutex_t gpio_wakeup_mutex;
extern pthread_mutex_t ncp_device_status_mutex;
extern sem_t cmd_sem;

/* -------------------------------------------------------------------------- */
/*                           Function prototypes                              */
/* -------------------------------------------------------------------------- */

static void ot_ncp_mainloop(void);
static void ot_ncp_send_command(uint8_t *userinputcmd, uint8_t userinputcmd_len);
static void ot_ncp_handle_cmd_input(uint8_t *cmd, uint32_t len);

/* -------------------------------------------------------------------------- */
/*                              Private Functions                             */
/* -------------------------------------------------------------------------- */

/*Callback function for ot*/
static void ot_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
    /*Receive the tvl message, store it, and return the handle.*/
    recv_item.response_sz = tlv_sz;
    recv_item.recv_buf    = (uint8_t *)malloc(tlv_sz + 1); /*Plus one for a null character*/

    if (recv_item.recv_buf == NULL)
    {
        ncp_adap_e("failed to allocate memory for the received response");
        return;
    }
    ot_ncp_handle_cmd_input((uint8_t *)tlv, tlv_sz);
    return;
}

static void ot_ncp_mpu_sleep_cfm(NCP_TLV_COMMAND *header)
{
    header->cmd      = NCP_CMD_SYSTEM_POWERMGMT_MCU_SLEEP_CFM;
    header->size     = NCP_TLV_HDR_LEN;
    header->result   = NCP_CMD_RESULT_OK;
}

static int ot_ncp_process_sleep_status(uint8_t *res)
{
    NCP_TLV_COMMAND *event  = (NCP_TLV_COMMAND *)res;
    int          status = 0;

    if (event->cmd == NCP_EVENT_MCU_SLEEP_ENTER)
    {
        NCP_TLV_COMMAND sleep_cfm;

        printf("Get device sleep event, it will enter sleep mode\r\n");
        memset(&sleep_cfm, 0x0, sizeof(sleep_cfm));
        ot_ncp_mpu_sleep_cfm(&sleep_cfm);
        status = (int)ncp_tlv_send((void *)&sleep_cfm, sleep_cfm.size);
        if (status != NCP_STATUS_SUCCESS)
            printf("Failed to send mpu sleep cfm\r\n");
        usleep(100000); // Wait 100ms to make sure NCP device enters low power.
        ncp_device_status = NCP_DEVICE_STATUS_SLEEP;
        pthread_mutex_lock(&gpio_wakeup_mutex);

        pthread_mutex_lock(&ncp_device_status_mutex);
        pthread_mutex_unlock(&ncp_device_status_mutex);
    }
    else
    {
        printf("NCP device exits sleep mode\r\n");
        ncp_device_status = NCP_DEVICE_STATUS_ACTIVE;
        pthread_mutex_unlock(&gpio_wakeup_mutex);
    }

    return NCP_STATUS_SUCCESS;
}

static int ot_system_process_event(uint8_t *res)
{
    int ret = NCP_STATUS_SUCCESS;
    NCP_TLV_COMMAND *evt = (NCP_TLV_COMMAND *)res;

    switch (evt->cmd)
    {
        case NCP_EVENT_MCU_SLEEP_ENTER:
        case NCP_EVENT_MCU_SLEEP_EXIT:
            ret = ot_ncp_process_sleep_status(res);
            break;
#if CONFIG_NCP_USE_ENCRYPT
        case NCP_EVENT_SYSTEM_ENCRYPT:
            ret = ncp_process_encrypt_event(res);
            break;
        case NCP_EVENT_SYSTEM_ENCRYPT_STOP:
            ret = ncp_process_encrypt_stop_event(res);
            break;
#endif
        default:
            printf("Invaild event!\r\n");
            break;
    }
    return ret;
}

static void ot_ncp_handle_cmd_input(uint8_t *cmd, uint32_t len)
{
    uint32_t msg_type = 0;
    int ret = NCP_STATUS_SUCCESS;

    msg_type = GET_MSG_TYPE(((NCP_TLV_COMMAND *)cmd)->cmd);
    if (msg_type == NCP_MSG_TYPE_EVENT)
    {
        ret = ot_system_process_event(cmd);
        if (ret != NCP_STATUS_SUCCESS)
        {
            printf("Failed to parse ncp event.\r\n");
        }
    }
    else
    {
        switch (((NCP_TLV_COMMAND *)cmd)->cmd)
        {
#if CONFIG_NCP_USE_ENCRYPT
            case NCP_RSP_SYSTEM_CONFIG_ENCRYPT:
                ret = ncp_process_encrypt_response(cmd);
                break;
#endif
            default:
                /* output cmd response */
                cmd[len] = '\0';
                printf("%s\r\n", cmd + NCP_TLV_HDR_LEN);
                break;



        }
    }
    /* TODO: release semaphore */
    sem_post(&cmd_sem);
}

/*Main loop function*/
static void ot_ncp_mainloop(void)
{
    /* Main task function should check if user has entered command
     * and check if something is pending to receive (check on the
     * buffer which was filled during call back) from NCP device.*/
    uint8_t user_cmd[256];
    uint8_t input_cmd_length = 0;
    uint8_t tempcharc;
    uint8_t response_completed =
        0; /*To check if we have received ">" character indicating complete execution of command*/

    while (1)
    {

        scanf("%c", &tempcharc);

        if (tempcharc == '\n')
        {
            /* Wait for command response semaphore. */
            sem_wait(&cmd_sem);

            /*User pressed enter*/
            if (input_cmd_length != 0)
            {
                /*Structure the command into tlv format and then send over ncp_tlv_send function*/
                *(user_cmd + input_cmd_length) = '\r'; /* NCP device will check this to start processing command*/
                input_cmd_length++;
                ot_ncp_send_command(user_cmd, input_cmd_length);
                input_cmd_length   = 0;
                command_is_pending = 1; /*Command is sent, wait for response*/
            }
            else
            {
                /*No command entered*/
                printf("> ");
                sem_post(&cmd_sem);
                continue;
            }
        }
        else
        {
            /*Continue reading characters from the user*/
            *(user_cmd + input_cmd_length) = tempcharc;
            input_cmd_length++;
        }
    }

    return;
}

static void ot_ncp_send_command(uint8_t *userinputcmd, uint8_t userinputcmd_len)
{
    uint8_t *cmd_buf   = NULL;
    uint32_t total_len = 0;
    uint8_t  otcommandlen;
    int8_t   opcode;
    uint8_t  wakeup_mode;
#ifdef CONFIG_NCP_SDIO
    NCP_TLV_COMMAND wakeup_buf;
#endif

    // Determine the size of ot command excluding parameters
    for (otcommandlen = 0; otcommandlen < userinputcmd_len; otcommandlen++)
    {
        if (userinputcmd[otcommandlen] == SPACE_CHARACTER || otcommandlen == (userinputcmd_len - 1))
        {
            /* we break either first space is encountered or user just entered a
             * command without any parameters.
             */
            break;
        }
    }

    opcode    = ot_get_opcode(userinputcmd, otcommandlen);
    total_len = (userinputcmd_len - otcommandlen + OT_OPCODE_SIZE) + NCP_TLV_HDR_LEN;

    cmd_buf = (uint8_t *)malloc(total_len);

    if (cmd_buf == NULL)
    {
        ncp_adap_e("failed to allocate memory for command");
        sem_post(&cmd_sem);
        return;
    }

    NCP_TLV_COMMAND *cmd_hdr = (NCP_TLV_COMMAND *)cmd_buf;

    cmd_hdr->cmd      = (NCP_TLV_CMD_CLASS << 28) | (NCP_TLV_CMD_SUBCLASS << 20) | (NCP_TLV_CMD_MSGTYPE << 16) | NCP_TLV_CMD_TYPE;
    cmd_hdr->size     = total_len;
    cmd_hdr->seqnum   = 0x00;
    cmd_hdr->result   = NCP_TLV_CMD_RESULT;
    cmd_hdr->rsvd     = 0;

    if (userinputcmd_len > 0)
    {
        *(cmd_buf + NCP_TLV_HDR_LEN) = opcode;
        memcpy((cmd_buf + NCP_TLV_HDR_LEN + OT_OPCODE_SIZE), (userinputcmd + otcommandlen),
               (userinputcmd_len - otcommandlen));
    }

    /* Before sending ot ncp tlv command to device side, we should wake up device first */
    if (ncp_device_status == NCP_DEVICE_STATUS_SLEEP)
    {
        if (global_power_config.wake_mode == WAKE_MODE_INTF)
        {
            pthread_mutex_lock(&ncp_device_status_mutex);
            while (ncp_device_status != NCP_DEVICE_STATUS_SLEEP)
            {
                usleep(10000); // Wait 10ms to make sure NCP device enters low power.
            }
            pthread_mutex_unlock(&ncp_device_status_mutex);
#if defined(CONFIG_NCP_SDIO)
            memset(&wakeup_buf, 0x0, sizeof(NCP_TLV_COMMAND));
            wakeup_buf.size = NCP_TLV_HDR_LEN - 1;
            printf("%s: send wakeup_buf", __FUNCTION__);
            ncp_tlv_send(&wakeup_buf, NCP_TLV_HDR_LEN);
#elif defined(CONFIG_NCP_UART)
            /* Send the magic pattern to wakeup the NCP device */
            ncp_tlv_send(&uart_wakeup_magic, sizeof(uart_wakeup_magic));
            /* Block here to wait for NCP device complete the PM2 exit process */
            pthread_mutex_lock(&gpio_wakeup_mutex);
            /* Release semaphore here to make sure software can get it successfully when receiving sleep enter event for next sleep loop. */
            pthread_mutex_unlock(&gpio_wakeup_mutex);
#endif
        }
        else if (global_power_config.wake_mode == WAKE_MODE_GPIO)
        {
            pthread_mutex_lock(&ncp_device_status_mutex);
            while (ncp_device_status != NCP_DEVICE_STATUS_SLEEP)
            {
                usleep(10000); // Wait 10ms to make sure NCP device enters low power.
            }
            pthread_mutex_unlock(&ncp_device_status_mutex);
            set_lpm_gpio_value(0);
            pthread_mutex_lock(&gpio_wakeup_mutex);
            set_lpm_gpio_value(1);
            pthread_mutex_unlock(&gpio_wakeup_mutex);
        }
    }

    ncp_tlv_send(cmd_buf, total_len);

    if (opcode == ot_get_opcode("ncp-wake-cfg", strlen("ncp-wake-cfg")))
    {
        wakeup_mode = *((uint8_t *)cmd_buf + NCP_TLV_HDR_LEN + 2);

        if (wakeup_mode == INBAND_WAKEUP_PARAM)
        {
            printf("select inband mode to wake up\r\n");
            global_power_config.wake_mode = WAKE_MODE_INTF;
        }
        else if (wakeup_mode == OUTBAND_WAKEUP_PARAM)
        {
            printf("select outband mode to wake up\r\n");
            global_power_config.wake_mode = WAKE_MODE_GPIO;
        }
        else
        {
            printf("select wrong wake up param, please use:\r\n");
            printf("\tncp-wake-cfg 0 --> select inband mode\r\n");
            printf("\tncp-wake-cfg 1 --> select outband mode\r\n");
        }
    }

    free(cmd_buf);

    return;
}

/* -------------------------------------------------------------------------- */
/*                              Public Functions                             */
/* -------------------------------------------------------------------------- */

void main(int argc, char *argv[])
{
    /*NCP adapter init*/
    int ret;

    ret = ncp_adapter_init(argv[1]);

    if (ret != 0)
    {
        printf("ERROR: ncp_adapter_init \n");
        goto err_adapter_init;
    }

    /*Thread/Mutex initialization*/
    pthread_mutex_init(&main_mutex, NULL);

    /*Install tlv handler fo ot*/
    ncp_tlv_install_handler(NCP_TLV_CMD_CLASS, (void *)ot_ncp_callback);

    if (sem_init(&cmd_sem, 0, 1) == -1)
    {
        printf("Failed to init semaphore!\r\n");
        goto err_sem_init;
    }

    printf("> ");

    /*Call main task*/
    ot_ncp_mainloop();

    sem_destroy(&cmd_sem);
err_sem_init:
    ncp_adapter_deinit();
err_adapter_init:
    exit(EXIT_FAILURE);

    return;
}
