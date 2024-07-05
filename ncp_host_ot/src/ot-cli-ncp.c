/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */
#include "ncp_adapter.h"
#include "ncp_intf_uart.h"
#include "ncp_tlv_adapter.h"
#include "otopcode.h"
#include "uart.h"

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

/* -------------------------------------------------------------------------- */
/*                           Function prototypes                              */
/* -------------------------------------------------------------------------- */

static void ot_ncp_mainloop(void);
static void ot_ncp_send_command(uint8_t *userinputcmd, uint8_t userinputcmd_len);

/* -------------------------------------------------------------------------- */
/*                              Private Functions                             */
/* -------------------------------------------------------------------------- */

/*Callback function for ot*/
static void ot_ncp_callback(void *tlv, size_t tlv_sz, int status)
{
    /*Receive the tvl message, store it, and return the handle.*/
    pthread_mutex_lock(&main_mutex);
    recv_item.response_sz = tlv_sz;
    recv_item.recv_buf    = (uint8_t *)malloc(tlv_sz + 1); /*Plus one for a null character*/

    if (recv_item.recv_buf == NULL)
    {
        ncp_adap_e("failed to allocate memory for the received response");
        return;
    }

    memcpy(recv_item.recv_buf, tlv, tlv_sz); /*Last item of recv_item.recv_buf will empty to put null character */
    g_rx = 1;
    pthread_mutex_unlock(&main_mutex);

    return;
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
        /*Receive command from user*/
        if (command_is_pending == 0)
        {
            /*User has not sent command yet.*/

            scanf("%c", &tempcharc);

            if (tempcharc == '\n')
            {
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

        /*If command is already sent, display everything you are receiving*/
        else
        {
            /*check if we need to send anything in the buffer ?*/

            if (g_rx == 1)
            {
                pthread_mutex_lock(&main_mutex);
                for (int i = 0; i < (recv_item.response_sz - NCP_TLV_HDR_LEN); i++)
                {
                    if (*(recv_item.recv_buf + NCP_TLV_HDR_LEN + i) == 0x3E) /*0x3E indicates ">" character*/
                    {
                        response_completed = 1;
                        break;
                    }
                }

                *(recv_item.recv_buf + recv_item.response_sz) = '\0';
                printf("%s", (recv_item.recv_buf + NCP_TLV_HDR_LEN));
                free(recv_item.recv_buf);
                g_rx = 0;
                pthread_mutex_unlock(&main_mutex);

                if (response_completed == 1)
                {
                    command_is_pending = 0;
                    response_completed = 0;
                }
            }
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

    ncp_tlv_send(cmd_buf, total_len);
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
    }

    /*Thread/Mutex initialization*/
    pthread_mutex_init(&main_mutex, NULL);

    /*Install tlv handler fo ot*/
    ncp_tlv_install_handler(NCP_TLV_CMD_CLASS, (void *)ot_ncp_callback);

    printf("> ");

    /*Call main task*/
    ot_ncp_mainloop();

    return;
}
