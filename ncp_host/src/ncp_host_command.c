/** @file ncp_host_command.c
 *
 *  Copyright 2020-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ncp_host_app.h"
#include "ncp_host_command.h"
#include "ncp_tlv_adapter.h"

extern uint8_t cmd_buf[NCP_COMMAND_LEN];

static struct mpu_host_commands
{
    const struct mpu_host_cli_command *commands[MPU_HOST_MAX_COMMANDS];
    unsigned int num_commands;
} mpu_host_app_cmd;

static struct mpu_host_cli_command built_ins[] = {
    {"help", NULL, help_command},
};

int mpu_host_register_command(const struct mpu_host_cli_command *command)
{
    int i;
    if (!command->name || !command->function)
        return FALSE;

    if (mpu_host_app_cmd.num_commands < MPU_HOST_MAX_COMMANDS)
    {
        /* Check if the command has already been registered.
         * Return TURE, if it has been registered.
         */
        for (i = 0; i < mpu_host_app_cmd.num_commands; i++)
        {
            if (mpu_host_app_cmd.commands[i] == command)
                return TRUE;
        }
        mpu_host_app_cmd.commands[mpu_host_app_cmd.num_commands++] = command;
        return TRUE;
    }

    return FALSE;
}

int mpu_host_unregister_command(const struct mpu_host_cli_command *command)
{
    int i;
    if (!command->name || !command->function)
        return FALSE;

    for (i = 0; i < mpu_host_app_cmd.num_commands; i++)
    {
        if (mpu_host_app_cmd.commands[i] == command)
        {
            mpu_host_app_cmd.num_commands--;
            int remaining_cmds = mpu_host_app_cmd.num_commands - i;
            if (remaining_cmds > 0)
            {
                (void)memmove(&mpu_host_app_cmd.commands[i], &mpu_host_app_cmd.commands[i + 1],
                              (remaining_cmds * sizeof(struct mpu_host_cli_command *)));
            }
            mpu_host_app_cmd.commands[mpu_host_app_cmd.num_commands] = NULL;
            return TRUE;
        }
    }

    return FALSE;
}

int mpu_host_register_commands(const struct mpu_host_cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
        if (mpu_host_register_command(commands++) != 0)
            return FALSE;
    return TRUE;
}

int mpu_host_unregister_commands(const struct mpu_host_cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
        if (mpu_host_unregister_command(commands++) != 0)
            return FALSE;

    return TRUE;
}

int mpu_host_init_cli_commands()
{
    if (mpu_host_register_commands(built_ins,
            sizeof(built_ins) / sizeof(struct mpu_host_cli_command)) != 0)
        return FALSE;

    return TRUE;
}

int mpu_host_deinit_cli_commands()
{
    if (mpu_host_unregister_commands(built_ins,
            sizeof(built_ins) / sizeof(struct mpu_host_cli_command)) != 0)
        return FALSE;

    return TRUE;
}

void clear_mpu_host_command_buffer()
{
    memset(cmd_buf, 0, NCP_COMMAND_LEN);
}


int help_command(int argc, char **argv)
{
    int i, n;

    (void)printf("\r\n");
    for (i = 0, n = 0; i < MPU_HOST_MAX_COMMANDS && n < mpu_host_app_cmd.num_commands; i++)
    {
        if (mpu_host_app_cmd.commands[i]->name != NULL)
        {
            printf("%s %s\r\n", mpu_host_app_cmd.commands[i]->name,
                   mpu_host_app_cmd.commands[i]->help ? mpu_host_app_cmd.commands[i]->help : "");
            n++;
        }
    }

    return TRUE;
}



/* Find the command 'name' in the mpu ncp host app commands table.
 * If len is 0 then full match will be performed else upto len bytes.
 * Returns: a pointer to the corresponding bridge_cli_command struct or NULL.
 */
const struct mpu_host_cli_command *lookup_command(char *name, int len)
{
    int i = 0;
    int n = 0;

    while (i < MPU_HOST_MAX_COMMANDS && n < mpu_host_app_cmd.num_commands)
    {
        if (mpu_host_app_cmd.commands[i]->name == NULL)
        {
            i++;
            continue;
        }
        /* See if partial or full match is expected */
        if (len != 0)
        {
            if (!strncmp(mpu_host_app_cmd.commands[i]->name, name, len))
                return mpu_host_app_cmd.commands[i];
        }
        else
        {
            if (!strcmp(mpu_host_app_cmd.commands[i]->name, name))
                return mpu_host_app_cmd.commands[i];
        }

        i++;
        n++;
    }

    return NULL;
}

