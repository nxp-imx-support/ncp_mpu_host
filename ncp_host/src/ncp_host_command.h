/** @file ncp_host_command.h
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_HOST_COMMAND_H__
#define __NCP_HOST_COMMAND_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/times.h>

#define NCP_CMD_HEADER_LEN sizeof(NCP_COMMAND)
#define NCP_TLV_HEADER_LEN sizeof(NCP_TLV_HEADER)

#define NCP_CMD_WLAN   0x00000000
#define NCP_CMD_BLE    0x10000000
#define NCP_CMD_15D4   0x20000000
#define NCP_CMD_MATTER 0x30000000
#define NCP_CMD_SYSTEM 0x40000000

#define GET_MSG_TYPE(cmd)     ((cmd) & 0x000f0000)
#define GET_CMD_CLASS(cmd)    (((cmd)&0xf0000000) >> 28)
#define GET_CMD_SUBCLASS(cmd) (((cmd)&0x0ff00000) >> 20)

#define NCP_CMD_RESULT_OK 0x0000

/*General error*/
#define NCP_CMD_RESULT_ERROR 0x0001
/*MCU device enter low power mode*/
#define NCP_CMD_RESULT_ENTER_SLEEP 0x0006
/*MCU device exit low power mode*/
#define NCP_CMD_RESULT_EXIT_SLEEP 0x0007

#define NCP_MSG_TYPE_CMD   0x00010000
#define NCP_MSG_TYPE_EVENT 0x00020000
#define NCP_MSG_TYPE_RESP  0x00030000

#define MOD_ERROR_START(x) (x << 12 | 0)
/* Globally unique success code */
#define WM_SUCCESS 0

enum wm_errno
{
    /* First Generic Error codes */
    WM_GEN_E_BASE = MOD_ERROR_START(0),
    WM_FAIL,     /* 1 */
    WM_E_PERM,   /* 2: Operation not permitted */
    WM_E_NOENT,  /* 3: No such file or directory */
    WM_E_SRCH,   /* 4: No such process */
    WM_E_INTR,   /* 5: Interrupted system call */
    WM_E_IO,     /* 6: I/O error */
    WM_E_NXIO,   /* 7: No such device or address */
    WM_E_2BIG,   /* 8: Argument list too long */
    WM_E_NOEXEC, /* 9: Exec format error */
    WM_E_BADF,   /* 10: Bad file number */
    WM_E_CHILD,  /* 11: No child processes */
    WM_E_AGAIN,  /* 12: Try again */
    WM_E_NOMEM,  /* 13: Out of memory */
    WM_E_ACCES,  /* 14: Permission denied */
    WM_E_FAULT,  /* 15: Bad address */
    WM_E_NOTBLK, /* 16: Block device required */
    WM_E_BUSY,   /* 17: Device or resource busy */
    WM_E_EXIST,  /* 18: File exists */
    WM_E_XDEV,   /* 19: Cross-device link */
    WM_E_NODEV,  /* 20: No such device */
    WM_E_NOTDIR, /* 21: Not a directory */
    WM_E_ISDIR,  /* 22: Is a directory */
    WM_E_INVAL,  /* 23: Invalid argument */
    WM_E_NFILE,  /* 24: File table overflow */
    WM_E_MFILE,  /* 25: Too many open files */
    WM_E_NOTTY,  /* 26: Not a typewriter */
    WM_E_TXTBSY, /* 27: Text file busy */
    WM_E_FBIG,   /* 28: File too large */
    WM_E_NOSPC,  /* 29: No space left on device */
    WM_E_SPIPE,  /* 30: Illegal seek */
    WM_E_ROFS,   /* 31: Read-only file system */
    WM_E_MLINK,  /* 32: Too many links */
    WM_E_PIPE,   /* 33: Broken pipe */
    WM_E_DOM,    /* 34: Math argument out of domain of func */
    WM_E_RANGE,  /* 35: Math result not representable */

    /* WMSDK generic error codes */
    WM_E_CRC,     /* 36: Error in CRC check */
    WM_E_UNINIT,  /* 37: Module is not yet initialized */
    WM_E_TIMEOUT, /* 38: Timeout occurred during operation */

    /* Defined for Hostcmd specific API*/
    WM_E_INBIG,   /* 39: Input buffer too big */
    WM_E_INSMALL, /* 40: A finer version for WM_E_INVAL, where it clearly specifies that input is much smaller than
                     minimum requirement */
    WM_E_OUTBIG,  /* 41: Data output exceeds the size provided */
};

#pragma pack(1)

typedef struct _NCP_COMMAND
{
    /*bit0 ~ bit15 cmd id  bit16 ~ bit23 cmd subclass bit24 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t rsvd;
} NCP_COMMAND, NCP_RESPONSE;

typedef struct TLVTypeHeader_t
{
    uint16_t type;
    uint16_t size;
} TypeHeader_t, NCP_TLV_HEADER;

/** Structure for registering CLI commands */
struct mpu_host_cli_command
{
    /** The name of the CLI command */
    const char *name;
    /** The help text associated with the command */
    const char *help;
    /** The function that should be invoked for this command. */
    int (*function)(int argc, char **argv);
};

#pragma pack()

void clear_mpu_host_command_buffer();

int mpu_host_init_cli_commands();
int mpu_host_deinit_cli_commands();

const struct mpu_host_cli_command *lookup_command(char *name, int len);

/** Register a mpu ncp host cli command
 *
 * This function registers a command with the command-line interface.
 *
 * \param[in] command The structure to register one mpu ncp host cli command
 * \return TRUE on success
 * \return FALSE on failure
 */
int mpu_host_register_command(const struct mpu_host_cli_command *command);

/** Unregister a mpu ncp host cli command
 *
 * This function unregisters a command from the command-line interface.
 *
 * \param[in] command The structure to unregister one mpu ncp host cli command
 * \return TRUE on success
 * \return FALSE on failure
 */
int mpu_host_unregister_command(const struct mpu_host_cli_command *command);

/** Register a batch of mpu ncp host cli commands
 *
 * Often, a module will want to register several commands.
 *
 * \param[in] commands Pointer to an array of commands.
 * \param[in] num_commands Number of commands in the array.
 * \return TRUE on success
 * \return FALSE on failure
 */
int mpu_host_register_commands(const struct mpu_host_cli_command *commands, int num_commands);

/** Unregister a batch of mpu ncp host cli commands
 *
 * \param[in] commands Pointer to an array of commands.
 * \param[in] num_commands Number of commands in the array.
 * \return TRUE on success
 * \return FLASE on failure
 */
int mpu_host_unregister_commands(const struct mpu_host_cli_command *commands, int num_commands);

/* Built-in "help" command: prints all registered commands and their help
 * text string, if any. */
int help_command(int argc, char **argv);


#endif /*__NCP_HOST_COMMAND_H__*/
