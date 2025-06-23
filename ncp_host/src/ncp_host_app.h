/** @file ncp_host_app.h
 *
 *  @brief This file provides  mpu ncp host interfaces
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include <semaphore.h>

#define NCP_MPU_HOST_VERSION v1.r1.p1

#define FALSE             -1
#define TRUE              0
#define MAX_SEND_RECV_LEN 400

#define MPU_HOST_INBUF_SIZE   400
#define MPU_HOST_MAX_COMMANDS 500

#define NCP_COMMAND_LEN             4096 // The max number bytes which UART can receive.
#define NCP_RESPONSE_LEN            4096
#define NCP_CMD_SIZE_LOW_BYTES      4
#define NCP_CMD_SIZE_HIGH_BYTES     5
#define NCP_CMD_SEQUENCE_LOW_BYTES  6
#define NCP_CMD_SEQUENCE_HIGH_BYTES 7

#define MPU_DUMP_WRAPAROUND 16

#define CRC32_POLY   0x04c11db7
#define CHECKSUM_LEN 4

#define mpu_in_range(c, lo, up) ((uint8_t)(c) >= (lo) && (uint8_t)(c) <= (up))
#define mpu_isdigit(c)          mpu_in_range((c), '0', '9')
#define mpu_islower(c)          mpu_in_range((c), 'a', 'z')
#define mpu_isupper(c)          mpu_in_range((c), 'A', 'Z')

/** Find minimum */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/** Find maximum */
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define CHAR2INT(x) (('0' <= x && x <= '9') ? \
    (x - '0') : \
    (('a' <= x && x <= 'f') ? \
        (10 + (x - 'a')) : \
        (('A' <= x && x <= 'F') ? (10 + (x - 'A')) : (0))))

/*! @brief Computes the number of elements in an array. */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define NCP_RING_BUFFER_SIZE 4096
/* Note: the actual allocated space is subject to NCP_RING_BUFFER_SIZE_ALIGN, so round
 * NCP_RING_BUFFER_SIZE up to a power of 2.*/
#define _ALIGN                            8
#define NCP_RING_BUFFER_SIZE_ALIGN ((NCP_RING_BUFFER_SIZE + (_ALIGN - 1)) & ~(_ALIGN - 1))
#define min(a, b)                         (((a) < (b)) ? (a) : (b))

#define ICMP_ECHO             8 /* echo */
#define IP_HEADER_LEN         20
#define PING_RECVFROM_TIMEOUT 2000

typedef struct _ring_buffer
{
    void *buffer;            /* ring buffer */
    uint32_t size;           /* buffer size*/
    uint32_t head;           /* ring buffer head*/
    uint32_t tail;           /* ring buffer tail*/
    pthread_mutex_t *f_lock; /* mutex */
} ring_buffer_t;

typedef struct serial_data_send
{
    uint8_t *data_buf;
    int serial_fd;
} send_data_t;

typedef struct serial_data_recv
{
    ring_buffer_t *data_buf;
    int serial_fd;
} recv_data_t;

void send_tlv_command(send_data_t *S_D);

#ifdef CONFIG_MATTER_NCP
/**
 * @brief        The main function of ncp-host provided to MATTER
 *
 * @param argc   argc
 * @param argv   argv
 * @return       TRUE
 */
int ncp_host_main();
#endif

int string_equal(const char *s1, const char *s2);

/**
 * @brief       This function convters string to decimal number.
 */
int get_uint(const char *arg, unsigned int *dest, unsigned int len);

/*
 * @brief convert String to integer
 *
 *@param value        A pointer to string
 *@return             integer
 **/
uint32_t a2hex_or_atoi(char *value);

/**
 *@brief convert string to hex integer
 *
 *@param s            A pointer string buffer
 *@return             hex integer
 **/
uint32_t a2hex(const char *s);

/**
 *@brief convert char to hex integer
 *
 *@param chr          char
 *@return             hex integer
 **/
uint8_t hexc2bin(char chr);

/* Parse string 'arg' formatted "AA:BB:CC:DD:EE:FF" (assuming 'sep' is ':')
 * into a 6-byte array 'dest' such that dest = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}
 * set 'sep' accordingly. */
int get_mac(const char *arg, char *dest, char sep);

/*Dump buffer in hex format on console.*/
void mpu_dump_hex(const void *data, unsigned int len);

extern ring_buffer_t *ring_buf;
extern sem_t cmd_sem;

