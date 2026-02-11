/** @file spi_master.h
 *
 *  @brief This file provides  mpu ncp host spi interfaces
 *
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NCP_INTF_SPI_MASTER_H__
#define __NCP_INTF_SPI_MASTER_H__

#define SPI_DEV_PATH           "/dev/spidev1.0"
#define GPIO_DEV_PATH          "/dev/gpiochip4"

#define MAX_TRANSFER_COUNT     1024
#define NCP_SPI_MASTER_CLOCK   25000000U

/*******************************************************************************
 * API
 ******************************************************************************/
typedef enum
{
    NCP_MASTER_SPI_IDLE = 0,
    NCP_MASTER_SPI_TX,
    NCP_MASTER_SPI_RX,
    NCP_MASTER_SPI_DROP_SLAVE_TX,
    NCP_MASTER_SPI_END,
} ncp_state;

typedef enum
{
    GPIO_RX_SIGNAL = 1,
    GPIO_RX_READY_SIGNAL,
    GPIO_RX_END,
} gpio_signal_type;

int ncp_host_spi_init(void);
void ncp_host_spi_deinit(void);
int ncp_host_spi_master_tx(uint8_t *buff, uint16_t data_size);
int ncp_host_spi_master_rx(uint8_t *buff, size_t *tlv_sz);

typedef struct _gpio_signal_msg
{
    uint8_t msg_type;
} spi_gpio_signal_msg_t;

#pragma pack(1)
typedef struct _ncp_spi_hs_rx_header
{
    uint16_t direct;
} ncp_spi_hs_tx_header;

typedef struct _ncp_spi_hs_tx_header
{
    uint32_t crc;
} ncp_spi_hs_rx_header;
#pragma pack()

#define NCP_SPI_SEND 0x9b
#define NCP_SPI_RECV 0xb9
#define NCP_SPI_CRC  0x5a5b9a9b

#define NCP_SPI_IN_TRANSFERING     0x5a5a
#define NCP_SPI_NOT_IN_TRANSFERING 0xb5b5


#define NCP_SPI_RX_READY_SIG_QUEUE_NAME "/ncp_system_spi_rx_ready_sig_queue"
#define NCP_SPI_RX_SIG_QUEUE_NAME "/ncp_system_spi_rx_sig_queue"

#endif /* __NCP_INTF_SPI_MASTER_H__ */

