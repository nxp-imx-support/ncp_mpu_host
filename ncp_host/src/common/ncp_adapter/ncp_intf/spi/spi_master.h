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


#endif /* __NCP_INTF_SPI_MASTER_H__ */

