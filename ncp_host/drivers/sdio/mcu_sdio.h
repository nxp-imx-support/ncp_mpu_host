/** @file mcu_sdio.h
 *
 * @brief This file contains definitions for SDIO interface.
 * driver.
 *
 *
 *  Copyright 2022-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 * 
 */

#ifndef _MCU_SDIO_H
#define _MCU_SDIO_H

/* Host Control Registers */
/** Host Control Registers : Host to Card Event */
#define HOST_TO_CARD_EVENT_REG 0x00
/** Host Control Registers : Host terminates Command 53 */
#define HOST_TERM_CMD53 (0x1U << 2)
/** Host Control Registers : Host without Command 53 finish host */
#define HOST_WO_CMD53_FINISH_HOST (0x1U << 2)
/** Host Control Registers : Host power up */
#define HOST_POWER_UP (0x1U << 1)
/** Host Control Registers : Host power down */
#define HOST_POWER_DOWN (0x1U << 0)

/** Host Control Registers : Upload host interrupt RSR */
#define UP_LD_HOST_INT_RSR (0x1U)
#define HOST_INT_RSR_MASK 0xFF

/** Host Control Registers : Upload command port host interrupt status */
#define UP_LD_CMD_PORT_HOST_INT_STATUS (0x40U)
/** Host Control Registers : Download command port host interrupt status */
#define DN_LD_CMD_PORT_HOST_INT_STATUS (0x80U)

/** Host Control Registers : Upload host interrupt mask */
#define UP_LD_HOST_INT_MASK (0x1U)
/** Host Control Registers : Download host interrupt mask */
#define DN_LD_HOST_INT_MASK (0x2U)
/** Host Control Registers : Cmd port upload interrupt mask */
#define CMD_PORT_UPLD_INT_MASK (0x1U << 6)
/** Host Control Registers : Cmd port download interrupt mask */
#define CMD_PORT_DNLD_INT_MASK (0x1U << 7)
/** Enable Host interrupt mask */
#define HIM_ENABLE                                                             \
	(UP_LD_HOST_INT_MASK | DN_LD_HOST_INT_MASK | CMD_PORT_UPLD_INT_MASK |  \
	 CMD_PORT_DNLD_INT_MASK)
/** Disable Host interrupt mask */
#define HIM_DISABLE 0xff

/** Host Control Registers : Upload host interrupt status */
#define UP_LD_HOST_INT_STATUS (0x1U)
/** Host Control Registers : Download host interrupt status */
#define DN_LD_HOST_INT_STATUS (0x2U)

/** Host Control Registers : Download CRC error */
#define DN_LD_CRC_ERR (0x1U << 2)
/** Host Control Registers : Upload restart */
#define UP_LD_RESTART (0x1U << 1)
/** Host Control Registers : Download restart */
#define DN_LD_RESTART (0x1U << 0)

/** Card Control Registers : Command port upload ready */
#define UP_LD_CP_RDY (0x1U << 6)
/** Card Control Registers : Command port download ready */
#define DN_LD_CP_RDY (0x1U << 7)
/** Card Control Registers : Card I/O ready */
#define CARD_IO_READY (0x1U << 3)
/** Card Control Registers : CIS card ready */
#define CIS_CARD_RDY (0x1U << 2)
/** Card Control Registers : Upload card ready */
#define UP_LD_CARD_RDY (0x1U << 1)
/** Card Control Registers : Download card ready */
#define DN_LD_CARD_RDY (0x1U << 0)

/** Card Control Registers : Host power interrupt mask */
#define HOST_POWER_INT_MASK (0x1U << 3)
/** Card Control Registers : Abort card interrupt mask */
#define ABORT_CARD_INT_MASK (0x1U << 2)
/** Card Control Registers : Upload card interrupt mask */
#define UP_LD_CARD_INT_MASK (0x1U << 1)
/** Card Control Registers : Download card interrupt mask */
#define DN_LD_CARD_INT_MASK (0x1U << 0)

/** Card Control Registers : Power up interrupt */
#define POWER_UP_INT (0x1U << 4)
/** Card Control Registers : Power down interrupt */
#define POWER_DOWN_INT (0x1U << 3)

/** Card Control Registers : Power up RSR */
#define POWER_UP_RSR (0x1U << 4)
/** Card Control Registers : Power down RSR */
#define POWER_DOWN_RSR (0x1U << 3)

/** Card Control Registers : SD test BUS 0 */
#define SD_TESTBUS0 (0x1U)
/** Card Control Registers : SD test BUS 1 */
#define SD_TESTBUS1 (0x1U)
/** Card Control Registers : SD test BUS 2 */
#define SD_TESTBUS2 (0x1U)
/** Card Control Registers : SD test BUS 3 */
#define SD_TESTBUS3 (0x1U)

/** Port for registers */
#define REG_PORT 0
/** Port for memory */
#define MEM_PORT 0x10000
/** Card Control Registers : cmd53 new mode */
#define CMD53_NEW_MODE (0x1U << 0)
/** Card Control Registers : cmd53 tx len format 1 (0x10) */
#define CMD53_TX_LEN_FORMAT_1 (0x1U << 4)
/** Card Control Registers : cmd53 tx len format 2 (0x20)*/
#define CMD53_TX_LEN_FORMAT_2 (0x1U << 5)
/** Card Control Registers : cmd53 rx len format 1 (0x40) */
#define CMD53_RX_LEN_FORMAT_1 (0x1U << 6)
/** Card Control Registers : cmd53 rx len format 2 (0x80)*/
#define CMD53_RX_LEN_FORMAT_2 (0x1U << 7)

#define CMD_PORT_RD_LEN_EN (0x1U << 2)
/* Card Control Registers : cmd port auto enable */
#define CMD_PORT_AUTO_EN (0x1U << 0)

/* Command port */
#define CMD_PORT_SLCT 0x8000

/** Misc. Config Register : Auto Re-enable interrupts */
#define AUTO_RE_ENABLE_INT BIT(4)

/** Enable GPIO-1 as a duplicated signal of interrupt as appear of SDIO_DAT1*/
#define ENABLE_GPIO_1_INT_MODE 0x88
/** Scratch reg 3 2  :     Configure GPIO-1 INT*/
#define SCRATCH_REG_32 0xEE

/** Event header Len*/
#define MLAN_EVENT_HEADER_LEN 8

/* define SDIO block size for data Tx/Rx */
/* We support up to 480-byte block size due to FW buffer limitation. */
#define MLAN_SDIO_BLOCK_SIZE 256

typedef struct _sdio_header
{
    uint16_t len;
    uint16_t type;
} sdio_header;

/** Interface header length */
#define SDIO_INTF_HEADER_LEN 4

/** Type data */
#define MLAN_TYPE_DATA 0
/** Type command */
#define MLAN_TYPE_CMD 1
/** Type event */
#define MLAN_TYPE_EVENT 3

typedef struct _mcu_sdio_card_reg {
	u8 start_rd_port;
	u8 start_wr_port;
	u8 base_0_reg;
	u8 base_1_reg;
	u8 poll_reg;
	u8 host_int_enable;
	u8 host_int_status;
	u8 status_reg_0;
	u8 status_reg_1;
	u8 sdio_int_mask;
	u32 data_port_mask;
	u8 max_mp_regs;
	u8 rd_bitmap_l;
	u8 rd_bitmap_u;
	u8 rd_bitmap_1l;
	u8 rd_bitmap_1u;
	u8 wr_bitmap_l;
	u8 wr_bitmap_u;
	u8 wr_bitmap_1l;
	u8 wr_bitmap_1u;
	u8 rd_len_p0_l;
	u8 rd_len_p0_u;
	u8 card_config_2_1_reg;
	u8 cmd_config_0;
	u8 cmd_config_1;
	u8 cmd_config_2;
	u8 cmd_config_3;
	u8 cmd_rd_len_0;
	u8 cmd_rd_len_1;
	u8 cmd_rd_len_2;
	u8 cmd_rd_len_3;
	u8 io_port_0_reg;
	u8 io_port_1_reg;
	u8 io_port_2_reg;
	u8 host_int_rsr_reg;
	u8 host_int_mask_reg;
	u8 host_int_status_reg;
	u8 host_restart_reg;
	u8 card_to_host_event_reg;
	u8 host_interrupt_mask_reg;
	u8 card_interrupt_status_reg;
	u8 card_interrupt_rsr_reg;
	u8 card_revision_reg;
	u8 card_ocr_0_reg;
	u8 card_ocr_1_reg;
	u8 card_ocr_3_reg;
	u8 card_config_reg;
	u8 card_misc_cfg_reg;
	u8 debug_0_reg;
	u8 debug_1_reg;
	u8 debug_2_reg;
	u8 debug_3_reg;
	u32 fw_reset_reg;
	u8 fw_reset_val;
	u8 fw_dnld_offset_0_reg;
	u8 fw_dnld_offset_1_reg;
	u8 fw_dnld_offset_2_reg;
	u8 fw_dnld_offset_3_reg;
	u8 fw_dnld_status_0_reg;
	u8 fw_dnld_status_1_reg;
	u8 winner_check_reg;
} mcu_sdio_card_reg;

#endif /* _MCU_SDIO_H */
