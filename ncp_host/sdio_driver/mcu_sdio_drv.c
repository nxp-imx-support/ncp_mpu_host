/*
 *  Copyright 2022-2024 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#define MCU_SDIO_VERSION	"0.1"

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/circ_buf.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sd.h>
#include <linux/mmc/core.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>

#include "mcu_sdio.h"

#define NXP_VENDOR_ID			0x0471
#define SD_DEVICE_ID_RW610		0x0209

#define MAX_WAIT_TIME			(5000)

#define SDIO_BUFF_ALIGN				(32U)

#define RX_DEVICE_RING_SIZE			64
#define TX_DEVICE_RING_SIZE			64
#define MAX_DATA_PAYLOAD_SIZE		4096//(4096 + SDIO_INTF_HEADER_LEN)
#define DATA_BUFFER_SIZE				MAX_DATA_PAYLOAD_SIZE//(MAX_DATA_PAYLOAD_SIZE + 4)

#define CMD_RING_SIZE				2
#define EVENT_RING_SIZE				6
#define CMDRSP_EVENT_RING_SIZE		(CMD_RING_SIZE + EVENT_RING_SIZE)
#define MAX_CMD_EVENT_PAYLOAD_SIZE	4096//(4096 + SDIO_INTF_HEADER_LEN)
#define CMD_EVENT_BUFFER_SIZE		MAX_CMD_EVENT_PAYLOAD_SIZE//(MAX_CMD_EVENT_PAYLOAD_SIZE + 4)

#define MAX_DATA_PORT				32

#define RETRY_CNT					1

#define SDIO_SET_RE_ENUM				1
#define SDIO_SET_DIS_INT_IRQ			2
#define SDIO_SET_DIS_INT_IRQ_TEST	3

static u32 drvdbg = 0;

#define PRINT_ERR pr_err
#define PRINT_INFO pr_info
#define PRINT_DEBUG pr_info//pr_debug
#define PRINT_HEXDUMP print_hex_dump

#define PRINT_HEXDUMP_LEVEL KERN_DEBUG //KERN_INFO

/** DEBUG HEX dump */
#define DBG_BIT_DEBUG			BIT(1)
#define DBG_BIT_HEXDUMP			BIT(0)

/** Print hex dump */
#define PRINTM_HEXDUMP(msg...)  do {if (drvdbg & DBG_BIT_HEXDUMP)  PRINT_HEXDUMP(PRINT_HEXDUMP_LEVEL,msg);} while(0)
/** Print hex dump */
#define PRINTM_DEBUG(msg...)  do {if (drvdbg & DBG_BIT_DEBUG)  PRINT_DEBUG(msg);} while(0)


#define GET_MSG_TYPE(cmd)     ((cmd) & 0x000f0000)

/** Find minimum */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/** Find maximum */
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

typedef u64 t_ptr;

/** Macros for Data Alignment : size */
#define ALIGN_SZ(p, a) (((p) + ((a)-1)) & ~((a)-1))

/** Macros for Data Alignment : address */
#define ALIGN_ADDR(p, a)                                                       \
	((((t_ptr)(p)) + (((t_ptr)(a)) - 1)) & ~(((t_ptr)(a)) - 1))

static const struct sdio_device_id mcu_sdio_ids[] = {
	{ SDIO_DEVICE(NXP_VENDOR_ID, SD_DEVICE_ID_RW610) },
	{},
};

static const mcu_sdio_card_reg mcu_reg_rw610 = {
	.start_rd_port = 0,
	.start_wr_port = 0,
	.base_0_reg = 0xf8,
	.base_1_reg = 0xf9,
	.poll_reg = 0x5C,
	.host_int_enable = UP_LD_HOST_INT_MASK | DN_LD_HOST_INT_MASK |
			   CMD_PORT_UPLD_INT_MASK | CMD_PORT_DNLD_INT_MASK,
	.host_int_status = DN_LD_HOST_INT_STATUS | UP_LD_HOST_INT_STATUS |
			   DN_LD_CMD_PORT_HOST_INT_STATUS |
			   UP_LD_CMD_PORT_HOST_INT_STATUS,
	.status_reg_0 = 0xe8,
	.status_reg_1 = 0xe9,
	.sdio_int_mask = 0xff,
	.data_port_mask = 0xffffffff,
	.max_mp_regs = 196,
	.rd_bitmap_l = 0x10,
	.rd_bitmap_u = 0x11,
	.rd_bitmap_1l = 0x12,
	.rd_bitmap_1u = 0x13,
	.wr_bitmap_l = 0x14,
	.wr_bitmap_u = 0x15,
	.wr_bitmap_1l = 0x16,
	.wr_bitmap_1u = 0x17,
	.rd_len_p0_l = 0x18,
	.rd_len_p0_u = 0x19,
	.card_config_2_1_reg = 0xD9,
	.cmd_config_0 = 0xC4,
	.cmd_config_1 = 0xC5,
	.cmd_config_2 = 0xC6,
	.cmd_config_3 = 0xC7,
	.cmd_rd_len_0 = 0xC0,
	.cmd_rd_len_1 = 0xC1,
	.cmd_rd_len_2 = 0xC2,
	.cmd_rd_len_3 = 0xC3,
	.io_port_0_reg = 0xE4,
	.io_port_1_reg = 0xE5,
	.io_port_2_reg = 0xE6,
	.host_int_rsr_reg = 0x04,
	.host_int_mask_reg = 0x08,
	.host_int_status_reg = 0x0C,
	.host_restart_reg = 0x58,
	.card_to_host_event_reg = 0x5C,
	.host_interrupt_mask_reg = 0x60,
	.card_interrupt_status_reg = 0x64,
	.card_interrupt_rsr_reg = 0x68,
	.card_revision_reg = 0xC8,
	.card_ocr_0_reg = 0xD4,
	.card_ocr_1_reg = 0xD5,
	.card_ocr_3_reg = 0xD6,
	.card_config_reg = 0xD7,
	.card_misc_cfg_reg = 0xD8,
	.debug_0_reg = 0xDC,
	.debug_1_reg = 0xDD,
	.debug_2_reg = 0xDE,
	.debug_3_reg = 0xDF,
	.fw_reset_reg = 0x0EE,
	.fw_reset_val = 0x99,
	.fw_dnld_offset_0_reg = 0xEC,
	.fw_dnld_offset_1_reg = 0xED,
	.fw_dnld_offset_2_reg = 0xEE,
	.fw_dnld_offset_3_reg = 0xEF,
	.fw_dnld_status_0_reg = 0xE8,
	.fw_dnld_status_1_reg = 0xE9,
	.winner_check_reg = 0xFC,
};

int g_dev_noblock = 0;
uint32_t g_last_cmd_all = 0;
uint32_t g_last_cmd_app = 0;


struct sdio_buffer {
	char buf[DATA_BUFFER_SIZE + SDIO_BUFF_ALIGN];
	char *buf_align;
	/* size of the buffer in *buf above */
	size_t size;
};

struct sdio_cmd_event_buffer {
	char buf[CMD_EVENT_BUFFER_SIZE + SDIO_BUFF_ALIGN];
	char *buf_align;
	/* size of the buffer in *buf above */
	size_t size;
};

/**
 * struct cmd_ring_buf - CMD ring buffers.
 * @buffer: Queue buffer.
 * @qhead: Head of cmd queue.
 * @qtail: Tail of cmd queue.
 * @rx_lock: Queue lock.
 */
struct cmd_ring_buf {
	struct sdio_cmd_event_buffer buffers[CMD_RING_SIZE];
	unsigned int qhead;
	unsigned int qtail;
	spinlock_t lock;	/* protect access to the queue */
};

/**
 * struct event_ring_buf - EVENT ring buffers.
 * @buffer: Queue buffer.
 * @qhead: Head of event queue.
 * @qtail: Tail of event queue.
 * @rx_lock: Queue lock.
 */
struct cmd_event_ring_buf {
	struct sdio_cmd_event_buffer buffers[CMDRSP_EVENT_RING_SIZE];
	unsigned int qhead;
	unsigned int qtail;
	spinlock_t lock;	/* protect access to the queue */
};

/**
 * struct rx_ring_buf - RX ring buffers.
 * @buffer: Queue buffer.
 * @qhead: Head of rx queue.
 * @qtail: Tail of rx queue.
 * @rx_lock: Queue lock.
 */
struct rx_ring_buf {
	struct sdio_buffer buffers[RX_DEVICE_RING_SIZE];
	unsigned int qhead;
	unsigned int qtail;
	spinlock_t rx_lock;	/* protect access to the queue */
};

/**
 * struct tx_ring_buf - TX ring buffers.
 * @buffer: Queue buffer.
 * @qhead: Head of rx queue.
 * @qtail: Tail of rx queue.
 * @tx_lock: Queue lock.
 */
struct tx_ring_buf {
	struct sdio_buffer buffers[TX_DEVICE_RING_SIZE];
	unsigned int qhead;
	unsigned int qtail;
	spinlock_t tx_lock;	/* protect access to the queue */
};

struct mcu_sdio_misc_priv {
	struct workqueue_struct *tx_workqueue;
	struct delayed_work tx_dwork;
	struct workqueue_struct *rx_workqueue;
	struct delayed_work rx_dwork;
	struct sdio_driver *sdio_drv;
	struct device *sdio_dev;
	wait_queue_head_t wq;
	u32 wq_wkcond;
	spinlock_t state_lock;
	int open_cnt;	/* #times opened */
};

struct mcu_sdio_mmc_card {
	/** sdio_func structure pointer */
	struct sdio_func *func;
	mcu_sdio_card_reg *regs;
	struct mcu_sdio_misc_priv *misc_priv;
	/** saved host clock value */
	unsigned int host_clock;
	/** INT Status reg */
	u32 ireg;
	/* protect access to INT */
	spinlock_t int_lock;
	/** IO port */
	u32 ioport;
	/** SDIO multiple port read bitmap */
	u32 mp_rd_bitmap;
	/** SDIO multiple port write bitmap */
	u32 mp_wr_bitmap;
	/** Current available port for read */
	u8 curr_rd_port;
	/** Current available port for write */
	u8 curr_wr_port;
	/** Used port numbers for write */
	u8 used_wr_port_num;
	/** Used port numbers for read */
	u8 used_rd_port_num;
	bool cmd_sent;
	bool cmd_resp_received;
	bool data_received;
	bool data_sent;
	u8 *mp_regs;
	struct cmd_ring_buf tx_cmd_ring;
	struct cmd_event_ring_buf rx_cmd_event_ring;
	//struct event_ring_buf event_ring;
	struct rx_ring_buf rx_ring;
	struct tx_ring_buf tx_ring;
};

#define NCP_CMD_WLAN   0x00000000
#define NCP_CMD_BLE    0x10000000
#define NCP_CMD_15D4   0x20000000
#define NCP_CMD_MATTER 0x30000000
#define NCP_CMD_SYSTEM 0x40000000

#define NCP_MSG_TYPE_CMD   0x00010000
#define NCP_MSG_TYPE_EVENT 0x00020000
#define NCP_MSG_TYPE_RESP  0x00030000

#define NCP_CMD_WLAN_SOCKET      0x00900000

#define NCP_CMD_WLAN_SOCKET_SEND     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000004)
#define NCP_CMD_WLAN_SOCKET_SENDTO   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000005)


#define NCP_CMD_SYSTEM_CONFIG   0x00000000

#define NCP_CMD_SYSTEM_CONFIG_SDIO_SET  (NCP_CMD_SYSTEM | NCP_CMD_SYSTEM_CONFIG | NCP_MSG_TYPE_CMD | 0x00000003) /* set-sdio-cfg */


typedef struct _NCP_COMMAND
{
    /*bit0 ~ bit15 cmd id  bit16 ~ bit23 cmd subclass bit24 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t rsvd;
} NCP_COMMAND, NCP_RESPONSE;

static inline void inc_cmdqhead(struct cmd_ring_buf *ring)
{
	ring->qhead = (ring->qhead + 1) % CMD_RING_SIZE;
}

static inline void dec_cmdqhead(struct cmd_ring_buf *ring)
{
	if (ring->qhead > 0)
		ring->qhead = ring->qhead - 1;
	else
		ring->qhead = CMD_RING_SIZE - 1;
}

static inline void inc_cmdqtail(struct cmd_ring_buf *ring)
{
	ring->qtail = (ring->qtail + 1) % CMD_RING_SIZE;
}

static inline bool cmdq_has_space(struct cmd_ring_buf *ring)
{
	unsigned long head = ring->qhead;
	unsigned long tail = ring->qtail;

	return (CIRC_SPACE(head, tail, CMD_RING_SIZE) > 0);
}

static inline unsigned int cmdq_count(struct cmd_ring_buf *ring)
{
	return CIRC_CNT_TO_END(ring->qhead, ring->qtail,
			       CMD_RING_SIZE);
}

static inline void inc_cmdeventqhead(struct cmd_event_ring_buf *ring)
{
	ring->qhead = (ring->qhead + 1) % CMDRSP_EVENT_RING_SIZE;
}

static inline void inc_cmdeventqtail(struct cmd_event_ring_buf *ring)
{
	ring->qtail = (ring->qtail + 1) % CMDRSP_EVENT_RING_SIZE;
}

static inline bool cmdeventq_has_space(struct cmd_event_ring_buf *ring)
{
	unsigned long head = ring->qhead;
	unsigned long tail = ring->qtail;

	return (CIRC_SPACE(head, tail, CMDRSP_EVENT_RING_SIZE) > 0);
}

static inline unsigned int cmdeventq_count(struct cmd_event_ring_buf *ring)
{
	return CIRC_CNT_TO_END(ring->qhead, ring->qtail,
			       CMDRSP_EVENT_RING_SIZE);
}

static inline void inc_txqhead(struct tx_ring_buf *tx_ring)
{
	tx_ring->qhead = (tx_ring->qhead + 1) % TX_DEVICE_RING_SIZE;
}

static inline void inc_txqtail(struct tx_ring_buf *tx_ring)
{
	tx_ring->qtail = (tx_ring->qtail + 1) % TX_DEVICE_RING_SIZE;
}

static inline bool txq_has_space(struct tx_ring_buf *tx_ring)
{
	unsigned long head = tx_ring->qhead;
	unsigned long tail = tx_ring->qtail;

	return (CIRC_SPACE(head, tail, TX_DEVICE_RING_SIZE) > 0);
}

static inline unsigned int txq_count(struct tx_ring_buf *tx_ring)
{
	return CIRC_CNT_TO_END(tx_ring->qhead, tx_ring->qtail,
			       TX_DEVICE_RING_SIZE);
}

static inline void inc_rxqhead(struct rx_ring_buf *rx_ring)
{
	rx_ring->qhead = (rx_ring->qhead + 1) % RX_DEVICE_RING_SIZE;
}

static inline void inc_rxqtail(struct rx_ring_buf *rx_ring)
{
	rx_ring->qtail = (rx_ring->qtail + 1) % RX_DEVICE_RING_SIZE;
}

static inline bool rxq_has_space(struct rx_ring_buf *rx_ring)
{
	unsigned long head = rx_ring->qhead;
	unsigned long tail = rx_ring->qtail;

	return (CIRC_SPACE(head, tail, RX_DEVICE_RING_SIZE) > 0);
}

static inline unsigned int rxq_count(struct rx_ring_buf *rx_ring)
{
	return CIRC_CNT_TO_END(rx_ring->qhead, rx_ring->qtail,
			       RX_DEVICE_RING_SIZE);
}

/**
 *  @brief This function writes data into card register
 *
 *  @param card     A Pointer to the mcu_sdio_mmc_card structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         0 on success
 */
static int mcu_sdio_write_reg(struct mcu_sdio_mmc_card *card, u32 reg, u32 data)
{
	int ret = 0;
	struct sdio_func *func = card->func;

	sdio_claim_host(func);
	sdio_writeb(func, (u8) data, reg, (int *)&ret);
	sdio_release_host(func);

	return ret;
}

/**
 *  @brief This function reads data from card register
 *
 *  @param card     A Pointer to the mcu_sdio_mmc_card structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         0 on success
 */
static int mcu_sdio_read_reg(struct mcu_sdio_mmc_card *card, u32 reg, u32 *data)
{
	int ret = 0;
	struct sdio_func *func = card->func;
	u8 val;

	sdio_claim_host(func);
	val = sdio_readb(func, reg, (int *)&ret);
	sdio_release_host(func);
	*data = (u32) val;

	return ret;
}

static int mcu_sdio_update_wr_bitmap(struct mcu_sdio_mmc_card *card)
{
	int ret = 0;
	u32 reg[4];

	ret = mcu_sdio_read_reg(card, card->regs->wr_bitmap_l, &reg[0]);
	ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_u, &reg[1]);
	ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_1l, &reg[2]);
	ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_1u, &reg[3]);
	if (ret) {
		PRINT_ERR("%s: mcu_sdio_read_reg ret=0x%x\n", __FUNCTION__, ret);
		goto done;
	}

	card->mp_wr_bitmap = reg[0];
	card->mp_wr_bitmap |= (reg[1] << 8);
	card->mp_wr_bitmap |= (reg[2] << 16);
	card->mp_wr_bitmap |= (reg[3] << 24);

done:
	return ret;
}

/**
 *  @brief This function writes multiple bytes into card memory
 *
 *  @param card     A Pointer to the mcu_sdio_mmc_card structure
 *  @param buf      Pointer to buffer structure
 *  @param len      Transmitted data length
 *  @param port     Port
 *
 *  @return         0 on success
 */
static int mcu_sdio_write_data_sync(struct mcu_sdio_mmc_card *card,
					u8 *buf, u32 len, u32 port)
{
	struct sdio_func *func = card->func;
	u32 aligned_size = ALIGN(len, func->cur_blksize);
	int ret;

	if (len) {
		sdio_claim_host(func);
		PRINTM_DEBUG("%s: port=0x%x buf=%p len=%u cur_blksize=%u aligned_size=%u\n", __FUNCTION__, port, buf, len, func->cur_blksize, aligned_size);
		ret = sdio_writesb(func, port, buf, aligned_size);

		if (ret) {
			PRINT_ERR("cmd53 write error=%d\n", ret);
			/* issue abort cmd52 command through F0*/
			sdio_f0_writeb(func, 0x01, SDIO_CCCR_ABORT, &ret);
		}
		sdio_release_host(func);
	} else {
		ret = 0;
	}

	return ret;
}

/**
 *  @brief This function reads multiple bytes from card memory
 *
 *  @param card     A Pointer to the mcu_sdio_mmc_card structure
 *  @param buf      Pointer to buffer structure
 *  @param len      Received data length
 *  @param port     Port
 *
 *  @return         0 on success
 */
static int mcu_sdio_read_data_sync(struct mcu_sdio_mmc_card *card,
					u8 *buf, u32 len, u32 port)
{
	struct sdio_func *func = card->func;
	u32 aligned_size = ALIGN(len, func->cur_blksize);
	int ret;

	if (len) {
		sdio_claim_host(func);
		PRINTM_DEBUG("%s: port=%u buf=%p len=%u cur_blksize=%u aligned_size=%u\n", __FUNCTION__, port, buf, len, func->cur_blksize, aligned_size);
		ret = sdio_readsb(func, buf, port, aligned_size);
		if (ret) {
			PRINT_ERR("cmd53 read error=%d\n", ret);
			/* issue abort cmd52 command through F0*/
			sdio_f0_writeb(func, 0x01, SDIO_CCCR_ABORT, &ret);
		}
		sdio_release_host(func);
	} else {
		ret = 0;
	}

	return ret;
}

/**
 *  @brief This function disables the host interrupts.
 *
 *  @param func      A Pointer to the mcu_sdio_mmc_card structure
 *  @param mask      Interrupt to be masked
 *
 *  @return          0 on success
 */
static int mcu_disable_sdio_host_int(struct mcu_sdio_mmc_card *card, u32 mask)
{
	int ret;
	u32 host_int_mask = 0;

	/* Read back the host_int_mask register */
	ret = mcu_sdio_read_reg(card, card->regs->host_int_mask_reg,
							&host_int_mask);
	if (ret) {
		PRINTM_DEBUG("%s: read %u fail.\n", __FUNCTION__, card->regs->host_int_mask_reg);
		return ret;
	}

	/* Update with the mask and write back to the register */
	host_int_mask &= ~mask;

	ret = mcu_sdio_write_reg(card, card->regs->host_int_mask_reg,
							host_int_mask);
	if (ret) {
		PRINTM_DEBUG("%s: write %u to %u fail.\n", __FUNCTION__, card->regs->host_int_mask_reg, host_int_mask);
	}
	return ret;
}

/**
 *  @brief This function enables the host interrupts.
 *
 *  @param func      A Pointer to the mcu_sdio_mmc_card structure
 *  @param mask      Interrupt to be masked
 *
 *  @return          0 on success
 */
static int mcu_enable_sdio_host_int(struct mcu_sdio_mmc_card *card, u32 mask)
{
	int ret;
	u32 host_int_mask = 0;

	/* Read back the host_int_mask register */
	ret = mcu_sdio_read_reg(card, card->regs->host_int_mask_reg,
							&host_int_mask);
	if (ret) {
		PRINTM_DEBUG("%s: read %u fail.\n", __FUNCTION__, card->regs->host_int_mask_reg);
		return ret;
	}

	/* Update with the mask and write back to the register */
	host_int_mask |= mask;

	ret = mcu_sdio_write_reg(card, card->regs->host_int_mask_reg,
							host_int_mask);
	if (ret) {
		PRINTM_DEBUG("%s: write %u to %u fail.\n", __FUNCTION__, card->regs->host_int_mask_reg, host_int_mask);
	}
	return ret;
}

/**
 *  @brief This function gets available SDIO port for reading data
 *
 *  @param pmadapter  A pointer to mlan_adapter structure
 *  @param pport      A pointer to port number
 *  @return           MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int wlan_get_rd_port(struct mcu_sdio_mmc_card *card, u8 *pport)
{
	u32 rd_bitmap = card->mp_rd_bitmap;

	if (!rd_bitmap) {
		return -EFAULT;
	}

	if (card->mp_rd_bitmap & (1 << card->curr_rd_port)) {
		card->mp_rd_bitmap &= (u32)(~(1 << card->curr_rd_port));
		*pport = card->curr_rd_port;
		card->curr_rd_port = (card->curr_rd_port + 1) % MIN(card->used_rd_port_num, MAX_DATA_PORT);
	} else {
		    return -ENODATA;
	}

	PRINTM_DEBUG("port=%d mp_rd_bitmap=0x%08x -> 0x%08x\n", *pport,
		rd_bitmap, card->mp_rd_bitmap);

	return 0;
}

static void mcu_sdio_rx_function(struct work_struct *work)
{
	struct mcu_sdio_mmc_card *card;
	struct sdio_func *func;
	struct mcu_sdio_misc_priv *priv = container_of(work,
						    struct mcu_sdio_misc_priv,
						    rx_dwork.work);
	int ret;
	u32 ireg, reg[4];
	unsigned long flags;

	PRINTM_DEBUG("%s: Enter\n", __FUNCTION__);
	func = dev_to_sdio_func(priv->sdio_dev);
	card = sdio_get_drvdata(func);
	if (! card) {
		PRINT_ERR("%s: sdio_mmc_interrupt(func = %p) card or handle is NULL, card=%p\n",
			__FUNCTION__, func, card);
		return;
	}

#if 0
	ret = mcu_sdio_read_reg(card, card->regs->host_int_status_reg, &ireg);
	if (ret)
		return;
#endif
	spin_lock_irqsave(&card->int_lock, flags);
	ireg = card->ireg;
	card->ireg = 0;
	spin_unlock_irqrestore(&card->int_lock, flags);

	PRINTM_DEBUG("%s: sdio_ireg = 0x%x\n", __FUNCTION__, ireg);
	if (! ireg)
		goto done;

	/* check the command port */
	if (ireg & DN_LD_CMD_PORT_HOST_INT_STATUS) {
		PRINTM_DEBUG("%s: DNLD_CMD DONE---\n", __FUNCTION__);
		card->cmd_sent = false;
		PRINTM_DEBUG("%s: cmd_sent=%d\n", __FUNCTION__, card->cmd_sent);
	}

	if (ireg & UP_LD_CMD_PORT_HOST_INT_STATUS) {
		u32 rx_len = 0;
		struct sdio_cmd_event_buffer *rx_buf = NULL;
		sdio_header *sdio_hdr = NULL;
		struct mcu_sdio_misc_priv *priv = card->misc_priv;
		u32 rx_cmd_ok = 0;

		PRINTM_DEBUG("%s: UPLD_CMD---\n", __FUNCTION__);

		ret = mcu_sdio_read_reg(card, card->regs->cmd_rd_len_0, &reg[0]);
		ret |= mcu_sdio_read_reg(card, card->regs->cmd_rd_len_1, &reg[1]);
		if (ret) {
			PRINT_ERR("%s: UPLD_CMD: mcu_sdio_read_reg ret=0x%x\n", __FUNCTION__, ret);
			goto done_UPLD_CMD;
		}

		rx_len = ((u32)reg[0]);
		rx_len |= ((u32)reg[1]) << 8;
		PRINTM_DEBUG("%s: UPLD_CMD: cmd port rx_len=%u\n", __FUNCTION__, rx_len);
		if (rx_len <= SDIO_INTF_HEADER_LEN || rx_len > MAX_CMD_EVENT_PAYLOAD_SIZE) {
			PRINT_ERR("%s: UPLD_CMD: invalid rx_len=%d\n", __FUNCTION__, rx_len);
			goto done_UPLD_CMD;
		}

		//spin_lock_irqsave(&card->rx_cmd_event_ring.lock, flags);
		if (!cmdeventq_has_space(&card->rx_cmd_event_ring)) {
			PRINT_ERR("%s: UPLD_CMD: No space in cmdrsp_ring\n", __FUNCTION__);
			//spin_unlock_irqrestore(&card->rx_cmd_event_ring.lock, flags);
			goto done_UPLD_CMD;
		}
		//spin_unlock_irqrestore(&card->rx_cmd_event_ring.lock, flags);

		rx_buf = &card->rx_cmd_event_ring.buffers[card->rx_cmd_event_ring.qhead];
		ret = mcu_sdio_read_data_sync(card, rx_buf->buf_align, rx_len,
						card->ioport | CMD_PORT_SLCT);
		if (ret) {
			PRINT_ERR("%s: UPLD_CMD: mcu_sdio_read_data_sync ret=0x%x\n", __FUNCTION__, ret);
			//spin_unlock_irqrestore(&card->rx_cmd_event_ring.lock, flags);
			goto done_UPLD_CMD;
		}
		sdio_hdr = (sdio_header *)(rx_buf->buf_align);
		if (((sdio_hdr->type != MLAN_TYPE_CMD) && (sdio_hdr->type != MLAN_TYPE_EVENT)) ||
		((sdio_hdr->len < SDIO_INTF_HEADER_LEN) || (sdio_hdr->len > MAX_CMD_EVENT_PAYLOAD_SIZE))) {
			PRINT_ERR("%s: UPLD_CMD: receive a wrong packet from CMD PORT: type=%d len=%d\n", __FUNCTION__, sdio_hdr->type, sdio_hdr->len);
			//spin_unlock_irqrestore(&card->rx_cmd_event_ring.lock, flags);
			goto done_UPLD_CMD;
		}
		rx_buf->size = sdio_hdr->len;
		//spin_lock_irqsave(&card->rx_cmd_event_ring.lock, flags);
		inc_cmdeventqhead(&card->rx_cmd_event_ring);
		//spin_unlock_irqrestore(&card->rx_cmd_event_ring.lock, flags);
		rx_cmd_ok = 1;
		card->cmd_resp_received = true;
done_UPLD_CMD:
		if (rx_buf)
			PRINTM_HEXDUMP("UPLD_CMD rx cmdrsp: ", DUMP_PREFIX_OFFSET, 16, 1, &(rx_buf->buf_align), rx_buf->size, 1);
		if (!g_dev_noblock && rx_cmd_ok) {
			if (priv) {
				PRINTM_DEBUG("%s: UPLD_CMD: wake_up_all wq\n", __FUNCTION__);
				priv->wq_wkcond = true;
				wake_up_all(&priv->wq);
			}
		}
	}

	if (ireg & DN_LD_HOST_INT_STATUS) {
		PRINTM_DEBUG("%s: DNLD_DATA DONE---\n", __FUNCTION__);
		ret = mcu_sdio_read_reg(card, card->regs->wr_bitmap_l, &reg[0]);
		ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_u, &reg[1]);
		ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_1l, &reg[2]);
		ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_1u, &reg[3]);
		if (ret) {
			PRINT_ERR("%s: DNLD_DATA DONE: mcu_sdio_read_reg ret=0x%x\n", __FUNCTION__, ret);
			goto done;
		}

		card->mp_wr_bitmap = reg[0];
		card->mp_wr_bitmap |= (reg[1] << 8);
		card->mp_wr_bitmap |= (reg[2] << 16);
		card->mp_wr_bitmap |= (reg[3] << 24);
		if (card->data_sent && (card->mp_wr_bitmap & (1 << card->curr_wr_port))) {
			PRINTM_DEBUG("%s: data_sent=%d\n", __FUNCTION__, card->data_sent);
			card->data_sent = false;
		}
	}

	if (ireg & UP_LD_HOST_INT_STATUS) {
		u32 rd_len_p0_l = card->regs->rd_len_p0_l;
		u32 rd_len_p0_u = card->regs->rd_len_p0_u;
		u32 len_reg_l, len_reg_u;
		u32 rx_len;
		struct sdio_buffer *rx_buf;
		sdio_header *sdio_hdr = NULL;
		struct mcu_sdio_misc_priv *priv = card->misc_priv;
		u8 port = 0;
		u32 rx_data_ok = 0;

		PRINTM_DEBUG("%s: UPLD_DATA ---\n", __FUNCTION__);
		ret = mcu_sdio_read_reg(card, card->regs->rd_bitmap_l, &reg[0]);
		ret |= mcu_sdio_read_reg(card, card->regs->rd_bitmap_u, &reg[1]);
		ret |= mcu_sdio_read_reg(card, card->regs->rd_bitmap_1l, &reg[2]);
		ret |= mcu_sdio_read_reg(card, card->regs->rd_bitmap_1u, &reg[3]);
		if (ret) {
			PRINT_ERR("%s: UPLD_DATA: mcu_sdio_read_reg rd_bitmap ret=0x%x\n", __FUNCTION__, ret);
			goto done;
		}

		card->mp_rd_bitmap = reg[0];
		card->mp_rd_bitmap |= (reg[1] << 8);
		card->mp_rd_bitmap |= (reg[2] << 16);
		card->mp_rd_bitmap |= (reg[3] << 24);

		while (1) {
			rx_data_ok = 0;
			ret = wlan_get_rd_port(card, &port);
			if (ret) {
				//PRINT_ERR("UPLD_DATA: wlan_get_rd_port fail ret=%d\n", ret);
				break;
			}

			len_reg_l = rd_len_p0_l + (port << 1);
			len_reg_u = rd_len_p0_u + (port << 1);
			ret = mcu_sdio_read_reg(card, len_reg_l, &reg[0]);
			ret |= mcu_sdio_read_reg(card, len_reg_u, &reg[1]);
			if (ret) {
				PRINT_ERR("%s: UPLD_DATA: mcu_sdio_read_reg en_reg ret=0x%x\n", __FUNCTION__, ret);
				goto done_UPLD_DATA;
			}

			rx_len = (((u32) reg[1]) << 8);
			rx_len |= (u32) reg[0];
			PRINTM_DEBUG("%s: UPLD_DATA: port=%d rx_len=%u\n", __FUNCTION__, port, rx_len);
			if ((rx_len <= SDIO_INTF_HEADER_LEN) || (rx_len > MAX_DATA_PAYLOAD_SIZE)) {
				PRINT_ERR("%s: UPLD_DATA: invalid rx_len=%d\n", __FUNCTION__, rx_len);
				goto done_UPLD_DATA;
			}

			//spin_lock_irqsave(&card->rx_ring.rx_lock, flags);
			if (! rxq_has_space(&card->rx_ring)) {
				PRINT_ERR("%s: No space in rx_ring\n", __FUNCTION__);
				//spin_unlock_irqrestore(&card->rx_ring.rx_lock, flags);
				goto done_UPLD_DATA;
			}
			//spin_unlock_irqrestore(&card->rx_ring.rx_lock, flags);
			rx_buf = &card->rx_ring.buffers[card->rx_ring.qhead];

			ret = mcu_sdio_read_data_sync(card, rx_buf->buf_align, rx_len,
							card->ioport | port);
			if (ret) {
				PRINT_ERR("%s: UPLD_DATA: mcu_sdio_read_data_sync ret=0x%x\n", __FUNCTION__, ret);
				//spin_unlock_irqrestore(&card->rx_ring.rx_lock, flags);
				goto done_UPLD_DATA;
			}
			sdio_hdr = (sdio_header *)(rx_buf->buf_align);
			if ((sdio_hdr->type != MLAN_TYPE_DATA) ||
			((sdio_hdr->len < SDIO_INTF_HEADER_LEN) || (sdio_hdr->len > MAX_DATA_PAYLOAD_SIZE))) {
				PRINT_ERR("%s: UPLD_DATA: receive a wrong packet from DATA PORT: type=%d len=%d\n", __FUNCTION__, sdio_hdr->type, sdio_hdr->len);
				//spin_unlock_irqrestore(&card->rx_ring.rx_lock, flags);
				goto done_UPLD_DATA;
			}
			rx_buf->size = sdio_hdr->len;
			//spin_lock_irqsave(&card->rx_ring.rx_lock, flags);
			inc_rxqhead(&card->rx_ring);
			//spin_unlock_irqrestore(&card->rx_ring.rx_lock, flags);
			rx_data_ok = 1;
			card->data_received = true;
			PRINTM_HEXDUMP("UPLD_DATA rx data: ", DUMP_PREFIX_OFFSET, 16, 1, &(rx_buf->buf_align), rx_buf->size, 1);
done_UPLD_DATA:
			if (!g_dev_noblock && rx_data_ok) {
				if (priv) {
					PRINTM_DEBUG("%s: UPLD_DATA: wake_up_all wq\n", __FUNCTION__);
					priv->wq_wkcond = true;
					wake_up_all(&priv->wq);
				}
			}
		}
	}

done:
	PRINTM_DEBUG("%s: Leave\n", __FUNCTION__);
	return;
}

static void mcu_sdio_interrupt(struct sdio_func *func)
{
	struct mcu_sdio_mmc_card *card;
	int ret;
	u32 ireg = 0;
	u32 ireg_old = 0;
	unsigned long flags;

	//PRINTM_DEBUG("%s: Enter\n", __FUNCTION__);
	if (! func) {
		PRINTM_DEBUG("%s: func = %p\n", __FUNCTION__, func);
		return;
	}
	card = sdio_get_drvdata(func);
	if (! card) {
		PRINT_ERR("sdio_mmc_interrupt(func = %p) card or handle is NULL, card=%p\n",
			func, card);
		return;
	}

	ret = mcu_sdio_read_reg(card, card->regs->host_int_status_reg, &ireg);
	if (ret) {
		PRINT_ERR("%s: ret=%d\n", __FUNCTION__, ret);
		return;
	}

	PRINTM_DEBUG("%s: ireg=0x%x\n", __FUNCTION__, ireg);
	if (!ireg) {
		PRINTM_DEBUG("%s: ireg 0 return\n", __FUNCTION__);
		return;
	}

	spin_lock_irqsave(&card->int_lock, flags);
	ireg_old = card->ireg;
	card->ireg |= ireg;
	PRINTM_DEBUG("%s: ireg = 0x%x -> 0x%x\n", __FUNCTION__, ireg_old, card->ireg);
	spin_unlock_irqrestore(&card->int_lock, flags);
	if (card->misc_priv)
		queue_delayed_work(card->misc_priv->rx_workqueue, &card->misc_priv->rx_dwork, 1);

#if 0

	ret = mcu_sdio_read_reg(card, card->regs->host_int_status_reg, &ireg);
	if (ret)
		return;

	PRINTM_DEBUG("mcu_sdio_interrupt: sdio_ireg = 0x%x\n", ireg);
	if (! ireg)
		goto done;

	/* check the command port */
	if (ireg & DN_LD_CMD_PORT_HOST_INT_STATUS) {
		PRINTM_DEBUG("cmd_sent\n");
		card->cmd_sent = false;
	}

	if (ireg & UP_LD_CMD_PORT_HOST_INT_STATUS) {
		u32 rx_len = 0;
		struct sdio_cmd_event_buffer *rx_buf = NULL;
		sdio_header *sdio_hdr = NULL;
		struct mcu_sdio_misc_priv *priv = card->misc_priv;

		PRINTM_DEBUG("cmd_recv\n");

		ret = mcu_sdio_read_reg(card, card->regs->cmd_rd_len_0, &reg[0]);
		ret |= mcu_sdio_read_reg(card, card->regs->cmd_rd_len_1, &reg[1]);
		if (ret) {
			PRINT_ERR("UPLD_CMD: mcu_sdio_read_reg ret=0x%x\n", ret);
			goto done;
		}

		rx_len = ((u32)reg[0]);
		rx_len |= ((u32)reg[1]) << 8;
		PRINTM_DEBUG("UPLD_CMD: cmd port rx_len=%u\n", rx_len);
		if (rx_len <= SDIO_INTF_HEADER_LEN || rx_len > MAX_CMD_EVENT_PAYLOAD_SIZE) {
			PRINT_ERR("UPLD_CMD: invalid rx_len=%d\n", rx_len);
			goto done;
		}

		spin_lock(&card->rx_cmd_event_ring.lock);
		if (!cmdeventq_has_space(&card->rx_cmd_event_ring)) {
			PRINT_ERR("UPLD_CMD: No space in cmdrsp_ring\n");
			spin_unlock(&card->rx_cmd_event_ring.lock);
			return;
		}
		rx_buf = &card->rx_cmd_event_ring.buffers[card->rx_cmd_event_ring.qhead];
		ret = mcu_sdio_read_data_sync(card, rx_buf->buf_align, rx_len,
						card->ioport | CMD_PORT_SLCT);
		if (ret) {
			PRINT_ERR("UPLD_CMD: mcu_sdio_read_data_sync ret=0x%x\n", ret);
			spin_unlock(&card->rx_cmd_event_ring.lock);
			return;
		}
		sdio_hdr = (sdio_header *)(rx_buf->buf_align);
		if (((sdio_hdr->type != MLAN_TYPE_CMD) && (sdio_hdr->type != MLAN_TYPE_EVENT)) ||
		((sdio_hdr->len < SDIO_INTF_HEADER_LEN) || (sdio_hdr->len > MAX_CMD_EVENT_PAYLOAD_SIZE))) {
			PRINT_ERR("UPLD_CMD: receive a wrong packet from CMD PORT: type=%d len=%d\n", sdio_hdr->type, sdio_hdr->len);
			spin_unlock(&card->rx_cmd_event_ring.lock);
			return;
		}
		inc_cmdeventqhead(&card->rx_cmd_event_ring);
		spin_unlock(&card->rx_cmd_event_ring.lock);

		rx_buf->size = SDIO_INTF_HEADER_LEN + sdio_hdr->len;
		card->cmd_resp_received = true;
		PRINTM_HEXDUMP("UPLD_CMD rx cmdrsp: ", DUMP_PREFIX_OFFSET, 16, 1, &(rx_buf->buf_align), rx_buf->size, 1);
		wake_up_all(&priv->wq);
	}

	if (ireg & DN_LD_HOST_INT_STATUS) {
		ret = mcu_sdio_read_reg(card, card->regs->wr_bitmap_l, &reg[0]);
		ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_u, &reg[1]);
		ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_1l, &reg[2]);
		ret |= mcu_sdio_read_reg(card, card->regs->wr_bitmap_1u, &reg[3]);
		if (ret) {
			PRINT_ERR("DNLD_DATA DONE: mcu_sdio_read_reg ret=0x%x\n", ret);
			goto done;
		}

		card->mp_wr_bitmap = reg[0];
		card->mp_wr_bitmap |= (reg[1] << 8);
		card->mp_wr_bitmap |= (reg[2] << 16);
		card->mp_wr_bitmap |= (reg[3] << 24);
		if (card->data_sent && (card->mp_wr_bitmap & (1 << card->curr_wr_port))) {
			PRINTM_DEBUG(" <--- Tx DONE Interrupt --->\n");
			card->data_sent = false;
		}
	}

	if (ireg & UP_LD_HOST_INT_STATUS) {
		u32 rd_len_p0_l = card->regs->rd_len_p0_l;
		u32 rd_len_p0_u = card->regs->rd_len_p0_u;
		u32 len_reg_l, len_reg_u;
		u32 rx_len;
		struct sdio_buffer *rx_buf;
		sdio_header *sdio_hdr = NULL;
		struct mcu_sdio_misc_priv *priv = card->misc_priv;

		ret = mcu_sdio_read_reg(card, card->regs->rd_bitmap_l, &reg[0]);
		ret |= mcu_sdio_read_reg(card, card->regs->rd_bitmap_u, &reg[1]);
		ret |= mcu_sdio_read_reg(card, card->regs->rd_bitmap_1l, &reg[2]);
		ret |= mcu_sdio_read_reg(card, card->regs->rd_bitmap_1u, &reg[3]);
		if (ret) {
			PRINT_ERR("UPLD_DATA: mcu_sdio_read_reg rd_bitmap ret=0x%x\n", ret);
			goto done;
		}

		card->mp_rd_bitmap = reg[0];
		card->mp_rd_bitmap |= (reg[1] << 8);
		card->mp_rd_bitmap |= (reg[2] << 16);
		card->mp_rd_bitmap |= (reg[3] << 24);

		len_reg_l = rd_len_p0_l + (card->curr_rd_port << 1);
		len_reg_u = rd_len_p0_u + (card->curr_rd_port << 1);
		ret = mcu_sdio_read_reg(card, len_reg_l, &reg[0]);
		ret |= mcu_sdio_read_reg(card, len_reg_u, &reg[1]);
		if (ret) {
			PRINT_ERR("UPLD_DATA: mcu_sdio_read_reg en_reg ret=0x%x\n", ret);
			goto done;
		}

		rx_len = (((u32) reg[1]) << 8);
		rx_len |= (u32) reg[0];
		PRINTM_DEBUG("UPLD_DATA: port=%d rx_len=%u\n", card->curr_rd_port, rx_len);
		if ((rx_len <= SDIO_INTF_HEADER_LEN) || (rx_len > MAX_DATA_PAYLOAD_SIZE)) {
			PRINT_ERR("UPLD_DATA: invalid rx_len=%d\n", rx_len);
			return;
		}

		spin_lock(&card->rx_ring.rx_lock);
		if (! rxq_has_space(&card->rx_ring)) {
			PRINT_ERR("No space in rx_ring\n");
			spin_unlock(&card->rx_ring.rx_lock);
			return;
		}
		rx_buf = &card->rx_ring.buffers[card->rx_ring.qhead];

		ret = mcu_sdio_read_data_sync(card, rx_buf->buf_align, rx_len,
						card->ioport | card->curr_rd_port);
		if (ret) {
			PRINT_ERR("UPLD_DATA: mcu_sdio_read_data_sync ret=0x%x\n", ret);
			spin_unlock(&card->rx_ring.rx_lock);
			return;
		}
		sdio_hdr = (sdio_header *)(rx_buf->buf_align);
		if ((sdio_hdr->type != MLAN_TYPE_DATA) ||
		((sdio_hdr->len < SDIO_INTF_HEADER_LEN) || (sdio_hdr->len > MAX_DATA_PAYLOAD_SIZE))) {
			PRINT_ERR("UPLD_DATA: receive a wrong packet from DATA PORT: type=%d len=%d\n", sdio_hdr->type, sdio_hdr->len);
			spin_unlock(&card->rx_ring.rx_lock);
			return;
		}
		inc_rxqhead(&card->rx_ring);
		spin_unlock(&card->rx_ring.rx_lock);

		rx_buf->size = SDIO_INTF_HEADER_LEN + sdio_hdr->len;
		card->data_received = true;
		PRINTM_HEXDUMP("UPLD_DATA rx data: ", DUMP_PREFIX_OFFSET, 16, 1, &(rx_buf->buf_align), rx_buf->size, 1);
		wake_up_all(&priv->wq);
	}

done:
	return;
#endif
}

/**
 *  @brief This function initialize the SDIO port
 *
 *  @param pmadapter    A pointer to mlan_adapter structure
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int mcu_sdio_init_ioport(struct mcu_sdio_mmc_card *card)
{
	int ret;
	u32 reg;
	u32 host_int_rsr_reg = card->regs->host_int_rsr_reg;
	u32 host_int_rsr_mask = card->regs->sdio_int_mask;
	u32 card_misc_cfg_reg = card->regs->card_misc_cfg_reg;
	u32 card_config_2_1_reg = card->regs->card_config_2_1_reg;
	u32 cmd_config_0 = card->regs->cmd_config_0;
	u32 cmd_config_1 = card->regs->cmd_config_1;

	PRINT_INFO("SDIO FUNC1 IO port: 0x%x\n", card->ioport);

	/* Enable SDIO CMD-53 new mode */
	ret = mcu_sdio_read_reg(card, card_config_2_1_reg, &reg);
	if (ret)
		return ret;

	ret = mcu_sdio_write_reg(card, card_config_2_1_reg,
				reg | CMD53_NEW_MODE);
	if (ret)
		return ret;

	/* Configure cmd port */
	/* Enable reading rx length from the register */
	ret = mcu_sdio_read_reg(card, cmd_config_0, &reg);
	if (ret)
		return ret;
	ret = mcu_sdio_write_reg(card, cmd_config_0,
				reg | CMD_PORT_RD_LEN_EN);
	if (ret)
		return ret;

	/* Enable Dnld/Upld ready auto reset for cmd port after cmd53 is completed */
	ret = mcu_sdio_read_reg(card, cmd_config_1, &reg);
	if (ret)
		return ret;
	ret = mcu_sdio_write_reg(card, cmd_config_1, reg | CMD_PORT_AUTO_EN);
	if (ret)
		return ret;

	/* Set Host interrupt reset to read to clear */
	ret = mcu_sdio_read_reg(card, host_int_rsr_reg, &reg);
	if (ret)
		return ret;
	ret = mcu_sdio_write_reg(card, host_int_rsr_reg,
				reg | host_int_rsr_mask);
	if (ret)
		return ret;

	/* Dnld/Upld ready set to auto reset */
	ret = mcu_sdio_read_reg(card, card_misc_cfg_reg, &reg);
	if (ret)
		return ret;
	ret = mcu_sdio_write_reg(card, card_misc_cfg_reg,
				reg | AUTO_RE_ENABLE_INT);

	return ret;
}

static int mcu_sdio_init(struct mcu_sdio_mmc_card *card)
{
	int ret;
#if 0
	u32 sdio_ireg = 0;

	/*
	 * Read the HOST_INT_STATUS_REG for ACK the first interrupt got
	 * from the bootloader. If we don't do this we get a interrupt
	 * as soon as we register the irq.
	 */
	ret = mcu_sdio_read_reg(card, card->regs->host_int_status_reg,
				&sdio_ireg);
	if (ret)
		return ret;
#endif

	/* Disable host interrupt mask register for SDIO */
	ret = mcu_disable_sdio_host_int(card, HIM_DISABLE);
	if (ret)
		return ret;

	/* Get SDIO ioport */
	ret = mcu_sdio_init_ioport(card);

	return ret;
}

int mcu_sdio_probe(struct sdio_func *func, const struct sdio_device_id *id)
{
	struct mcu_sdio_mmc_card *card = NULL;
	int ret;
	u32 i = 0;

	PRINT_INFO("vendor=0x%4.04X device=0x%4.04X class=%d function=%d\n",
		func->vendor, func->device, func->class, func->num);

	card = kzalloc(sizeof(struct mcu_sdio_mmc_card), GFP_KERNEL);
	if (! card) {
		PRINT_ERR("Failed to allocate memory in probe function!\n");
		return -ENOMEM;
	}

	card->tx_cmd_ring.qhead = 0;
	card->tx_cmd_ring.qtail = 0;
	spin_lock_init(&card->tx_cmd_ring.lock);
	for (i = 0; i < CMD_RING_SIZE; i ++) {
		card->tx_cmd_ring.buffers[i].buf_align = (char *)ALIGN_ADDR(card->tx_cmd_ring.buffers[i].buf, SDIO_BUFF_ALIGN);
		PRINTM_DEBUG("tx_cmd_ring.buffers[%u]: buf=%p buf_align=%p\n", i,
			card->tx_cmd_ring.buffers[i].buf, card->tx_cmd_ring.buffers[i].buf_align);
	}

	card->rx_cmd_event_ring.qhead = 0;
	card->rx_cmd_event_ring.qtail = 0;
	spin_lock_init(&card->rx_cmd_event_ring.lock);
	for (i = 0; i < CMDRSP_EVENT_RING_SIZE; i ++) {
		card->rx_cmd_event_ring.buffers[i].buf_align = (char *)ALIGN_ADDR(card->rx_cmd_event_ring.buffers[i].buf, SDIO_BUFF_ALIGN);
		PRINTM_DEBUG("rx_cmd_event_ring.buffers[%u]: buf=%p buf_align=%p\n", i,
			card->rx_cmd_event_ring.buffers[i].buf, card->rx_cmd_event_ring.buffers[i].buf_align);
	}

	card->rx_ring.qhead = 0;
	card->rx_ring.qtail = 0;
	spin_lock_init(&card->rx_ring.rx_lock);
	for (i = 0; i < RX_DEVICE_RING_SIZE; i ++) {
		card->rx_ring.buffers[i].buf_align = (char *)ALIGN_ADDR(card->rx_ring.buffers[i].buf, SDIO_BUFF_ALIGN);
		PRINTM_DEBUG("rx_ring.buffers[%u]: buf=%p buf_align=%p\n", i,
			card->rx_ring.buffers[i].buf, card->rx_ring.buffers[i].buf_align);
	}

	card->tx_ring.qhead = 0;
	card->tx_ring.qtail = 0;
	spin_lock_init(&card->tx_ring.tx_lock);
	for (i = 0; i < TX_DEVICE_RING_SIZE; i ++) {
		card->tx_ring.buffers[i].buf_align = (char *)ALIGN_ADDR(card->tx_ring.buffers[i].buf, SDIO_BUFF_ALIGN);
		PRINTM_DEBUG("tx_ring.buffers[%u]: buf=%p buf_align=%p\n", i,
			card->tx_ring.buffers[i].buf, card->tx_ring.buffers[i].buf_align);
	}

	card->func = func;
	card->regs = (mcu_sdio_card_reg *) &mcu_reg_rw610;
	card->ireg = 0;
	spin_lock_init(&card->int_lock);
	card->ioport = MEM_PORT;
	card->mp_rd_bitmap = 0;
	card->mp_wr_bitmap = 0;
	card->curr_rd_port = card->regs->start_rd_port;
	card->curr_wr_port = card->regs->start_wr_port;
	card->used_wr_port_num = 1;
	card->used_rd_port_num = 1;

	func->card->quirks |= MMC_QUIRK_LENIENT_FN0;

	/* wait for chip fully wake up */
	if (!func->enable_timeout)
		func->enable_timeout = 200;

	sdio_claim_host(func);

	ret = sdio_enable_func(func);
	if (ret) {
		PRINT_ERR("sdio_enable_func() failed: ret=%d\n", ret);
		goto err;
	}

	ret = mcu_sdio_init(card);
	if (ret) {
		PRINT_ERR("mcu_sdio_init() failed: ret=%d\n", ret);
		goto err;
	}

	/* Request the SDIO IRQ */
	ret = sdio_claim_irq(func, mcu_sdio_interrupt);
	if (ret) {
		PRINT_ERR("sdio_claim_irq failed: ret=%d\n", ret);
		goto err;
	}

	/* Set block size */
	ret = sdio_set_block_size(card->func, MLAN_SDIO_BLOCK_SIZE);
	if (ret) {
		PRINT_ERR("sdio_set_block_seize(): cannot set SDIO block size\n");
		sdio_release_irq(func);
		goto err;
	}

	/* re-enable host interrupt */
	ret = mcu_enable_sdio_host_int(card, card->regs->host_int_enable);

	sdio_release_host(func);
	sdio_set_drvdata(func, card);

	return ret;

err:
	sdio_release_host(func);
	sdio_disable_func(func);
	if (card)
		kfree(card);

	return ret;
}

void mcu_sdio_remove(struct sdio_func *func)
{
	struct mcu_sdio_mmc_card *card;

	if (func) {
		PRINT_INFO("SDIO func=%d\n", func->num);
		card = sdio_get_drvdata(func);
		if (card) {
			/* Release the SDIO IRQ */
			sdio_claim_host(card->func);
			sdio_release_irq(card->func);
			sdio_disable_func(card->func);
			sdio_release_host(card->func);
			sdio_set_drvdata(card->func, NULL);
			kfree(card);
		}
	}
}

int mcu_sdio_suspend(struct device *dev)
{
	/* TBD */
	/* struct sdio_func *func = dev_to_sdio_func(dev); */
	int ret = 0;

	return ret;
}

int mcu_sdio_resume(struct device *dev)
{
	/* TBD */
	/* struct sdio_func *func = dev_to_sdio_func(dev); */
	int ret = 0;

	return ret;
}

void mcu_sdio_shutdown(struct device *dev)
{
	/* TBD */
	/* struct sdio_func *func = dev_to_sdio_func(dev); */
}

static struct dev_pm_ops mcu_sdio_pm_ops = {
	.suspend = mcu_sdio_suspend,
	.resume = mcu_sdio_resume,
};

static struct sdio_driver mcu_sdio_driver = {
	.name = "mcu_sdio",
	.id_table = mcu_sdio_ids,
	.probe = mcu_sdio_probe,
	.remove = mcu_sdio_remove,
	.drv = {
		.owner = THIS_MODULE,
		.pm = &mcu_sdio_pm_ops,
		.shutdown = mcu_sdio_shutdown,
	}
};

/**
 *  @brief This function gets available SDIO port for writing data
 *
 *  @param pmadapter  A pointer to mlan_adapter structure
 *  @param pport      A pointer to port number
 *  @return           MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int wlan_get_wr_port_data(struct mcu_sdio_mmc_card *card, u8 *pport)
{
	u32 wr_bitmap = 0;

	mcu_sdio_update_wr_bitmap(card);

	wr_bitmap = card->mp_wr_bitmap;
	PRINTM_DEBUG("%s: mp_wr_bitmap=0x%08x\n", __FUNCTION__, wr_bitmap);
	if (!wr_bitmap) {
		card->data_sent = true;
		return -EBUSY;
	}

	if (card->mp_wr_bitmap & (1 << card->curr_wr_port)) {
		card->mp_wr_bitmap &= (u32)(~(1 << card->curr_wr_port));
		*pport = card->curr_wr_port;
		card->curr_wr_port = (card->curr_wr_port + 1) % MIN(card->used_wr_port_num, MAX_DATA_PORT);
	} else {
		card->data_sent = true;
		return -EBUSY;
	}
	PRINTM_DEBUG("port=%d mp_wr_bitmap=0x%08x -> 0x%08x\n", *pport,
	       wr_bitmap, card->mp_wr_bitmap);
	return 0;
}

static void mcu_sdio_tx_function(struct work_struct *work)
{
	struct mcu_sdio_mmc_card *card;
	struct sdio_func *func;
	struct mcu_sdio_misc_priv *priv = container_of(work,
						    struct mcu_sdio_misc_priv,
						    tx_dwork.work);
	//unsigned long flags;
	int ret;

	PRINTM_DEBUG("%s: Enter\n", __FUNCTION__);
	func = dev_to_sdio_func(priv->sdio_dev);
	card = sdio_get_drvdata(func);

start:
	/* Write data from the cmd queue */
	//spin_lock_irqsave(&card->tx_cmd_ring.lock, flags);
	if (cmdq_count(&card->tx_cmd_ring)) {
		struct sdio_cmd_event_buffer *cmd_buf = NULL;
		cmd_buf = &card->tx_cmd_ring.buffers[card->tx_cmd_ring.qtail];
		PRINTM_DEBUG("%s: CMD write_data_sync %p %p %lu\n", __FUNCTION__, cmd_buf, cmd_buf->buf_align, cmd_buf->size);
		PRINTM_HEXDUMP("TXFUNC cmd buf: ", DUMP_PREFIX_OFFSET, 16, 1, cmd_buf->buf_align, cmd_buf->size, 1);
		//sdio_claim_host(card->func);
		ret = mcu_sdio_write_data_sync(card, (u8 *)(cmd_buf->buf_align),
				cmd_buf->size, card->ioport | CMD_PORT_SLCT);
		//sdio_release_host(card->func);
		inc_cmdqtail(&card->tx_cmd_ring);
	}
	//spin_unlock_irqrestore(&card->tx_cmd_ring.lock, flags);

	/* Write data from the data queue */
	//spin_lock_irqsave(&card->tx_ring.tx_lock, flags);
	if (txq_count(&card->tx_ring)) {
		u8 port = 0;
		struct sdio_buffer *tx_buf = NULL;
		ret = wlan_get_wr_port_data(card, &port);
		if (ret)
			goto done;
		tx_buf = &card->tx_ring.buffers[card->tx_ring.qtail];
		PRINTM_DEBUG("%s: DATA write_data_sync %p %p %lu port=%u\n", __FUNCTION__, tx_buf, tx_buf->buf_align, tx_buf->size, port);
		PRINTM_HEXDUMP("TXFUNC data buf: ", DUMP_PREFIX_OFFSET, 16, 1, tx_buf->buf_align, tx_buf->size, 1);
		//sdio_claim_host(card->func);
		ret = mcu_sdio_write_data_sync(card, (u8 *)(tx_buf->buf_align),
				tx_buf->size, card->ioport | port);
		//sdio_release_host(card->func);
		inc_txqtail(&card->tx_ring);
	}
	//spin_unlock_irqrestore(&card->tx_ring.tx_lock, flags);

done:
	PRINTM_DEBUG("%s: cmdq_count=%u txq_count=%u\n", __FUNCTION__,
		cmdq_count(&card->tx_cmd_ring), txq_count(&card->tx_ring));
	if (cmdq_count(&card->tx_cmd_ring) || txq_count(&card->tx_ring)) {
		//queue_delayed_work(priv->tx_workqueue, &priv->tx_dwork, 1);
		goto start;
	}

	PRINTM_DEBUG("%s: Leave\n", __FUNCTION__);
}

/*
 * The are the file operation function for user access to /dev/mcu-sdio
 */
static ssize_t mcu_sdio_misc_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	struct mcu_sdio_mmc_card *card;
	struct sdio_func *func;
	struct miscdevice *miscdev = file->private_data;
	struct mcu_sdio_misc_priv *priv = dev_get_drvdata(miscdev->this_device);
	unsigned long timeout;
	u32 rx_len = 0;
	int noblock = file->f_flags & O_NONBLOCK;
	DEFINE_WAIT(wait);
	struct sdio_cmd_event_buffer *cmdevent_buf = NULL;
	struct sdio_buffer *rx_buf = NULL;
	unsigned long flags;

	PRINTM_DEBUG("%s: Enter file=%p buf=%p count=%lu ppos=%p noblock=%d\n", __FUNCTION__, file, buf, count, ppos, noblock);
	if (! priv->sdio_dev)
		return -EIO;

	func = dev_to_sdio_func(priv->sdio_dev);
	card = sdio_get_drvdata(func);
	if (!card)
		return -EIO;

	timeout = jiffies + msecs_to_jiffies(MAX_WAIT_TIME);

#if 0
	while (1) {
#endif
		if (!noblock) {
			if (priv) {
				PRINTM_DEBUG("%s: wait_event before: %d\n", __FUNCTION__, priv->wq_wkcond);
				//prepare_to_wait(&priv->wq, &wait, TASK_INTERRUPTIBLE);
				wait_event_interruptible_timeout(priv->wq, priv->wq_wkcond, 60 * HZ);
				PRINTM_DEBUG("%s: wait_event after: %d\n", __FUNCTION__, priv->wq_wkcond);
				priv->wq_wkcond = false;
			}
		}

		spin_lock_irqsave(&priv->state_lock, flags);

		/* Read data from the queue */
		//spin_lock_irqsave(&card->rx_cmd_event_ring.lock, flags);
		//PRINTM_DEBUG("%s: cmdeventq: qhead=%u qtail=%u count=%d\n", __FUNCTION__,
		//	card->rx_cmd_event_ring.qhead, card->rx_cmd_event_ring.qtail,
		//	cmdeventq_count(&card->rx_cmd_event_ring));
		if (cmdeventq_count(&card->rx_cmd_event_ring)) {
			cmdevent_buf = &card->rx_cmd_event_ring.buffers[card->rx_cmd_event_ring.qtail];
			rx_len = cmdevent_buf->size - SDIO_INTF_HEADER_LEN;
			PRINTM_DEBUG("%s: cmdevent rx_len: %d \n", __FUNCTION__, rx_len);
			if (copy_to_user(buf, (cmdevent_buf->buf_align + SDIO_INTF_HEADER_LEN), rx_len)) {
				PRINT_ERR("%s: cmdevent rx_len: %d \n", __FUNCTION__, rx_len);
				ret = -EFAULT;
			} else {
				ret = rx_len;
			}
			inc_cmdeventqtail(&card->rx_cmd_event_ring);
			card->cmd_resp_received = true;
		}
		//spin_unlock_irqrestore(&card->rx_cmd_event_ring.lock, flags);

		if (cmdevent_buf) {
			PRINTM_HEXDUMP("READ rx cmdevent buf: ", DUMP_PREFIX_OFFSET, 16, 1, cmdevent_buf->buf_align, cmdevent_buf->size, 1);
			goto out;
		}

		/* Read data from the queue */
		//spin_lock_irqsave(&card->rx_ring.rx_lock, flags);
		//PRINTM_DEBUG("%s: rxq_count: %d \n", __FUNCTION__, rxq_count(&card->rx_ring));
		if (rxq_count(&card->rx_ring)) {
			rx_buf = &card->rx_ring.buffers[card->rx_ring.qtail];
			rx_len = rx_buf->size - SDIO_INTF_HEADER_LEN;
			PRINTM_DEBUG("%s: data rx_len: %d \n", __FUNCTION__, rx_len);
			if (copy_to_user(buf, (rx_buf->buf_align + SDIO_INTF_HEADER_LEN), rx_len)) {
				PRINT_ERR("%s: data rx_len: %d \n", __FUNCTION__, rx_len);
				ret = -EFAULT;
			} else {
				ret = rx_len;
			}
			inc_rxqtail(&card->rx_ring);
			card->data_received = true;
		}
		//spin_unlock_irqrestore(&card->rx_ring.rx_lock, flags);

		if (rx_buf) {
			PRINTM_HEXDUMP("READ rx data buf: ", DUMP_PREFIX_OFFSET, 16, 1, rx_buf->buf_align, rx_buf->size, 1);
			goto out;
		}

		if (noblock) {
			ret = -EAGAIN;
			goto out;
		}

#if 0
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (time_after(jiffies, timeout)) {
			PRINT_ERR("RX timeout\n");
			ret = -EIO;
			goto out;
		}

		spin_unlock(&priv->state_lock);
		/* Nothing to read, let's sleep */
		schedule();
		spin_lock(&priv->state_lock);
	}
#endif

out:
#if 0
	if (!noblock) {
		if (priv) {
			PRINTM_DEBUG("%s: noblock=%d finish_wait AAA\n", __FUNCTION__, noblock);
			finish_wait(&priv->wq, &wait);
			PRINTM_DEBUG("%s: noblock=%d finish_wait BBB\n", __FUNCTION__, noblock);
		}
	}
#endif

	spin_unlock_irqrestore(&priv->state_lock, flags);
	//PRINTM_DEBUG("%s: Leave ret=%ld\n", __FUNCTION__, ret);
	return ret;
}

static void mcu_sdio_wakeup_card(struct mcu_sdio_misc_priv *priv, struct mcu_sdio_mmc_card * card)
{
    int ret = 0;

    ret = mcu_sdio_write_reg(card, HOST_TO_CARD_EVENT_REG, HOST_POWER_UP);
    if (ret)
        PRINT_ERR("%s: mcu_sdio_write_reg %x fail stat=0x%x\n", __FUNCTION__, HOST_TO_CARD_EVENT_REG, ret);
    ret = mcu_sdio_write_reg(card, HOST_TO_CARD_EVENT_REG, HOST_POWER_DOWN);
    if (ret)
        PRINT_ERR("%s: mcu_sdio_write_reg %x fail stat=0x%x\n", __FUNCTION__, HOST_TO_CARD_EVENT_REG, ret);
    ret = mcu_sdio_write_reg(card, HOST_TO_CARD_EVENT_REG, HOST_POWER_UP);
	if (ret)
        PRINT_ERR("%s: mcu_sdio_write_reg %x fail stat=0x%x\n", __FUNCTION__, HOST_TO_CARD_EVENT_REG, ret);
    mdelay(100);
    ret = mcu_sdio_write_reg(card, HOST_TO_CARD_EVENT_REG, HOST_POWER_DOWN);
	if (ret)
        PRINT_ERR("%s: mcu_sdio_write_reg %x fail stat=0x%x\n", __FUNCTION__, HOST_TO_CARD_EVENT_REG, ret);
}

static ssize_t mcu_sdio_misc_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret = -EFAULT;
	struct mcu_sdio_mmc_card *card;
	struct sdio_func *func;
	struct miscdevice *miscdev = file->private_data;
	struct mcu_sdio_misc_priv *priv = dev_get_drvdata(miscdev->this_device);
	u32 tx_len;
	NCP_COMMAND ncp_cmd = {0};
	bool is_data = false;
	u32 max_len = 0;
	sdio_header *sdio_hdr = NULL;
	unsigned long flags;

	PRINTM_DEBUG("%s: Enter file=%p buf=%p count=%lu ppos=%p\n", __FUNCTION__, file, buf, count, ppos);

	if (!priv->sdio_dev)
		return -EIO;

	if (count < sizeof(NCP_COMMAND))
		return -EINVAL;

	func = dev_to_sdio_func(priv->sdio_dev);
	card = sdio_get_drvdata(func);
	if (!card)
		return -EIO;

	if (copy_from_user((char *)(&ncp_cmd), buf, sizeof(NCP_COMMAND)) != 0) {
		PRINT_ERR("%s: copy_from_user fail for ncp hdr!\n", __FUNCTION__);
		ret = -EFAULT;
		goto out_w1;
	}
	PRINTM_HEXDUMP("WRITE input buf: ", DUMP_PREFIX_OFFSET, 16, 1, buf, count, 1);
	PRINTM_HEXDUMP("WRITE ncp_cmd: ", DUMP_PREFIX_OFFSET, 16, 1, (void *)&ncp_cmd, sizeof(NCP_COMMAND), 1);

	if ((ncp_cmd.cmd == 0) && (ncp_cmd.size == sizeof(NCP_COMMAND) - 1) &&
		(ncp_cmd.seqnum == 0) && (ncp_cmd.result == 0) && (GET_MSG_TYPE(ncp_cmd.cmd) == 0)) {
		PRINTM_DEBUG("%s: Special cmd to wakeup card!\n", __FUNCTION__);
		mcu_sdio_wakeup_card(priv, card);
		ret = count;
		goto out_w1;
	}

	if (ncp_cmd.size < sizeof(NCP_COMMAND)) {
		PRINT_ERR("%s: invalid ncp_cmd.size=%d!\n", __FUNCTION__, ncp_cmd.size);
		ret = -EFAULT;
		goto out_w1;
	}

	g_last_cmd_all = ncp_cmd.cmd;
	PRINTM_DEBUG("%s: g_last_cmd_all=0x%x\n", __FUNCTION__, g_last_cmd_all);

	if (ncp_cmd.cmd == NCP_CMD_SYSTEM_CONFIG_SDIO_SET) {
		int val = 0;
		int ret1 = 0;
		if (count >= (sizeof(NCP_COMMAND) + sizeof(int))) {
			if (copy_from_user((char *)(&val), buf + sizeof(NCP_COMMAND), sizeof(int)) != 0) {
				PRINT_ERR("%s: copy_from_user fail for SYSTEM_CONFIG_SDIO_SET!\n", __FUNCTION__);
				ret = -EFAULT;
				goto out_w1;
			}
			PRINTM_DEBUG("%s: SDIO_SET val=%d\n", __FUNCTION__, val);
			if (val == SDIO_SET_RE_ENUM) {
				int retry_cnt = 0;
				func->card->quirks |= MMC_QUIRK_LENIENT_FN0;
				/* wait for chip fully wake up */
				if (!func->enable_timeout)
					func->enable_timeout = 200;
				PRINTM_DEBUG("%s: sdio_claim_host ===\n", __FUNCTION__);
				sdio_claim_host(func);
				retry_cnt = 100;
				PRINTM_DEBUG("%s: try mmc_hw_reset retry_cnt=%d\n", __FUNCTION__, retry_cnt);
				do {
					ret1 = mmc_hw_reset(func->card);
					mdelay(100);
					PRINTM_DEBUG("try hw reset %d time\n", retry_cnt);
					retry_cnt--;
				} while (ret1 && retry_cnt > 0);
				if (ret1) {
					PRINT_ERR("%s: mmc_hw_reset %d time ret1=%d\n", __FUNCTION__, retry_cnt, ret1);
					//goto out_w1;
				}
				retry_cnt = RETRY_CNT;
				PRINTM_DEBUG("%s: try sdio_enable_func retry_cnt=%d\n", __FUNCTION__, retry_cnt);
				do {
					ret1 = sdio_enable_func(func);
					retry_cnt--;
				} while (ret1 && retry_cnt > 0);
				if (ret1) {
					PRINT_ERR("%s: sdio_enable_func() %d failed: ret1=%d\n", __FUNCTION__, retry_cnt, ret1);
					//goto out_w1;
				}

				retry_cnt = RETRY_CNT;
				PRINTM_DEBUG("%s: try mcu_sdio_init retry_cnt=%d\n", __FUNCTION__, retry_cnt);
				do {
					ret1 = mcu_sdio_init(card);
					retry_cnt--;
				} while (ret1 && retry_cnt > 0);
				if (ret1) {
					PRINT_ERR("%s: mcu_sdio_init() %d failed: ret1=%d\n", __FUNCTION__, retry_cnt, ret1);
					//goto out_w1;
				}

				/* Request the SDIO IRQ */
				retry_cnt = RETRY_CNT;
				PRINTM_DEBUG("%s: try sdio_claim_irq retry_cnt=%d\n", __FUNCTION__, retry_cnt);
				do {
					ret1 = sdio_claim_irq(func, mcu_sdio_interrupt);
					retry_cnt--;
				} while (ret1 && retry_cnt > 0);
				if (ret1) {
					PRINT_ERR("%s: sdio_claim_irq() %d failed: ret1=%d\n", __FUNCTION__, retry_cnt, ret1);
					//goto out_w1;
				}

				/* Set block size */
				retry_cnt = RETRY_CNT;
				PRINTM_DEBUG("%s: try sdio_set_block_size retry_cnt=%d\n", __FUNCTION__, retry_cnt);
				do {
					ret1 = sdio_set_block_size(func, MLAN_SDIO_BLOCK_SIZE);
					retry_cnt--;
				} while (ret1 && retry_cnt > 0);
				if (ret1) {
					//sdio_release_irq(func);
					PRINT_ERR("%s: sdio_set_block_size() %d %d failed: ret1=%d\n", __FUNCTION__, retry_cnt, MLAN_SDIO_BLOCK_SIZE, ret1);
					//goto out_w1;
				}

				/* re-enable host interrupt */
				retry_cnt = RETRY_CNT;
				PRINTM_DEBUG("%s: try mcu_enable_sdio_host_int retry_cnt=%d\n", __FUNCTION__, retry_cnt);
				do {
					ret1 = mcu_enable_sdio_host_int(card, card->regs->host_int_enable);
					retry_cnt--;
				} while (ret1 && retry_cnt > 0);
				if (ret1) {
					PRINT_ERR("%s: mcu_enable_sdio_host_int() %d failed: ret1=%d\n", __FUNCTION__, retry_cnt, ret1);
					//goto out_w1;
				}
				PRINTM_DEBUG("%s: sdio_release_host ===\n", __FUNCTION__);
				sdio_release_host(func);
			} else if ((val == SDIO_SET_DIS_INT_IRQ) || (val == SDIO_SET_DIS_INT_IRQ_TEST)) {
				while (card->cmd_sent) {
					//PRINTM_DEBUG("%s: mdelay(1) for cmd_sent=%d\n", __FUNCTION__, card->cmd_sent);
					mdelay(1);
				}
				while (card->data_sent) {
					//PRINTM_DEBUG("%s: mdelay(1) for data_sent=%d\n", __FUNCTION__, card->data_sent);
					mdelay(1);
				}
				sdio_claim_host(func);
				ret1 = mcu_disable_sdio_host_int(card, HIM_DISABLE);
				PRINTM_DEBUG("%s: mcu_disable_sdio_host_int ret1=%d\n", __FUNCTION__, ret1);
				ret1 = sdio_release_irq(func);
				PRINTM_DEBUG("%s: sdio_release_irq ret1=%d\n", __FUNCTION__, ret1);
				if (val == SDIO_SET_DIS_INT_IRQ_TEST) {
					ret1 = sdio_disable_func(func);
					PRINTM_DEBUG("%s: sdio_disable_func ret1=%d\n", __FUNCTION__, ret1);
				}
				sdio_release_host(func);
			}
		}
		ret = count;
		goto out_w1;
	}

	spin_lock_irqsave(&priv->state_lock, flags);

	g_last_cmd_app = ncp_cmd.cmd;
	PRINTM_DEBUG("%s: g_last_cmd_app=0x%x\n", __FUNCTION__, g_last_cmd_app);

	if ((ncp_cmd.cmd == NCP_CMD_WLAN_SOCKET_SEND) ||
		(ncp_cmd.cmd == NCP_CMD_WLAN_SOCKET_SENDTO)) {
		max_len = MAX_DATA_PAYLOAD_SIZE - SDIO_INTF_HEADER_LEN;
		if ((count > max_len) || (ncp_cmd.size > max_len)) {
			PRINT_ERR("%s: max_data_len=%d : invalid ncp_cmd: cmd=0x%x size=%d !\n",
				__FUNCTION__, max_len, ncp_cmd.cmd, ncp_cmd.size);
			ret = -EINVAL;
			goto out_w;
		}
		is_data = true;
	} else {
		max_len = MAX_CMD_EVENT_PAYLOAD_SIZE - SDIO_INTF_HEADER_LEN;
		if ((count > max_len) || (ncp_cmd.size > max_len)) {
			PRINT_ERR("%s: max_cmd_len=%d : invalid ncp_cmd: cmd=0x%x size=%d !\n",
				__FUNCTION__, max_len, ncp_cmd.cmd, ncp_cmd.size);
			ret = -EINVAL;
			goto out_w;
		}
	}

	if (is_data) {
		struct sdio_buffer *tx_buf = NULL;
		//spin_lock_irqsave(&card->tx_ring.tx_lock, flags);
		if (! txq_has_space(&card->tx_ring)) {
			PRINTM_DEBUG("TX ring full!\n");
			//spin_unlock_irqrestore(&card->tx_ring.tx_lock, flags);
			ret = count;
			goto out_w;
		}
		tx_buf = &card->tx_ring.buffers[card->tx_ring.qhead];
		tx_len = (count < max_len) ? count : max_len;
		if (copy_from_user((tx_buf->buf_align + SDIO_INTF_HEADER_LEN), buf, tx_len) != 0) {
			//spin_unlock_irqrestore(&card->tx_ring.tx_lock, flags);
			ret = -EFAULT;
			goto out_w;
		}
		sdio_hdr = (sdio_header *)(tx_buf->buf_align);
		sdio_hdr->len = tx_len + SDIO_INTF_HEADER_LEN;
		sdio_hdr->type = MLAN_TYPE_DATA;
		tx_buf->size = tx_len + SDIO_INTF_HEADER_LEN;
		inc_txqhead(&card->tx_ring);
		//spin_unlock_irqrestore(&card->tx_ring.tx_lock, flags);
		card->data_sent = true;
		PRINTM_DEBUG("%s: WRITE tx data buf %p %p %lu\n", __FUNCTION__, tx_buf, tx_buf->buf_align, tx_buf->size);
		PRINTM_HEXDUMP("WRITE tx data buf: ", DUMP_PREFIX_OFFSET, 16, 1, tx_buf->buf_align, tx_buf->size, 1);
	} else {
		struct sdio_cmd_event_buffer *cmd_buf = NULL;
		//spin_lock_irqsave(&card->tx_cmd_ring.lock, flags);
		if (! cmdq_has_space(&card->tx_cmd_ring)) {
			PRINTM_DEBUG("CMD ring full!\n");
			//spin_unlock_irqrestore(&card->tx_cmd_ring.lock, flags);
			ret = count;
			goto out_w;
		}
		cmd_buf = &card->tx_cmd_ring.buffers[card->tx_cmd_ring.qhead];
		tx_len = (count < max_len) ? count : max_len;
		if (copy_from_user((cmd_buf->buf_align + SDIO_INTF_HEADER_LEN), buf, tx_len) != 0) {
			//spin_unlock_irqrestore(&card->tx_cmd_ring.lock, flags);
			ret = -EFAULT;
			goto out_w;
		}
		sdio_hdr = (sdio_header *)(cmd_buf->buf_align);
		sdio_hdr->len = tx_len + SDIO_INTF_HEADER_LEN;
		sdio_hdr->type = MLAN_TYPE_CMD;
		cmd_buf->size = tx_len + SDIO_INTF_HEADER_LEN;
		inc_cmdqhead(&card->tx_cmd_ring);
		//spin_unlock_irqrestore(&card->tx_cmd_ring.lock, flags);
		card->cmd_sent = true;
		PRINTM_DEBUG("%s: WRITE tx cmd buf %p %p %lu\n", __FUNCTION__, cmd_buf, cmd_buf->buf_align, cmd_buf->size);
		PRINTM_HEXDUMP("WRITE tx cmd buf: ", DUMP_PREFIX_OFFSET, 16, 1, cmd_buf->buf_align, cmd_buf->size, 1);
	}

	queue_delayed_work(priv->tx_workqueue, &priv->tx_dwork, 1);
	ret = tx_len;

out_w:
	spin_unlock_irqrestore(&priv->state_lock, flags);
out_w1:
	PRINTM_DEBUG("%s: Leave count=%lu ret=%ld\n", __FUNCTION__, count, ret);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
static int match_first_device(struct device *dev, void *data)
#else
static int match_first_device(struct device *dev, const void *data)
#endif
{
	struct sdio_driver *sdio_drv = (struct sdio_driver *) data;
	struct mcu_sdio_mmc_card *card;
	struct sdio_func *func;
	int i;

	func = dev_to_sdio_func(dev);
	card = sdio_get_drvdata(func);

	for (i = 0; sdio_drv->id_table[i].vendor && sdio_drv->id_table[i].device;
		i++) {
		if ((sdio_drv->id_table[i].vendor == func->vendor) &&
			(sdio_drv->id_table[i].device == func->device) &&
			card)
			return 1;
	}

	return 0;
}

static int mcu_sdio_misc_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct mcu_sdio_misc_priv *priv = dev_get_drvdata(miscdev->this_device);
	unsigned long flags;
	int ret;
	g_dev_noblock = file->f_flags & O_NONBLOCK;

	PRINTM_DEBUG("%s: Enter inode=%p file=%p priv=%p open_cnt=%d g_dev_noblock=%d\n", __FUNCTION__, inode, file, priv, priv->open_cnt, g_dev_noblock);
	if (! priv->sdio_dev) {
		struct bus_type *sdio_bus_type;
		struct device *mcu_sdio_dev;
		struct mcu_sdio_mmc_card *card;
		struct sdio_func *func;

		sdio_bus_type = (priv->sdio_drv)->drv.bus;
		mcu_sdio_dev = bus_find_device(sdio_bus_type, NULL,
						(void *) priv->sdio_drv,
						match_first_device);
		if (! mcu_sdio_dev) {
			PRINT_ERR("Cannot find MCU SDIO device\n");
			return -EIO;
		}
		priv->sdio_dev = mcu_sdio_dev;

		func = dev_to_sdio_func(mcu_sdio_dev);
		card = sdio_get_drvdata(func);
		card->misc_priv = priv;
	};

	spin_lock_irqsave(&priv->state_lock, flags);

	/* Prevent multiple readers/writers if desired. */
	if (priv->open_cnt) {
		ret = -EBUSY;
	} else {
		priv->open_cnt++;
		ret = 0;
	}

	spin_unlock_irqrestore(&priv->state_lock, flags);

	PRINTM_DEBUG("%s: Leave priv=%p open_cnt=%d\n", __FUNCTION__, priv, priv->open_cnt);
	return ret;
}

static int mcu_sdio_misc_release(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct mcu_sdio_misc_priv *priv = dev_get_drvdata(miscdev->this_device);
	unsigned long flags;

	PRINTM_DEBUG("%s: Enter inode=%p file=%p priv=%p open_cnt=%d\n", __FUNCTION__, inode, file, priv, priv->open_cnt);
	spin_lock_irqsave(&priv->state_lock, flags);

	if (priv->open_cnt)
		priv->open_cnt--;

	spin_unlock_irqrestore(&priv->state_lock, flags);

	PRINTM_DEBUG("%s: Leave priv=%p open_cnt=%d\n", __FUNCTION__, priv, priv->open_cnt);
	return 0;
}

static const struct file_operations mcu_sdio_misc_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.read		= mcu_sdio_misc_read,
	.write		= mcu_sdio_misc_write,
	.open		= mcu_sdio_misc_open,
	.release	= mcu_sdio_misc_release,
};

static struct miscdevice mcu_sdio_misc = {
	MISC_DYNAMIC_MINOR,
	"mcu-sdio",
	&mcu_sdio_misc_fops,
};

static int __init mcu_sdio_module_init(void)
{
	int ret;
	struct mcu_sdio_misc_priv *priv;

	/* SDIO driver registration */
	ret = sdio_register_driver(&mcu_sdio_driver);
	if (ret) {
		PRINT_ERR("mcu-sdio: SDIO driver registration failed \n");
		return ret;
	}

	ret = misc_register(&mcu_sdio_misc);
	if (ret) {
		PRINT_ERR("mcu-sdio: can't misc_register\n");
		return ret;
	}

	priv = kzalloc(sizeof(struct mcu_sdio_mmc_card), GFP_KERNEL);
	if (! priv) {
		PRINT_ERR("Failed to allocate memory!\n");
		return -ENOMEM;
	}

	priv->sdio_drv = &mcu_sdio_driver;
	priv->sdio_dev = NULL;
	priv->open_cnt = 0;

	spin_lock_init(&priv->state_lock);
	priv->wq_wkcond = false;
	init_waitqueue_head(&priv->wq);

	priv->tx_workqueue = alloc_workqueue("MCU_SDIO_TX_WORKQ",
				WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (! priv->tx_workqueue) {
		PRINT_ERR("Failed to allocate tx workqueue!\n");
		return -ENOMEM;
	}
	INIT_DELAYED_WORK(&priv->tx_dwork, mcu_sdio_tx_function);

	priv->rx_workqueue = alloc_workqueue("MCU_SDIO_RX_WORKQ",
				WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (! priv->rx_workqueue) {
		PRINT_ERR("Failed to allocate rx workqueue!\n");
		return -ENOMEM;
	}
	INIT_DELAYED_WORK(&priv->rx_dwork, mcu_sdio_rx_function);

	dev_set_drvdata(mcu_sdio_misc.this_device, priv);

	PRINT_INFO("MCU SDIO simple driver v" MCU_SDIO_VERSION "\n");
	return 0;
}

static void __exit mcu_sdio_module_exit(void)
{
	/* SDIO driver unregistration */
	sdio_unregister_driver(&mcu_sdio_driver);

	misc_deregister(&mcu_sdio_misc);
}

module_param(drvdbg, uint, 0);
MODULE_PARM_DESC(drvdbg, "BIT0:HEXDUMP BIT1:DEBUG");

module_init(mcu_sdio_module_init);
module_exit(mcu_sdio_module_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("devname:mcu-sdio");
