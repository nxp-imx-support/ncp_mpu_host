/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NCP_LPM_H__
#define __NCP_LPM_H__
#include "ncp_adapter.h"

#define GPIO_DEV_PATH          "/dev/gpiochip4"
#define GPIO_POLL_BUF_LEN 32

/* Power Mode Index */
#define NCP_PM_STATE_PM0           (0U)
#define NCP_PM_STATE_PM1           (1U)
#define NCP_PM_STATE_PM2           (2U)
#define NCP_PM_STATE_PM3           (3U)
#define NCP_PM_STATE_PM4           (4U)

ncp_status_t device_notify_gpio_init();
ncp_status_t device_notify_gpio_deinit();
void set_lpm_gpio_value(uint8_t aValue);
void ncp_lpm_gpio_init(void);

#endif /* __NCP_LPM_H__ */

