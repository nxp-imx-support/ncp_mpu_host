/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#include "gpio_ncp_adapter.h"
#include "ncp_pm_os.h"
#include "ncp_pm_defs.h"

/*******************************************************************************
 * Code
 ******************************************************************************/

void ncp_pm_gpio_wakeup_peer(void)
{
    ncp_gpio_wakeup_peer(100);
}

int ncp_pm_os_init(void)
{
    ncp_gpio_adapter_init();

    return NCP_PM_STATUS_SUCCESS;
}

void ncp_pm_os_deinit(void)
{
    ncp_gpio_adapter_deinit();
}

void ncp_pm_init_wakeup_source(void *ws, uint32_t wsId, bool enable)
{
}

void ncp_pm_enable_wakeup_source(void *ws)
{
}

void ncp_pm_disable_wakeup_source(void *ws)
{
}

void ncp_pm_get_wakeup_source(void *ws)
{
}

void ncp_pm_os_activate_lp_timer(uint32_t duration_ms)
{
}