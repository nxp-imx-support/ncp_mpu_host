/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "gpio_ncp_adapter.h"
#include "ncp_log.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

NCP_LOG_MODULE_REGISTER(ncp_gpio, CONFIG_LOG_NCP_GPIO_LEVEL);

/* Event flags for NCP GPIO signals */
#define NCP_GPIO_EVENT_DEVICE_NOTIFY  (1U << 0)
#define NCP_GPIO_EVENT_ALL            (NCP_GPIO_EVENT_DEVICE_NOTIFY)

/*******************************************************************************
 * Variables
 ******************************************************************************/

static ncp_gpio_context_t g_ncp_gpio_ctx = {0};

OSA_MUTEX_HANDLE_DEFINE(ncp_gpio_mutex_handle);
OSA_EVENT_HANDLE_DEFINE(ncp_gpio_event_handle);

/* GPIO configuration for NCP signals */
static const ncp_gpio_config_t ncp_gpio_configs[NCP_GPIO_SIG_MAX] = {
    [NCP_GPIO_SIG_WAKEUP_DEVICE] = {
        .chip_num = NCP_GPIO_CHIP_NUM,
        .pin_num = NCP_GPIO_WAKEUP_DEVICE_PIN,
        .direction = GPIO_DIR_OUTPUT,
        .pull = GPIO_PULL_NONE,
        .interrupt_edge = GPIO_EDGE_NONE,
        .enable_interrupt = false,
        .label = "ncp_wakeup_device"
    }
};

/*******************************************************************************
 * Code
 ******************************************************************************/

static void ncp_gpio_event_callback(gpio_handle_t *handle, gpio_edge_t edge, void *data)
{
    ncp_gpio_signal_t signal = (ncp_gpio_signal_t)(uintptr_t)data;
    uint32_t event_flag = 0;

    switch (signal)
    {
        default:
            return;
    }

    /* Set event flag atomically */
    __atomic_or_fetch(&g_ncp_gpio_ctx.event_flags, event_flag, __ATOMIC_SEQ_CST);

    /* Signal the event for waiters */
    if (g_ncp_gpio_ctx.event)
    {
        OSA_EventSet(g_ncp_gpio_ctx.event, event_flag);
    }
}

int ncp_gpio_adapter_init(void)
{
    int ret;
    osa_status_t status;

    if (g_ncp_gpio_ctx.initialized)
    {
        NCP_LOG_DBG("NCP GPIO adapter already initialized");
        return 0;
    }

    /* Initialize base GPIO subsystem */
    ret = gpio_init();
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to initialize GPIO subsystem");
        return ret;
    }

    /* Create mutex */
    g_ncp_gpio_ctx.mutex = (osa_mutex_handle_t)ncp_gpio_mutex_handle;
    status = OSA_MutexCreate(g_ncp_gpio_ctx.mutex);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to create mutex");
        gpio_deinit();
        return -1;
    }

    /* Create event */
    g_ncp_gpio_ctx.event = (osa_event_handle_t)ncp_gpio_event_handle;
    status = OSA_EventCreate(g_ncp_gpio_ctx.event, 1); /* Auto-clear */
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to create event");
        OSA_MutexDestroy(g_ncp_gpio_ctx.mutex);
        gpio_deinit();
        return -1;
    }

    /* Initialize event IDs to invalid */
    for (int i = 0; i < NCP_GPIO_SIG_MAX; i++)
    {
        g_ncp_gpio_ctx.event_ids[i] = -1;
    }

    /* Clear event flags */
    g_ncp_gpio_ctx.event_flags = 0;

    /* Initialize GPIO signals */
    for (int i = 0; i < NCP_GPIO_SIG_MAX; i++)
    {
        const ncp_gpio_config_t *cfg = &ncp_gpio_configs[i];
        gpio_handle_t *handle = &g_ncp_gpio_ctx.handles[i];

        ret = gpio_open(handle, cfg->chip_num, cfg->pin_num);
        if (ret != 0)
        {
            NCP_LOG_ERR("Failed to open GPIO %d_%d", cfg->chip_num, cfg->pin_num);
            continue;
        }

        if (cfg->direction == GPIO_DIR_OUTPUT)
        {
            /* Configure as output */
            ret = gpio_configure(handle, cfg->direction, cfg->pull,
                                GPIO_LEVEL_HIGH, cfg->label);
            if (ret != 0)
            {
                NCP_LOG_ERR("Failed to configure GPIO %d_%d as output",
                                cfg->chip_num, cfg->pin_num);
                gpio_close(handle);
                continue;
            }
            NCP_LOG_DBG("Configured GPIO %d_%d as output (%s)",
                        cfg->chip_num, cfg->pin_num, cfg->label);
        }
        else if (cfg->enable_interrupt)
        {
            /* Register interrupt event (handled by single epoll task in driver) */
            g_ncp_gpio_ctx.event_ids[i] = gpio_register_event(handle, cfg->interrupt_edge,
                                                            ncp_gpio_event_callback,
                                                             (void *)(uintptr_t)i);

            if (g_ncp_gpio_ctx.event_ids[i] < 0)
            {
                NCP_LOG_ERR("Failed to register event for GPIO %d_%d",
                                cfg->chip_num, cfg->pin_num);
                gpio_close(handle);
                continue;
            }
            NCP_LOG_DBG("Registered event %d for GPIO %d_%d",
                            g_ncp_gpio_ctx.event_ids[i], cfg->chip_num, cfg->pin_num);
        }
        else
        {
            /* Configure as input without interrupt */
            ret = gpio_configure(handle, cfg->direction, cfg->pull,
                                GPIO_LEVEL_LOW, cfg->label);
            if (ret != 0)
            {
                NCP_LOG_ERR("Failed to configure GPIO %d_%d as input",
                                cfg->chip_num, cfg->pin_num);
                gpio_close(handle);
                continue;
            }
            NCP_LOG_INF("Configured GPIO %d_%d as input (%s)",
                        cfg->chip_num, cfg->pin_num, cfg->label);
        }
    }

    g_ncp_gpio_ctx.initialized = true;
    NCP_LOG_DBG("NCP GPIO adapter initialized");

    return 0;
}

int ncp_gpio_adapter_deinit(void)
{
    if (!g_ncp_gpio_ctx.initialized)
    {
        return 0;
    }

    OSA_MutexLock(g_ncp_gpio_ctx.mutex, osaWaitForever_c);

    /* Unregister events and close GPIOs */
    for (int i = 0; i < NCP_GPIO_SIG_MAX; i++)
    {
        if (g_ncp_gpio_ctx.event_ids[i] >= 0)
        {
            gpio_unregister_event(g_ncp_gpio_ctx.event_ids[i]);
            g_ncp_gpio_ctx.event_ids[i] = -1;
        }

        if (g_ncp_gpio_ctx.handles[i].is_open)
        {
            gpio_close(&g_ncp_gpio_ctx.handles[i]);
        }
    }

    OSA_MutexUnlock(g_ncp_gpio_ctx.mutex);

    /* Destroy OS resources */
    if (g_ncp_gpio_ctx.event)
    {
        OSA_EventDestroy(g_ncp_gpio_ctx.event);
        g_ncp_gpio_ctx.event = NULL;
    }

    if (g_ncp_gpio_ctx.mutex)
    {
        OSA_MutexDestroy(g_ncp_gpio_ctx.mutex);
        g_ncp_gpio_ctx.mutex = NULL;
    }

    /* Deinitialize base GPIO subsystem */
    gpio_deinit();

    g_ncp_gpio_ctx.initialized = false;
    NCP_LOG_DBG("NCP GPIO adapter deinitialized");

    return 0;
}

int ncp_gpio_wakeup_peer(uint32_t pulse_duration_us)
{
    gpio_handle_t *handle;
    int ret;

    if (!g_ncp_gpio_ctx.initialized)
    {
        NCP_LOG_ERR("NCP GPIO adapter not initialized");
        return -EINVAL;
    }

    handle = &g_ncp_gpio_ctx.handles[NCP_GPIO_SIG_WAKEUP_DEVICE];

    if (!handle->is_open)
    {
        NCP_LOG_ERR("Wakeup device GPIO not available");
        return -EINVAL;
    }

    OSA_MutexLock(g_ncp_gpio_ctx.mutex, osaWaitForever_c);

    /* Generate wakeup pulse: LOW -> HIGH */
    ret = gpio_set_value(handle, GPIO_LEVEL_LOW);
    if (ret == 0)
    {
        usleep(pulse_duration_us);
        ret = gpio_set_value(handle, GPIO_LEVEL_HIGH);
    }

    OSA_MutexUnlock(g_ncp_gpio_ctx.mutex);

    if (ret == 0)
    {
        NCP_LOG_DBG("Wakeup pulse sent (%u us)", pulse_duration_us);
    }
    else
    {
        NCP_LOG_ERR("Failed to send wakeup pulse");
    }

    return ret;
}

int ncp_gpio_set_signal(ncp_gpio_signal_t signal, gpio_level_t value)
{
    gpio_handle_t *handle;
    int ret;

    if (!g_ncp_gpio_ctx.initialized || signal >= NCP_GPIO_SIG_MAX)
    {
        return -EINVAL;
    }

    handle = &g_ncp_gpio_ctx.handles[signal];

    if (!handle->is_open)
    {
        return -EINVAL;
    }

    if (handle->direction != GPIO_DIR_OUTPUT)
    {
        NCP_LOG_ERR("Signal %d is not configured as output", signal);
        return -EINVAL;
    }

    OSA_MutexLock(g_ncp_gpio_ctx.mutex, osaWaitForever_c);
    ret = gpio_set_value(handle, value);
    OSA_MutexUnlock(g_ncp_gpio_ctx.mutex);

    if (ret == 0)
    {
        NCP_LOG_DBG("Set signal %d to %s", signal,
                        value == GPIO_LEVEL_HIGH ? "HIGH" : "LOW");
    }

    return ret;
}

int ncp_gpio_get_signal(ncp_gpio_signal_t signal, gpio_level_t *value)
{
    gpio_handle_t *handle;
    int ret;

    if (!g_ncp_gpio_ctx.initialized || signal >= NCP_GPIO_SIG_MAX || !value)
    {
        return -EINVAL;
    }

    handle = &g_ncp_gpio_ctx.handles[signal];

    if (!handle->is_open)
    {
        return -EINVAL;
    }

    OSA_MutexLock(g_ncp_gpio_ctx.mutex, osaWaitForever_c);
    ret = gpio_get_value(handle, value);
    OSA_MutexUnlock(g_ncp_gpio_ctx.mutex);

    if (ret == 0)
    {
        NCP_LOG_DBG("Get signal %d: %s", signal,
                     *value == GPIO_LEVEL_HIGH ? "HIGH" : "LOW");
    }

    return ret;
}

int ncp_gpio_wait_event(uint32_t event_mask, uint32_t timeout_ms, uint32_t *triggered_events)
{
    osa_status_t status;
    osa_event_flags_t flags = 0;

    if (!g_ncp_gpio_ctx.initialized || !g_ncp_gpio_ctx.event)
    {
        return -EINVAL;
    }

    /* Clear any already handled events from our tracking */
    uint32_t pending = __atomic_and_fetch(&g_ncp_gpio_ctx.event_flags,
                                        ~event_mask, __ATOMIC_SEQ_CST);
    /* If events are already pending, return immediately */
    pending &= event_mask;
    if (pending)
    {
        if (triggered_events)
        {
            *triggered_events = pending;
        }
        return 0;
    }

    /* Wait for new events */
    status = OSA_EventWait(g_ncp_gpio_ctx.event, event_mask, 0, timeout_ms, &flags);

    if (triggered_events)
    {
        *triggered_events = flags & event_mask;
    }

    if (status == KOSA_StatusSuccess)
    {
        NCP_LOG_DBG("Events received: 0x%08x", flags);
        return 0;
    }
    else if (status == KOSA_StatusTimeout)
    {
        NCP_LOG_DBG("Wait timeout");
        return -ETIMEDOUT;
    }
    else
    {
        NCP_LOG_ERR("Wait failed: %d", status);
        return -1;
    }
}

int ncp_gpio_clear_events(uint32_t event_mask)
{
    if (!g_ncp_gpio_ctx.initialized)
    {
        return -EINVAL;
    }

    /* Clear event flags atomically */
    __atomic_and_fetch(&g_ncp_gpio_ctx.event_flags, ~event_mask, __ATOMIC_SEQ_CST);

    /* Also clear from OSA event if needed */
    if (g_ncp_gpio_ctx.event)
    {
        OSA_EventClear(g_ncp_gpio_ctx.event, event_mask);
    }

    NCP_LOG_DBG("Cleared events: 0x%08x", event_mask);

    return 0;
}

int ncp_gpio_get_pending_events(uint32_t *events)
{
    if (!g_ncp_gpio_ctx.initialized || !events)
    {
        return -EINVAL;
    }

    /* Read event flags atomically */
    *events = __atomic_load_n(&g_ncp_gpio_ctx.event_flags, __ATOMIC_SEQ_CST);

    NCP_LOG_DBG("Pending events: 0x%08x", *events);

    return 0;
}
