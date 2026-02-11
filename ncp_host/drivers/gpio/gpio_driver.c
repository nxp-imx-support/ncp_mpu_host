/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <linux/gpio.h>
#include <linux/version.h>
#include "gpio_driver.h"
#include "ncp_log.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

NCP_LOG_MODULE_REGISTER(gpio, CONFIG_LOG_GPIO_LEVEL);

#define GPIO_DEV_PATH_FMT "/dev/gpiochip%d"
#define GPIO_DEV_PATH_LEN 32
#define GPIO_LABEL_LEN    32

#define GPIO_CHECK_INIT() \
    do { \
        if (!g_gpio_manager.initialized) { \
            NCP_LOG_ERR("GPIO subsystem not initialized"); \
            return -EINVAL; \
        } \
    } while(0)

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* Task resources */
static void gpio_monitor_task(osa_task_param_t param);
OSA_TASK_HANDLE_DEFINE(gpio_monitor_task_handle);
OSA_TASK_DEFINE(gpio_monitor_task, OSA_PRIORITY_NORMAL, 1, 4096, 0);
OSA_MUTEX_HANDLE_DEFINE(gpio_mutex_handle);

static gpio_manager_t g_gpio_manager = {0};

/*******************************************************************************
 * Internal Functions
 ******************************************************************************/

static int gpio_cleanup_event_internal(gpio_event_handler_t *handler)
{
    if (!handler || !handler->active)
    {
        return -EINVAL;
    }

    gpio_handle_t *handle = handler->handle;

    if (g_gpio_manager.monitor.epoll_fd > 0 && handle->line_fd >= 0)
    {
        if (epoll_ctl(g_gpio_manager.monitor.epoll_fd, EPOLL_CTL_DEL,
                      handle->line_fd, NULL) != 0)
        {
            NCP_LOG_WRN("Failed to remove fd %d from epoll: %s",
                        handle->line_fd, strerror(errno));
        }
    }

    if (handle->line_fd >= 0)
    {
        close(handle->line_fd);
        handle->line_fd = -1;
    }

    handler->active = false;
    g_gpio_manager.monitor.handler_count--;

    NCP_LOG_DBG("Cleaned up event handler %d for GPIO %d_%d",
                handle->event_id, handle->chip_num, handle->line_num);

    memset(handler, 0, sizeof(gpio_event_handler_t));

    handle->event_id = -1;

    return 0;
}

/**
 * @brief Single task that monitors all GPIO events using epoll
 */
static void gpio_monitor_task(osa_task_param_t param)
{
    struct epoll_event events[GPIO_MAX_EVENT_HANDLERS];
    struct gpioevent_data gpio_event;
    gpio_edge_t edge = GPIO_EDGE_NONE;
    gpio_event_handler_t *handler = NULL;
    int nfds, i;

    NCP_LOG_DBG("GPIO monitor task started");

    g_gpio_manager.monitor.task_exited = false;

    while (g_gpio_manager.monitor.running)
    {
        nfds = epoll_wait(g_gpio_manager.monitor.epoll_fd, events,
                        GPIO_MAX_EVENT_HANDLERS, GPIO_EPOLL_TIMEOUT_MS);

        if (nfds > 0)
        {
            for (i = 0; i < nfds; i++)
            {
                handler = (gpio_event_handler_t *)events[i].data.ptr;

                if (!handler || !handler->active)
                {
                    NCP_LOG_DBG("Received event for inactive handler");
                    continue;
                }

                /* Read GPIO event data */
                if (read(handler->handle->line_fd, &gpio_event,
                        sizeof(gpio_event)) == sizeof(gpio_event))
                {
                    edge = GPIO_EDGE_NONE;

                    /* Determine edge type */
                    if (gpio_event.id == GPIOEVENT_EVENT_RISING_EDGE)
                    {
                        edge = GPIO_EDGE_RISING;
                    }
                    else if (gpio_event.id == GPIOEVENT_EVENT_FALLING_EDGE)
                    {
                        edge = GPIO_EDGE_FALLING;
                    }

                    NCP_LOG_DBG("GPIO event: chip%d_line%d, edge=%d, timestamp=%llu",
                                handler->handle->chip_num, handler->handle->line_num,
                                edge, gpio_event.timestamp);

                    /* Call user callback */
                    if (handler->callback)
                    {
                        handler->callback(handler->handle, edge, handler->user_data);
                    }
                }
            }
        }
        else if (nfds < 0 && errno != EINTR)
        {
            NCP_LOG_ERR("epoll_wait error: %s", strerror(errno));
            OSA_TimeDelay(100);
        }
    }

    NCP_LOG_DBG("GPIO monitor task exiting");
    g_gpio_manager.monitor.task_exited = true;
}

/**
 * @brief Initialize the GPIO monitor (epoll and monitoring task)
 */
static int gpio_monitor_init(void)
{
    osa_status_t status;

    if (g_gpio_manager.monitor.epoll_fd > 0)
    {
        return 0; /* Already initialized */
    }

    /* Create epoll instance */
    g_gpio_manager.monitor.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_gpio_manager.monitor.epoll_fd < 0)
    {
        NCP_LOG_ERR("Failed to create epoll: %s", strerror(errno));
        return -errno;
    }

    /* Initialize handlers */
    memset(g_gpio_manager.monitor.handlers, 0, sizeof(g_gpio_manager.monitor.handlers));
    g_gpio_manager.monitor.handler_count = 0;

    /* Create monitoring task */
    g_gpio_manager.monitor.running = true;
    g_gpio_manager.monitor.monitor_task = (osa_task_handle_t)gpio_monitor_task_handle;

    status = OSA_TaskCreate(g_gpio_manager.monitor.monitor_task,
                            OSA_TASK(gpio_monitor_task), NULL);

    if (status != KOSA_StatusSuccess)
    {
        close(g_gpio_manager.monitor.epoll_fd);
        g_gpio_manager.monitor.epoll_fd = -1;
        g_gpio_manager.monitor.running  = false;
        NCP_LOG_ERR("Failed to create monitor task");
        return -1;
    }

    NCP_LOG_DBG("GPIO monitor initialized");
    return 0;
}

/**
 * @brief Deinitialize the GPIO monitor
 */
static void gpio_monitor_deinit(void)
{
    if (g_gpio_manager.monitor.epoll_fd <= 0)
    {
        return;
    }

    /* Stop monitoring task */
    g_gpio_manager.monitor.running = false;

    if (g_gpio_manager.monitor.monitor_task)
    {
        while (!g_gpio_manager.monitor.task_exited)
        {
            OSA_TimeDelay(10);
        }
        OSA_TaskDestroy(g_gpio_manager.monitor.monitor_task);
        g_gpio_manager.monitor.monitor_task = NULL;
    }

    /* Clean up all active handlers */
    OSA_MutexLock(g_gpio_manager.mutex, osaWaitForever_c);

    for (int i = 0; i < GPIO_MAX_EVENT_HANDLERS; i++)
    {
        if (g_gpio_manager.monitor.handlers[i].active)
        {
            gpio_event_handler_t *handler = &g_gpio_manager.monitor.handlers[i];

            if (handler->handle->line_fd >= 0)
            {
                epoll_ctl(g_gpio_manager.monitor.epoll_fd, EPOLL_CTL_DEL,
                          handler->handle->line_fd, NULL);
                close(handler->handle->line_fd);
                handler->handle->line_fd = -1;
            }

            if (handler->handle->event_id == i)
            {
                handler->handle->event_id = -1;
            }

            /* Clear handler */
            handler->active = false;
            g_gpio_manager.monitor.handler_count--;

            NCP_LOG_DBG("Cleaned up event handler %d during deinit", i);
        }
    }

    /* Clear all handler data */
    memset(g_gpio_manager.monitor.handlers, 0, sizeof(g_gpio_manager.monitor.handlers));

    OSA_MutexUnlock(g_gpio_manager.mutex);

    /* Close epoll */
    close(g_gpio_manager.monitor.epoll_fd);
    g_gpio_manager.monitor.epoll_fd = -1;

    NCP_LOG_DBG("GPIO monitor deinitialized");
}

/*******************************************************************************
 * Public Functions
 ******************************************************************************/

int gpio_init(void)
{
    osa_status_t status;

    if (g_gpio_manager.initialized)
    {
        NCP_LOG_WRN("GPIO already initialized");
        return 0;
    }

    /* Create mutex */
    g_gpio_manager.mutex = (osa_mutex_handle_t)gpio_mutex_handle;
    status = OSA_MutexCreate(g_gpio_manager.mutex);
    if (status != KOSA_StatusSuccess)
    {
        NCP_LOG_ERR("Failed to create mutex");
        return -1;
    }

    /* Initialize monitor */
    memset(&g_gpio_manager.monitor, 0, sizeof(g_gpio_manager.monitor));

    if (gpio_monitor_init() < 0)
    {
        NCP_LOG_ERR("Failed to initialize GPIO monitor");
        OSA_MutexDestroy(g_gpio_manager.mutex);
        return -1;
    }

    g_gpio_manager.initialized = true;

    NCP_LOG_DBG("GPIO subsystem initialized");

    return 0;
}

int gpio_deinit(void)
{
    GPIO_CHECK_INIT();

    /* Deinitialize monitor */
    gpio_monitor_deinit();

    OSA_MutexDestroy(g_gpio_manager.mutex);

    g_gpio_manager.initialized = false;
    NCP_LOG_DBG("GPIO subsystem deinitialized");

    return 0;
}

int gpio_open(gpio_handle_t *handle, uint8_t chip_num, uint8_t line_num)
{
    char dev_path[GPIO_DEV_PATH_LEN];

    GPIO_CHECK_INIT();

    if (!handle)
    {
        NCP_LOG_ERR("Invalid handle");
        return -EINVAL;
    }

    if (chip_num >= GPIO_MAX_CHIPS || line_num >= GPIO_MAX_LINES)
    {
        NCP_LOG_ERR("Invalid chip %d or line %d", chip_num, line_num);
        return -EINVAL;
    }

    snprintf(dev_path, sizeof(dev_path), GPIO_DEV_PATH_FMT, chip_num);

    handle->chip_fd = open(dev_path, O_RDONLY);
    if (handle->chip_fd < 0)
    {
        NCP_LOG_ERR("Failed to open %s: %s", dev_path, strerror(errno));
        return -errno;
    }

    handle->chip_num = chip_num;
    handle->line_num = line_num;
    handle->line_fd = -1;
    handle->is_open = true;
    handle->event_id = -1;

    NCP_LOG_DBG("Opened GPIO chip %d, line %d", chip_num, line_num);

    return 0;
}

int gpio_close(gpio_handle_t *handle)
{
    GPIO_CHECK_INIT();

    if (!handle || !handle->is_open)
    {
        return -EINVAL;
    }

    OSA_MutexLock(g_gpio_manager.mutex, osaWaitForever_c);

    if (handle->event_id >= 0 && handle->event_id < GPIO_MAX_EVENT_HANDLERS)
    {
        gpio_event_handler_t *handler = &g_gpio_manager.monitor.handlers[handle->event_id];
        gpio_cleanup_event_internal(handler);
    }

    if (handle->line_fd >= 0)
    {
        close(handle->line_fd);
        handle->line_fd = -1;
    }

    if (handle->chip_fd >= 0)
    {
        close(handle->chip_fd);
        handle->chip_fd = -1;
    }

    handle->is_open = false;

    OSA_MutexUnlock(g_gpio_manager.mutex);

    NCP_LOG_DBG("Closed GPIO chip %d, line %d", handle->chip_num, handle->line_num);

    return 0;
}

int gpio_configure(gpio_handle_t *handle, gpio_direction_t direction,
                  gpio_pull_t pull, gpio_level_t initial_value, const char *label)
{
    struct gpiohandle_request req;
    int ret;

    if (!handle || !handle->is_open)
    {
        return -EINVAL;
    }

    OSA_MutexLock(g_gpio_manager.mutex, osaWaitForever_c);

    if (handle->event_id >= 0)
    {
        gpio_event_handler_t *handler = &g_gpio_manager.monitor.handlers[handle->event_id];
        gpio_cleanup_event_internal(handler);
    }

    if (handle->line_fd >= 0)
    {
        close(handle->line_fd);
        handle->line_fd = -1;
    }

    memset(&req, 0, sizeof(req));
    req.lines = 1;
    req.lineoffsets[0] = handle->line_num;

    /* Set direction flags */
    if (direction == GPIO_DIR_OUTPUT)
    {
        req.flags = GPIOHANDLE_REQUEST_OUTPUT;
        req.default_values[0] = initial_value;
    }
    else
    {
        req.flags = GPIOHANDLE_REQUEST_INPUT;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    /* Set pull flags */
    if (pull == GPIO_PULL_UP)
    {
        req.flags |= GPIOHANDLE_REQUEST_BIAS_PULL_UP;
    }
    else if (pull == GPIO_PULL_DOWN)
    {
        req.flags |= GPIOHANDLE_REQUEST_BIAS_PULL_DOWN;
    }
#endif

    /* Set consumer label */
    if (label)
    {
        snprintf(req.consumer_label, sizeof(req.consumer_label), "%s", label);
    }
    else
    {
        snprintf(req.consumer_label, sizeof(req.consumer_label), "gpio_%d_%d",
                handle->chip_num, handle->line_num);
    }

    ret = ioctl(handle->chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &req);
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to configure GPIO line %d: %s", handle->line_num, strerror(errno));
        OSA_MutexUnlock(g_gpio_manager.mutex);
        return -errno;
    }

    handle->line_fd = req.fd;
    handle->direction = direction;

    OSA_MutexUnlock(g_gpio_manager.mutex);

    NCP_LOG_DBG("Configured GPIO %d_%d as %s", handle->chip_num, handle->line_num,
                direction == GPIO_DIR_OUTPUT ? "output" : "input");

    return 0;
}

int gpio_set_value(gpio_handle_t *handle, gpio_level_t value)
{
    struct gpiohandle_data data;
    int ret;

    if (!handle || !handle->is_open || handle->line_fd < 0)
    {
        return -EINVAL;
    }

    if (handle->direction != GPIO_DIR_OUTPUT)
    {
        NCP_LOG_ERR("Cannot set value on input GPIO");
        return -EINVAL;
    }

    data.values[0] = value;
    ret = ioctl(handle->line_fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data);
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to set GPIO value: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int gpio_get_value(gpio_handle_t *handle, gpio_level_t *value)
{
    struct gpiohandle_data data;
    int ret;

    if (!handle || !handle->is_open || handle->line_fd < 0 || !value)
    {
        return -EINVAL;
    }

    ret = ioctl(handle->line_fd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, &data);
    if (ret != 0)
    {
        NCP_LOG_ERR("Failed to get GPIO value: %s", strerror(errno));
        return -errno;
    }

    *value = data.values[0] ? GPIO_LEVEL_HIGH : GPIO_LEVEL_LOW;

    return 0;
}

int gpio_register_event(gpio_handle_t *handle, gpio_edge_t edge,
                       gpio_event_callback_t callback, void *user_data)
{
    struct gpioevent_request req;
    struct epoll_event ev;
    gpio_event_handler_t *handler = NULL;
    int ret, i, handler_idx = -1;

    GPIO_CHECK_INIT();

    if (!handle || !handle->is_open || !callback)
    {
        return -EINVAL;
    }

    OSA_MutexLock(g_gpio_manager.mutex, osaWaitForever_c);

    if (handle->event_id >= 0 && handle->event_id < GPIO_MAX_EVENT_HANDLERS)
    {
        OSA_MutexUnlock(g_gpio_manager.mutex);
        NCP_LOG_ERR("Event already registered for GPIO %d_%d",
                    handle->chip_num, handle->line_num);
        return -EEXIST;
    }

    /* Find free event handler slot */
    for (i = 0; i < GPIO_MAX_EVENT_HANDLERS; i++)
    {
        if (!g_gpio_manager.monitor.handlers[i].active)
        {
            handler = &g_gpio_manager.monitor.handlers[i];
            handler_idx = i;
            break;
        }
    }

    if (!handler)
    {
        OSA_MutexUnlock(g_gpio_manager.mutex);
        NCP_LOG_ERR("No free event handler slots");
        return -ENOMEM;
    }

    /* Close existing line handle if any */
    if (handle->line_fd >= 0)
    {
        close(handle->line_fd);
        handle->line_fd = -1;
    }

    /* Setup event request */
    memset(&req, 0, sizeof(req));
    req.lineoffset = handle->line_num;
    req.handleflags = GPIOHANDLE_REQUEST_INPUT;

    if (edge == GPIO_EDGE_RISING || edge == GPIO_EDGE_BOTH)
    {
        req.eventflags |= GPIOEVENT_REQUEST_RISING_EDGE;
    }
    if (edge == GPIO_EDGE_FALLING || edge == GPIO_EDGE_BOTH)
    {
        req.eventflags |= GPIOEVENT_REQUEST_FALLING_EDGE;
    }

    snprintf(req.consumer_label, sizeof(req.consumer_label), "gpio_event_%d_%d",
            handle->chip_num, handle->line_num);

    ret = ioctl(handle->chip_fd, GPIO_GET_LINEEVENT_IOCTL, &req);
    if (ret != 0)
    {
        OSA_MutexUnlock(g_gpio_manager.mutex);
        NCP_LOG_ERR("Failed to setup GPIO event: %s", strerror(errno));
        return -errno;
    }

    handle->line_fd = req.fd;

    /* Add to epoll monitoring */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = handler;

    ret = epoll_ctl(g_gpio_manager.monitor.epoll_fd, EPOLL_CTL_ADD,
                    handle->line_fd, &ev);
    if (ret != 0)
    {
        close(handle->line_fd);
        handle->line_fd = -1;
        OSA_MutexUnlock(g_gpio_manager.mutex);
        NCP_LOG_ERR("Failed to add to epoll: %s", strerror(errno));
        return -errno;
    }

    /* Setup event handler */
    handler->handle = handle;
    handler->callback = callback;
    handler->user_data = user_data;
    handler->event_id = handler_idx;
    handler->active = true;

    handle->direction = GPIO_DIR_INPUT;
    handle->event_id = handler_idx;

    g_gpio_manager.monitor.handler_count++;

    OSA_MutexUnlock(g_gpio_manager.mutex);

    NCP_LOG_DBG("Registered event handler %d for GPIO %d_%d (edge=%d)",
            handler_idx, handle->chip_num, handle->line_num, edge);

    return handler_idx;
}

int gpio_unregister_event(int event_id)
{
    gpio_event_handler_t *handler;
    int ret = -1;

    if (event_id < 0 || event_id >= GPIO_MAX_EVENT_HANDLERS)
    {
        NCP_LOG_ERR("Invalid event ID %d", event_id);
        return -EINVAL;
    }

    OSA_MutexLock(g_gpio_manager.mutex, osaWaitForever_c);

    handler = &g_gpio_manager.monitor.handlers[event_id];

    if (!handler->active)
    {
        OSA_MutexUnlock(g_gpio_manager.mutex);
        NCP_LOG_WRN("Event handler %d not active", event_id);
        return -EINVAL;
    }

    ret = gpio_cleanup_event_internal(handler);

    OSA_MutexUnlock(g_gpio_manager.mutex);

    if (ret == 0)
    {
        NCP_LOG_DBG("Unregistered event handler %d", event_id);
    }

    return 0;
}
