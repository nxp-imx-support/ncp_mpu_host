/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _GPIO_DRIVER_H_
#define _GPIO_DRIVER_H_

#include <stdint.h>
#include <stdbool.h>
#include "fsl_os_abstraction.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define GPIO_MAX_CHIPS          8
#define GPIO_MAX_LINES          32
#define GPIO_MAX_EVENT_HANDLERS 16
#define GPIO_EPOLL_TIMEOUT_MS   100

/* GPIO Direction */
typedef enum {
    GPIO_DIR_INPUT = 0,
    GPIO_DIR_OUTPUT = 1
} gpio_direction_t;

/* GPIO Level */
typedef enum {
    GPIO_LEVEL_LOW = 0,
    GPIO_LEVEL_HIGH = 1
} gpio_level_t;

/* GPIO Edge */
typedef enum {
    GPIO_EDGE_NONE = 0,
    GPIO_EDGE_RISING = 1,
    GPIO_EDGE_FALLING = 2,
    GPIO_EDGE_BOTH = 3
} gpio_edge_t;

/* GPIO Pull */
typedef enum {
    GPIO_PULL_NONE = 0,
    GPIO_PULL_UP = 1,
    GPIO_PULL_DOWN = 2
} gpio_pull_t;

  /* GPIO Handle */
typedef struct {
    int chip_fd;
    int line_fd;
    uint8_t chip_num;
    uint8_t line_num;
    gpio_direction_t direction;
    bool is_open;
} gpio_handle_t;

/* GPIO Event Callback */
typedef void (*gpio_event_callback_t)(gpio_handle_t *handle, gpio_edge_t edge, void *user_data);

/* GPIO Event Handler */
typedef struct {
    gpio_handle_t *handle;
    gpio_event_callback_t callback;
    void *user_data;
    bool active;
    int event_id;  /* Handler ID */
} gpio_event_handler_t;

/* GPIO Monitor - Single task monitors all GPIO events */
typedef struct {
    int epoll_fd;                                         /* epoll file descriptor */
    gpio_event_handler_t handlers[GPIO_MAX_EVENT_HANDLERS];
    osa_task_handle_t monitor_task;                      /* Single monitoring task */
    volatile bool running;                               /* Task running flag */
    int handler_count;                                   /* Active handler count */
} gpio_monitor_t;

/* GPIO Manager */
typedef struct {
    osa_mutex_handle_t mutex;
    gpio_monitor_t monitor;
    bool initialized;
} gpio_manager_t;

/*******************************************************************************
 * API
 ******************************************************************************/

/**
 * @brief Initialize GPIO subsystem
 * @return 0 on success, negative on error
 */
int gpio_init(void);

/**
 * @brief Deinitialize GPIO subsystem
 * @return 0 on success, negative on error
 */
int gpio_deinit(void);

/**
 * @brief Open a GPIO chip and line
 * @param handle GPIO handle to initialize
 * @param chip_num Chip number (e.g., 4 for /dev/gpiochip4)
 * @param line_num Line/pin number on the chip
 * @return 0 on success, negative on error
 */
int gpio_open(gpio_handle_t *handle, uint8_t chip_num, uint8_t line_num);

/**
 * @brief Close a GPIO handle
 * @param handle GPIO handle to close
 * @return 0 on success, negative on error
 */
int gpio_close(gpio_handle_t *handle);

/**
 * @brief Configure GPIO line
 * @param handle GPIO handle
 * @param direction Input or output
 * @param pull Pull-up/down configuration
 * @param initial_value Initial value for output (ignored for input)
 * @param label Consumer label for debugging
 * @return 0 on success, negative on error
 */
int gpio_configure(gpio_handle_t *handle, gpio_direction_t direction, 
                  gpio_pull_t pull, gpio_level_t initial_value, const char *label);

/**
 * @brief Set GPIO output value
 * @param handle GPIO handle
 * @param value Level to set
 * @return 0 on success, negative on error
 */
int gpio_set_value(gpio_handle_t *handle, gpio_level_t value);

/**
 * @brief Get GPIO input value
 * @param handle GPIO handle
 * @param value Pointer to store the level
 * @return 0 on success, negative on error
 */
int gpio_get_value(gpio_handle_t *handle, gpio_level_t *value);

/**
 * @brief Toggle GPIO output value
 * @param handle GPIO handle
 * @return 0 on success, negative on error
 */
int gpio_toggle(gpio_handle_t *handle);

/**
 * @brief Register GPIO event handler
 * @param handle GPIO handle
 * @param edge Edge to trigger on
 * @param callback Callback function
 * @param user_data User data to pass to callback
 * @return Event handler ID on success, negative on error
 */
int gpio_register_event(gpio_handle_t *handle, gpio_edge_t edge,
                        gpio_event_callback_t callback, void *user_data);

/**
 * @brief Unregister GPIO event handler
 * @param event_id Event handler ID
 * @return 0 on success, negative on error
 */
int gpio_unregister_event(int event_id);

/**
 * @brief Wait for GPIO event (blocking)
 * @param handle GPIO handle
 * @param edge Pointer to store edge type
 * @param timeout_ms Timeout in milliseconds (0 = no wait, -1 = infinite)
 * @return 0 on success, negative on error or timeout
 */
int gpio_wait_event(gpio_handle_t *handle, gpio_edge_t *edge, int timeout_ms);

/**
 * @brief Set GPIO line direction
 * @param handle GPIO handle
 * @param direction New direction
 * @return 0 on success, negative on error
 */
int gpio_set_direction(gpio_handle_t *handle, gpio_direction_t direction);

#endif /* _GPIO_DRIVER_H_ */