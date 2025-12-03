/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _GPIO_NCP_ADAPTER_H_
#define _GPIO_NCP_ADAPTER_H_

#include "gpio_driver.h"
#include "fsl_os_abstraction.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* NCP GPIO pins definition */
#define NCP_GPIO_CHIP_NUM           4    /* /dev/gpiochip4 */
#define NCP_GPIO_DEVICE_NOTIFY_PIN  8    /* Input - Device notification */
#define NCP_GPIO_WAKEUP_DEVICE_PIN  9    /* Output - Wake up device */

/* GPIO signal types for NCP */
typedef enum {
    NCP_GPIO_SIG_WAKEUP_DEVICE = 0,
    NCP_GPIO_SIG_MAX
} ncp_gpio_signal_t;

/* NCP GPIO configuration */
typedef struct {
    uint8_t chip_num;
    uint8_t pin_num;
    gpio_direction_t direction;
    gpio_pull_t pull;
    gpio_edge_t interrupt_edge;
    bool enable_interrupt;
    const char *label;
} ncp_gpio_config_t;

/* NCP GPIO context */
typedef struct {
    gpio_handle_t handles[NCP_GPIO_SIG_MAX];
    int event_ids[NCP_GPIO_SIG_MAX];
    osa_mutex_handle_t mutex;
    osa_event_handle_t event;
    volatile uint32_t event_flags;  /* Track pending events */
    bool initialized;
} ncp_gpio_context_t;

/*******************************************************************************
 * API
 ******************************************************************************/

/**
 * @brief Initialize NCP GPIO adapter
 * @return 0 on success, negative on error
 */
int ncp_gpio_adapter_init(void);

/**
 * @brief Deinitialize NCP GPIO adapter
 * @return 0 on success, negative on error
 */
int ncp_gpio_adapter_deinit(void);

/**
 * @brief Wakeup peer device
 * @param pulse_duration_us Pulse duration in microseconds
 * @return 0 on success, negative on error
 */
int ncp_gpio_wakeup_peer(uint32_t pulse_duration_us);

/**
 * @brief Set GPIO signal
 * @param signal Signal type
 * @param value Level to set
 * @return 0 on success, negative on error
 */
int ncp_gpio_set_signal(ncp_gpio_signal_t signal, gpio_level_t value);

/**
 * @brief Get GPIO signal
 * @param signal Signal type
 * @param value Pointer to store level
 * @return 0 on success, negative on error
 */
int ncp_gpio_get_signal(ncp_gpio_signal_t signal, gpio_level_t *value);

/**
 * @brief Wait for GPIO event
 * @param event_mask Event mask to wait for
 * @param timeout_ms Timeout in milliseconds
 * @param triggered_events Pointer to store triggered events
 * @return 0 on success, negative on error
 */
int ncp_gpio_wait_event(uint32_t event_mask, uint32_t timeout_ms, uint32_t *triggered_events);

/**
 * @brief Clear GPIO events
 * @param event_mask Events to clear
 * @return 0 on success, negative on error
 */
int ncp_gpio_clear_events(uint32_t event_mask);

/**
 * @brief Get pending GPIO events
 * @param events Pointer to store pending events
 * @return 0 on success, negative on error
 */
int ncp_gpio_get_pending_events(uint32_t *events);

#endif /* _GPIO_NCP_ADAPTER_H_ */