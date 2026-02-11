/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _FSL_OS_ABSTRACTION_LINUX_H_
#define _FSL_OS_ABSTRACTION_LINUX_H_

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdbool.h>

/* USE_RTOS = 1 for Linux */
#define USE_RTOS (1)

/* Linux-specific task structure */
typedef struct osa_linux_task {
    pthread_t thread;
    pthread_attr_t attr;
    bool active;
    bool detached;
    osa_task_ptr_t taskFunction;
    osa_task_param_t taskParam;
    osa_task_priority_t priority;
    char name[32];
    list_element_t link;
    pthread_mutex_t notifyMutex;
    pthread_cond_t notifyCond;
    bool notifyPending;
} osa_linux_task_t;

/* Linux-specific semaphore structure */
typedef struct osa_linux_sem {
    sem_t semaphore;
    bool initialized;
    uint32_t maxCount;
    uint32_t currentCount;
    pthread_mutex_t countMutex;
} osa_linux_sem_t;

/* Linux-specific mutex structure */
typedef struct osa_linux_mutex {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
    bool initialized;
    pthread_t owner;
} osa_linux_mutex_t;

/* Linux-specific event structure */
typedef struct osa_linux_event {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    osa_event_flags_t flags;
    bool autoClear;
    bool initialized;
} osa_linux_event_t;

/* Linux-specific message queue structure */
typedef struct osa_linux_msgq {
    pthread_mutex_t mutex;
    pthread_cond_t notEmpty;
    pthread_cond_t notFull;
    uint8_t *buffer;
    uint32_t msgSize;
    uint32_t msgCount;
    uint32_t maxMsgs;
    uint32_t readIndex;
    uint32_t writeIndex;
    bool initialized;
} osa_linux_msgq_t;

/* Linux-specific timer structure */
typedef struct osa_linux_timer {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool active;
    bool periodic;
    uint32_t period_ms;
    osa_timer_fct_ptr_t callback;
    void *argument;
    bool initialized;
    bool stopRequested;
} osa_linux_timer_t;

/* Handle sizes - automatically calculated from actual structure sizes */
#define OSA_TASK_HANDLE_SIZE    (sizeof(osa_linux_task_t))
#define OSA_SEM_HANDLE_SIZE     (sizeof(osa_linux_sem_t))
#define OSA_MUTEX_HANDLE_SIZE   (sizeof(osa_linux_mutex_t))
#define OSA_EVENT_HANDLE_SIZE   (sizeof(osa_linux_event_t))
#define OSA_MSGQ_HANDLE_SIZE    (sizeof(osa_linux_msgq_t))
#define OSA_TIMER_HANDLE_SIZE   (sizeof(osa_linux_timer_t))

#endif /* _FSL_OS_ABSTRACTION_LINUX_H_ */
