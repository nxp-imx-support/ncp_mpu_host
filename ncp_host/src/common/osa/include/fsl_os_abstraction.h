/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _FSL_OS_ABSTRACTION_H_
#define _FSL_OS_ABSTRACTION_H_

#include "fsl_common.h"
#include "fsl_component_list.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Type for the Task Priority*/
typedef uint16_t osa_task_priority_t;
/* Type for a task handler */
typedef void *osa_task_handle_t;
/* Type for the parameter to be passed to the task at its creation */
typedef void *osa_task_param_t;
/* Type for task pointer. Task prototype declaration */
typedef void (*osa_task_ptr_t)(osa_task_param_t task_param);
/* Type for the semaphore handler */
typedef void *osa_semaphore_handle_t;
/* Type for the mutex handler */
typedef void *osa_mutex_handle_t;
/* Type for the event handler */
typedef void *osa_event_handle_t;
/* Type for an event flags group, bit 32 is reserved. */
typedef uint32_t osa_event_flags_t;
/* Message definition. */
typedef void *osa_msg_handle_t;
/* Type for the message queue handler */
typedef void *osa_msgq_handle_t;
/* Type for the Timer handler */
typedef void *osa_timer_handle_t;
/* Type for the Timer callback function pointer. */
typedef void (*osa_timer_fct_ptr_t)(void const *argument);
/* Type for the semaphore counter. */
typedef uint32_t osa_semaphore_count_t;
/* Type for the notification wait time. */
typedef uint32_t osa_notify_time_ms_t;

/* Thread Definition structure contains startup information of a thread.*/
typedef struct osa_task_def_tag {
    osa_task_ptr_t pthread;  /* Thread function pointer */
    uint32_t tpriority;      /* Initial thread priority */
    uint32_t instances;      /* Maximum number of instances */
    uint32_t stacksize;      /* Stack size in bytes */
    uint8_t *tstack;         /* Stack pointer */
    void *tlink;             /* Link pointer */
    uint8_t *tname;          /* Thread name */
    uint8_t useFloat;        /* Use FPU */
} osa_task_def_t;

/* Timer Definition structure */
typedef struct osa_time_def_tag {
    osa_timer_fct_ptr_t pfCallback;  /* Timer callback function */
    void *argument;                   /* Timer callback argument */
} osa_time_def_t;

/* Timer type */
typedef enum _osa_timer {
    KOSA_TimerOnce = 0,      /* One-shot timer */
    KOSA_TimerPeriodic = 1   /* Repeating timer */
} osa_timer_t;

/* OSA Status codes */
typedef enum _osa_status {
    KOSA_StatusSuccess = 0,
    KOSA_StatusError   = 1,
    KOSA_StatusTimeout = 2,
    KOSA_StatusIdle    = 3,
} osa_status_t;

/* Priority definitions */
#define OSA_PRIORITY_IDLE           (1U)
#define OSA_PRIORITY_LOW            (2U)
#define OSA_PRIORITY_BELOW_NORMAL   (3U)
#define OSA_PRIORITY_NORMAL         (4U)
#define OSA_PRIORITY_ABOVE_NORMAL   (5U)
#define OSA_PRIORITY_HIGH           (6U)
#define OSA_PRIORITY_REAL_TIME      (7U)

#define OSA_TASK_PRIORITY_MAX       (15U)
#define OSA_TASK_PRIORITY_MIN       (0U)

/* Wait time constants */
#define osaWaitNone_c        ((uint32_t)(0UL))
#define osaWaitForever_c     ((uint32_t)(~0UL))
#define osaEventFlagsAll_c   ((osa_event_flags_t)(0x00FFFFFF))

/* Include Linux-specific definitions */
#include "fsl_os_abstraction_linux.h"

/* Macros for defining OS objects */
#define OSA_TASK_DEFINE(name, priority, instances, stackSz, useFloat) \
    static uint8_t name##_stack[stackSz]; \
    static const osa_task_def_t os_thread_def_##name = { \
        (name), (priority), (instances), (stackSz), \
        name##_stack, NULL, (uint8_t *)#name, (useFloat) \
    }

#define OSA_TASK(name) (&os_thread_def_##name)

#define OSA_TIMER_DEF(name, function) \
    static const osa_time_def_t os_timer_def_##name = {(function), NULL}

#define OSA_TIMER(name) (&os_timer_def_##name)

/* Handle definition macros */
#define OSA_TASK_HANDLE_DEFINE(name) \
    uint8_t name[OSA_TASK_HANDLE_SIZE] __attribute__((aligned(8)))

#define OSA_SEMAPHORE_HANDLE_DEFINE(name) \
    uint8_t name[OSA_SEM_HANDLE_SIZE] __attribute__((aligned(8)))

#define OSA_MUTEX_HANDLE_DEFINE(name) \
    uint8_t name[OSA_MUTEX_HANDLE_SIZE] __attribute__((aligned(8)))

#define OSA_EVENT_HANDLE_DEFINE(name) \
    uint8_t name[OSA_EVENT_HANDLE_SIZE] __attribute__((aligned(8)))

#define OSA_MSGQ_HANDLE_DEFINE(name, msgNo, msgSize) \
    uint8_t name[OSA_MSGQ_HANDLE_SIZE + ((msgNo) * (msgSize))] __attribute__((aligned(8)))

#define OSA_TIMER_HANDLE_DEFINE(name) \
    uint8_t name[OSA_TIMER_HANDLE_SIZE] __attribute__((aligned(8)))

/* Critical section macros */
#define OSA_SR_ALLOC()       /* Nothing needed */
#define OSA_ENTER_CRITICAL() OSA_EnterCritical(NULL)
#define OSA_EXIT_CRITICAL()  OSA_ExitCritical(0)

/*******************************************************************************
 * API
 ******************************************************************************/

/* Memory Management */
void *OSA_MemoryAllocate(uint32_t memLength);
void OSA_MemoryFree(void *p);
void *OSA_MemoryAllocateAlign(uint32_t memLength, uint32_t alignbytes);
void OSA_MemoryFreeAlign(void *p);

/* Critical Section */
void OSA_EnterCritical(uint32_t *sr);
void OSA_ExitCritical(uint32_t sr);

/* System */
void OSA_Init(void);
void OSA_Start(void);

/* Task Management */
osa_status_t OSA_TaskCreate(osa_task_handle_t taskHandle,
                            const osa_task_def_t *thread_def,
                            osa_task_param_t task_param);
osa_status_t OSA_TaskDestroy(osa_task_handle_t taskHandle);
osa_task_handle_t OSA_TaskGetCurrentHandle(void);
void OSA_TaskYield(void);
osa_task_priority_t OSA_TaskGetPriority(osa_task_handle_t taskHandle);
osa_status_t OSA_TaskSetPriority(osa_task_handle_t taskHandle,
                                osa_task_priority_t taskPriority);
osa_status_t OSA_TaskNotifyGet(osa_notify_time_ms_t waitTime_ms);
osa_status_t OSA_TaskNotifyPost(osa_task_handle_t taskHandle);

/* Semaphore */
osa_status_t OSA_SemaphoreCreate(osa_semaphore_handle_t semaphoreHandle,
                                uint32_t initValue);
osa_status_t OSA_SemaphoreCreateBinary(osa_semaphore_handle_t semaphoreHandle);
osa_status_t OSA_SemaphoreDestroy(osa_semaphore_handle_t semaphoreHandle);
osa_status_t OSA_SemaphoreWait(osa_semaphore_handle_t semaphoreHandle,
                                uint32_t millisec);
osa_status_t OSA_SemaphorePost(osa_semaphore_handle_t semaphoreHandle);
osa_semaphore_count_t OSA_SemaphoreGetCount(osa_semaphore_handle_t semaphoreHandle);

/* Mutex */
osa_status_t OSA_MutexCreate(osa_mutex_handle_t mutexHandle);
osa_status_t OSA_MutexLock(osa_mutex_handle_t mutexHandle, uint32_t millisec);
osa_status_t OSA_MutexUnlock(osa_mutex_handle_t mutexHandle);
osa_status_t OSA_MutexDestroy(osa_mutex_handle_t mutexHandle);

/* Event */
osa_status_t OSA_EventCreate(osa_event_handle_t eventHandle, uint8_t autoClear);
osa_status_t OSA_EventSet(osa_event_handle_t eventHandle,
                            osa_event_flags_t flagsToSet);
osa_status_t OSA_EventClear(osa_event_handle_t eventHandle,
                            osa_event_flags_t flagsToClear);
osa_status_t OSA_EventGet(osa_event_handle_t eventHandle,
                            osa_event_flags_t flagsMask,
                            osa_event_flags_t *pFlagsOfEvent);
osa_status_t OSA_EventWait(osa_event_handle_t eventHandle,
                            osa_event_flags_t flagsToWait,
                            uint8_t waitAll,
                            uint32_t millisec,
                            osa_event_flags_t *pSetFlags);
osa_status_t OSA_EventDestroy(osa_event_handle_t eventHandle);

/* Message Queue */
osa_status_t OSA_MsgQCreate(osa_msgq_handle_t msgqHandle,
                            uint32_t msgNo,
                            uint32_t msgSize);
osa_status_t OSA_MsgQPut(osa_msgq_handle_t msgqHandle,
                            osa_msg_handle_t pMessage);
osa_status_t OSA_MsgQPutBlock(osa_msgq_handle_t msgqHandle,
                               osa_msg_handle_t pMessage,
                               uint32_t millisec);
osa_status_t OSA_MsgQGet(osa_msgq_handle_t msgqHandle,
                            osa_msg_handle_t pMessage,
                            uint32_t millisec);
int OSA_MsgQAvailableMsgs(osa_msgq_handle_t msgqHandle);
osa_status_t OSA_MsgQDestroy(osa_msgq_handle_t msgqHandle);

/* Timer and Delay */
void OSA_TimeDelay(uint32_t millisec);
uint32_t OSA_TimeGetMsec(void);
/* Interrupt Management */
void OSA_InterruptEnable(void);
void OSA_InterruptDisable(void);
void OSA_EnableIRQGlobal(void);
void OSA_DisableIRQGlobal(void);
void OSA_DisableScheduler(void);
void OSA_EnableScheduler(void);
void OSA_InstallIntHandler(uint32_t IRQNumber, void (*handler)(int));

#endif /* _FSL_OS_ABSTRACTION_H_ */