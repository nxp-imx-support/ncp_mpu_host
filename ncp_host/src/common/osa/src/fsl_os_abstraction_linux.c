/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#define _GNU_SOURCE /* For CPU_SET macros */
#include "fsl_os_abstraction.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <limits.h>
#include <sched.h>
#include <assert.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Private Type Definitions
 ******************************************************************************/

/* State structure for Linux OSA manager */
typedef struct _osa_state
{
    list_label_t taskList;
    pthread_mutex_t taskListMutex;
    /* Interrupt disable management */
    uint32_t interruptDisableNesting;
    pthread_mutex_t interruptMutex;
    uint32_t disableIRQGlobalNesting;
    sigset_t oldSigMask;
    /* Critical section management */
    pthread_mutex_t criticalMutex;
    /* Initialization flag */
    bool initialized;
} osa_state_t;

/*******************************************************************************
 * Variables
 ******************************************************************************/

const uint8_t gUseRtos_c = USE_RTOS;

static osa_state_t s_osaState = {0};
static pthread_once_t s_osaInitOnce = PTHREAD_ONCE_INIT;

/*******************************************************************************
 * Private Functions
 ******************************************************************************/

static void OSA_InitOnce(void)
{
    struct sched_param param;

    /* Initialize task list */
    list_init(&s_osaState.taskList, 0);
    pthread_mutex_init(&s_osaState.taskListMutex, NULL);

    /* Initialize interrupt management */
    pthread_mutex_init(&s_osaState.interruptMutex, NULL);
    s_osaState.interruptDisableNesting = 0;
    s_osaState.disableIRQGlobalNesting = 0;

    /* Initialize critical section */
    pthread_mutex_init(&s_osaState.criticalMutex, NULL);

    /* Configure real-time scheduling */
    /* Set main process to use SCHED_FIFO for real-time scheduling */
    param.sched_priority = OSA_PRIORITY_IDLE;

    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        /* Non-fatal: Continue without RT scheduling if no permission */
        fprintf(stderr, "OSA: Warning - Failed to set SCHED_FIFO scheduler: %s\n",
                strerror(errno));
        fprintf(stderr, "OSA: For real-time scheduling, run with sudo or "
                        "set CAP_SYS_NICE capability:\n");
        fprintf(stderr, "     sudo setcap cap_sys_nice+ep <executable>\n");
        fprintf(stderr, "OSA: Falling back to normal scheduling (SCHED_OTHER)\n");
    } else {
        printf("OSA: Successfully enabled SCHED_FIFO real-time scheduling\n");
        s_osaState.initialized = true;
    }
}

static void* task_wrapper(void *arg)
{
    osa_linux_task_t *task = (osa_linux_task_t *)arg;

    /* Set CPU affinity to CPU 0 for all tasks */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);  /* Bind to CPU 0 */
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    /* Set thread name for debugging */
    if (task->name[0] != '\0') {
        pthread_setname_np(pthread_self(), task->name);
    }

    /* Call the actual task function */
    if (task->taskFunction) {
        task->taskFunction(task->taskParam);
    }

    /* Mark task as inactive */
    task->active = false;

    return NULL;
}

static struct timespec calculate_timeout(uint32_t millisec)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    ts.tv_sec += millisec / 1000;
    ts.tv_nsec += (millisec % 1000) * 1000000;
    
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }
    
    return ts;
}

/*******************************************************************************
 * Memory Management
 ******************************************************************************/

void *OSA_MemoryAllocate(uint32_t memLength)
{
    void *ptr = malloc(memLength);
    if (ptr) {
        memset(ptr, 0, memLength);
    }
    return ptr;
}

void OSA_MemoryFree(void *p)
{
    free(p);
}

void *OSA_MemoryAllocateAlign(uint32_t memLength, uint32_t alignbytes)
{
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignbytes, memLength) == 0) {
        memset(ptr, 0, memLength);
        return ptr;
    }
    return NULL;
}

void OSA_MemoryFreeAlign(void *p)
{
    free(p);
}

/*******************************************************************************
 * Critical Section - Using Signal Masking
 ******************************************************************************/

void OSA_EnterCritical(uint32_t *sr)
{
    sigset_t newMask;
    sigset_t *oldMask = (sigset_t *)sr;
    
    /* Block all signals */
    sigfillset(&newMask);
    pthread_sigmask(SIG_BLOCK, &newMask, oldMask);
    
    /* Also lock the critical mutex for thread safety */
    pthread_mutex_lock(&s_osaState.criticalMutex);
}

void OSA_ExitCritical(uint32_t sr)
{
    sigset_t *oldMask = (sigset_t *)&sr;
    
    /* Unlock critical mutex */
    pthread_mutex_unlock(&s_osaState.criticalMutex);
    
    /* Restore signal mask */
    pthread_sigmask(SIG_SETMASK, oldMask, NULL);
}

/*******************************************************************************
 * System Functions
 ******************************************************************************/

void OSA_Init(void)
{
    pthread_once(&s_osaInitOnce, OSA_InitOnce);
}

void OSA_Start(void)
{
    /* Nothing to do on Linux - threads start immediately */
}

/*******************************************************************************
 * Task Management
 ******************************************************************************/

osa_status_t OSA_TaskCreate(osa_task_handle_t taskHandle,
                            const osa_task_def_t *thread_def,
                            osa_task_param_t task_param)
{
    osa_linux_task_t *task = (osa_linux_task_t *)taskHandle;
    struct sched_param param = {0};

    if (!taskHandle || !thread_def || !thread_def->pthread) {
        return KOSA_StatusError;
    }

    /* Ensure OSA is initialized */
    OSA_Init();

    memset(task, 0, sizeof(osa_linux_task_t));

    /* Initialize task structure */
    task->taskFunction = thread_def->pthread;
    task->taskParam = task_param;
    task->priority = thread_def->tpriority;
    task->active = true;

    if (thread_def->tname) {
        strncpy(task->name, (char *)thread_def->tname, sizeof(task->name) - 1);
    }

    /* Initialize notification */
    pthread_mutex_init(&task->notifyMutex, NULL);
    pthread_cond_init(&task->notifyCond, NULL);
    task->notifyPending = false;

    /* Set thread attributes */
    pthread_attr_init(&task->attr);

    /* Set stack size if specified */
    if (thread_def->stacksize > 0) {
        pthread_attr_setstacksize(&task->attr, thread_def->stacksize);
    }

    /* Set to SCHED_FIFO for real-time scheduling without time slicing */
    if (pthread_attr_setschedpolicy(&task->attr, SCHED_FIFO) != 0) {
        fprintf(stderr, "OSA: Failed to set SCHED_FIFO for task %s: %s\n", 
                task->name, strerror(errno));
    }
    param.sched_priority = thread_def->tpriority;
    if (pthread_attr_setschedparam(&task->attr, &param) != 0) {
        fprintf(stderr, "OSA: Failed to set priority %d for task %s: %s\n",
                param.sched_priority, task->name, strerror(errno));
    }
    /* Set inherit scheduler attribute to PTHREAD_EXPLICIT_SCHED */
    pthread_attr_setinheritsched(&task->attr, PTHREAD_EXPLICIT_SCHED);

    /* Create thread */
    if (pthread_create(&task->thread, &task->attr, task_wrapper, task) != 0) {
        pthread_attr_destroy(&task->attr);
        pthread_mutex_destroy(&task->notifyMutex);
        pthread_cond_destroy(&task->notifyCond);
        return KOSA_StatusError;
    }

    /* Verify the thread actually got the requested scheduling policy */
    int policy;
    struct sched_param actual_param;
    if (pthread_getschedparam(task->thread, &policy, &actual_param) == 0) {
        printf("OSA: Task '%s' created - Policy: %s, Priority: %d (requested: %d)\n",
            task->name,
            (policy == SCHED_FIFO) ? "SCHED_FIFO" : 
            (policy == SCHED_RR) ? "SCHED_RR" : "SCHED_OTHER",
            actual_param.sched_priority,
            param.sched_priority);
    } else {
        printf("OSA: Failed to get scheduling params for task '%s'\n", task->name);
    }

    /* Add to task list */
    pthread_mutex_lock(&s_osaState.taskListMutex);
    list_add_tail(&s_osaState.taskList, &task->link);
    pthread_mutex_unlock(&s_osaState.taskListMutex);

    return KOSA_StatusSuccess;
}

osa_status_t OSA_TaskDestroy(osa_task_handle_t taskHandle)
{
    osa_linux_task_t *task = (osa_linux_task_t *)taskHandle;

    if (!taskHandle) {
        return KOSA_StatusError;
    }

    /* Cancel the thread */
    pthread_cancel(task->thread);
    pthread_join(task->thread, NULL);

    /* Clean up */
    pthread_attr_destroy(&task->attr);
    pthread_mutex_destroy(&task->notifyMutex);
    pthread_cond_destroy(&task->notifyCond);

    /* Remove from list */
    pthread_mutex_lock(&s_osaState.taskListMutex);
    list_remove(&task->link);
    pthread_mutex_unlock(&s_osaState.taskListMutex);

    task->active = false;

    return KOSA_StatusSuccess;
}

osa_task_handle_t OSA_TaskGetCurrentHandle(void)
{
    pthread_t currentThread = pthread_self();
    osa_task_handle_t foundHandle = NULL;

    pthread_mutex_lock(&s_osaState.taskListMutex);

    list_element_t *element = list_get_head(&s_osaState.taskList);
    while (element) {
        osa_linux_task_t *task = (osa_linux_task_t *)element;
        if (pthread_equal(task->thread, currentThread)) {
            foundHandle = (osa_task_handle_t)task;
            break;
        }
        element = list_get_next(element);
    }

    pthread_mutex_unlock(&s_osaState.taskListMutex);

    return foundHandle;
}

void OSA_TaskYield(void)
{
    sched_yield();
}

osa_task_priority_t OSA_TaskGetPriority(osa_task_handle_t taskHandle)
{
    if (!taskHandle) {
        return OSA_PRIORITY_IDLE;
    }

    osa_linux_task_t *task = (osa_linux_task_t *)taskHandle;
    return task->priority;
}

osa_status_t OSA_TaskSetPriority(osa_task_handle_t taskHandle,
                                 osa_task_priority_t taskPriority)
{
    osa_linux_task_t *task = (osa_linux_task_t *)taskHandle;
    struct sched_param param = {0};
    int policy;

    if (!taskHandle) {
        return KOSA_StatusError;
    }

    /* Get current scheduling policy */
    if (pthread_getschedparam(task->thread, &policy, &param) != 0) {
        return KOSA_StatusError;
    }

    param.sched_priority = taskPriority;

    /* Set new priority with SCHED_FIFO policy */
    if (pthread_setschedparam(task->thread, SCHED_FIFO, &param) != 0) {
        return KOSA_StatusError;
    }

    /* Update actual thread priority */
    task->priority = taskPriority;

    return KOSA_StatusSuccess;
}

osa_status_t OSA_TaskNotifyGet(osa_notify_time_ms_t waitTime_ms)
{
    osa_task_handle_t currentHandle = OSA_TaskGetCurrentHandle();
    if (!currentHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_task_t *task = (osa_linux_task_t *)currentHandle;
    
    pthread_mutex_lock(&task->notifyMutex);
    
    if (!task->notifyPending) {
        if (waitTime_ms == 0) {
            pthread_mutex_unlock(&task->notifyMutex);
            return KOSA_StatusTimeout;
        } else if (waitTime_ms == osaWaitForever_c) {
            pthread_cond_wait(&task->notifyCond, &task->notifyMutex);
        } else {
            struct timespec ts = calculate_timeout(waitTime_ms);
            int ret = pthread_cond_timedwait(&task->notifyCond, &task->notifyMutex, &ts);
            if (ret == ETIMEDOUT) {
                pthread_mutex_unlock(&task->notifyMutex);
                return KOSA_StatusTimeout;
            }
        }
    }
    
    task->notifyPending = false;
    pthread_mutex_unlock(&task->notifyMutex);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_TaskNotifyPost(osa_task_handle_t taskHandle)
{
    if (!taskHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_task_t *task = (osa_linux_task_t *)taskHandle;
    
    pthread_mutex_lock(&task->notifyMutex);
    task->notifyPending = true;
    pthread_cond_signal(&task->notifyCond);
    pthread_mutex_unlock(&task->notifyMutex);
    
    return KOSA_StatusSuccess;
}

/*******************************************************************************
 * Semaphore
 ******************************************************************************/

osa_status_t OSA_SemaphoreCreate(osa_semaphore_handle_t semaphoreHandle,
                                 uint32_t initValue)
{
    if (!semaphoreHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_sem_t *sem = (osa_linux_sem_t *)semaphoreHandle;
    memset(sem, 0, sizeof(osa_linux_sem_t));
    
    if (sem_init(&sem->semaphore, 0, initValue) != 0) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_init(&sem->countMutex, NULL);
    sem->initialized = true;
    sem->maxCount = UINT_MAX;
    sem->currentCount = initValue;
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_SemaphoreCreateBinary(osa_semaphore_handle_t semaphoreHandle)
{
    return OSA_SemaphoreCreate(semaphoreHandle, 1);
}

osa_status_t OSA_SemaphoreDestroy(osa_semaphore_handle_t semaphoreHandle)
{
    if (!semaphoreHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_sem_t *sem = (osa_linux_sem_t *)semaphoreHandle;
    
    if (!sem->initialized) {
        return KOSA_StatusError;
    }
    
    sem_destroy(&sem->semaphore);
    pthread_mutex_destroy(&sem->countMutex);
    sem->initialized = false;
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_SemaphoreWait(osa_semaphore_handle_t semaphoreHandle,
                               uint32_t millisec)
{
    if (!semaphoreHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_sem_t *sem = (osa_linux_sem_t *)semaphoreHandle;
    
    if (!sem->initialized) {
        return KOSA_StatusError;
    }
    
    int ret;
    
    if (millisec == 0) {
        ret = sem_trywait(&sem->semaphore);
    } else if (millisec == osaWaitForever_c) {
        ret = sem_wait(&sem->semaphore);
    } else {
        struct timespec ts = calculate_timeout(millisec);
        ret = sem_timedwait(&sem->semaphore, &ts);
    }
    
    if (ret == 0) {
        pthread_mutex_lock(&sem->countMutex);
        if (sem->currentCount > 0) {
            sem->currentCount--;
        }
        pthread_mutex_unlock(&sem->countMutex);
        return KOSA_StatusSuccess;
    }
    
    return (errno == ETIMEDOUT) ? KOSA_StatusTimeout : KOSA_StatusError;
}

osa_status_t OSA_SemaphorePost(osa_semaphore_handle_t semaphoreHandle)
{
    if (!semaphoreHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_sem_t *sem = (osa_linux_sem_t *)semaphoreHandle;
    
    if (!sem->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&sem->countMutex);
    if (sem->currentCount < sem->maxCount) {
        sem->currentCount++;
    }
    pthread_mutex_unlock(&sem->countMutex);
    
    if (sem_post(&sem->semaphore) != 0) {
        return KOSA_StatusError;
    }
    
    return KOSA_StatusSuccess;
}

osa_semaphore_count_t OSA_SemaphoreGetCount(osa_semaphore_handle_t semaphoreHandle)
{
    if (!semaphoreHandle) {
        return 0;
    }
    
    osa_linux_sem_t *sem = (osa_linux_sem_t *)semaphoreHandle;
    
    if (!sem->initialized) {
        return 0;
    }
    
    int value;
    sem_getvalue(&sem->semaphore, &value);
    return (osa_semaphore_count_t)value;
}

/*******************************************************************************
 * Mutex
 ******************************************************************************/

osa_status_t OSA_MutexCreate(osa_mutex_handle_t mutexHandle)
{
    if (!mutexHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_mutex_t *mutex = (osa_linux_mutex_t *)mutexHandle;
    memset(mutex, 0, sizeof(osa_linux_mutex_t));
    
    pthread_mutexattr_init(&mutex->attr);
    pthread_mutexattr_settype(&mutex->attr, PTHREAD_MUTEX_RECURSIVE);
    
    if (pthread_mutex_init(&mutex->mutex, &mutex->attr) != 0) {
        pthread_mutexattr_destroy(&mutex->attr);
        return KOSA_StatusError;
    }
    
    mutex->initialized = true;
    mutex->recursiveCount = 0;
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_MutexLock(osa_mutex_handle_t mutexHandle, uint32_t millisec)
{
    if (!mutexHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_mutex_t *mutex = (osa_linux_mutex_t *)mutexHandle;
    
    if (!mutex->initialized) {
        return KOSA_StatusError;
    }
    
    int ret;
    
    if (millisec == 0) {
        ret = pthread_mutex_trylock(&mutex->mutex);
    } else if (millisec == osaWaitForever_c) {
        ret = pthread_mutex_lock(&mutex->mutex);
    } else {
        struct timespec ts = calculate_timeout(millisec);
        ret = pthread_mutex_timedlock(&mutex->mutex, &ts);
    }
    
    if (ret == 0) {
        mutex->owner = pthread_self();
        mutex->recursiveCount++;
        return KOSA_StatusSuccess;
    }
    
    return (ret == ETIMEDOUT) ? KOSA_StatusTimeout : KOSA_StatusError;
}

osa_status_t OSA_MutexUnlock(osa_mutex_handle_t mutexHandle)
{
    if (!mutexHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_mutex_t *mutex = (osa_linux_mutex_t *)mutexHandle;
    
    if (!mutex->initialized) {
        return KOSA_StatusError;
    }
    
    if (mutex->recursiveCount > 0) {
        mutex->recursiveCount--;
    }
    
    if (pthread_mutex_unlock(&mutex->mutex) != 0) {
        return KOSA_StatusError;
    }
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_MutexDestroy(osa_mutex_handle_t mutexHandle)
{
    if (!mutexHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_mutex_t *mutex = (osa_linux_mutex_t *)mutexHandle;
    
    if (!mutex->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_destroy(&mutex->mutex);
    pthread_mutexattr_destroy(&mutex->attr);
    mutex->initialized = false;
    
    return KOSA_StatusSuccess;
}

/*******************************************************************************
 * Event
 ******************************************************************************/

osa_status_t OSA_EventCreate(osa_event_handle_t eventHandle, uint8_t autoClear)
{
    if (!eventHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_event_t *event = (osa_linux_event_t *)eventHandle;
    memset(event, 0, sizeof(osa_linux_event_t));
    
    pthread_mutex_init(&event->mutex, NULL);
    pthread_cond_init(&event->cond, NULL);
    event->flags = 0;
    event->autoClear = autoClear;
    event->initialized = true;
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_EventSet(osa_event_handle_t eventHandle,
                         osa_event_flags_t flagsToSet)
{
    if (!eventHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_event_t *event = (osa_linux_event_t *)eventHandle;
    
    if (!event->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&event->mutex);
    event->flags |= flagsToSet;
    pthread_mutex_unlock(&event->mutex);
    pthread_cond_broadcast(&event->cond);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_EventClear(osa_event_handle_t eventHandle,
                            osa_event_flags_t flagsToClear)
{
    if (!eventHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_event_t *event = (osa_linux_event_t *)eventHandle;
    
    if (!event->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&event->mutex);
    event->flags &= ~flagsToClear;
    pthread_mutex_unlock(&event->mutex);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_EventGet(osa_event_handle_t eventHandle,
                         osa_event_flags_t flagsMask,
                         osa_event_flags_t *pFlagsOfEvent)
{
    if (!eventHandle || !pFlagsOfEvent) {
        return KOSA_StatusError;
    }
    
    osa_linux_event_t *event = (osa_linux_event_t *)eventHandle;
    
    if (!event->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&event->mutex);
    *pFlagsOfEvent = event->flags & flagsMask;
    pthread_mutex_unlock(&event->mutex);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_EventWait(osa_event_handle_t eventHandle,
                          osa_event_flags_t flagsToWait,
                          uint8_t waitAll,
                          uint32_t millisec,
                          osa_event_flags_t *pSetFlags)
{
    if (!eventHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_event_t *event = (osa_linux_event_t *)eventHandle;
    
    if (!event->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&event->mutex);
    
    /* Check if flags already set */
    bool conditionMet = false;
    if (waitAll) {
        conditionMet = ((event->flags & flagsToWait) == flagsToWait);
    } else {
        conditionMet = ((event->flags & flagsToWait) != 0);
    }
    
    if (!conditionMet) {
        if (millisec == 0) {
            pthread_mutex_unlock(&event->mutex);
            return KOSA_StatusTimeout;
        } else if (millisec == osaWaitForever_c) {
            while (!conditionMet) {
                pthread_cond_wait(&event->cond, &event->mutex);
                if (waitAll) {
                    conditionMet = ((event->flags & flagsToWait) == flagsToWait);
                } else {
                    conditionMet = ((event->flags & flagsToWait) != 0);
                }
            }
        } else {
            struct timespec ts = calculate_timeout(millisec);
            int ret = 0;
            while (!conditionMet && ret == 0) {
                ret = pthread_cond_timedwait(&event->cond, &event->mutex, &ts);
                if (waitAll) {
                    conditionMet = ((event->flags & flagsToWait) == flagsToWait);
                } else {
                    conditionMet = ((event->flags & flagsToWait) != 0);
                }
            }
            if (ret == ETIMEDOUT) {
                pthread_mutex_unlock(&event->mutex);
                return KOSA_StatusTimeout;
            }
        }
    }
    
    /* Return the flags that woke us up */
    if (pSetFlags) {
        *pSetFlags = event->flags & flagsToWait;
    }
    
    /* Clear flags if auto-clear */
    if (event->autoClear) {
        event->flags &= ~flagsToWait;
    }
    
    pthread_mutex_unlock(&event->mutex);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_EventDestroy(osa_event_handle_t eventHandle)
{
    if (!eventHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_event_t *event = (osa_linux_event_t *)eventHandle;
    
    if (!event->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_destroy(&event->mutex);
    pthread_cond_destroy(&event->cond);
    event->initialized = false;
    
    return KOSA_StatusSuccess;
}

/*******************************************************************************
 * Message Queue
 ******************************************************************************/

osa_status_t OSA_MsgQCreate(osa_msgq_handle_t msgqHandle,
                           uint32_t msgNo,
                           uint32_t msgSize)
{
    if (!msgqHandle || msgNo == 0 || msgSize == 0) {
        return KOSA_StatusError;
    }
    
    osa_linux_msgq_t *msgq = (osa_linux_msgq_t *)msgqHandle;
    memset(msgq, 0, sizeof(osa_linux_msgq_t));
    
    /* Allocate buffer */
    msgq->buffer = (uint8_t *)((uint8_t *)msgqHandle + sizeof(osa_linux_msgq_t));
    msgq->msgSize = msgSize;
    msgq->maxMsgs = msgNo;
    msgq->msgCount = 0;
    msgq->readIndex = 0;
    msgq->writeIndex = 0;
    
    pthread_mutex_init(&msgq->mutex, NULL);
    pthread_cond_init(&msgq->notEmpty, NULL);
    pthread_cond_init(&msgq->notFull, NULL);
    
    msgq->initialized = true;
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_MsgQPut(osa_msgq_handle_t msgqHandle,
                         osa_msg_handle_t pMessage)
{
    if (!msgqHandle || !pMessage) {
        return KOSA_StatusError;
    }
    
    osa_linux_msgq_t *msgq = (osa_linux_msgq_t *)msgqHandle;
    
    if (!msgq->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&msgq->mutex);
    
    /* Check if queue is full */
    if (msgq->msgCount >= msgq->maxMsgs) {
        pthread_mutex_unlock(&msgq->mutex);
        return KOSA_StatusError;
    }
    
    /* Copy message to buffer */
    uint8_t *dst = msgq->buffer + (msgq->writeIndex * msgq->msgSize);
    memcpy(dst, pMessage, msgq->msgSize);
    
    /* Update indices */
    msgq->writeIndex = (msgq->writeIndex + 1) % msgq->maxMsgs;
    msgq->msgCount++;
    
    /* Signal waiting threads */
    pthread_cond_signal(&msgq->notEmpty);
    
    pthread_mutex_unlock(&msgq->mutex);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_MsgQPutBlock(osa_msgq_handle_t msgqHandle,
                               osa_msg_handle_t pMessage,
                               uint32_t millisec)
{
    if (!msgqHandle || !pMessage) {
        return KOSA_StatusError;
    }
    
    osa_linux_msgq_t *msgq = (osa_linux_msgq_t *)msgqHandle;
    
    if (!msgq->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&msgq->mutex);
    
    /* Wait if queue is full */
    if (msgq->msgCount >= msgq->maxMsgs) {
        if (millisec == 0) {
            /* Non-blocking, return immediately */
            pthread_mutex_unlock(&msgq->mutex);
            return KOSA_StatusTimeout;
        } else if (millisec == osaWaitForever_c) {
            /* Wait forever until space is available */
            while (msgq->msgCount >= msgq->maxMsgs) {
                pthread_cond_wait(&msgq->notFull, &msgq->mutex);
            }
        } else {
            /* Wait with timeout */
            struct timespec ts = calculate_timeout(millisec);
            while (msgq->msgCount >= msgq->maxMsgs) {
                int ret = pthread_cond_timedwait(&msgq->notFull, &msgq->mutex, &ts);
                if (ret == ETIMEDOUT) {
                    pthread_mutex_unlock(&msgq->mutex);
                    return KOSA_StatusTimeout;
                }
            }
        }
    }
    
    /* Copy message to buffer */
    uint8_t *dst = msgq->buffer + (msgq->writeIndex * msgq->msgSize);
    memcpy(dst, pMessage, msgq->msgSize);
    
    /* Update indices */
    msgq->writeIndex = (msgq->writeIndex + 1) % msgq->maxMsgs;
    msgq->msgCount++;
    
    /* Signal waiting threads */
    pthread_cond_signal(&msgq->notEmpty);
    
    pthread_mutex_unlock(&msgq->mutex);
    
    return KOSA_StatusSuccess;
}

osa_status_t OSA_MsgQGet(osa_msgq_handle_t msgqHandle,
                         osa_msg_handle_t pMessage,
                         uint32_t millisec)
{
    if (!msgqHandle || !pMessage) {
        return KOSA_StatusError;
    }
    
    osa_linux_msgq_t *msgq = (osa_linux_msgq_t *)msgqHandle;
    
    if (!msgq->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_lock(&msgq->mutex);
    
    /* Wait for message if queue is empty */
    if (msgq->msgCount == 0) {
        if (millisec == 0) {
            pthread_mutex_unlock(&msgq->mutex);
            return KOSA_StatusTimeout;
        } else if (millisec == osaWaitForever_c) {
            while (msgq->msgCount == 0) {
                pthread_cond_wait(&msgq->notEmpty, &msgq->mutex);
            }
        } else {
            struct timespec ts = calculate_timeout(millisec);
            while (msgq->msgCount == 0) {
                int ret = pthread_cond_timedwait(&msgq->notEmpty, &msgq->mutex, &ts);
                if (ret == ETIMEDOUT) {
                    pthread_mutex_unlock(&msgq->mutex);
                    return KOSA_StatusTimeout;
                }
            }
        }
    }
    
    /* Copy message from buffer */
    uint8_t *src = msgq->buffer + (msgq->readIndex * msgq->msgSize);
    memcpy(pMessage, src, msgq->msgSize);
    
    /* Update indices */
    msgq->readIndex = (msgq->readIndex + 1) % msgq->maxMsgs;
    msgq->msgCount--;
    
    /* Signal waiting threads */
    pthread_cond_signal(&msgq->notFull);
    
    pthread_mutex_unlock(&msgq->mutex);
    
    return KOSA_StatusSuccess;
}

int OSA_MsgQAvailableMsgs(osa_msgq_handle_t msgqHandle)
{
    if (!msgqHandle) {
        return 0;
    }
    
    osa_linux_msgq_t *msgq = (osa_linux_msgq_t *)msgqHandle;
    
    if (!msgq->initialized) {
        return 0;
    }
    
    pthread_mutex_lock(&msgq->mutex);
    int count = msgq->msgCount;
    pthread_mutex_unlock(&msgq->mutex);
    
    return count;
}

osa_status_t OSA_MsgQDestroy(osa_msgq_handle_t msgqHandle)
{
    if (!msgqHandle) {
        return KOSA_StatusError;
    }
    
    osa_linux_msgq_t *msgq = (osa_linux_msgq_t *)msgqHandle;
    
    if (!msgq->initialized) {
        return KOSA_StatusError;
    }
    
    pthread_mutex_destroy(&msgq->mutex);
    pthread_cond_destroy(&msgq->notEmpty);
    pthread_cond_destroy(&msgq->notFull);
    
    msgq->initialized = false;
    
    return KOSA_StatusSuccess;
}

/*******************************************************************************
 * Time Functions
 ******************************************************************************/

void OSA_TimeDelay(uint32_t millisec)
{
    struct timespec ts;
    ts.tv_sec = millisec / 1000;
    ts.tv_nsec = (millisec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

uint32_t OSA_TimeGetMsec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/*******************************************************************************
 * Interrupt Management - Using Signal Masking
 ******************************************************************************/

void OSA_InterruptEnable(void)
{
    pthread_mutex_lock(&s_osaState.interruptMutex);
    if (s_osaState.interruptDisableNesting > 0) {
        s_osaState.interruptDisableNesting--;
        
        if (s_osaState.interruptDisableNesting == 0) {
            /* Restore signal mask */
            pthread_sigmask(SIG_SETMASK, &s_osaState.oldSigMask, NULL);
        }
    }
    pthread_mutex_unlock(&s_osaState.interruptMutex);
}

void OSA_InterruptDisable(void)
{
    pthread_mutex_lock(&s_osaState.interruptMutex);
    if (s_osaState.interruptDisableNesting == 0) {
        sigset_t newMask;
        sigfillset(&newMask);
        pthread_sigmask(SIG_BLOCK, &newMask, &s_osaState.oldSigMask);
    }
    s_osaState.interruptDisableNesting++;
    pthread_mutex_unlock(&s_osaState.interruptMutex);
}

void OSA_EnableIRQGlobal(void)
{
    if (s_osaState.disableIRQGlobalNesting > 0U) {
        s_osaState.disableIRQGlobalNesting--;
        
        if (0U == s_osaState.disableIRQGlobalNesting) {
            /* Restore signal mask */
            pthread_sigmask(SIG_SETMASK, &s_osaState.oldSigMask, NULL);
        }
    }
}

void OSA_DisableIRQGlobal(void)
{
    if (0 == s_osaState.disableIRQGlobalNesting) {
        sigset_t newMask;
        sigfillset(&newMask);
        pthread_sigmask(SIG_BLOCK, &newMask, &s_osaState.oldSigMask);
    }
    
    s_osaState.disableIRQGlobalNesting++;
}

/*******************************************************************************
 * Scheduler Control (Not applicable for Linux user space)
 ******************************************************************************/

void OSA_DisableScheduler(void)
{
    /* Linux doesn't provide a direct way to disable scheduler in user space */
    /* We could use real-time scheduling with high priority as workaround */
    /* Option: Set current thread to highest real-time priority */
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
}

void OSA_EnableScheduler(void)
{
    /* Restore normal scheduling */
    struct sched_param param;
    param.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &param);
}

/*******************************************************************************
 * Signal Handler Installation 
 ******************************************************************************/

void OSA_InstallIntHandler(uint32_t IRQNumber, void (*handler)(int))
{
    /* In Linux user space, we use signal handlers instead of interrupt handlers */
    struct sigaction sa;
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    /* Map IRQ number to signal number (customize as needed) */
    /* Using real-time signals for better performance */
    int signum = SIGRTMIN + (IRQNumber % (SIGRTMAX - SIGRTMIN + 1));
    
    sigaction(signum, &sa, NULL);
}
