/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#ifndef _FSL_COMPONENT_LIST_H_
#define _FSL_COMPONENT_LIST_H_

#include <stdint.h>

typedef struct list_element {
    struct list_element *next;
    struct list_element *prev;
    void *data;
} list_element_t;

typedef struct {
    list_element_t *head;
    list_element_t *tail;
    uint32_t size;
    uint32_t max;
} list_label_t;

typedef enum {
    kLIST_Ok = 0,
    kLIST_Full = 1,
    kLIST_Empty = 2,
    kLIST_NotFound = 3,
    kLIST_Error = 4
} list_status_t;

/* List API */
void list_init(list_label_t *list, uint32_t max);
list_status_t list_add_tail(list_label_t *list, list_element_t *element);
list_status_t list_add_head(list_label_t *list, list_element_t *element);
list_element_t *list_get_head(list_label_t *list);
list_element_t *list_get_next(list_element_t *element);
list_status_t list_remove(list_element_t *element);
uint32_t list_get_size(list_label_t *list);

#endif /* _FSL_COMPONENT_LIST_H_ */