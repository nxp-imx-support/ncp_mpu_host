/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */

#include "fsl_component_list.h"
#include <stdlib.h>
#include <string.h>

void list_init(list_label_t *list, uint32_t max)
{
    if (list) {
        list->head = NULL;
        list->tail = NULL;
        list->size = 0;
        list->max = max;
    }
}

list_status_t list_add_tail(list_label_t *list, list_element_t *element)
{
    if (!list || !element) {
        return kLIST_Error;
    }

    if (list->max > 0 && list->size >= list->max) {
        return kLIST_Full;
    }

    element->next = NULL;
    element->prev = list->tail;

    if (list->tail) {
        list->tail->next = element;
    } else {
        list->head = element;
    }

    list->tail = element;
    list->size++;

    return kLIST_Ok;
}

list_status_t list_add_head(list_label_t *list, list_element_t *element)
{
    if (!list || !element) {
        return kLIST_Error;
    }

    if (list->max > 0 && list->size >= list->max) {
        return kLIST_Full;
    }

    element->prev = NULL;
    element->next = list->head;

    if (list->head) {
        list->head->prev = element;
    } else {
        list->tail = element;
    }

    list->head = element;
    list->size++;

    return kLIST_Ok;
}

list_element_t *list_get_head(list_label_t *list)
{
    if (!list) {
        return NULL;
    }

    return list->head;
}

list_element_t *list_get_next(list_element_t *element)
{
    if (!element) {
        return NULL;
    }

    return element->next;
}

list_status_t list_remove(list_element_t *element)
{
    if (!element) {
        return kLIST_Error;
    }

    if (element->prev) {
        element->prev->next = element->next;
    }

    if (element->next) {
        element->next->prev = element->prev;
    }

    element->prev = NULL;
    element->next = NULL;

    return kLIST_Ok;
}

uint32_t list_get_size(list_label_t *list)
{
    if (!list) {
        return 0;
    }

    return list->size;
}