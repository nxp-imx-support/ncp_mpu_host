/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */
#include "otopcode.h"
#include "otopcode_private.h"
#include <string.h>

/* -------------------------------------------------------------------------- */
/*                              Variables                                     */
/* -------------------------------------------------------------------------- */

const static uint8_t no_of_ot_cmds = (sizeof(otcommands) / sizeof(otcommands[0]));

/* -------------------------------------------------------------------------- */
/*                                  Function prototypes                       */
/* -------------------------------------------------------------------------- */

static int8_t binarySearch(uint8_t *searcharray[], uint8_t stringtosearch[], uint8_t length);

/* -------------------------------------------------------------------------- */
/*                              Private Functions                             */
/* -------------------------------------------------------------------------- */

/* This function will do a binary search on searcharray[] with a given "length"
 * for a given string stringtosearch[], and will return index of string in the
 * array searcharray[]. Returns -1 if no match is found. */

static int8_t binarySearch(uint8_t *searcharray[], uint8_t stringtosearch[], uint8_t length)
{
    int8_t left  = 0;
    int8_t right = length - 1;

    // Loop to implement binary search
    while (left <= right)
    {
        // Calculate mid point
        uint8_t mid = left + (right - left) / 2;

        if (strcmp(stringtosearch, (searcharray[mid])) == 0)
        {
            return mid;
        }

        // If string to search is greater, ignore left half
        if (strcmp(stringtosearch, (searcharray[mid])) > 0)
        {
            left = mid + 1;
        }

        // If string to search is smaller, ignore right half
        else
        {
            right = mid - 1;
        }
    }

    return -1;
}

/* -------------------------------------------------------------------------- */
/*                              Public Functions                              */
/* -------------------------------------------------------------------------- */

int8_t ot_get_opcode(uint8_t *userinputcmd, uint8_t otcmdlen)
{
    uint8_t inputcommand[otcmdlen + 1]; //+1 is for null character
    int8_t  ret;

    memcpy(inputcommand, userinputcmd, otcmdlen);
    inputcommand[otcmdlen] = '\0'; // add null character at the end of stream of characters

    ret = binarySearch(otcommands, inputcommand, no_of_ot_cmds);

    return ret;
}
