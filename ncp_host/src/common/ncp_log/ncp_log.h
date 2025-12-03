/*
 * Copyright 2024 - 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * The BSD-3-Clause license can be found at https://spdx.org/licenses/BSD-3-Clause.html
 */
#ifndef __NCP_LOG_H__
#define __NCP_LOG_H__

#include <stdio.h>
#include <stdint.h>

#define CONFIG_LOG_NCP_LEVEL          NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_HOST_APP_LEVEL NCP_LOG_LEVEL_INF
#define CONFIG_LOG_GPIO_LEVEL         NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_GPIO_LEVEL     NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_INTF_LEVEL     NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_PM_LEVEL       NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_ADAPTER_LEVEL  NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_INET_LEVEL     NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_MBEDTLS_LEVEL  NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_SYSTEM_LEVEL   NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_WIFI_LEVEL     NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_BLE_LEVEL      NCP_LOG_LEVEL_INF
#define CONFIG_LOG_NCP_OT_LEVEL       NCP_LOG_LEVEL_INF


#define NCP_LOG_LEVEL_ERR   1
#define NCP_LOG_LEVEL_WRN   2
#define NCP_LOG_LEVEL_INF   3
#define NCP_LOG_LEVEL_DBG   4

#ifndef CONFIG_NCP_LOG_DEFAULT_LEVEL
#define CONFIG_NCP_LOG_DEFAULT_LEVEL NCP_LOG_LEVEL_INF
#endif

#define NCP_LOG_MODULE_REGISTER(module_name, level) \
    static const char *NCP_LOG_MODULE_NAME = #module_name; \
    static const int NCP_LOG_MODULE_LEVEL = level;

#define NCP_LOG_MODULE_DEFINE(module_name, level) \
    const char NCP_LOG_MODULE_NAME_##module_name[] = #module_name; \
    const int NCP_LOG_MODULE_LEVEL_##module_name = level;

#define NCP_LOG_MODULE_DECLARE(module_name) \
    extern const char NCP_LOG_MODULE_NAME_##module_name[]; \
    extern const int NCP_LOG_MODULE_LEVEL_##module_name; \
    static const char *NCP_LOG_MODULE_NAME = NCP_LOG_MODULE_NAME_##module_name; \
    static int NCP_LOG_MODULE_LEVEL = CONFIG_NCP_LOG_DEFAULT_LEVEL; \
    __attribute__((constructor)) static void _log_init_##module_name(void) { \
        NCP_LOG_MODULE_LEVEL = NCP_LOG_MODULE_LEVEL_##module_name; \
    }

#define NCP_LOG_ERR(...) do { \
    if (NCP_LOG_LEVEL_ERR <= NCP_LOG_MODULE_LEVEL) \
        printf("[%s] ERR: ", NCP_LOG_MODULE_NAME), printf(__VA_ARGS__), printf("\n"); \
} while(0)

#define NCP_LOG_WRN(...) do { \
    if (NCP_LOG_LEVEL_WRN <= NCP_LOG_MODULE_LEVEL) \
        printf("[%s] WRN: ", NCP_LOG_MODULE_NAME), printf(__VA_ARGS__), printf("\n"); \
} while(0)

#define NCP_LOG_INF(...) do { \
    if (NCP_LOG_LEVEL_INF <= NCP_LOG_MODULE_LEVEL) \
        printf("[%s] ", NCP_LOG_MODULE_NAME), printf(__VA_ARGS__), printf("\n"); \
} while(0)

#define NCP_LOG_DBG(...) do { \
    if (NCP_LOG_LEVEL_DBG <= NCP_LOG_MODULE_LEVEL) \
        printf("[%s] DBG: ", NCP_LOG_MODULE_NAME), printf(__VA_ARGS__), printf("\n"); \
} while(0)

#define NCP_LOG_HEXDUMP_DBG(data, len) do { \
    if (NCP_LOG_LEVEL_DBG <= NCP_LOG_MODULE_LEVEL) { \
        printf("[%s] HEX: ", NCP_LOG_MODULE_NAME); \
        for (int _i = 0; _i < (len); _i++) { \
            printf("%02x ", ((uint8_t*)(data))[_i]); \
            if ((_i + 1) % 16 == 0) printf("\n            "); \
        } \
        printf("\n"); \
    } \
} while(0)

#endif /* __NCP_LOG_H__ */
