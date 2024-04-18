/*
 *  Copyright 2023-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __MPU_BRIDGE_WIFI_CONFIG_H__
#define __MPU_BRIDGE_WIFI_CONFIG_H__

/* WLAN SCAN OPT */
#define CONFIG_SCAN_WITH_RSSIFILTER
#define CONFIG_WIFI_CAPA
#define CONFIG_OWE
#define CONFIG_11R  1

#define CONFIG_IPV6               1
#define CONFIG_MAX_IPV6_ADDRESSES 3

#define CONFIG_WIFI_DTIM_PERIOD

#undef CONFIG_MPU_IO_DUMP

#undef CONFIG_NCP_MPU_HOST_DEBUG

#define CONFIG_MEM_MONITOR_DEBUG

#define CONFIG_5GHz_SUPPORT
#define CONFIG_11AC
#define CONFIG_NCP_RF_TEST_MODE

#define CONFIG_NCP_SUPP

#ifdef CONFIG_NCP_SUPP
#define CONFIG_WPA_SUPP 1
#ifdef CONFIG_WPA_SUPP
//#define CONFIG_WPA_SUPP_P2P 1
#undef CONFIG_WPA_SUPP_DPP
#define CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE 1
#define CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE 1

#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE)
#define CONFIG_EAP_TLS
#define CONFIG_EAP_PEAP
#define CONFIG_EAP_TTLS
#define CONFIG_EAP_FAST
#define CONFIG_EAP_SIM
#define CONFIG_EAP_AKA
#define CONFIG_EAP_AKA_PRIME

#if defined(CONFIG_EAP_PEAP) || defined(CONFIG_EAP_TTLS) || defined(CONFIG_EAP_FAST)
#define CONFIG_EAP_MSCHAPV2
#define CONFIG_EAP_GTC
#endif
#endif
#endif

#define CONFIG_NCP_SUPP_WPS
#else
#undef CONFIG_WPA_SUPP
#endif /*CONFIG_NCP_SUPP*/

#endif /*__MPU_BRIDGE_WIFI_CONFIG_H__*/