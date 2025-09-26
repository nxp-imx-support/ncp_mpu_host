/*
 * iperf, Copyright (c) 2014-2018, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */

/*
 *  Copyright 2023-2024 NXP
 */

#ifndef __NCP_HOST_COMMAND_WIFI_H__
#define __NCP_HOST_COMMAND_WIFI_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/times.h>
#include <sys/time.h>
#include "ncp_host_wifi_config.h"
#include "ncp_host_command.h"

#define MACSTR                    "%02X:%02X:%02X:%02X:%02X:%02X "
#define MAC2STR(a)                a[0], a[1], a[2], a[3], a[4], a[5]
#define NCP_MAX_AP_ENTRIES 30
#define NCP_IP_LENGTH      4
#define NCP_IP_VALID       255

#define WLAN_NETWORK_NAME_MAX_LENGTH    32
#define IEEEtypes_SSID_SIZE             32
#define IEEEtypes_ADDRESS_SIZE          6
#define NCP_WLAN_KNOWN_NETWORKS  5
#define MAX_NUM_CLIENTS                 16
#define MODULE_NAME_MAX_LEN             16
#define VAR_NAME_MAX_LEN                32
#define CONFIG_VALUE_MAX_LEN            256

#define NCP_CMD_WLAN_STA         0x00000000
#define NCP_CMD_WLAN_BASIC       0x00100000
#define NCP_CMD_WLAN_REGULATORY  0x00200000
#define NCP_CMD_WLAN_POWERMGMT   0x00300000
#define NCP_CMD_WLAN_DEBUG       0x00400000
#define NCP_CMD_WLAN_OTHER       0x00500000
#define NCP_CMD_WLAN_MEMORY      0x00600000
#define NCP_CMD_WLAN_NETWORK     0x00700000
#define NCP_CMD_WLAN_OFFLOAD     0x00800000
#define NCP_CMD_WLAN_SOCKET      0x00900000
#define NCP_CMD_WLAN_UAP         0x00a00000
#define NCP_CMD_WLAN_HTTP        0x00b00000
#define NCP_CMD_WLAN_COEX        0x00c00000
#define NCP_CMD_WLAN_MATTER      0x00d00000
#define NCP_CMD_WLAN_EDGE_LOCK   0x00e00000
#define NCP_CMD_WLAN_ASYNC_EVENT 0x00f00000

/* The max size of the network list*/
#define NCP_WLAN_KNOWN_NETWORKS 5

#define FOLD_U32T(u)          ((uint32_t)(((u) >> 16) + ((u)&0x0000ffffUL)))
#define SWAP_BYTES_IN_WORD(w) (((w)&0xff) << 8) | (((w)&0xff00) >> 8)

#define PING_INTERVAL 1000
#define PING_DEFAULT_TIMEOUT_SEC 2
#define PING_DEFAULT_COUNT       10
#define PING_DEFAULT_SIZE        56
#define PING_MAX_SIZE            65507
#define PING_ID 0xAFAF
#define IP_ADDR_LEN 16

#pragma pack(1)
#define MLAN_MAC_ADDR_LENGTH (6)
#ifdef CONFIG_IPV6
/** The maximum number of IPV6 addresses that will be stored */
#define MAX_IPV6_ADDRESSES 3
#endif

struct icmp_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
};

typedef uint32_t in_addr_t;

struct ip_hdr {
    /* version / header length */
    uint8_t _v_hl;
    /* type of service */
    uint8_t _tos;
    /* total length */
    uint16_t _len;
    /* identification */
    uint16_t _id;
    /* fragment offset field */
    uint16_t _offset;
#define IP_RF 0x8000U        /* reserved fragment flag */
#define IP_DF 0x4000U        /* don't fragment flag */
#define IP_MF 0x2000U        /* more fragments flag */
#define IP_OFFMASK 0x1fffU   /* mask for fragmenting bits */
    /* time to live */
    uint8_t _ttl;
    /* protocol*/
    uint8_t _proto;
    /* checksum */
    uint16_t _chksum;
    /* source and destination IP addresses */
    in_addr_t src;
    in_addr_t dest;
};

typedef struct _ping_msg_t
{
    uint16_t size;
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
} ping_msg_t;

typedef struct _ping_time_t
{
    uint64_t secs;
    uint64_t usecs;
} ping_time_t;

typedef struct _ping_res
{
    int seq_no;
    int echo_resp;
    ping_time_t time;
    uint32_t recvd;
    int ttl;
    char ip_addr[IP_ADDR_LEN];
    uint16_t size;
} ping_res_t;

/**
 * @brief This function prepares ncp iperf command
 *
 * @return Status returned
 */

#define NCP_IPERF_TCP_SERVER_PORT_DEFAULT 5001
#define NCP_IPERF_UDP_SERVER_PORT_DEFAULT NCP_IPERF_TCP_SERVER_PORT_DEFAULT + 2
#define NCP_IPERF_UDP_RATE           30*1024
#define NCP_IPERF_UDP_TIME           1000
#define NCP_IPERF_PKG_COUNT          1000
#define NCP_IPERF_PER_TCP_PKG_SIZE   1448
#define NCP_IPERF_PER_UDP_PKG_SIZE   1472

#define IPERF_TCP_RECV_TIMEOUT           1000
#define IPERF_UDP_RECV_TIMEOUT           1000
#define NCP_IPERF_END_TOKEN_SIZE     11
extern uint32_t g_udp_recv_timeout;

enum ncp_iperf_item
{
    NCP_IPERF_TCP_TX,
    NCP_IPERF_TCP_RX,
    NCP_IPERF_UDP_TX,
    NCP_IPERF_UDP_RX,
    FALSE_ITEM,
};

typedef struct _iperf_set_t
{
	uint32_t iperf_type;
	uint32_t iperf_count;
    uint32_t iperf_udp_rate;
    uint32_t iperf_udp_time;
    uint32_t iperf_per_size;
} iperf_set_t;

typedef struct _iperf_msg_t
{
    int16_t status[2];
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    uint32_t port;
    uint16_t per_size;
    char ip_addr[IP_ADDR_LEN];
    iperf_set_t iperf_set;
} iperf_msg_t;


extern int cli_optind;
extern char *cli_optarg;
static inline int cli_getopt(int argc, char ** argv, char * fmt)
{
    char *opt, *c;

    if (cli_optind == argc)
        return -1;
    cli_optarg = NULL;
    opt        = argv[cli_optind];
    if (opt[0] != '-')
        return -1;
    if (opt[0] == 0 || opt[1] == 0)
        return '?';
    cli_optind++;
    c = strchr(fmt, opt[1]);
    if (c == NULL)
        return opt[1];
    if (c[1] == ':')
    {
        if (cli_optind < argc)
            cli_optarg = argv[cli_optind++];
    }
    return c[0];
}

static inline uint16_t inet_chksum(const void *dataptr, int len)
{
    const uint8_t *pb = (const uint8_t *)dataptr;
    const uint16_t *ps;
    uint16_t t   = 0;
    uint32_t sum = 0;
    int odd      = ((uintptr_t)pb & 1);

    /* Get aligned to u16_t */
    if (odd && len > 0)
    {
        ((uint8_t *)&t)[1] = *pb++;
        len--;
    }

    /* Add the bulk of the data */
    ps = (const uint16_t *)(const void *)pb;
    while (len > 1)
    {
        sum += *ps++;
        len -= 2;
    }

    /* Consume left-over byte, if any */
    if (len > 0)
    {
        ((uint8_t *)&t)[0] = *(const uint8_t *)ps;
    }

    /* Add end bytes */
    sum += t;

    /* Fold 32-bit sum to 16 bits
       calling this twice is probably faster than if statements... */
    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum);

    /* Swap if alignment was odd */
    if (odd)
    {
        sum = SWAP_BYTES_IN_WORD(sum);
    }

    return (uint16_t)(~(unsigned int)(uint16_t)sum);
}

static inline int ping_time_now(ping_time_t *time)
{
    struct timeval tv;
    int result;
    result = gettimeofday(&tv, NULL);
    time->secs = tv.tv_sec;
    time->usecs = tv.tv_usec;
    return result;
}

/* ping_time_compare
 *
 * Compare two timestamps
 *
 * Returns -1 if time1 is earlier, 1 if time1 is later,
 * or 0 if the timestamps are equal.
 */
static inline int ping_time_compare(ping_time_t *time1, ping_time_t *time2)
{
    if (time1->secs < time2->secs)
        return -1;
    if (time1->secs > time2->secs)
        return 1;
    if (time1->usecs < time2->usecs)
        return -1;
    if (time1->usecs > time2->usecs)
        return 1;
    return 0;
}

/* ping_time_diff
 *
 * Calculates the time from time2 to time1, assuming time1 is later than time2.
 * The diff will always be positive, so the return value should be checked
 * to determine if time1 was earlier than time2.
 *
 * Returns 1 if the time1 is less than or equal to time2, otherwise 0.
 */
static inline int ping_time_diff(ping_time_t *time1, ping_time_t *time2, ping_time_t *diff)
{
    int past = 0;
    int cmp = 0;

    cmp = ping_time_compare(time1, time2);
    if (cmp == 0) {
        diff->secs = 0;
        diff->usecs = 0;
        past = 1;
    }
    else if (cmp == 1) {
        diff->secs = time1->secs - time2->secs;
        diff->usecs = time1->usecs;
        if (diff->usecs < time2->usecs) {
            diff->secs --;
            diff->usecs += 1000000;
        }
        diff->usecs = diff->usecs - time2->usecs;
    } else {
        diff->secs = time2->secs - time1->secs;
        diff->usecs = time2->usecs;
        if (diff->usecs < time1->usecs) {
            diff->secs --;
            diff->usecs += 1000000;
        }
        diff->usecs = diff->usecs - time1->usecs;
        past = 1;
    }

    return past;
}

static inline uint64_t ping_time_in_msecs(ping_time_t *time)
{
    return time->secs * 1000 + time->usecs / 1000;
}

/*MPU ncp host TLV definitions*/
#define NCP_CMD_NETWORK_SSID_TLV     0x0001
#define NCP_CMD_NETWORK_BSSID_TLV    0x0002
#define NCP_CMD_NETWORK_CHANNEL_TLV  0x0003
#define NCP_CMD_NETWORK_IP_TLV       0x0004
#define NCP_CMD_NETWORK_SECURITY_TLV 0x0005
#define NCP_CMD_NETWORK_ROLE_TLV     0x0006
#define NCP_CMD_NETWORK_DTIM_TLV     0x0007
#define NCP_CMD_NETWORK_CAPA_TLV     0x0008
#define NCP_CMD_NETWORK_ACSBAND_TLV  0x0009
#define NCP_CMD_NETWORK_PMF_TLV      0x000A
#define NCP_CMD_NETWORK_PWE_TLV      0x000B
#define NCP_CMD_NETWORK_TR_TLV       0x000C
#define NCP_CMD_NETWORK_EAP_TLV      0x000D

#define NCP_CMD_WLAN_HE_CAP_TLV 0x00FF

/* MPU ncp host MDNS Result TLV */
#define NCP_CMD_NETWORK_MDNS_RESULT_PTR 0x0011
#define NCP_CMD_NETWORK_MDNS_RESULT_SRV 0x0012
#define NCP_CMD_NETWORK_MDNS_RESULT_TXT 0x0013
#define NCP_CMD_NETWORK_MDNS_RESULT_IP_ADDR 0x0014

#define NCP_WLAN_MAC_ADDR_LENGTH 6
#define MAX_MONIT_MAC_FILTER_NUM 3


enum wlan_monitor_opt
{
    MONITOR_FILTER_OPT_ADD_MAC = 0,
    MONITOR_FILTER_OPT_DELETE_MAC,
    MONITOR_FILTER_OPT_CLEAR_MAC,
    MONITOR_FILTER_OPT_DUMP,
};

enum wlan_csi_opt
{
    CSI_FILTER_OPT_ADD = 0,
    CSI_FILTER_OPT_DELETE,
    CSI_FILTER_OPT_CLEAR,
    CSI_FILTER_OPT_DUMP,
};

enum wlan_mef_type
{
    MEF_TYPE_DELETE = 0,
    MEF_TYPE_PING,
    MEF_TYPE_ARP,
    MEF_TYPE_MULTICAST,
    MEF_TYPE_IPV6_NS,
    MEF_TYPE_END,
};

#define NCP_WLAN_DEFAULT_RSSI_THRESHOLD 70

/** The space reserved for storing network names */
#define WLAN_NETWORK_NAME_MAX_LENGTH 32

#define WLAN_SSID_MAX_LENGTH 32

/* Min WPA2 passphrase can be upto 8 ASCII chars */
#define WLAN_PSK_MIN_LENGTH 8
/* Max WPA2 passphrase can be upto 63 ASCII chars or 64 hexadecimal digits*/
#define WLAN_PSK_MAX_LENGTH 65
/* Min WPA3 password can be upto 8 ASCII chars */
#define WLAN_PASSWORD_MIN_LENGTH 8
/* Max WPA3 password can be upto 255 ASCII chars */
#define WLAN_PASSWORD_MAX_LENGTH 255
/* Max WPA2 Enterprise identity can be upto 64 characters */
#define IDENTITY_MAX_LENGTH 64
/* Max WPA2 Enterprise password can be upto 128 unicode characters */
#define PASSWORD_MAX_LENGTH 128

/** The operation could not be performed in the current system state. */
#define WLAN_ERROR_STATE 3

/*Set UAP max client count status*/
#define WLAN_SET_MAX_CLIENT_CNT_SUCCESS          0
#define WLAN_SET_MAX_CLIENT_CNT_FAIL             1
#define WLAN_SET_MAX_CLIENT_CNT_START            2
#define WLAN_SET_MAX_CLIENT_CNT_EXCEED           3

#define ACTION_GET   0
#define ACTION_SET   1

/* DNS field TYPE used for "Resource Records" */
#define DNS_RRTYPE_A     1   /* a host address */
#define DNS_RRTYPE_PTR   12  /* a domain name pointer */
#define DNS_RRTYPE_AAAA  28  /* IPv6 address */
#define DNS_RRTYPE_SRV   33  /* service location */
#define DNS_RRTYPE_ANY   255 /* any type */

enum mdns_sd_proto {
  DNSSD_PROTO_UDP = 0,
  DNSSD_PROTO_TCP = 1
};

#define MDNS_ADDRTYPE_IPV4      0
#define MDNS_ADDRTYPE_IPV6      1

typedef struct _NCP_CMD_WLAN_RESET_CFG
{
    int option;
} NCP_CMD_WLAN_RESET_CFG;

/** Scan Result */
typedef struct _ncp_wlan_scan_result
{
    /** The network SSID, represented as a NULL-terminated C string of 0 to 32
     *  characters.  If the network has a hidden SSID, this will be the empty
     *  string.
     */
    char ssid[33];
    /** SSID length */
    unsigned int ssid_len;
    /** The network BSSID, represented as a 6-byte array. */
    char bssid[6];
    /** The network channel. */
    unsigned int channel;

    /* network features */

    /** The network supports 802.11N.  This is set to 0 if the network does not
     *	support 802.11N or if the system does not have 802.11N support enabled. */
    unsigned dot11n : 1;
#if CONFIG_NCP_11AC
    /** The network supports 802.11AC.	This is set to 0 if the network does not
     *	support 802.11AC or if the system does not have 802.11AC support enabled. */
    unsigned dot11ac : 1;
#endif
#if CONFIG_NCP_11AX
    /** The network supports 802.11AX.	This is set to 0 if the network does not
     *	support 802.11AX or if the system does not have 802.11AX support enabled. */
    unsigned dot11ax : 1;
#endif
    unsigned wmm : 1;
#ifdef CONFIG_NCP_SUPP_WPS
    /** The network supports WPS.  This is set to 0 if the network does not
     *  support WPS or if the system does not have WPS support enabled. */
    unsigned wps : 1;
    /** WPS Type PBC/PIN */
    unsigned int wps_session;
#endif
    /** WPA2 Enterprise security */
    unsigned wpa2_entp : 1;
    /** The network uses WEP security. */
    unsigned wep : 1;
    /** The network uses WPA security. */
    unsigned wpa : 1;
    /** The network uses WPA2 security */
    unsigned wpa2 : 1;
    /** The network uses WPA2 SHA256 security */
    unsigned wpa2_sha256 : 1;
    /** The network uses WPA3 SAE security */
    unsigned wpa3_sae : 1;
    /** The network uses WPA3 Enterprise security */
    unsigned wpa3_entp: 1;
    /** The network uses WPA3 Enterprise SHA256 security */
    unsigned wpa3_1x_sha256 : 1;
    /** The network uses WPA3 Enterprise SHA384 security */
    unsigned wpa3_1x_sha384 : 1;

    /** The signal strength of the beacon */
    unsigned char rssi;
    /** The network SSID, represented as a NULL-terminated C string of 0 to 32
     *  characters.  If the network has a hidden SSID, this will be the empty
     *  string.
     */
    char trans_ssid[33];
    /** SSID length */
    unsigned int trans_ssid_len;
    /** The network BSSID, represented as a 6-byte array. */
    char trans_bssid[6];

    /** Beacon Period */
    uint16_t beacon_period;

    /** DTIM Period */
    uint8_t dtim_period;
    /** MFPC (Management Frame Protection Capable) bit of AP (Access Point) */
    uint8_t ap_mfpc;
    /** MFPR (Management Frame Protection Required) bit of AP (Access Point) */
    uint8_t ap_mfpr;

#if CONFIG_NCP_11K
    /** Neighbor report support */
    bool neighbor_report_supported;
#endif
#if CONFIG_NCP_11V
    /** bss transition support */
    bool bss_transition_supported;
#endif
} NCP_WLAN_SCAN_RESULT;


typedef struct _NCP_CMD_SCAN_NETWORK_INFO
{
    uint32_t res_cnt;
    NCP_WLAN_SCAN_RESULT res[NCP_MAX_AP_ENTRIES];
} NCP_CMD_SCAN_NETWORK_INFO;

typedef struct _NCP_CMD_FW_VERSION
{
    /** Driver version string */
    char driver_ver_str[16];
    /** Firmware version string */
    char fw_ver_str[128];
} NCP_CMD_FW_VERSION;

typedef struct _NCP_CMD_MAC_ADDRESS
{
    uint8_t mac_addr[NCP_WLAN_MAC_ADDR_LENGTH];
} NCP_CMD_MAC_ADDRESS;

typedef struct _NCP_CMD_GET_MAC_ADDRESS
{
    uint8_t uap_mac[NCP_WLAN_MAC_ADDR_LENGTH];
    uint8_t sta_mac[NCP_WLAN_MAC_ADDR_LENGTH];
} NCP_CMD_GET_MAC_ADDRESS;

/** Wi-Fi Statistics counter */
typedef struct _NCP_CMD_PKT_STATS
{
 /** Multicast transmitted frame count */
    uint32_t mcast_tx_frame;
    /** Failure count */
    uint32_t failed;
    /** Retry count */
    uint32_t retry;
    /** Multi entry count */
    uint32_t multi_retry;
    /** Duplicate frame count */
    uint32_t frame_dup;
    /** RTS success count */
    uint32_t rts_success;
    /** RTS failure count */
    uint32_t rts_failure;
    /** Ack failure count */
    uint32_t ack_failure;
    /** Rx fragmentation count */
    uint32_t rx_frag;
    /** Multicast Tx frame count */
    uint32_t mcast_rx_frame;
    /** FCS error count */
    uint32_t fcs_error;
    /** Tx frame count */
    uint32_t tx_frame;
    /** WEP ICV error count */
    uint32_t wep_icv_error[4];
    /** beacon recv count */
    uint32_t bcn_rcv_cnt;
    /** beacon miss count */
    uint32_t bcn_miss_cnt;
    /** received amsdu count*/
    uint32_t amsdu_rx_cnt;
    /** received msdu count in amsdu*/
    uint32_t msdu_in_rx_amsdu_cnt;
    /** tx amsdu count*/
    uint32_t amsdu_tx_cnt;
    /** tx msdu count in amsdu*/
    uint32_t msdu_in_tx_amsdu_cnt;
    /** Tx frag count */
    uint32_t tx_frag_cnt;
    /** Qos Tx frag count */
    uint32_t qos_tx_frag_cnt[8];
    /** Qos failed count */
    uint32_t qos_failed_cnt[8];
    /** Qos retry count */
    uint32_t qos_retry_cnt[8];
    /** Qos multi retry count */
    uint32_t qos_multi_retry_cnt[8];
    /** Qos frame dup count */
    uint32_t qos_frm_dup_cnt[8];
    /** Qos rts success count */
    uint32_t qos_rts_suc_cnt[8];
    /** Qos rts failure count */
    uint32_t qos_rts_failure_cnt[8];
    /** Qos ack failure count */
    uint32_t qos_ack_failure_cnt[8];
    /** Qos Rx frag count */
    uint32_t qos_rx_frag_cnt[8];
    /** Qos Tx frame count */
    uint32_t qos_tx_frm_cnt[8];
    /** Qos discarded frame count */
    uint32_t qos_discarded_frm_cnt[8];
    /** Qos mpdus Rx count */
    uint32_t qos_mpdus_rx_cnt[8];
    /** Qos retry rx count */
    uint32_t qos_retries_rx_cnt[8];
    /** CMACICV errors count */
    uint32_t cmacicv_errors;
    /** CMAC replays count */
    uint32_t cmac_replays;
    /** mgmt CCMP replays count */
    uint32_t mgmt_ccmp_replays;
    /** TKIP ICV errors count */
    uint32_t tkipicv_errors;
    /** TKIP replays count */
    uint32_t tkip_replays;
    /** CCMP decrypt errors count */
    uint32_t ccmp_decrypt_errors;
    /** CCMP replays count */
    uint32_t ccmp_replays;
    /** Tx amsdu count */
    uint32_t tx_amsdu_cnt;
    /** failed amsdu count */
    uint32_t failed_amsdu_cnt;
    /** retry amsdu count */
    uint32_t retry_amsdu_cnt;
    /** multi-retry amsdu count */
    uint32_t multi_retry_amsdu_cnt;
    /** Tx octets in amsdu count */
    uint64_t tx_octets_in_amsdu_cnt;
    /** amsdu ack failure count */
    uint32_t amsdu_ack_failure_cnt;
    /** Rx amsdu count */
    uint32_t rx_amsdu_cnt;
    /** Rx octets in amsdu count */
    uint64_t rx_octets_in_amsdu_cnt;
    /** Tx ampdu count */
    uint32_t tx_ampdu_cnt;
    /** tx mpdus in ampdu count */
    uint32_t tx_mpdus_in_ampdu_cnt;
    /** tx octets in ampdu count */
    uint64_t tx_octets_in_ampdu_cnt;
    /** ampdu Rx count */
    uint32_t ampdu_rx_cnt;
    /** mpdu in Rx ampdu count */
    uint32_t mpdu_in_rx_ampdu_cnt;
    /** Rx octets ampdu count */
    uint64_t rx_octets_in_ampdu_cnt;
    /** ampdu delimiter CRC error count */
    uint32_t ampdu_delimiter_crc_error_cnt;
    /** Rx Stuck Related Info*/
    /** Rx Stuck Issue count */
    uint32_t rx_stuck_issue_cnt[2];
    /** Rx Stuck Recovery count */
    uint32_t rx_stuck_recovery_cnt;
    /** Rx Stuck TSF */
    uint64_t rx_stuck_tsf[2];
    /** Tx Watchdog Recovery Related Info */
    /** Tx Watchdog Recovery count */
    uint32_t tx_watchdog_recovery_cnt;
    /** Tx Watchdog TSF */
    uint64_t tx_watchdog_tsf[2];
    /** Channel Switch Related Info */
    /** Channel Switch Announcement Sent */
    uint32_t channel_switch_ann_sent;
    /** Channel Switch State */
    uint32_t channel_switch_state;
    /** Register Class */
    uint32_t reg_class;
    /** Channel Number */
    uint32_t channel_number;
    /** Channel Switch Mode */
    uint32_t channel_switch_mode;
    /** Reset Rx Mac Recovery Count */
    uint32_t rx_reset_mac_recovery_cnt;
    /** ISR2 Not Done Count*/
    uint32_t rx_Isr2_NotDone_Cnt;
    /** GDMA Abort Count */
    uint32_t gdma_abort_cnt;
    /** Rx Reset MAC Count */
    uint32_t g_reset_rx_mac_cnt;
    // Ownership error counters
    /** Error Ownership error count*/
    uint32_t dwCtlErrCnt;
    /** Control Ownership error count*/
    uint32_t dwBcnErrCnt;
    /** Control Ownership error count*/
    uint32_t dwMgtErrCnt;
    /** Control Ownership error count*/
    uint32_t dwDatErrCnt;
    /** BIGTK MME good count*/
    uint32_t bigtk_mmeGoodCnt;
    /** BIGTK Replay error count*/
    uint32_t bigtk_replayErrCnt;
    /** BIGTK MIC error count*/
    uint32_t bigtk_micErrCnt;
    /** BIGTK MME not included count*/
    uint32_t bigtk_mmeNotFoundCnt;
    /** RX unicast count */
    uint32_t rx_unicast_cnt;
    /** TX Buffer Overrun Dropped Count */
    uint32_t tx_overrun_cnt;
    /** RX Buffer Overrun Dropped Count */
    uint32_t rx_overrun_cnt;
} NCP_CMD_PKT_STATS;

/** Get current rssi */
typedef struct _NCP_CMD_GET_CURRENT_RSSI
{
    /** The signal strength of the beacon */
    short rssi;
} NCP_CMD_GET_CURRENT_RSSI;

/** Get current channel */
typedef struct _NCP_CMD_GET_CURRENT_CHANNEL
{
    /** Channel Number */
    uint16_t channel;
} NCP_CMD_GET_CURRENT_CHANNEL;

/** Get netif flags */
typedef struct _NCP_CMD_GET_NETIF_FLAGS
{
    /** Netif flags */
    uint8_t flags;
} NCP_CMD_GET_NETIF_FLAGS;

/** This data structure represents an IPv4 address */
struct ipv4_config
{
    /** Set to \ref ADDR_TYPE_DHCP to use DHCP to obtain the IP address or
     *  \ref ADDR_TYPE_STATIC to use a static IP. In case of static IP
     *  address ip, gw, netmask and dns members must be specified.  When
     *  using DHCP, the ip, gw, netmask and dns are overwritten by the
     *  values obtained from the DHCP server. They should be zeroed out if
     *  not used. */
    unsigned addr_type;
    /** The system's IP address in network order. */
    unsigned address;
    /** The system's default gateway in network order. */
    unsigned gw;
    /** The system's subnet mask in network order. */
    unsigned netmask;
    /** The system's primary dns server in network order. */
    unsigned dns1;
    /** The system's secondary dns server in network order. */
    unsigned dns2;
};

#ifdef CONFIG_IPV6
/** This data structure represents an IPv6 address */
struct ipv6_config
{
    /** The system's IPv6 address in network order. */
    unsigned address[4];
    /** The address type: linklocal, site-local or global. */
    unsigned char addr_type;
    /** The state of IPv6 address (Tentative, Preferred, etc). */
    unsigned char addr_state;
    /** For structure alignment */
    unsigned char padding[2];
};
#endif

/** Network IP configuration.
 *
 *  This data structure represents the network IP configuration
 *  for IPv4 as well as IPv6 addresses
 */
typedef struct _NCP_CMD_IP_CONFIG
{
#ifdef CONFIG_IPV6
    /** The network IPv6 address configuration that should be
     * associated with this interface. */
    struct ipv6_config ipv6[MAX_IPV6_ADDRESSES];
    /** The network IPv6 valid addresses count */
    unsigned ipv6_count;
#endif
    /** The network IPv4 address configuration that should be
     * associated with this interface. */
    struct ipv4_config ipv4;
} NCP_CMD_IP_CONFIG;

typedef struct _NCP_CMD_CONNECT_STAT
{
    uint8_t ps_mode;
    uint8_t uap_conn_stat;
    uint8_t sta_conn_stat;
} NCP_CMD_CONNECT_STAT;

typedef struct _NCP_CMD_ROAMING
{
    uint32_t enable;
    uint8_t rssi_threshold;
} NCP_CMD_ROAMING;

/** This structure is used for OKC configuration. */
typedef struct _NCP_CMD_OKC
{
    /** STA OKC enable flag,
     *  1: enable OKC,
     *  0: disable OKC.
     */
    uint32_t enable;
} NCP_CMD_OKC;

#ifdef CONFIG_WIFI_CAPA
#define WIFI_SUPPORT_11AX   (1 << 3)
#define WIFI_SUPPORT_11AC   (1 << 2)
#define WIFI_SUPPORT_11N    (1 << 1)
#define WIFI_SUPPORT_LEGACY (1 << 0)
#endif

/** Network wireless BSS Role */
enum wlan_bss_role
{
    /** Infrastructure network. The system will act as a station connected
     *  to an Access Point. */
    WLAN_BSS_ROLE_STA = 0,
    /** uAP (micro-AP) network.  The system will act as an uAP node to
     * which other Wireless clients can connect. */
    WLAN_BSS_ROLE_UAP = 1,
    /** Either Infrastructure network or micro-AP network */
    WLAN_BSS_ROLE_ANY = 0xff,
};

/** Network security types*/
enum wlan_security_type
{
 /** The network does not use security. */
    WLAN_SECURITY_NONE,
    /** The network uses WEP security with open key. */
    WLAN_SECURITY_WEP_OPEN,
    /** The network uses WEP security with shared key. */
    WLAN_SECURITY_WEP_SHARED,
    /** The network uses WPA security with PSK. */
    WLAN_SECURITY_WPA,
    /** The network uses WPA2 security with PSK. */
    WLAN_SECURITY_WPA2,
    /** The network uses WPA/WPA2 mixed security with PSK */
    WLAN_SECURITY_WPA_WPA2_MIXED,
#ifdef CONFIG_11R
    /** The network uses WPA2 security with PSK FT. */
    WLAN_SECURITY_WPA2_FT,
#endif
    /** The network uses WPA3 security with SAE. */
    WLAN_SECURITY_WPA3_SAE,
#ifdef CONFIG_WPA_SUPP
#ifdef CONFIG_11R
    /** The network uses WPA3 security with SAE FT. */
    WLAN_SECURITY_WPA3_FT_SAE,
#endif
#endif
    /** The network uses WPA3 security with SAE EXT KEY. */
    WLAN_SECURITY_WPA3_SAE_EXT_KEY,
    /** The network uses WPA2/WPA3 SAE mixed security with PSK. This security mode
     * is specific to uAP or SoftAP only */
    WLAN_SECURITY_WPA2_WPA3_SAE_MIXED,
#ifdef CONFIG_OWE
    /** The network uses OWE only security without Transition mode support. */
    WLAN_SECURITY_OWE_ONLY,
#endif
#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-TLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS,
#endif
#ifdef CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_TLS
    /** The network uses WPA2 Enterprise EAP-TLS SHA256 security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_SHA256,
#ifdef CONFIG_11R
    /** The network uses WPA2 Enterprise EAP-TLS FT security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_FT,
    /** The network uses WPA2 Enterprise EAP-TLS FT SHA384 security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_FT_SHA384,
#endif
#endif
#ifdef CONFIG_EAP_TTLS
    /** The network uses WPA2 Enterprise EAP-TTLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TTLS,
#ifdef CONFIG_EAP_MSCHAPV2
    /** The network uses WPA2 Enterprise EAP-TTLS-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_TTLS_MSCHAPV2,
#endif
#endif
#endif
#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_PEAP_MSCHAPV2) || defined(CONFIG_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-PEAP-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_MSCHAPV2,
#endif
#ifdef CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_TLS
    /** The network uses WPA2 Enterprise EAP-PEAP-TLS security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_TLS,
#endif
#ifdef CONFIG_EAP_GTC
    /** The network uses WPA2 Enterprise EAP-PEAP-GTC security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_GTC,
#endif
#endif
#ifdef CONFIG_EAP_FAST
#ifdef CONFIG_EAP_MSCHAPV2
    /** The network uses WPA2 Enterprise EAP-FAST-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_MSCHAPV2,
#endif
#ifdef CONFIG_EAP_GTC
    /** The network uses WPA2 Enterprise EAP-FAST-GTC security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_GTC,
#endif
#endif
#ifdef CONFIG_EAP_SIM
    /** The network uses WPA2 Enterprise EAP-SIM security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_SIM,
#endif
#ifdef CONFIG_EAP_AKA
    /** The network uses WPA2 Enterprise EAP-AKA security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA,
#endif
#ifdef CONFIG_EAP_AKA_PRIME
    /** The network uses WPA2 Enterprise EAP-AKA-PRIME security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA_PRIME,
#endif
#endif
#ifdef CONFIG_WPA_SUPP_DPP
    /** The network uses DPP security with NAK(Net Access Key) */
    WLAN_SECURITY_DPP,
#endif
    /** The network can use any security method. This is often used when
     * the user only knows the name and passphrase but not the security
     * type.  */
    WLAN_SECURITY_WILDCARD,
};

enum
{
    /** static IP address */
    ADDR_TYPE_STATIC = 0,
    /** Dynamic  IP address*/
    ADDR_TYPE_DHCP = 1,
    /** Link level address */
    ADDR_TYPE_LLA = 2,
};

#ifdef CONFIG_IPV6
/** This data structure represents an IPv6 address */
typedef struct _ncp_wlan_ipv6_config
{
    /** The system's IPv6 address in network order. */
    unsigned address[4];
    /** The address type: linklocal, site-local or global. */
    unsigned char addr_type_str[16];
    /** The state of IPv6 address (Tentative, Preferred, etc). */
    unsigned char addr_state_str[32];
} NCP_WLAN_IPV6_CONFIG;
#endif

/** This data structure represents an IPv4 address */
typedef struct _ncp_wlan_ipv4_config
{
    /** Set to \ref ADDR_TYPE_DHCP to use DHCP to obtain the IP address or
     *  \ref ADDR_TYPE_STATIC to use a static IP. In case of static IP
     *  address ip, gw, netmask and dns members must be specified.  When
     *  using DHCP, the ip, gw, netmask and dns are overwritten by the
     *  values obtained from the DHCP server. They should be zeroed out if
     *  not used. */
    uint32_t addr_type : 2;
    /** The system's IP address in network order. */
    uint32_t address;
    /** The system's default gateway in network order. */
    uint32_t gw;
    /** The system's subnet mask in network order. */
    uint32_t netmask;
    /** The system's primary dns server in network order. */
    uint32_t dns1;
    /** The system's secondary dns server in network order. */
    uint32_t dns2;
} NCP_WLAN_IPV4_CONFIG;

/** WLAN Network Profile
 *  This data structure represents a WLAN network profile. It consists of an
 *  arbitrary name, WiFi configuration, and IP address configuration.
 */
typedef struct _ncp_wlan_network
{
    /** The name of this network profile. */
    char name[WLAN_NETWORK_NAME_MAX_LENGTH + 1];
    /** The network SSID, represented as a C string of up to 32 characters
     *  in length.
     *  If this profile is used in the micro-AP mode, this field is
     *  used as the SSID of the network.
     *  If this profile is used in the station mode, this field is
     *  used to identify the network. Set the first byte of the SSID to NULL
     *  (a 0-length string) to use only the BSSID to find the network.
     */
    char ssid[IEEEtypes_SSID_SIZE + 1];
    /** The network BSSID, represented as a 6-byte array.
     *  If this profile is used in the micro-AP mode, this field is
     *  ignored.
     *  If this profile is used in the station mode, this field is
     *  used to identify the network. Set all 6 bytes to 0 to use any BSSID,
     *  in which case only the SSID will be used to find the network.
     */
    char bssid[IEEEtypes_ADDRESS_SIZE];
    /** The channel for this network.
     *  If this profile is used in micro-AP mode, this field
     *  specifies the channel to start the micro-AP interface on. Set this
     *  to 0 for auto channel selection.
     *  If this profile is used in the station mode, this constrains the
     *  channel on which the network to connect should be present. Set this
     *  to 0 to allow the network to be found on any channel. */
    unsigned int channel;
    /** The ACS band if set channel to 0. **/
    uint16_t acs_band;
    /** Rssi threshold */
    short rssi_threshold;
    /** BSS type */
    uint8_t type;
    /** The network wireless mode enum wlan_bss_role. Set this
     *  to specify what type of wireless network mode to use.
     *  This can either be \ref WLAN_BSS_ROLE_STA for use in
     *  the station mode, or it can be \ref WLAN_BSS_ROLE_UAP
     *  for use in the micro-AP mode.
     */
    uint8_t role;

    /** Type of network security to use specified by enum
     * wlan_security_type. */
    uint8_t security_type;

    /** WPA3 Enterprise mode \n
     *  1: enable; \n
     *  0: disable.
     */
    uint8_t wpa3_ent : 1;

    /** WPA3 Enterprise Suite B mode \n
     *  1: enable; \n
     *  0: disable.
     */
    uint8_t wpa3_sb : 1;

    /** WPA3 Enterprise Suite B 192 mode \n
     *  1: enable; \n
     *  0: disable.
     */
    uint8_t wpa3_sb_192 : 1;

    /** EAP (Extensible Authentication Protocol) version */
    uint8_t eap_ver : 1;

    uint8_t enable_11ax : 1;
    uint8_t enable_11ac : 1;
    uint8_t enable_11n : 1;

    /** The network IP address configuration. */
    /** The network IPv6 address configuration */
    NCP_WLAN_IPV6_CONFIG ipv6[CONFIG_MAX_IPV6_ADDRESSES];
    /** The network IPv4 address configuration */
    NCP_WLAN_IPV4_CONFIG ipv4;

    uint8_t is_sta_ipv4_connected;

    char identity[IDENTITY_MAX_LENGTH];

    /* Private Fields */
    /** If set to 1, the ssid field contains the specific SSID for this
     * network.*/
    unsigned ssid_specific : 1;
    /** If set to 1, the bssid field contains the specific BSSID for this
     *  network. */
    unsigned bssid_specific : 1;
    /** If set to 1, the channel field contains the specific channel for this
     * network. */
    unsigned channel_specific : 1;
    /** If set to 0, any security that matches is used. */
    unsigned security_specific : 1;
    /** This indicates this network is used as an internal network for
     * WPS */
    unsigned wps_specific : 1;
    /** Beacon period of associated BSS */
    uint16_t beacon_period;
    /** DTIM period of associated BSS */
    uint8_t dtim_period;
    uint8_t wlan_capa;
} NCP_WLAN_NETWORK;

typedef struct _NCP_CMD_NETWORK_INFO
{
    uint8_t uap_conn_stat;
    uint8_t sta_conn_stat;
    NCP_WLAN_NETWORK uap_network;
    NCP_WLAN_NETWORK sta_network;
} NCP_CMD_NETWORK_INFO;

/*ncp response: wlan network address*/
typedef struct _NCP_CMD_NETWORK_ADDRESS
{
    uint8_t sta_conn_stat;
    NCP_WLAN_NETWORK sta_network;
} NCP_CMD_NETWORK_ADDRESS;

typedef struct _NCP_CMD_NETWORK_LIST
{
    uint8_t count;
    NCP_WLAN_NETWORK net_list[NCP_WLAN_KNOWN_NETWORKS];
} NCP_CMD_NETWORK_LIST;

typedef struct _NCP_CMD_NETWORK_REMOVE
{
    uint8_t name[WLAN_NETWORK_NAME_MAX_LENGTH + 1];
    int8_t remove_state;
} NCP_CMD_NETWORK_REMOVE;

typedef struct _NCP_CMD_GET_CURRENT_NETWORK
{
    NCP_WLAN_NETWORK sta_network;
} NCP_CMD_GET_CURRENT_NETWORK;

typedef struct _NCP_CMD_SCAN_RESULT_COUNT
{
    uint8_t count;
} NCP_CMD_SCAN_RESULT_COUNT;

typedef struct _NCP_CMD_GET_SCAN_RESULT
{
    NCP_WLAN_SCAN_RESULT scan_result;
} NCP_CMD_GET_SCAN_RESULT;

/*NCP SSID tlv*/
typedef struct _SSID_ParamSet_t
{
    TypeHeader_t header;
    char ssid[IEEEtypes_SSID_SIZE + 1];
} SSID_ParamSet_t;

/*NCP BSSID tlv*/
typedef struct _BSSID_ParamSet_t
{
    TypeHeader_t header;
    char bssid[IEEEtypes_ADDRESS_SIZE];
} BSSID_ParamSet_t;

/*NCP bss role tlv*/
typedef struct _BSSRole_ParamSet_t
{
    TypeHeader_t header;
    uint8_t role;
} BSSRole_ParamSet_t;

/*NCP channel tlv*/
typedef struct _Channel_ParamSet_t
{
    TypeHeader_t header;
    uint8_t channel;
} Channel_ParamSet_t;

/*NCP pwe_derivation tlv*/
typedef struct _Pwe_Derivation_ParamSet_t
{
    TypeHeader_t header;
    uint8_t pwe_derivation;
} Pwe_Derivation_ParamSet_t;

/*NCP transition_Disable tlv*/
typedef struct _Transition_Disable_ParamSet_t
{
    TypeHeader_t header;
    uint8_t transition_disable;
} Tr_Disable_ParamSet_t;

/*NCP acs_band tlv*/
typedef struct _ACSBand_ParamSet_t
{
    TypeHeader_t header;
    uint16_t acs_band;
} ACSBand_ParamSet_t;

/*NCP IP address tlv*/
typedef struct _IP_ParamSet_t
{
    TypeHeader_t header;
    uint8_t is_autoip;
    uint32_t address;
    uint32_t gateway;
    uint32_t netmask;
    uint32_t dns1;
    uint32_t dns2;
} IP_ParamSet_t;

/*NCP security tlv*/
typedef struct _Security_ParamSet_t
{
    TypeHeader_t header;
    uint8_t type;
    /** WPA3 Enterprise mode */
    uint8_t wpa3_ent;
    /** WPA3 Enterprise Suite B mode */
    uint8_t wpa3_sb;
    /** WPA3 Enterprise Suite B 192 mode */
    uint8_t wpa3_sb_192;
    uint8_t password_len;
    char password[1];
} Security_ParamSet_t;

/*NCP PMF tlv*/
typedef struct _PMF_ParamSet_t
{
    TypeHeader_t header;
    uint8_t mfpc;
    uint8_t mfpr;
} PMF_ParamSet_t;

/*NCP eap-tls tlv*/
typedef struct _EAP_ParamSet_t
{
    /** Header type and size information. */
    TypeHeader_t header;
    /** Cipher for EAP TLS (Extensible Authentication Protocol Transport Layer Security) */
    unsigned char tls_cipher;
    /** Identity string for EAP */
    char identity[IDENTITY_MAX_LENGTH];
    /** Password string for EAP. */
    char eap_password[PASSWORD_MAX_LENGTH];
    /** Anonymous identity string for EAP */
    char anonymous_identity[IDENTITY_MAX_LENGTH];
    /** Client key password */
    char client_key_passwd[PASSWORD_MAX_LENGTH];
    /** EAP (Extensible Authentication Protocol) version */
    uint8_t eap_ver;
    /** whether verify peer with CA or not
     *  false: not verify,
     *  true: verify. */
    bool verify_peer_cert;
} EAP_ParamSet_t;

#ifdef CONFIG_WIFI_DTIM_PERIOD
/*NCP DTIM tlv*/
typedef struct _DTIM_ParamSet_t
{
    TypeHeader_t header;
    uint8_t dtim_period;
} DTIM_ParamSet_t;
#endif

#ifdef CONFIG_WIFI_CAPA
/*NCP CAPA tlv*/
typedef struct _CAPA_ParamSet_t
{
    TypeHeader_t header;
    uint8_t capa;
} CAPA_ParamSet_t;
#endif

typedef struct _NCP_CMD_NETWORK_ADD
{
    char name[WLAN_NETWORK_NAME_MAX_LENGTH];
    /** Length of TLVs sent in command starting at tlvBuffer */
    uint32_t tlv_buf_len;
    /**
     * SSID TLV, SSID_ParamSet_t
     * BSSID TLV, BSSID_ParamSet_t
     * BSS role TLV, BSSRole_ParamSet_t
     * Channel TLV, Channel_ParamSet_t
     * ACS band TLV, ACSBand_ParamSet_t
     * IP address TLV, IP_ParamSet_t
     * Security TLV, Security_ParamSet_t
     * DTIM period TLV, DTIM_ParamSet_t
     * CAPA TLV, CAPA_ParamSet_t
     */
    uint8_t tlv_buf[1];
} NCP_CMD_NETWORK_ADD;

typedef struct _NCP_CMD_NETWORK_START
{
    char name[32];
    char ssid[32 + 1];
} NCP_CMD_NETWORK_START;

/** This structure is used to configure the provisioning UAP. */
typedef struct _NCP_CMD_UAP_PROV_SET_UAPCFG
{   
   /** Security type, detail value refer to enum wlan_security_type. */
    uint32_t security_type;
   /** SSID string, the maximum valid length of SSID is 32 bytes. */   
    char ssid[WLAN_SSID_MAX_LENGTH + 1];
   /** Password string, the maximum valid length of password is 255 bytes. */
    char uapPass[WLAN_PASSWORD_MAX_LENGTH + 1];
} NCP_CMD_UAP_PROV_SET_UAPCFG;

/** Station information structure */
typedef struct _wlan_sta_info
{
    /** MAC address buffer */
    uint8_t mac[IEEEtypes_ADDRESS_SIZE];
    /**
     * Power management status
     * 0 = active (not in power save)
     * 1 = in power save status
     */
    uint8_t power_mgmt_status;
    /** RSSI: dBm */
    signed char rssi;
} wlan_sta_info;

typedef struct _NCP_CMD_NETWORK_UAP_STA_LIST
{
    /** station count */
    uint16_t sta_count;
    /** station list */
    wlan_sta_info info[MAX_NUM_CLIENTS];
} NCP_CMD_NETWORK_UAP_STA_LIST;

/*NCP Wlan Socket Open*/
#define HTTP_PARA_LEN 16
#define SETH_NAME_LENGTH  64
#define SETH_VALUE_LENGTH 128
#define HTTP_URI_LEN 512
typedef struct _NCP_CMD_SOCKET_OPEN_CFG
{
    char socket_type[HTTP_PARA_LEN];
    char domain_type[HTTP_PARA_LEN];
    char protocol[HTTP_PARA_LEN];
    uint32_t opened_handle;
} NCP_CMD_SOCKET_OPEN_CFG;

/*NCP Wlan Socket Connect*/
#define IP_ADDR_LEN 16
typedef struct _NCP_CMD_SOCKET_CON_CFG
{
    uint32_t handle;
    uint32_t port;
    char ip_addr[IP_ADDR_LEN];
} NCP_CMD_SOCKET_CON_CFG;

/*NCP Wlan Socket Bind*/
typedef struct _NCP_CMD_SOCKET_BIND_CFG
{
    uint32_t handle;
    uint32_t port;
    char ip_addr[IP_ADDR_LEN];
} NCP_CMD_SOCKET_BIND_CFG;

/*NCP Wlan Socket Close*/
typedef struct _NCP_CMD_SOCKET_CLOSE_CFG
{
    uint32_t handle;
} NCP_CMD_SOCKET_CLOSE_CFG;

/*NCP Wlan Socket Listen*/
typedef struct _NCP_CMD_SOCKET_LISTEN_CFG
{
    uint32_t handle;
    uint32_t number;
} NCP_CMD_SOCKET_LISTEN_CFG;

/*NCP Wlan Socket Accept*/
typedef struct _NCP_CMD_SOCKET_ACCEPT_CFG
{
    uint32_t handle;
    int accepted_handle;
} NCP_CMD_SOCKET_ACCEPT_CFG;

/*NCP Wlan Socket Send*/
typedef struct _NCP_CMD_SOCKET_SEND_CFG
{
    uint32_t handle;
    uint32_t size;
    char send_data[1];
} NCP_CMD_SOCKET_SEND_CFG;

/*NCP Wlan Socket Sendto*/
typedef struct _NCP_CMD_SOCKET_SENDTO_CFG
{
    uint32_t handle;
    uint32_t size;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
    char send_data[1];
} NCP_CMD_SOCKET_SENDTO_CFG;

/*NCP Wlan Socket Receive*/
typedef struct _NCP_CMD_SOCKET_RECEIVE_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char recv_data[1];
} NCP_CMD_SOCKET_RECEIVE_CFG;

/*NCP Wlan Socket Recvfrom*/
typedef struct _NCP_CMD_SOCKET_RECVFROM_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char peer_ip[IP_ADDR_LEN];
    uint32_t peer_port;
    char recv_data[1];
} NCP_CMD_SOCKET_RECVFROM_CFG;

/*NCP Wlan Http Connect*/
typedef struct _MPU_NCP_CMD_HTTP_CONNECT_CFG
{
    int opened_handle;
    char host[1];
} NCP_CMD_HTTP_CON_CFG;

/*NCP Wlan Http Disconnect*/
typedef struct _MPU_NCP_CMD_HTTP_DISCONNECT_CFG
{
    uint32_t handle;
} NCP_CMD_HTTP_DISCON_CFG;

/*NCP Wlan Http Seth*/
typedef struct _MPU_NCP_CMD_HTTP_SETH_CFG
{
    char name[SETH_NAME_LENGTH];
    char value[SETH_VALUE_LENGTH];
} NCP_CMD_HTTP_SETH_CFG;

/*NCP Wlan Http Unseth*/
typedef struct _MPU_NCP_CMD_HTTP_UNSETH_CFG
{
    char name[SETH_NAME_LENGTH];
} NCP_CMD_HTTP_UNSETH_CFG;

/*NCP Wlan Http Req*/
typedef struct _MPU_NCP_CMD_HTTP_REQ_CFG
{
    uint32_t handle;
    char method[HTTP_PARA_LEN];
    char uri[HTTP_URI_LEN];
    uint32_t req_size;
    char req_data[1];
} NCP_CMD_HTTP_REQ_CFG;

/*NCP Wlan Http Recv Resp*/
typedef struct _MPU_NCP_CMD_HTTP_REQ_RESP_CFG
{
    uint32_t header_size;
    char recv_header[1];
} NCP_CMD_HTTP_REQ_RESP_CFG;

/*NCP Wlan Http Recv*/
typedef struct _MPU_NCP_CMD_HTTP_RECV_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char recv_data[1];
} NCP_CMD_HTTP_RECV_CFG;

/*NCP Wlan Http Upgrade*/
typedef struct _MPU_NCP_CMD_HTTP_UPG_CFG
{
    uint32_t handle;
    char     uri[HTTP_URI_LEN];
    char     protocol[HTTP_PARA_LEN];
} NCP_CMD_HTTP_UPG_CFG;

/*NCP Wlan Socket Send*/
typedef struct _MPU_NCP_CMD_WEBSOCKET_SEND_CFG
{
    uint32_t handle;
    char type[HTTP_PARA_LEN];
    uint32_t size;
    char send_data[1];
} NCP_CMD_WEBSOCKET_SEND_CFG;


/*NCP Wlan Websocket Receive*/
typedef struct _MPU_NCP_CMD_WEBSOCKET_RECV_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
	uint32_t fin;
    char recv_data[1];
} NCP_CMD_WEBSOCKET_RECV_CFG;

/** Network monitor structure */
typedef struct
{
    /** Action */
    uint16_t action;
    /** Monitor activity */
    uint16_t monitor_activity;
    /** Filter flags */
    uint16_t filter_flags;
    /** Channel scan parameter : Radio type */
    uint8_t radio_type;
    /** Channel number */
    uint8_t chan_number;
    /** mac num of filter*/
    uint8_t filter_num;
    /** Source address of the packet to receive */
    uint8_t mac_addr[MAX_MONIT_MAC_FILTER_NUM][NCP_WLAN_MAC_ADDR_LENGTH];
} NCP_WLAN_NET_MONITOR_PARA;

typedef struct _NCP_CMD_NET_MONITOR
{
    NCP_WLAN_NET_MONITOR_PARA monitor_para;
} NCP_CMD_NET_MONITOR;

typedef struct _NCP_CMD_REGISTER_ACCESS
{
    uint8_t action;
    uint8_t type;
    uint32_t offset;
    uint32_t value;
} NCP_CMD_REGISTER_ACCESS;

typedef struct _NCP_CMD_MEM_STAT
{
    uint32_t free_heap_size;
    uint32_t minimun_ever_free_heap_size;
} NCP_CMD_MEM_STAT;

#define CSI_FILTER_MAX 16
/** Structure of CSI filters */
typedef struct _wlan_csi_filter_t
{
    /** Source address of the packet to receive */
    uint8_t mac_addr[NCP_WLAN_MAC_ADDR_LENGTH];
    /** Pakcet type of the interested CSI */
    uint8_t pkt_type;
    /* Packet subtype of the interested CSI */
    uint8_t subtype;
    /* Other filter flags */
    uint8_t flags;
} wlan_csi_filter_t;

/** Structure of CSI parameters */
typedef struct _wlan_csi_config_params_t
{
    uint8_t bss_type;
    /** CSI enable flag. 1: enable, 2: disable */
    uint16_t csi_enable;
    /** Header ID*/
    uint32_t head_id;
    /** Tail ID */
    uint32_t tail_id;
    /** Number of CSI filters */
    uint8_t csi_filter_cnt;
    /** Chip ID */
    uint8_t chip_id;
    /** band config */
    uint8_t band_config;
    /** Channel num */
    uint8_t channel;
    /** Enable getting CSI data on special channel */
    uint8_t csi_monitor_enable;
    /** CSI data received in cfg channel with mac addr filter, not only RA is us or other*/
    uint8_t ra4us;
    /** CSI filters */
    wlan_csi_filter_t csi_filter[CSI_FILTER_MAX];
} wlan_csi_config_params_t;

typedef struct _NCP_CMD_CSI
{
    wlan_csi_config_params_t csi_para;
} NCP_CMD_CSI;

typedef struct _NCP_CMD_11K_CFG
{
    int enable;
} NCP_CMD_11K_CFG;

typedef struct _NCP_CMD_NEIGHBOR_REQ
{
    SSID_ParamSet_t ssid_tlv;
} NCP_CMD_NEIGHBOR_REQ;

/** RSSI information */
typedef struct
{
    /** Data RSSI last */
    int16_t data_rssi_last;
    /** Data nf last */
    int16_t data_nf_last;
    /** Data RSSI average */
    int16_t data_rssi_avg;
    /** Data nf average */
    int16_t data_nf_avg;
    /** BCN SNR */
    int16_t bcn_snr_last;
    /** BCN SNR average */
    int16_t bcn_snr_avg;
    /** Data SNR last */
    int16_t data_snr_last;
    /** Data SNR average */
    int16_t data_snr_avg;
    /** BCN RSSI */
    int16_t bcn_rssi_last;
    /** BCN nf */
    int16_t bcn_nf_last;
    /** BCN RSSI average */
    int16_t bcn_rssi_avg;
    /** BCN nf average */
    int16_t bcn_nf_avg;
} NCP_WLAN_RSSI_INFO_T;

typedef struct _NCP_CMD_RSSI
{
    NCP_WLAN_RSSI_INFO_T rssi_info;
} NCP_CMD_RSSI;

/*NCP MPU Host command/response definitions*/
/*WLAN STA command/response*/
#define NCP_CMD_WLAN_STA_SCAN          (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-scan */
#define NCP_RSP_WLAN_STA_SCAN          (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_WLAN_STA_CONNECT       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-connect */
#define NCP_RSP_WLAN_STA_CONNECT       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP |0x00000002)
#define NCP_CMD_WLAN_STA_DISCONNECT    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-disconnect */
#define NCP_RSP_WLAN_STA_DISCONNECT    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_STA_VERSION       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-version */
#define NCP_RSP_WLAN_STA_VERSION       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_WLAN_STA_SET_MAC       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-set-mac */
#define NCP_RSP_WLAN_STA_SET_MAC       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_WLAN_STA_GET_MAC       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-get-mac */
#define NCP_RSP_WLAN_STA_GET_MAC       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_WLAN_STA_CONNECT_STAT  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000007) /* wlan-stat */
#define NCP_RSP_WLAN_STA_CONNECT_STAT  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_WLAN_STA_ROAMING       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-roaming */
#define NCP_RSP_WLAN_STA_ROAMING       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_WLAN_STA_ANTENNA       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000009) /* wlan-set-antenna / wlan-get-antenna*/
#define NCP_RSP_WLAN_STA_ANTENNA       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000009)
#define NCP_CMD_WLAN_STA_SIGNAL        (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000012) /* wlan-get-signal */
#define NCP_RSP_WLAN_STA_SIGNAL        (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000012)
#define NCP_CMD_WLAN_STA_CSI           (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000020) /* wlan-csi */
#define NCP_RSP_WLAN_STA_CSI           (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000020)
#define NCP_CMD_WLAN_STA_11K_CFG       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000021) /* wlan-11k-enable */
#define NCP_RSP_WLAN_STA_11K_CFG       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000021)
#define NCP_CMD_WLAN_STA_NEIGHBOR_REQ  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000022) /* wlan-11k-neighbor-req */
#define NCP_RSP_WLAN_STA_NEIGHBOR_REQ  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000022)
#define NCP_CMD_WLAN_MBO_ENABLE        (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000023) /*wlan-mbo-enable*/
#define NCP_RSP_WLAN_MBO_ENABLE        (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000023)
#define NCP_CMD_WLAN_MBO_NONPREFER_CH  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000024) /*wlan-mbo-nonprefer-ch*/
#define NCP_RSP_WLAN_MBO_NONPREFER_CH  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000024)
#define NCP_CMD_WLAN_MBO_SET_CELL_CAPA (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000025) /*wlan-mbo-set-cell-capa*/
#define NCP_RSP_WLAN_MBO_SET_CELL_CAPA (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000025)
#define NCP_CMD_WLAN_MBO_SET_OCE       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000026) /*wlan-mbo-set-oce*/
#define NCP_RSP_WLAN_MBO_SET_OCE       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000026)
#define NCP_CMD_WLAN_STA_WPS_PBC       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000031) /* wlan-start-wps-pbc */
#define NCP_RSP_WLAN_STA_WPS_PBC       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000031)
#define NCP_CMD_WLAN_STA_GEN_WPS_PIN   (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000032) /* wlan-generate-wps-pin */
#define NCP_RSP_WLAN_STA_GEN_WPS_PIN   (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000032)
#define NCP_CMD_WLAN_STA_WPS_PIN       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD |0x00000033) /* wlan-start-wps-pin */
#define NCP_RSP_WLAN_STA_WPS_PIN       (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000033)
#define NCP_CMD_WLAN_GET_CURRENT_NETWORK (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000034) /* wlan-get-current-network */
#define NCP_RSP_WLAN_GET_CURRENT_NETWORK (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000034)
#define NCP_CMD_WLAN_NETWORKS_REMOVE_ALL  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000035) /* wlan-remove-all-networks */
#define NCP_RSP_WLAN_NETWORKS_REMOVE_ALL  (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000035)
#define NCP_CMD_WLAN_GET_PKT_STATS    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000036)
#define NCP_RSP_WLAN_GET_PKT_STATS    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000036)
#define NCP_CMD_WLAN_STA_GET_CURRENT_RSSI    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000037)
#define NCP_RSP_WLAN_STA_GET_CURRENT_RSSI    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000037)
#define NCP_CMD_WLAN_STA_GET_CURRENT_CHANNEL    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000038)
#define NCP_RSP_WLAN_STA_GET_CURRENT_CHANNEL    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000038)
#define NCP_CMD_WLAN_GET_IP_CONFIG    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x00000039)
#define NCP_RSP_WLAN_GET_IP_CONFIG    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x00000039)
#define NCP_CMD_WLAN_STA_GET_NETIF_FLAGS    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x0000003a)
#define NCP_RSP_WLAN_STA_GET_NETIF_FLAGS    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x0000003a)
#define NCP_CMD_WLAN_STA_SET_OKC    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_CMD | 0x0000003b) /* wlan-set-okc */
#define NCP_RSP_WLAN_STA_SET_OKC    (NCP_CMD_WLAN | NCP_CMD_WLAN_STA | NCP_MSG_TYPE_RESP | 0x0000003b)
/*WLAN Basic command/response*/
#define NCP_CMD_WLAN_BASIC_WLAN_RESET           (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-reset */
#define NCP_RSP_WLAN_BASIC_WLAN_RESET           (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_WLAN_BASIC_WLAN_UAP_PROV_START  (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-uap-prov-start */
#define NCP_RSP_WLAN_BASIC_WLAN_UAP_PROV_START  (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_WLAN_BASIC_WLAN_UAP_PROV_RESET  (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-uap-prov-reset */
#define NCP_RSP_WLAN_BASIC_WLAN_UAP_PROV_RESET  (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_BASIC_WLAN_UAP_PROV_SET_UAPCFG  (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-uap-prov-set-uapcfg */
#define NCP_RSP_WLAN_BASIC_WLAN_UAP_PROV_SET_UAPCFG  (NCP_CMD_WLAN | NCP_CMD_WLAN_BASIC | NCP_MSG_TYPE_RESP | 0x00000004)


/*WLAN Socket command*/
#define NCP_CMD_WLAN_SOCKET_OPEN     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-socket-open */
#define NCP_RSP_WLAN_SOCKET_OPEN     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_WLAN_SOCKET_CON      (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-socket-connect */
#define NCP_RSP_WLAN_SOCKET_CON      (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_WLAN_SOCKET_RECV     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-socket-receive */
#define NCP_RSP_WLAN_SOCKET_RECV     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_SOCKET_SEND     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-socket-send */
#define NCP_RSP_WLAN_SOCKET_SEND     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_WLAN_SOCKET_SENDTO   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-socket-sendto */
#define NCP_RSP_WLAN_SOCKET_SENDTO   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_WLAN_SOCKET_BIND     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-socket-bind */
#define NCP_RSP_WLAN_SOCKET_BIND     (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_WLAN_SOCKET_LISTEN   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000007) /* wlan-socket-listen */
#define NCP_RSP_WLAN_SOCKET_LISTEN   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_WLAN_SOCKET_ACCEPT   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-socket-accept */
#define NCP_RSP_WLAN_SOCKET_ACCEPT   (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_WLAN_SOCKET_CLOSE    (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x00000009) /* wlan-socket-close */
#define NCP_RSP_WLAN_SOCKET_CLOSE    (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x00000009)
#define NCP_CMD_WLAN_SOCKET_RECVFROM (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_CMD | 0x0000000a) /* wlan-socket-recvfrom */
#define NCP_RSP_WLAN_SOCKET_RECVFROM (NCP_CMD_WLAN | NCP_CMD_WLAN_SOCKET | NCP_MSG_TYPE_RESP | 0x0000000a)

/*WLAN Http command*/
#define NCP_CMD_WLAN_HTTP_CON         (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-http-connect */
#define NCP_RSP_WLAN_HTTP_CON         (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_WLAN_HTTP_DISCON      (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-http-disconnect */
#define NCP_RSP_WLAN_HTTP_DISCON      (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_WLAN_HTTP_REQ         (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-http-req */
#define NCP_RSP_WLAN_HTTP_REQ         (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_HTTP_RECV        (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-http-recv */
#define NCP_RSP_WLAN_HTTP_RECV        (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_WLAN_HTTP_SETH        (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-http-seth */
#define NCP_RSP_WLAN_HTTP_SETH        (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_WLAN_HTTP_UNSETH      (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-http-unseth */
#define NCP_RSP_WLAN_HTTP_UNSETH      (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_WLAN_WEBSOCKET_UPG    (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000007) /* wlan-websocket-upg */
#define NCP_RSP_WLAN_WEBSOCKET_UPG    (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_WLAN_WEBSOCKET_SEND   (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-websocket-send */
#define NCP_RSP_WLAN_WEBSOCKET_SEND   (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_WLAN_WEBSOCKET_RECV   (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_CMD | 0x00000009) /* wlan-websocket-recv */
#define NCP_RSP_WLAN_WEBSOCKET_RECV   (NCP_CMD_WLAN | NCP_CMD_WLAN_HTTP | NCP_MSG_TYPE_RESP | 0x00000009)

/*WLAN Network command/response*/
#define NCP_CMD_WLAN_NETWORK_INFO             (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-info */
#define NCP_RSP_WLAN_NETWORK_INFO             (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_WLAN_NETWORK_MONITOR          (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-monitor */
#define NCP_RSP_WLAN_NETWORK_MONITOR          (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_WLAN_NETWORK_ADD              (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-add */
#define NCP_RSP_WLAN_NETWORK_ADD              (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_NETWORK_START            (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-start-network */
#define NCP_RSP_WLAN_NETWORK_START            (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_WLAN_NETWORK_STOP             (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-stop-network */
#define NCP_RSP_WLAN_NETWORK_STOP             (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_WLAN_NETWORK_GET_UAP_STA_LIST (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-get-uap-sta-list */
#define NCP_RSP_WLAN_NETWORK_GET_UAP_STA_LIST (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_WLAN_NETWORK_MDNS_QUERY       (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000007) /* wlan-mdns-query */
#define NCP_RSP_WLAN_NETWORK_MDNS_QUERY       (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_WLAN_NETWORK_LIST             (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-list */
#define NCP_RSP_WLAN_NETWORK_LIST             (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_WLAN_NETWORK_REMOVE           (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x00000009) /* wlan-remove */
#define NCP_RSP_WLAN_NETWORK_REMOVE           (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x00000009)
#define NCP_CMD_WLAN_NETWORK_ADDRESS          (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_CMD | 0x0000000A) /* wlan-address */
#define NCP_RSP_WLAN_NETWORK_ADDRESS          (NCP_CMD_WLAN | NCP_CMD_WLAN_NETWORK | NCP_MSG_TYPE_RESP | 0x0000000A)


/*WLAN Power Mgmt command/response*/
#define NCP_CMD_WLAN_POWERMGMT_MEF           (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-multi-mef */
#define NCP_RSP_WLAN_POWERMGMT_MEF           (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_WLAN_POWERMGMT_DEEP_SLEEP_PS (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-deep-sleep-ps */
#define NCP_RSP_WLAN_POWERMGMT_DEEP_SLEEP_PS (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_WLAN_POWERMGMT_IEEE_PS       (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-ieee-ps */
#define NCP_RSP_WLAN_POWERMGMT_IEEE_PS       (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_POWERMGMT_UAPSD         (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000004)  /* wlan-uapsd-enable */
#define NCP_RSP_WLAN_POWERMGMT_UAPSD         (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_WLAN_POWERMGMT_QOSINFO       (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-uapsd-qosinfo */
#define NCP_RSP_WLAN_POWERMGMT_QOSINFO       (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_WLAN_POWERMGMT_SLEEP_PERIOD  (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-uapsd-sleep-period */
#define NCP_RSP_WLAN_POWERMGMT_SLEEP_PERIOD  (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_WLAN_POWERMGMT_WOWLAN_CFG    (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-wowlan-cfg */
#define NCP_RSP_WLAN_POWERMGMT_WOWLAN_CFG    (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_WLAN_POWERMGMT_SUSPEND       (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_CMD | 0x0000000a) /* wlan-suspend */
#define NCP_RSP_WLAN_POWERMGMT_SUSPEND       (NCP_CMD_WLAN | NCP_CMD_WLAN_POWERMGMT | NCP_MSG_TYPE_RESP | 0x0000000a)

/*WLAN Debug command/response*/
#define  NCP_CMD_WLAN_DEBUG_REGISTER_ACCESS  (NCP_CMD_WLAN | NCP_CMD_WLAN_DEBUG | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-reg-access */
#define  NCP_RSP_WLAN_DEBUG_REGISTER_ACCESS  (NCP_CMD_WLAN | NCP_CMD_WLAN_DEBUG | NCP_MSG_TYPE_RESP | 0x00000001)

/*WLAN Memory command/response*/
#define NCP_CMD_WLAN_MEMORY_HEAP_SIZE        (NCP_CMD_WLAN | NCP_CMD_WLAN_MEMORY | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-mem-stat */
#define NCP_RSP_WLAN_MEMORY_HEAP_SIZE        (NCP_CMD_WLAN | NCP_CMD_WLAN_MEMORY | NCP_MSG_TYPE_RESP | 0x00000001)

/*WLAN UAP command*/
#define NCP_CMD_WLAN_UAP_MAX_CLIENT_CNT   (NCP_CMD_WLAN | NCP_CMD_WLAN_UAP | 0x00000001) /* wlan-set-max-clients-count */

/*WLAN Other command */
#define NCP_CMD_11AX_CFG       (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-set-11axcfg */
#define NCP_RSP_11AX_CFG       (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000001)
#define NCP_CMD_BTWT_CFG       (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD  | 0x00000002) /* wlan-set-11axcfg */
#define NCP_RSP_BTWT_CFG       (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_TWT_SETUP      (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-set-btwt-cfg */ 
#define NCP_RSP_TWT_SETUP      (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_TWT_TEARDOWN   (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-twt-teardown */
#define NCP_RSP_TWT_TEARDOWN   (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_TWT_GET_REPORT (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-get-twt-report */
#define NCP_RSP_TWT_GET_REPORT (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_11D_ENABLE     (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-set-11d-enable */
#define NCP_RSP_11D_ENABLE     (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_REGION_CODE    (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000007) /* wlan-region-code */
#define NCP_RSP_REGION_CODE    (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_DATE_TIME      (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-set/get-time */
#define NCP_RSP_DATE_TIME      (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_GET_TEMPERATUE (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x00000009) /* wlan-get-temp */
#define NCP_RSP_GET_TEMPERATUE (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x00000009)
#define NCP_CMD_INVALID_CMD    (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_CMD | 0x0000000a)
#define NCP_RSP_INVALID_CMD    (NCP_CMD_WLAN | NCP_CMD_WLAN_OTHER | NCP_MSG_TYPE_RESP | 0x0000000a)


/*WLAN Regulatory command*/
#define NCP_CMD_WLAN_REGULATORY_ED_MAC_MODE    (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000001) /* wlan-set-ed-mac-mode */
#define NCP_RSP_WLAN_REGULATORY_ED_MAC_MODE    (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000001)

#ifdef CONFIG_NCP_RF_TEST_MODE
#define NCP_CMD_WLAN_REGULATORY_SET_RF_TEST_MODE      (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000002) /* wlan-set-rf-test-mode */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_TEST_MODE      (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000002)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_TX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000003) /* wlan-set-rf-tx-antenna */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_TX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000003)
#define NCP_CMD_WLAN_REGULATORY_GET_RF_TX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000004) /* wlan-get-rf-tx-antenna */
#define NCP_RSP_WLAN_REGULATORY_GET_RF_TX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000004)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_RX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000005) /* wlan-set-rf-rx-antenna */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_RX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000005)
#define NCP_CMD_WLAN_REGULATORY_GET_RF_RX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000006) /* wlan-get-rf-rx-antenna */
#define NCP_RSP_WLAN_REGULATORY_GET_RF_RX_ANTENNA     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000006)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_BAND           (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000007) /* wlan-set-rf-band */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_BAND           (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000007)
#define NCP_CMD_WLAN_REGULATORY_GET_RF_BAND           (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000008) /* wlan-get-rf-band */
#define NCP_RSP_WLAN_REGULATORY_GET_RF_BAND           (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000008)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_BANDWIDTH      (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000009) /* wlan-set-rf-bandwidth */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_BANDWIDTH      (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000009)
#define NCP_CMD_WLAN_REGULATORY_GET_RF_BANDWIDTH      (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x0000000a) /* wlan-get-rf-bandwidth */
#define NCP_RSP_WLAN_REGULATORY_GET_RF_BANDWIDTH      (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x0000000a)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_CHANNEL        (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x0000000b) /* wlan-set-rf-channel */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_CHANNEL        (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x0000000b)
#define NCP_CMD_WLAN_REGULATORY_GET_RF_CHANNEL        (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x0000000c) /* wlan-get-rf-channel */
#define NCP_RSP_WLAN_REGULATORY_GET_RF_CHANNEL        (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x0000000c)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_RADIO_MODE     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x0000000d) /* wlan-set-rf-radio-mode */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_RADIO_MODE     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x0000000d)
#define NCP_CMD_WLAN_REGULATORY_GET_RF_RADIO_MODE     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x0000000e) /* wlan-get-rf-radio-mode */
#define NCP_RSP_WLAN_REGULATORY_GET_RF_RADIO_MODE     (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x0000000e)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_TX_POWER       (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x0000000f) /* wlan-set-rf-tx-power */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_TX_POWER       (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x0000000f)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_TX_CONT_MODE   (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000010) /* wlan-set-rf-tx-cont-mode */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_TX_CONT_MODE   (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000010)
#define NCP_CMD_WLAN_REGULATORY_SET_RF_TX_FRAME       (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000011) /* wlan-set-rf-tx-frame */
#define NCP_RSP_WLAN_REGULATORY_SET_RF_TX_FRAME       (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000011)
#define NCP_CMD_WLAN_REGULATORY_GET_AND_RESET_RF_PER  (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000012) /* wlan-get-and-reset-rf-per */
#define NCP_RSP_WLAN_REGULATORY_GET_AND_RESET_RF_PER  (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000012)

#endif
#define NCP_CMD_WLAN_REGULATORY_EU_CRYPTO_CCMP_128    (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000013) /* wlan-eu-crypto-ccmp-128 */
#define NCP_RSP_WLAN_REGULATORY_EU_CRYPTO_CCMP_128    (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000013)
#define NCP_CMD_WLAN_REGULATORY_EU_CRYPTO_GCMP_128    (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_CMD | 0x00000014) /* wlan-eu-crypto-gcmp-128 */
#define NCP_RSP_WLAN_REGULATORY_EU_CRYPTO_GCMP_128    (NCP_CMD_WLAN | NCP_CMD_WLAN_REGULATORY | NCP_MSG_TYPE_RESP | 0x00000014)

/*WLAN events*/
#define NCP_EVENT_WLAN_STA_CONNECT    (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000006) /* wlan sta connect */
#define NCP_EVENT_WLAN_STA_DISCONNECT (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000007) /* wlan sta disconnect */
#define NCP_EVENT_WLAN_STOP_NETWORK   (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000008) /* wlan stop network */

#define NCP_EVENT_MDNS_QUERY_RESULT   (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000003)
#define NCP_EVENT_MDNS_RESOLVE_DOMAIN (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000004)
#define NCP_EVENT_CSI_DATA            (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000005) /* csi data */

#define NCP_EVENT_WLAN_NCP_INET_RECV   (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x00000009) /* INET RECV event */
#define NCP_EVENT_INET_DAD_DONE        (NCP_CMD_WLAN | NCP_CMD_WLAN_ASYNC_EVENT | NCP_MSG_TYPE_EVENT | 0x0000000b) /* IPV6 DAD done */

typedef struct _NCP_CMD_POWERMGMT_MEF
{
    int type;
    uint8_t action;
} NCP_CMD_POWERMGMT_MEF;

typedef struct _NCP_CMD_POWERMGMT_UAPSD
{
    int enable;
} NCP_CMD_POWERMGMT_UAPSD;

typedef struct _NCP_CMD_POWERMGMT_QOSINFO
{
    uint8_t qos_info;
    /* 0 - get, 1 - set */
    uint8_t action;
} NCP_CMD_POWERMGMT_QOSINFO;

typedef struct _NCP_CMD_POWERMGMT_SLEEP_PERIOD
{
    uint32_t period;
    /* 0 - get, 1 - set */
    uint8_t action;
} NCP_CMD_POWERMGMT_SLEEP_PERIOD;


/** Station Power save mode */
enum wlan_ps_mode
{
    /** Active mode */
    WLAN_ACTIVE = 0,
    /** IEEE power save mode */
    WLAN_IEEE,
    /** Deep sleep power save mode */
    WLAN_DEEP_SLEEP,
    WLAN_IEEE_DEEP_SLEEP,
    WLAN_WNM,
    WLAN_WNM_DEEP_SLEEP,
};

/** WLAN station/micro-AP/Wi-Fi Direct Connection/Status state */
enum wlan_connection_state
{
    /** The WLAN Connection Manager is not connected and no connection attempt
     *  is in progress.  It is possible to connect to a network or scan. */
    WLAN_DISCONNECTED,
    /** The WLAN Connection Manager is not connected but it is currently
     *  attempting to connect to a network.  It is not possible to scan at this
     *  time.  It is possible to connect to a different network. */
    WLAN_CONNECTING,
    /** The WLAN Connection Manager is not connected but associated. */
    WLAN_ASSOCIATED,
    /** The WLAN Connection Manager is not connected but authenticated. */
    WLAN_AUTHENTICATED,
    /** The WLAN Connection Manager is connected.  It is possible to scan and
     *  connect to another network at this time.  Information about the current
     *  network configuration is available. */
    WLAN_CONNECTED,
    /** The WLAN Connection Manager has started uAP */
    WLAN_UAP_STARTED,
    /** The WLAN Connection Manager has stopped uAP */
    WLAN_UAP_STOPPED,
    /** The WLAN Connection Manager is not connected and network scan
     * is in progress. */
    WLAN_SCANNING,
    /** The WLAN Connection Manager is not connected and network association
     * is in progress. */
    WLAN_ASSOCIATING,
};

#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_TLS
/** EAP TLS Cipher types*/
enum eap_tls_cipher_type
{
    EAP_TLS_NONE,
    /** EAP TLS with ECDH & ECDSA with p384 */
    EAP_TLS_ECC_P384,
    /** EAP TLS with ECDH & RSA with > 3K */
    EAP_TLS_RSA_3K,
};
#endif
#endif

typedef struct _NCP_CMD_POWERMGMT_WOWLAN_CFG
{
    uint8_t is_mef;
    uint8_t wake_up_conds;
} NCP_CMD_POWERMGMT_WOWLAN_CFG;

typedef struct _NCP_CMD_POWERMGMT_SUSPEND
{
    int mode;
} NCP_CMD_POWERMGMT_SUSPEND;

/*NCP HE CAPA tlv*/
typedef struct _HE_CAP_ParamSet_t
{
    /** 0xff: Extension Capability IE */
    TypeHeader_t header;
    /** 35: HE capability */
    uint8_t ext_id;
    /** he mac capability info */
    uint8_t he_mac_cap[6];
    /** he phy capability info */
    uint8_t he_phy_cap[11];
    /** he txrx mcs support for 80MHz */
    uint8_t he_txrx_mcs_support[4];
    /** val for txrx mcs 160Mhz or 80+80, and PPE thresholds */
    uint8_t val[28];
} HE_CAP_ParamSet_t;

typedef struct _NCP_CMD_11AX_CFG_INFO
{
    /** band, BIT0:2.4G, BIT1:5G, both set for 2.4G and 5G*/
    uint8_t band;
    HE_CAP_ParamSet_t he_cap_tlv;
} NCP_CMD_11AX_CFG_INFO;

/** This structure is used for broadcast various TWT config sets */
#define BTWT_AGREEMENT_MAX 5
typedef struct
{
    /** BTWT ID */
    uint8_t btwt_id;
    /** BTWT Mantissa */
    uint16_t bcast_mantissa;
    /** BTWT Exponent */
    uint8_t bcast_exponent;
    /** Range 64-255 */
    uint8_t nominal_wake;
} ncp_btwt_set_t;

typedef struct _NCP_CMD_BTWT_CFG
{
    /** Action 0: get, 1: set */
    uint8_t action;
    /** Reserved */
    uint8_t bcast_bet_sta_wait;
    /** Reserved */
    uint16_t bcast_offset;
    /** Reserved */
    uint8_t bcast_twtli;
    /** Count of BTWT agreement sets */
    uint8_t count;
    /** BTWT agreement sets */
    ncp_btwt_set_t btwt_sets[BTWT_AGREEMENT_MAX];
} NCP_CMD_BTWT_CFG_INFO;

typedef struct _NCP_CMD_TWT_SETUP_CFG
{
    /** Implicit, 0: TWT session is explicit, 1: Session is implicit */
    uint8_t implicit;
    /** Announced, 0: Unannounced, 1: Announced TWT */
    uint8_t announced;
    /** Trigger Enabled, 0: Non-Trigger enabled, 1: Trigger enabled TWT */
    uint8_t trigger_enabled;
    /** TWT Information Disabled, 0: TWT info enabled, 1: TWT info disabled */
    uint8_t twt_info_disabled;
    /** Negotiation Type, 0: Individual TWT, 3: Broadcast TWT */
    uint8_t negotiation_type;
    /** TWT Wakeup Duration, time after which the TWT requesting STA can
     * transition to doze state */
    uint8_t twt_wakeup_duration;
    /** Flow Identifier. Range: [0-7]*/
    uint8_t flow_identifier;
    /** Hard Constraint, 0: FW can tweak the TWT setup parameters if it is
     *rejected by AP.
     ** 1: Firmware should not tweak any parameters. */
    uint8_t hard_constraint;
    /** TWT Exponent, Range: [0-63] */
    uint8_t twt_exponent;
    /** TWT Mantissa Range: [0-sizeof(UINT16)] */
    uint16_t twt_mantissa;
    /** TWT Request Type, 0: REQUEST_TWT, 1: SUGGEST_TWT*/
    uint8_t twt_request;
} NCP_CMD_TWT_SETUP_CFG;

typedef struct _NCP_CMD_TWT_TEARDOWN_CFG
{
    /** TWT Flow Identifier. Range: [0-7] */
    uint8_t flow_identifier;
    /** Negotiation Type. 0: Future Individual TWT SP start time, 1: Next
     * Wake TBTT time */
    uint8_t negotiation_type;
    /** Tear down all TWT. 1: To teardown all TWT, 0 otherwise */
    uint8_t teardown_all_twt;
} NCP_CMD_TWT_TEARDOWN_CFG;

typedef struct _IEEE_BTWT_ParamSet_t
{
    /*
     *  [Bit 0]     request
     *  [Bit 1-3]   setup_cmd
     *  [Bit 4]     trigger
     *  [Bit 5]     last_broadcast_parameter_set
     *  [Bit 6]     flow_type
     *  [Bit 7-9]   btwt_recommendation
     *  [Bit 10-14] wake_interval_exponent
     *  [Bit 15]    reserved
     */
    uint16_t request_type;
    uint16_t target_wake_time;
    uint8_t nominal_min_wake_duration;
    uint16_t wake_interval_mantissa;
    /*
     *  [Bit 0-2]   reserved
     *  [Bit 3-7]   btwt_id
     *  [Bit 8-15]  btwt_persistence
     */
    uint16_t twt_info;
} IEEE_BTWT_ParamSet_t;

typedef struct _NCP_CMD_TWT_REPORT
{
    /** TWT report type, 0: BTWT id */
    uint8_t type;
    /** TWT report length of value in data */
    uint8_t length;
    uint8_t reserve[2];
    /** TWT report payload for FW response to fill, 4 * 9bytes */
    IEEE_BTWT_ParamSet_t info[4];
} NCP_CMD_TWT_REPORT;

typedef struct _NCP_CMD_11D_ENABLE
{
    /** 0 - STA, 1 - UAP */
    uint32_t role;
    /** 0 - disable, 1 - enable */
    uint32_t state;
} NCP_CMD_11D_ENABLE_CFG;

typedef struct _NCP_CMD_REGION_CODE
{
    /** 0 - get, 1 - set */
    uint32_t action;
    /** region code, 0xaa for world wide safe, 0x10 for US FCC, etc */
    uint32_t region_code;
} NCP_CMD_REGION_CODE_CFG;

typedef struct _NCP_CMD_CLIENT_CNT
{
    uint16_t max_sta_count;
    uint8_t set_status;
    uint8_t support_count;
} NCP_CMD_CLIENT_CNT;

typedef struct _NCP_CMD_ANTENNA_CFG
{
    uint8_t action;
    uint32_t antenna_mode;
    uint16_t evaluate_time;
    uint8_t evaluate_mode;
    uint16_t current_antenna;
} NCP_CMD_ANTENNA_CFG;

typedef struct _NCP_CMD_WPS_GEN_PIN
{
    uint32_t pin;
} NCP_CMD_WPS_GEN_PIN;

typedef struct _NCP_CMD_WPS_PIN
{
    uint32_t pin;
} NCP_CMD_WPS_PIN;

typedef struct _NCP_CMD_DEEP_SLEEP_PS
{
    int enable;
} NCP_CMD_DEEP_SLEEP_PS;

typedef struct _NCP_CMD_IEEE_PS
{
    int enable;
} NCP_CMD_IEEE_PS;

typedef struct _NCP_CMD_ED_MAC
{
    uint8_t action;
    uint16_t ed_ctrl_2g;
    uint16_t ed_offset_2g;
#ifdef CONFIG_5GHz_SUPPORT
    uint16_t ed_ctrl_5g;
    uint16_t ed_offset_5g;
#endif
} NCP_CMD_ED_MAC;

typedef struct _NCP_CMD_RF_TX_ANTENNA
{
    uint8_t ant;
} NCP_CMD_RF_TX_ANTENNA;

typedef struct _NCP_CMD_RF_RX_ANTENNA
{
    uint8_t ant;
} NCP_CMD_RF_RX_ANTENNA;

typedef struct _NCP_CMD_RF_BAND
{
    uint8_t band;
} NCP_CMD_RF_BAND;

typedef struct _NCP_CMD_RF_BANDWIDTH
{
    uint8_t bandwidth;
} NCP_CMD_RF_BANDWIDTH;

typedef struct _NCP_CMD_RF_CHANNEL
{
    uint8_t channel;
} NCP_CMD_RF_CHANNEL;

typedef struct _NCP_CMD_RF_RADIO_MODE
{
    uint8_t radio_mode;
} NCP_CMD_RF_RADIO_MODE;

typedef struct _NCP_CMD_RF_TX_POWER
{
    uint8_t power;
    uint8_t mod;
    uint8_t path_id;
} NCP_CMD_RF_TX_POWER;

typedef struct _NCP_CMD_RF_TX_CONT_MODE
{
    uint32_t enable_tx;
    uint32_t cw_mode;
    uint32_t payload_pattern;
    uint32_t cs_mode;
    uint32_t act_sub_ch;
    uint32_t tx_rate;
} NCP_CMD_RF_TX_CONT_MODE;

typedef struct _NCP_CMD_RF_TX_FRAME
{
    uint32_t enable;
    uint32_t data_rate;
    uint32_t frame_pattern;
    uint32_t frame_length;
    uint32_t adjust_burst_sifs;
    uint32_t burst_sifs_in_us;
    uint32_t short_preamble;
    uint32_t act_sub_ch;
    uint32_t short_gi;
    uint32_t adv_coding;
    uint32_t tx_bf;
    uint32_t gf_mode;
    uint32_t stbc;
    uint8_t bssid[NCP_WLAN_MAC_ADDR_LENGTH];
} NCP_CMD_RF_TX_FRAME;

typedef struct _NCP_CMD_RF_PER
{
    uint32_t rx_tot_pkt_count;
    uint32_t rx_mcast_bcast_count;
    uint32_t rx_pkt_fcs_error;
} NCP_CMD_RF_PER;

typedef struct _NCP_CMD_EU_CRYPRTO
{
    uint8_t enc;
} NCP_CMD_EU_CRYPRTO;

typedef struct _wlan_date_time_t
{
    uint32_t action;
    uint16_t year;  /*!< Range from 1970 to 2099.*/
    uint8_t month;  /*!< Range from 1 to 12.*/
    uint8_t day;    /*!< Range from 1 to 31 (depending on month).*/
    uint8_t hour;   /*!< Range from 0 to 23.*/
    uint8_t minute; /*!< Range from 0 to 59.*/
    uint8_t second; /*!< Range from 0 to 59.*/
} wlan_date_time_t;

typedef struct _NCP_CMD_DATE_TIME
{
    uint32_t action;
    wlan_date_time_t date_time;
} NCP_CMD_DATE_TIME_CFG;

typedef struct _NCP_CMD_TEMPERATURE
{
    uint32_t temp;
} NCP_CMD_TEMPERATURE;

typedef struct _NCP_CMD_WLAN_CONN
{
    char name[WLAN_NETWORK_NAME_MAX_LENGTH];
    uint32_t ip;
    char ssid[IEEEtypes_SSID_SIZE + 1];
} NCP_CMD_WLAN_CONN;

typedef struct _QUERY_PTR_CFG
{
    /** Type of service, like '_http' */
    char service[63 + 1];
    /** Protocol, TCP or UDP */
    uint16_t proto;
} QUERY_PTR_CFG;

typedef struct _QUERY_A_CFG
{
    /** Domain name, like 'wifi-http.local' */
    char name[63 + 1];
} QUERY_A_CFG;

typedef struct _NCP_CMD_MDNS_QUERY
{
    /** Query type (PTR, SRV, A, AAAA...) */
    uint8_t qtype;
    union
    {
        QUERY_PTR_CFG ptr_cfg;
        QUERY_A_CFG a_cfg;
    } Q;
} NCP_CMD_MDNS_QUERY;

/*NCP PTR RR tlv*/
typedef struct _PTR_ParamSet_t
{
    TypeHeader_t header;
    /* instance name */
    char instance_name[63 + 1];
    /* service type */
    char service_type[63 + 1];
    /* srevice protocol */
    char proto[8];
} PTR_ParamSet_t;

/*NCP SRV RR tlv*/
typedef struct _SRV_ParamSet_t
{
    TypeHeader_t header;
    /* host name */
    char host_name[63 + 1];
    /* service port */
    uint16_t port;
    /* target name */
    char target[63 + 1];
} SRV_ParamSet_t;

/*NCP TXT RR tlv*/
typedef struct _TXT_ParamSet_t
{
    TypeHeader_t header;
    /* txt value len */
    uint8_t txt_len;
    /* txt string */
    char txt[63 + 1];
} TXT_ParamSet_t;

/*NCP A&AAAA RR tlv*/
typedef struct _IP_ADDR_ParamSet_t
{
    TypeHeader_t header;
    uint8_t addr_type;
    /* ip address */
    union {
        uint32_t ip_v4;
        uint32_t ip_v6[4];
    } ip;
} IP_ADDR_ParamSet_t;

typedef struct _NCP_EVT_MDNS_RESULT
{
    /* time to live */
    uint32_t ttl;
    /** Length of TLVs sent in command starting at tlvBuffer */
    uint32_t tlv_buf_len;
    /**
     *  PTR, PTR_ParamSet_t
     *  SRV, SRV_ParamSet_t
     *  TXT, TXT_ParamSet_t
     *  A&AAAA, IP_ADDR_ParamSet_t
     */
    uint8_t tlv_buf[1];
} NCP_EVT_MDNS_RESULT;

typedef struct _NCP_EVT_CSI_DATA
{
    /** Length in DWORDS, including header */
    uint16_t Len;
    /** CSI signature. 0xABCD fixed */
    uint16_t CSI_Sign;
    /** User defined HeaderID  */
    uint32_t CSI_HeaderID;
    /** Packet info field */
    uint16_t PKT_info;
    /** Frame control field for the received packet*/
    uint16_t FCF;
    /** Timestamp when packet received */
    uint64_t TSF;
    /** Received Packet Destination MAC Address */
    uint8_t Dst_MAC[6];
    /** Received Packet Source MAC Address */
    uint8_t Src_MAC[6];
    /** RSSI for antenna A */
    uint8_t Rx_RSSI_A;
    /** RSSI for antenna B */
    uint8_t Rx_RSSI_B;
    /** Noise floor for antenna A */
    uint8_t Rx_NF_A;
    /** Noise floor for antenna A */
    uint8_t Rx_NF_B;
    /** Rx signal strength above noise floor */
    uint8_t Rx_SINR;
    /** Channel */
    uint8_t channel;
    /** user defined Chip ID */
    uint16_t chip_id;
    /** Reserved */
    uint32_t rsvd;
    /** CSI data length in DWORDs */
    uint32_t CSI_Data_Length;
    /** Start of CSI data */
    uint8_t CSI_Data[0];
    /** At the end of CSI raw data, user defined TailID of 4 bytes*/
} NCP_EVT_CSI_DATA;

typedef struct _NCP_EVT_MDNS_RESOLVE
{
    uint8_t ip_type;
    union {
      uint32_t ip6_addr[4];
      uint32_t ip4_addr;
    } u_addr;
} NCP_EVT_MDNS_RESOLVE;

typedef struct _NCPCmd_DS_COMMAND
{
    /** Command Header : Command */
    NCP_COMMAND header;
    /** Command Body */
    union
    {
        /** Scan result*/
        NCP_CMD_SCAN_NETWORK_INFO scan_network_info;
        /** Firmware version*/
        NCP_CMD_FW_VERSION firmware_version;
        /** MAC address */
        NCP_CMD_MAC_ADDRESS mac_addr;
        /** Get MAC address */
        NCP_CMD_GET_MAC_ADDRESS get_mac_addr;
        /** wlan connnection state */
        NCP_CMD_CONNECT_STAT conn_stat;
        /** Roaming configuration */
        NCP_CMD_ROAMING roaming;
        /** OKC configurations */
        NCP_CMD_OKC okc_cfg;
        /** wlan network info*/
        NCP_CMD_NETWORK_INFO network_info;
		/** wlan network address*/
        NCP_CMD_NETWORK_ADDRESS network_address;
        NCP_CMD_NET_MONITOR monitor_cfg;
        /** wlan add network*/
        NCP_CMD_NETWORK_ADD network_add;
        /** wlan start network*/
        NCP_CMD_NETWORK_START network_start;
        /** pro set uap config */
        NCP_CMD_UAP_PROV_SET_UAPCFG prov_set_uap_cfg;
        /** wlan uap sta list*/
        NCP_CMD_NETWORK_UAP_STA_LIST uap_sta_list;
        NCP_CMD_CSI csi_cfg;
        NCP_CMD_11K_CFG wlan_11k_cfg;
        NCP_CMD_NEIGHBOR_REQ neighbor_req;
        /** RSSI Information*/
        NCP_CMD_RSSI signal_rssi;
        /** MAX client count*/
        NCP_CMD_CLIENT_CNT max_client_count;
        /** Antenna config*/
        NCP_CMD_ANTENNA_CFG antenna_cfg;
        NCP_CMD_WPS_GEN_PIN wps_gen_pin_info;
        NCP_CMD_WPS_PIN wps_pin_cfg;

        NCP_CMD_WLAN_RESET_CFG wlan_reset_cfg;
        /*socket command*/
        NCP_CMD_SOCKET_OPEN_CFG wlan_socket_open;
        NCP_CMD_SOCKET_CON_CFG wlan_socket_con;
        NCP_CMD_SOCKET_BIND_CFG wlan_socket_bind;
        NCP_CMD_SOCKET_CLOSE_CFG wlan_socket_close;
        NCP_CMD_SOCKET_LISTEN_CFG wlan_socket_listen;
        NCP_CMD_SOCKET_ACCEPT_CFG wlan_socket_accept;
        NCP_CMD_SOCKET_SEND_CFG wlan_socket_send;
        NCP_CMD_SOCKET_SENDTO_CFG wlan_socket_sendto;
        NCP_CMD_SOCKET_RECEIVE_CFG wlan_socket_receive;
        NCP_CMD_SOCKET_RECVFROM_CFG wlan_socket_recvfrom;

        /*http command*/
        NCP_CMD_HTTP_CON_CFG wlan_http_connect;
        NCP_CMD_HTTP_DISCON_CFG wlan_http_disconnect;
        NCP_CMD_HTTP_SETH_CFG wlan_http_seth;
        NCP_CMD_HTTP_UNSETH_CFG wlan_http_unseth;
        NCP_CMD_HTTP_REQ_CFG wlan_http_req;
        NCP_CMD_HTTP_REQ_RESP_CFG wlan_http_req_resp;
        NCP_CMD_HTTP_RECV_CFG wlan_http_recv;
        NCP_CMD_HTTP_UPG_CFG wlan_http_upg;
        NCP_CMD_WEBSOCKET_SEND_CFG wlan_websocket_send;
        NCP_CMD_WEBSOCKET_RECV_CFG wlan_websocket_recv;

        /*power mgmt command*/
        NCP_CMD_POWERMGMT_MEF mef_config;
        /** wlan deep sleep ps*/
        NCP_CMD_DEEP_SLEEP_PS wlan_deep_sleep_ps;
        /** wlan ieee ps*/
        NCP_CMD_IEEE_PS wlan_ieee_ps;
        NCP_CMD_POWERMGMT_UAPSD uapsd_cfg;
        NCP_CMD_POWERMGMT_QOSINFO qosinfo_cfg;
        NCP_CMD_POWERMGMT_SLEEP_PERIOD sleep_period_cfg;

        /** wlan wowlan config */
        NCP_CMD_POWERMGMT_WOWLAN_CFG wowlan_config;
        /** wlan suspend config */
        NCP_CMD_POWERMGMT_SUSPEND suspend_config;

        NCP_CMD_11AX_CFG_INFO he_cfg;
        NCP_CMD_BTWT_CFG_INFO btwt_cfg;
        NCP_CMD_TWT_SETUP_CFG twt_setup;
        NCP_CMD_TWT_TEARDOWN_CFG twt_teardown;
        NCP_CMD_TWT_REPORT twt_report;
        NCP_CMD_11D_ENABLE_CFG wlan_11d_cfg;
        NCP_CMD_REGION_CODE_CFG region_cfg;

        /*regulatory commands*/
        NCP_CMD_ED_MAC ed_mac_mode;
#ifdef CONFIG_NCP_RF_TEST_MODE
        NCP_CMD_RF_TX_ANTENNA rf_tx_antenna;
        NCP_CMD_RF_RX_ANTENNA rf_rx_antenna;
        NCP_CMD_RF_BAND rf_band;
        NCP_CMD_RF_BANDWIDTH rf_bandwidth;
        NCP_CMD_RF_CHANNEL rf_channel;
        NCP_CMD_RF_RADIO_MODE rf_radio_mode;
        NCP_CMD_RF_TX_POWER rf_tx_power;
        NCP_CMD_RF_TX_CONT_MODE rf_tx_cont_mode;
        NCP_CMD_RF_TX_FRAME rf_tx_frame;
        NCP_CMD_RF_PER rf_per;
#endif
        NCP_CMD_EU_CRYPRTO eu_crypto;

        /*Debug commands*/
        NCP_CMD_REGISTER_ACCESS register_access;
        /*Memory commands*/
        NCP_CMD_MEM_STAT mem_stat;

        NCP_CMD_DATE_TIME_CFG date_time;
        NCP_CMD_TEMPERATURE temperature;

        /** wlan connect*/
        NCP_CMD_WLAN_CONN wlan_connect;
        /** mdns query*/
        NCP_CMD_MDNS_QUERY mdns_query;
        /** mdns reuslt*/
        NCP_EVT_MDNS_RESULT mdns_result;
        /** mdns resolve*/
        NCP_EVT_MDNS_RESOLVE mdns_resolve;
        /** CSI data*/
        NCP_EVT_CSI_DATA csi_data;

        /** added network list*/
        NCP_CMD_NETWORK_LIST network_list;
        /** remove network*/
        NCP_CMD_NETWORK_REMOVE network_remove;
        /** get current network*/
        NCP_CMD_GET_CURRENT_NETWORK current_network;
        /** get pkt stats*/
        NCP_CMD_PKT_STATS get_pkt_stats;
        /** get current rssi*/
        NCP_CMD_GET_CURRENT_RSSI current_rssi;
        /** get current channel*/
        NCP_CMD_GET_CURRENT_CHANNEL current_channel;
        /** get ip config*/
        NCP_CMD_IP_CONFIG ip_config;
        /** get netif flag*/
        NCP_CMD_GET_NETIF_FLAGS netif_flags;
    } params;
} NCPCmd_DS_COMMAND;

#pragma pack()

NCPCmd_DS_COMMAND *mpu_host_get_wifi_command_buffer();

/*Dump buffer in hex format on console*/
void dump_hex(const void *data, unsigned len);

/*Prase command*/
int string_to_command(char *strcom);

/**
 * Scan for Wi-Fi networks.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-scan \n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_scan_command(int argc, char **argv);

/**
 * Connect to a Wi-Fi network (access point).
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 2.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-connect \n
 *                    argv[1]: string value of name (Required) \n
 *                             A string representing the name of the network to connect to.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_connect_command(int argc, char **argv);

/**
 * Disconnect from the current Wi-Fi network (access point).
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-disconnect
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_disconnect_command(int argc, char **argv);

/**
 * Reset Wi-Fi driver.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 2.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-reset \n
 *                    argv[1]: action (Required) \n
 *                             0: disable Wi-Fi  \n
 *                             1: enable Wi-Fi   \n
 *                             2: reset Wi-Fi    \n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_reset_command(int argc, char **argv);

int wlan_start_wps_pbc_command(int argc, char **argv);

int wlan_process_wps_pbc_response(uint8_t *res);

int wlan_wps_generate_pin_command(int argc, char **argv);

int wlan_process_wps_generate_pin_response(uint8_t *res);

int wlan_start_wps_pin_command(int argc, char **argv);

int wlan_process_wps_pin_response(uint8_t *res);

int wlan_start_network_command(int argc, char **argv);

int wlan_stop_network_command(int argc, char **argv);

int wlan_get_uap_sta_list_command(int argc, char **argv);

/**
 * Get the Wi-Fi driver and firmware extended version.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-version
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_version_command(int argc, char **argv);

/**
 * Set Wi-Fi MAC Address in Wi-Fi firmware.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 2.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-set-mac \n
 *                    argv[1]: string value of MAC (Required) \n
 *                             The MAC address format like "xx:xx:xx:xx:xx:xx".
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_set_mac_address_command(int argc, char **argv);

/**
 * Get Wi-Fi MAC Address in Wi-Fi firmware.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-get-mac
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_get_mac_address_command(int argc, char **argv);

/**
 * Retrieve the connection state of station and uAP interface.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-stat
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_stat_command(int argc, char **argv);

int wlan_roaming_command(int argc, char **argv);

/**
 * Enable/disable the Opportunistic Key Caching (OKC).
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 2.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-info \n
 *                    argv[1]: enable/disable OKC \n
 *                             0 -- Disable OKC (default) \n
 *                             1 -- Enable OKC
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_set_okc_command(int argc, char **argv);

/**
 * Get the configured Wi-Fi network information.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 1.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-info
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_info_command(int argc, char **argv);

/**
 * Add a network profile to the list of known networks.
 *
 * The network's 'name' field is unique and between \ref WLAN_NETWORK_NAME_MIN_LENGTH and
 * \ref WLAN_NETWORK_NAME_MAX_LENGTH characters.
 *
 * \note The network must specify at least an SSID or BSSID.
 *
 * \note This API can be used to add profiles for station or UAP interfaces.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should range from 3 to 14.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-add \n
 *                    argv[1]: string value of profile name (Required) \n
 *                             The name of network profile. \n
 *                    argv[2]: string value of ssid (Optional) \n
 *                             The network SSID, represented as a C string of up to 32 characters in length. \n
 *                    argv[3]: string value of ip address (Optional) \n
 *                             The ip address format like "ip:<ip_addr>,<gateway_ip>,<netmask>". \n
 *                             The network IP address configuration specified by struct \n
 *                             NCP_WLAN_IPV4_CONFIG that should be associated with this interface. \n
 *                             If this profile is used in the UAP mode, this field is mandatory. \n
 *                             If this profile is used in the station mode, this field is mandatory \n
 *                             if using static IP, and is optional if using DHCP. \n
 *                    argv[4]: string value of bssid (Optional) \n
 *                             The network BSSID, represented as a 6-byte array. \n
 *                             If this profile is used in the UAP mode, this field is ignored. \n
 *                             If this profile is used in the station mode, this field is used to \n
 *                             identify the network. Set all 6 bytes to 0 to use any BSSID, in which \n
 *                             case only the SSID is used to find the network. \n
 *                    argv[5]: string value of role (Required) \n
 *                             The network Wi-Fi mode enum wlan_bss_role. \n
 *                             Set this to specify what type of Wi-Fi network mode to use. \n
 *                             This can either be \ref WLAN_BSS_ROLE_STA for use in the station mode, \n
 *                             or it can be \ref WLAN_BSS_ROLE_UAP for use in the UAP mode. \n
 *                    argv[6]: string value of security (Optional) \n
 *                             The network security configuration specified for the network. \n
 *                    argv[7]: channel (Optional) \n
 *                             The channel for this network. \n
 *                             If this profile is used in UAP mode, this field specifies the channel to \n
 *                             start the UAP interface on. Set this to 0 for auto channel selection. \n
 *                             If this profile is used in the station mode, this constrains the channel on \n
 *                             which the network to connect should be present. Set this to 0 to allow the \n
 *                             network to be found on any channel. \n
 *                    argv[8]: capa (Optional) \n
 *                             Wi-Fi capabilities of UAP network 802.11n, 802.11ac or/and 802.11ax. \n
 *                    argv[9]: mfpc (Optional) \n
 *                             Management frame protection capable (MFPC) \n
 *                    argv[10]: mfpr (Optional) \n
 *                              Management frame protection required (MFPR) \n
 *                    argv[11]: dtim (Optional) \n
 *                              DTIM period of associated BSS \n
 *                    argv[12]: aid (Optional) \n
 *                              Client anonymous identity \n
 *                    argv[13]: string value of key_passwd (Optional) \n
 *                              Client Key password \n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_add_command(int argc, char **argv);

/**
 * This API can be used to get RSSI information.
 * 
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-signal
 *
 * \return WM_SUCCESS.
 */
int wlan_get_signal_command(int argc, char **argv);

int wlan_multi_mef_command(int argc, char **argv);

/**
 * This API can be used to set maximum number of stations that can be allowed to connect to the UAP.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-max-clients-count\n
 *                    argv[1]: string value of STA count, maximum supported STA count is 8.
 *
 * \return WM_SUCCESS if successful.
 * \return -WM_FAIL if unsuccessful.
 *
 * \note Set operation in not allowed in \ref WLAN_UAP_STARTED state.
 */
int wlan_set_max_clients_count_command(int argc, char **argv);

/** 
 * This API can be used to set the mode of TX/RX antenna.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2 or 3.
 * \param[in] argv    Argument vector\n
 *                    argc[0]: wlan-set-antenna-cfg\n
 *                    argv[1]: string of antenna mode (Required\n
 *                             0  -- TX/RX antenna 1\n
 *                             1  -- TX/RX antenna 2\n
 *                             15 -- TX/RX antenna diversity.\n
 *                    argv[2]: string of evaluate_time (Optional)\n
 *                             if ant mode = 15, SAD (slow antenna diversity) evaluate time interval.\n
 *                             default value is 6s(6000).
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 */
int wlan_set_antenna_cfg_command(int argc, char **argv);

/** 
 * This API can be used to get the mode of TX/RX antenna.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-antenna-cfg
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 */
int wlan_get_antenna_cfg_command(int argc, char **argv);

/**
 * This API can be used to enable/disable deep sleep power save mode.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-deep-sleep-ps\n
 *                    argv[1]: enable/disable deep sleep power save mode.\n
 *                             0 -- disable deep sleep\n
 *                             1 -- enable deep sleep
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 * \note Deep sleep power save is enabled by default.
 */
int wlan_deep_sleep_ps_command(int argc, char **argv);

/**
 * This API can be used to enable/disable ieee power save mode.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-ieee-ps\n
 *                    argv[1]: enable/disable ieee power save mode.\n
 *                             0 -- disable ieee power save mode\n
 *                             1 -- enable ieee power save mode
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 * \note Ieee power save is enabled by default.
 */
int wlan_ieee_ps_command(int argc, char **argv);

/**
 * This API can be used to configure ED(energy detect) MAC mode for station in Wi-Fi firmware.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv.\n
 *                    If enable CONFIG_NCP_5GHz_SUPPORT:\n
 *                              argc should be 5.\n
 *                    If disable CONFIG_NCP_5GHz_SUPPORT:\n
 *                              argc should be 3.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-ed-mac-mode\n
 *                    argv[1]: string of ed_ctrl_2g\n
 *                             0 -- disable EU adaptivity for 2.4GHz band.\n
 *                             1 -- enable EU adaptivity for 2.4GHz band.\n
 *                    argv[2]: string of ed_offset_2g\n
 *                             0 -- default dnergy detect threshold.\n
 *                             ed_threshold = ed_base - ed_offset_2g\n
 *                             e.g., if ed_base default is -62dBm, ed_offset_2g is 0x8, then ed_threshold is -70dBm.\n
 *             #if CONFIG_NCP_5GHz_SUPPORT\n
 *                    argv[3]: string of ed_ctrl_5g\n
 *                             0 -- disable EU adaptivity for 5GHz band.\n
 *                             1 -- enable EU adaptivity for 5GHz band.\n
 *                    argv[4]: string of ed_offset_5g\n
 *                             0 -- default energy detect threshold.\n
 *                             ed_threshold = ed_base - ed_offset_5g\n
 *                             e.g., if ed_base default is -62dBm, ed_offset_5g is 0x8, then ed_threshold is -70dBm.\n
 *             #endif
 * 
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 */
int wlan_ed_mac_mode_set_command(int argc, char **argv);

/**
 * This API can be used to get current ED MAC mode configuration for station.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-ed-mac-mode
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 */
int wlan_ed_mac_mode_get_command(int argc, char **argv);

/** This API can be used to reads/writes adapter registers value.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv.
 *                    argc should be 3 or 4.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-reg-access\n
 *                    argv[1]: type (Required)\n
 *                             1: MAC\n
 *                             2: BBP\n
 *                             3: RF\n
 *                             4: CAU\n
 *                    argv[2]: offset (Required)\n
 *                             offset value of register.\n
 *                    agrv[3]: value  (Optional)\n
 *                             Set register value.\n
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 */
int wlan_register_access_command(int argc, char **argv);

#ifdef CONFIG_MEM_MONITOR_DEBUG
/** This API can be used to get OS memory allocate and free info.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-mem-stat
 *
 * \return WM_SUCCESS if success.
 */
int wlan_memory_state_command(int argc, char **argv);
#endif

int wlan_list_command(int argc, char **argv);

int wlan_remove_command(int argc, char **argv);

int wlan_process_ncp_event(uint8_t *res);

int wlan_process_response(uint8_t *res);

/**
 * This API can be used to process disconnect response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_discon_response(uint8_t *res);

/**
 * This API can be used to process connect response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *                   Response body refer to \ref NCP_CMD_WLAN_CONN.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_con_response(uint8_t *res);

void print_security_mode(uint8_t sec);

/**
 * This API can be used to process scan response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response. \n
 *                   Response body refer to \ref NCP_CMD_SCAN_NETWORK_INFO.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_scan_response(uint8_t *res);

int wlan_process_ping_response(uint8_t *res);

/**
 * This API can be used to process Wi-Fi version response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *                   Response body refer to \ref NCP_CMD_FW_VERSION.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_version_response(uint8_t *res);

int wlan_process_monitor_response(uint8_t *res);

int wlan_process_csi_response(uint8_t *res);

int wlan_process_11k_cfg_response(uint8_t *res);

int wlan_process_neighbor_req_response(uint8_t *res);

/**
 * This API can be used to process RSSI information response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body refer to \ref NCP_CMD_RSSI.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_rssi_response(uint8_t *res);

/**
 * This API can be used to process set MAC address response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_set_mac_address(uint8_t *res);

/**
 * This API can be used to process get MAC address response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response. \n
 *                   Response body refer to \ref NCP_CMD_GET_MAC_ADDRESS.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_get_mac_address(uint8_t *res);

/**
 * This API can be used to process Wi-Fi connection state response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response. \n
 *                   Response body refer to \ref NCP_CMD_CONNECT_STAT.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_stat(uint8_t *res);

/**
 * This API can be used to process get Wi-Fi network information response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response. \n
 *                   Response body refer to \ref NCP_CMD_NETWORK_INFO.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_info(uint8_t *res);
int wlan_process_address(uint8_t *res);

/**
 * This API can be used to process Wi-Fi reset response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_wlan_reset_result_response(uint8_t *res);

/**
 * This API can be used to start UAP provisioning.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-uap-prov-start
 *
 * \return WM_SUCCESS if success.
 *
 */
int wlan_uap_prov_start_command(int argc, char **argv);

/**
 * This API can be used to process start UAP provisioning response.
 *
 * \param[in] res     A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                    Response body: None.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_wlan_uap_prov_start_result_response(uint8_t *res);

/**
 * This API can be used to reset UAP provisioning.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-uap-prov-reset
 *
 * \return WM_SUCCESS if success.
 *
 */
int wlan_uap_prov_reset_command(int argc, char **argv);

/**
 * This API can be used to process reset UAP provisioning response.
 *
 * \param[in] res     A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                    Response body: None.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_wlan_uap_prov_reset_result_response(uint8_t *res);

int wlan_process_roaming(uint8_t *res);

int wlan_process_okc_response(uint8_t *res);

int wlan_process_wlan_socket_open_response(uint8_t *res);

int wlan_process_wlan_socket_con_response(uint8_t *res);

int wlan_process_wlan_socket_bind_response(uint8_t *res);

int wlan_process_wlan_socket_close_response(uint8_t *res);

int wlan_process_wlan_socket_listen_response(uint8_t *res);

int wlan_process_wlan_socket_accept_response(uint8_t *res);

int wlan_process_wlan_socket_send_response(uint8_t *res);

int wlan_process_wlan_socket_sendto_response(uint8_t *res);

int wlan_process_wlan_socket_receive_response(uint8_t *res);

int wlan_process_wlan_socket_recvfrom_response(uint8_t *res);

int wlan_process_wlan_http_con_response(uint8_t *res);

int wlan_process_wlan_http_discon_response(uint8_t *res);

int wlan_process_wlan_http_req_response(uint8_t *res);

int wlan_process_wlan_http_recv_response(uint8_t *res);

int wlan_process_wlan_http_seth_response(uint8_t *res);

int wlan_process_wlan_http_unseth_response(uint8_t *res);

int wlan_process_wlan_websocket_upg_response(uint8_t *res);

int wlan_process_wlan_websocket_send_response(uint8_t *res);

int wlan_process_wlan_websocket_recv_response(uint8_t *res);

/**
 * This API can be used to process add network response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_add_response(uint8_t *res);

int wlan_process_start_network_response(uint8_t *res);

int wlan_process_stop_network_response(uint8_t *res);

int wlan_process_get_uap_sta_list(uint8_t *res);

int wlan_process_multi_mef_response(uint8_t *res);

int wlan_set_wmm_uapsd_command(int argc, char **argv);

int wlan_process_wmm_uapsd_response(uint8_t *res);

int wlan_wmm_uapsd_qosinfo_command(int argc, char **argv);

int wlan_process_uapsd_qosinfo_response(uint8_t *res);

int wlan_uapsd_sleep_period_command(int argc, char **argv);

int wlan_process_uapsd_sleep_period_response(uint8_t *res);

int wlan_process_wake_mode_response(uint8_t *res);

int wlan_wowlan_cfg_command(int argc, char **argv);

int wlan_process_wakeup_condition_response(uint8_t *res);

int wlan_process_mcu_sleep_response(uint8_t *res);

#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
int wlan_suspend_command(int argc, char **argv);

int wlan_process_suspend_response(uint8_t *res);
#endif

int wlan_process_sleep_status(uint8_t *res);

int wlan_set_11axcfg_command(int argc, char **argv);

int wlan_process_11axcfg_response(uint8_t *res);

int wlan_bcast_twt_command(int argc, char **argv);

int wlan_process_btwt_response(uint8_t *res);

int wlan_twt_setup_command(int argc, char **argv);

int wlan_process_twt_setup_response(uint8_t *res);

int wlan_twt_teardown_command(int argc, char **argv);

int wlan_process_twt_teardown_response(uint8_t *res);

int wlan_get_twt_report_command(int argc, char **argv);

int wlan_process_twt_report_response(uint8_t *res);

int wlan_set_11d_enable_command(int argc, char **argv);

int wlan_process_11d_enable_response(uint8_t *res);

int wlan_region_code_command(int argc, char **argv);

int wlan_process_region_code_response(uint8_t *res);

/**
 * This API can be used to process set maximum number of stations response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body refer to \ref NCP_CMD_CLIENT_CNT.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_client_count_response(uint8_t *res);

/**
 * This API can be used to process set/get antenna configuration response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body refer to \ref NCP_CMD_ANTENNA_CFG.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_antenna_cfg_response(uint8_t *res);

/**
 * This API can be used to process deep sleep ps response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_deep_sleep_ps_response(uint8_t *res);

/**
 * This API can be used to process ieee ps response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_ieee_ps_response(uint8_t *res);

/**
 * This API can be used to process set/get ED(energy detect) MAC mode for station response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body refer to \ref NCP_CMD_ED_MAC.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_ed_mac_response(uint8_t *res);

#ifdef CONFIG_NCP_RF_TEST_MODE
/**
 * This API can be used to set rf test mode.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-test-mode
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note If you test with RF test mode, don't use wlan-reset 2, it is not supported.
 */
int wlan_set_rf_test_mode_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf test mode response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_test_mode_response(uint8_t *res);

/**
 * This API can be used to set rf tx antenna.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-tx-antenna\n
 *                    argv[1]: antenna\n
 *                             1 -- Main\n
 *                             2 -- Aux
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_set_rf_tx_antenna_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf tx antenna response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_tx_antenna_response(uint8_t *res);

/**
 * This API can be used to get rf tx antenna.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-rf-tx-antenna
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note Please set rf tx antenna before get it.
 */
int wlan_get_rf_tx_antenna_command(int argc, char **argv);

/**
 * This API can be used to process get rf tx antenna response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_TX_ANTENNA.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_get_rf_tx_antenna_response(uint8_t *res);

/**
 * This API can be used to set rf rx antenna.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-rx-antenna\n
 *                    argv[1]: antenna\n
 *                             1 -- Main\n
 *                             2 -- Aux
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_set_rf_rx_antenna_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf rx antenna response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_rx_antenna_response(uint8_t *res);

/**
 * This API can be used to get rf rx antenna.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-rf-rx-antenna
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note Please set rf rx antenna before get it.
 */
int wlan_get_rf_rx_antenna_command(int argc, char **argv);

/**
 * This API can be used to process get rf rx antenna response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_RX_ANTENNA.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_get_rf_rx_antenna_response(uint8_t *res);

/**
 * This API can be used to set rf band.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-band\n
 *                    argv[1]: band\n
 *                             0 -- 2.4G\n
 *                             1 -- 5G
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_set_rf_band_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf band response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_band_response(uint8_t *res);

/**
 * This API can be used to get rf band.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-rf-band
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note Please set rf band before get it.
 */
int wlan_get_rf_band_command(int argc, char **argv);

/**
 * This API can be used to process get rf band response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_BAND.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_get_rf_band_response(uint8_t *res);

/**
 * This API can be used to set rf bandwidth.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-bandwidth\n
 *                    argv[1]: bandwidth\n
 *                             0 -- 20MHz\n
 *                             1 -- 40MHz\n
 *                             4 -- 80MHz
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_set_rf_bandwidth_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf bandwidth response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_bandwidth_response(uint8_t *res);

/**
 * This API can be used to get rf bandwidth.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-rf-bandwidth
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note Please set rf bandwidth before get it.
 */
int wlan_get_rf_bandwidth_command(int argc, char **argv);

/**
 * This API can be used to process get rf bandwidth response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_BANDWIDTH.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_get_rf_bandwidth_response(uint8_t *res);

/**
 * This API can be used to set rf channel.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-channel\n
 *                    argv[1]: channel, 2.4G channel numbers or 5G channel numbers
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_set_rf_channel_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf rx antenna response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_channel_response(uint8_t *res);

/**
 * This API can be used to get rf channel.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-rf-channel
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note Please set rf channel before get it.
 */
int wlan_get_rf_channel_command(int argc, char **argv);

/**
 * This API can be used to process get rf channel response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_CHANNEL.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_get_rf_channel_response(uint8_t *res);

/**
 * This API can be used to set rf radio mode.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-radio-mode\n
 *                    argv[1]: radio_mode\n
 *                             0 -- set the radio in power down mode\n
 *                             3 -- set the radio in 5GHz band, 1X1 mode(path A)\n
 *                             11 -- set the radio in 2.4GHz band, 1X1 mode(path A)
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_set_rf_radio_mode_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf radio mode response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_radio_mode_response(uint8_t *res);

/**
 * This API can be used to get rf radio mode.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-rf-radio-mode
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 * \note Please set rf radio mode before get it.
 */
int wlan_get_rf_radio_mode_command(int argc, char **argv);

/**
 * This API can be used to process get rf radio mode response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_RADIO_MODE.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_get_rf_radio_mode_response(uint8_t *res);

/**
 * This API can be used to set rf tx power.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 4.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-tx-power\n
 *                    argv[1]: power\n
 *                             0 to 24 (dBm)\n
 *                    argv[2]: modulation\n
 *                             0 -- CCK\n
 *                             1 -- OFDM\n
 *                             2 -- MCS\n
 *                    argv[3]: path ID\n
 *                             0 -- PathA\n
 *                             1 -- PathB\n
 *                             2 -- PathA+B\n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_set_rf_tx_power_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf tx power response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_tx_power_response(uint8_t *res);

/**
 * This API can be used to set rf tx cont mode.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2 or 6.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-tx-cont-mode\n
 *                    argv[1]: enable/disable rf tx cont mode (Required)\n
 *                             0 -- disable rf tx cont mode\n
 *                             1 -- enable rf tx cont mode\n
 *                    argv[2]: continuous Wave Mode (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable continuous Wave Mode\n
 *                             1 -- enable continuous Wave Mode\n
 *                    argv[3]: payload Pattern (Optional)\n
 *                             Required when argv[1] is 1\n
 *                             0 to 0xFFFFFFFF (Enter hexadecimal value)\n
 *                    argv[4]: CS mode (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             Applicable only when continuous wave is disabled.\n
 *                             0 -- disable CS mode\n
 *                             1 -- enable CS mode\n
 *                    argv[5]: Active SubChannel (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- low\n
 *                             1 -- upper\n
 *                             3 -- both\n
 *                    argv[6]: tx Data Rate (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             Rate index corresponding to legacy/HT/VHT rates.\n
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_ncp_set_rf_tx_cont_mode_command(int argc, char **argv);

/**
 * This API can be used to process wlan set rf tx cont mode response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_tx_cont_mode_response(uint8_t *res);

/**
 * This API can be used to set rf tx frame.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 4.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-set-rf-tx-frame\n
 *                    argv[1]: enable/disable rf tx frame (Required)\n
 *                             0 -- disable rf tx frame\n
 *                             1 -- enable rf tx frame\n
 *                    argv[2]: tx data rate (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             Rate index corresponding to legacy/HT/VHT rates).\n
 *                    argv[3]: Payload Pattern (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 to 0xFFFFFFFF (Enter hexadecimal value)\n
 *                    argv[4]: Payload Length (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             1 to 0x400 (Enter hexadecimal value)\n
 *                    argv[5]: Adjust burst SIFS3 gap (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[6]: Burst SIFS in us (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 to 255 (us)\n
 *                    argv[7]: Short preamble (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[8]: active subchannel (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- low\n
 *                             1 -- upper\n
 *                             3 -- both\n
 *                    argv[9]: short GI (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[10]: adv coding (Optional).\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[11]: Beamforming (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[12]: GreenField Mode (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[13]: STBC (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             0 -- disable\n
 *                             1 -- enable\n
 *                    argv[14]: BSSID (Optional)\n
 *                             Required when argv[1] is 1.\n
 *                             xx:xx:xx:xx:xx:xx
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_ncp_set_rf_tx_frame_command(int argc, char **argv);

/**
 * This API can be used to process set rf tx frame response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.
 *
 * \return TRUE
 */
int wlan_process_set_rf_tx_frame_response(uint8_t *res);

/**
 * This API can be used to get and reset rf per.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 1.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-get-and-reset-rf-per
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_ncp_set_rf_get_and_reset_rf_per_command(int argc, char **argv);

/**
 * This API can be used to process get and reset rf per response.
 *
 * \param[in] res    A pointer to \ref MCU_NCPCmd_DS_COMMAND response.\n
 *                   Response body refer to \ref NCP_CMD_RF_PER.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 *
 */
int wlan_process_set_rf_get_and_reset_rf_per_response(uint8_t *res);
#endif

/**
 * This API can be used to process reads/writes adapter registers value response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body refer to \ref NCP_CMD_REGISTER_ACCESS.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_register_access_response(uint8_t *res);

#ifdef CONFIG_MEM_MONITOR_DEBUG
/**
 * This API can be used to process get OS memory allocate and free info response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body refer to \ref NCP_CMD_MEM_STAT.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_memory_state_response(uint8_t *res);
#endif

/** 
 * This API can be used to verify algorithm AES-CCMP-128 encryption and decryption.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-eu-crypto-ccmp-128\n
 *                    argv[1]: string value of decrypt or encrypt option.\n
 *                             0 -- decrypt\n
 *                             1 -- encrypt\n
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 */
int wlan_eu_crypto_ccmp128_command(int argc, char **argv);

/**
 * This API can be used to process algorithm AES-CCMP-128 encryption and decryption response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body: None.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_eu_crypto_ccmp128_response(uint8_t *res);

/** 
 * This API can be used to verify algorithm AES-GCMP-128 encryption and decryption.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv,
 *                    argc should be 2.
 * \param[in] argv    Argument vector.\n
 *                    argv[0]: wlan-eu-crypto-gcmp-128\n
 *                    argv[1]: string value of decrypt or encrypt option.\n
 *                             0 -- decrypt\n
 *                             1 -- encrypt
 *
 * \return WM_SUCCESS if success.
 * \return -WM_FAIL if failure.
 *
 */
int wlan_eu_crypto_gcmp128_command(int argc, char **argv);

/**
 * This API can be used to process algorithm AES-GCMP-128 encryption and decryption response.
 *
 * \param[in] res     A pointer to \ref NCPCmd_DS_COMMAND response.\n
 *                    Response body: None.
 *
 * \return WM_SUCCESS if success.
 */
int wlan_process_eu_crypto_gcmp128_response(uint8_t *res);

int wlan_set_time_command(int argc, char **argv);

int wlan_get_time_command(int argc, char **argv);

int wlan_process_time_response(uint8_t *res);

int wlan_get_temperature_command(int argc, char **argv);

int wlan_process_get_temperature_response(uint8_t *res);

/**
 * This function returns a list of discovered service on the local network.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should be 3.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: wlan-mdns-query \n
 *                    argv[1]: string value of service types (Required) \n
 *                             The type of service to be discovered. \n
 *                             The service types can be found at http://www.dns-sd.org/ServiceTypes.html. \n
 *                    argv[2]: string value of protocol (Required) \n
 *                             e.g. TCP or UDP
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_mdns_query_command(int argc, char **argv);

/**
 * This API can be used to process mDNS query response.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_mdns_query_response(uint8_t *res);

int wlan_process_csi_data_event(uint8_t *res);

/**
 * This API can be used to process mDNS query event.
 *
 * \param[in] res    A pointer to \ref NCPCmd_DS_COMMAND response. \n
 *                   Event body refer to \ref NCP_EVT_MDNS_RESULT.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_process_mdns_query_result_event(uint8_t *res);

int wlan_process_mdns_resolve_domain_event(uint8_t *res);

int wlan_process_network_list_response(uint8_t *res);

int wlan_process_network_remove_response(uint8_t *res);

int wlan_process_con_event(uint8_t *res);

int wlan_process_discon_event(uint8_t *res);

int wlan_process_stop_network_event(uint8_t *res);

int wlan_process_ipv6_dad_done_event(uint8_t *res);

/**
 * Send an ICMP echo request, receive its response and print its statistics and result.
 *
 * \param[in] argc    Argument count, the number of strings pointed to by argv, \n
 *                    argc should range from 2 to 5.
 * \param[in] argv    Argument vector, \n
 *                    argv[0]: ping \n
 *                    argv[1]: value of -s <packet_size> (Optional)     \n
 *                    argv[2]: value of -c <packet_count> (Optional)    \n
 *                    argv[3]: value of -W <timeout in sec> (Optional)  \n
 *                    argv[4]: value of <ipv4 address> (Required)       \n
 *                             The ipv4 address of target device.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int ncp_ping_command(int argc, char **argv);

int mpu_host_init_cli_commands_wifi();
int mpu_host_deinit_cli_commands_wifi();

#endif /*__NCP_HOST_COMMAND_WIFI_H__*/
