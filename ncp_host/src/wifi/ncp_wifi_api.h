/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * Copyright 2025 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#ifndef __NCP_WIFI_API__
#define __NCP_WIFI_API__

#include "ncp_host_command_wifi.h"
#include "ncp_cmd_node.h"

#define NETIF_MAX_HWADDR_LEN      6U
#ifdef CONFIG_IPV6
#define IP6ADDR_STRLEN_MAX  46
#define LWIP_IPV6_SCOPES  0
#define LWIP_IPV4  1
#define LWIP_IPV6  1
#endif

/**
 * @defgroup netif_flags Flags
 * @ingroup netif
 * @{
 */

/** Whether the network interface is 'up'. This is
 * a software flag used to control whether this network
 * interface is enabled and processes traffic.
 * It must be set by the startup code before this netif can be used
 * (also for dhcp/autoip).
 */
#define NETIF_FLAG_UP           0x01U
/** If set, the netif has broadcast capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_BROADCAST    0x02U
/** If set, the interface has an active link
 *  (set by the network interface driver).
 * Either set by the netif driver in its init function (if the link
 * is up at that time) or at a later point once the link comes up
 * (if link detection is supported by the hardware). */
#define NETIF_FLAG_LINK_UP      0x04U
/** If set, the netif is an ethernet device using ARP.
 * Set by the netif driver in its init function.
 * Used to check input packet types and use of DHCP. */
#define NETIF_FLAG_ETHARP       0x08U
/** If set, the netif is an ethernet device. It might not use
 * ARP or TCP/IP if it is used for PPPoE only.
 */
#define NETIF_FLAG_ETHERNET     0x10U
/** If set, the netif has IGMP capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_IGMP         0x20U
/** If set, the netif has MLD6 capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_MLD6         0x40U

/** 255.255.255.255 */
#define IPADDR_NONE         ((uint32_t)0xffffffffUL)
/** 127.0.0.1 */
#define IPADDR_LOOPBACK     ((uint32_t)0x7f000001UL)
/** 0.0.0.0 */
#define IPADDR_ANY          ((uint32_t)0x00000000UL)
/** 255.255.255.255 */
#define IPADDR_BROADCAST    ((uint32_t)0xffffffffUL)

#define PP_HTONL(x) ((((x) & (uint32_t)0x000000ffUL) << 24) | \
                     (((x) & (uint32_t)0x0000ff00UL) <<  8) | \
                     (((x) & (uint32_t)0x00ff0000UL) >>  8) | \
                     (((x) & (uint32_t)0xff000000UL) >> 24))

/** Wifi current network */
typedef struct ncp_current_network_t
{
    /** Get current network result */
    uint16_t result;
    /** WLAN Network Profile */
    NCP_WLAN_NETWORK sta_network;
} ncp_current_network;

/** MAC address */
typedef struct ncp_get_mac_addr_t
{
    /** Get MAC address result */
    uint16_t result;
    /** MAC address */
    NCP_CMD_GET_MAC_ADDRESS mac_addr;
} ncp_get_mac_addr;

/** Wi-Fi Statistics counter */
typedef struct ncp_pkt_stats_t
{
    /** Get pkt stats result */
    uint16_t result;
    /** Pkt stats */
    NCP_CMD_PKT_STATS pkt_stats;
} ncp_pkt_stats;

/** MAC address */
typedef struct ncp_mac_addr_t
{
    /** Mac address array */
    char mac[MLAN_MAC_ADDR_LENGTH];
} ncp_mac_addr;

/** Network ip configuration */
typedef struct ncp_ip_config_t
{
    /** Get ip config result */
    uint16_t result;
    /** Network IP configuration. */
    NCP_CMD_IP_CONFIG ip_config;
} ncp_ip_config;

/** IPv4 address */
struct ip4_addr {
    uint32_t addr;
};

/** IPv4 address */
typedef struct ip4_addr ip4_addr_t;

#ifdef CONFIG_IPV6
/** This is the aligned version of ip6_addr_t,
    used as local variable, on the stack, etc. */
struct ip6_addr {
    uint32_t addr[4];
#if LWIP_IPV6_SCOPES
    uint8_t zone;
#endif /* LWIP_IPV6_SCOPES */
    };
      
/** IPv6 address */
typedef struct ip6_addr ip6_addr_t;
#endif

/**
 * @ingroup ipaddr
 * A union struct for both IP version's addresses.
 * ATTENTION: watch out for its size when adding IPv6 address scope!
 */
typedef struct ip_addr {
    union {
#ifdef CONFIG_IPV6
      ip6_addr_t ip6;
#endif
      ip4_addr_t ip4;
    } u_addr;
    /** @ref lwip_ip_addr_type */
    uint8_t type;
} ip_addr_t;

#define netif_is_up(netif) (((netif)->flags & NETIF_FLAG_UP) ? (uint8_t)1 : (uint8_t)0)

#ifdef CONFIG_IPV6
/** @ingroup ip6addr
 * Convert generic ip address to specific protocol version
 */
#define ip_2_ip6(ipaddr)   (&((ipaddr)->u_addr.ip6))
#endif
/** @ingroup ip4addr
 * Convert generic ip address to specific protocol version
 */
#define ip_2_ip4(ipaddr)   (&((ipaddr)->u_addr.ip4))

/** @ingroup ipaddr
 *  Check if an ip address is the 'any' address, by value. */
#define ip4_addr_isany_val(addr1)   ((addr1).addr == IPADDR_ANY)
#define ip4_addr_isany(addr1) ((addr1) == NULL || ip4_addr_isany_val(*(addr1)))
/** @ingroup netif_ip4 */
#define netif_ip4_addr(netif)    ((const ip4_addr_t*)ip_2_ip4(&((netif)->ip_addr)))
#define netif_ip4_netmask(netif) ((const ip4_addr_t*)ip_2_ip4(&((netif)->netmask)))
#define netif_ip4_gw(netif)      ((const ip4_addr_t*)ip_2_ip4(&((netif)->gw)))

#ifdef CONFIG_IPV6
/** This bit marks an address as valid (preferred or deprecated) */
#define IP6_ADDR_VALID        0x10
/** @ingroup ipaddr
 *  Check if an ip address is the 'any' address, by value. */
#define ip6_addr_isvalid(addr_state) (addr_state & IP6_ADDR_VALID)
#define ip6_addr_islinklocal(ip6addr) (((ip6addr)->addr[0] & PP_HTONL(0xffc00000UL)) == PP_HTONL(0xfe800000UL))
/** @ingroup netif_ip6 */
#define netif_ip6_addr_state(netif, i)  ((netif)->ip6_addr_state[i])
#define netif_ip6_addr(netif, i)  ((const ip6_addr_t*)ip_2_ip6(&((netif)->ip6_addr[i])))

#endif

/** Generic data structure used for MATTER NCP network interfaces.
 *  The following fields should be filled in by the API wlan_ncp_netif_update(). */
typedef struct ncp_netif_t
{
    struct ncp_netif_t *next; 
    /** IP address configuration in network byte order */
    ip_addr_t ip_addr;
    ip_addr_t netmask;
    ip_addr_t gw;
#ifdef CONFIG_IPV6
    /** Array of IPv6 addresses for this netif. */
    ip_addr_t ip6_addr[CONFIG_MAX_IPV6_ADDRESSES];
    /** The state of each IPv6 address (Tentative, Preferred, etc).
    * @see ip6_addr.h */
    uint8_t ip6_addr_state[CONFIG_MAX_IPV6_ADDRESSES];
#endif
    /** link level hardware address of this interface */
    uint8_t hwaddr[NETIF_MAX_HWADDR_LEN];
    /** number of bytes used in hwaddr */
    uint8_t hwaddr_len;
    /** flags (@see @ref netif_flags) */
    uint8_t flags;
    /** descriptive abbreviation */
    char name[10];
    /** number of this interface. Used for @ref if_api and @ref netifapi_netif,
     * as well as for IPv6 zones */
    uint8_t num;
} ncp_netif;

/**
 * This API can be used to get connection state.
 *
 * \return connection state.
 */
char * wlan_ncp_get_state(void);

/**
 * Remove a network profile from the list of known networks.
 *
 * \param[in] network    structure of network profile.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_remove_network(NCP_WLAN_NETWORK * network);

/**
 * Add a network profile to the list of known networks.
 *
 * \note This API can be used to add profiles for station or UAP interfaces.
 *
 * \param[in] ssid      The network SSID, represented as a C string of up to 32 characters in length. \n
 * \param[in] key       The network key, the lenth is set by key_len. \n
 * \param[in] mode      The value of security mode \n
 *                      The network security configuration specified for the network \n
 * \param[in] frequency The network frequency, set as channel \n
 * \param[in] network_name
 *                      profile name, the name of network profile \n
 * \param[in] key_len   The value of key_len, the lenth of network key \n
 *                    
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_add_network(char * ssid, char * key, int8_t mode, int8_t frequency, char * network_name, int8_t key_len);

/**
 * Disconnect from the current Wi-Fi network (access point).
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_disconnect(void);

/**
 * Scan for Wi-Fi networks.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_scan(void);

/**
 * Get the count of network profile from scan result.
 *
 * * \param[out] count  Number of networks from scan result list
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_get_scan_result_count(uint8_t * count);

/**
 * Connect to a Wi-Fi network (access point).
 *
 * \param[in] network_name    string value of name \n
 *                            A string representing the name of the network to connect to.
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_connect(char * network_name);

/**
 * Get current network profile which is connected.
 *
 * \param[in] network_name    string value of name \n
 *                            A string representing the name of the network to connect to.
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_get_current_network(NCP_WLAN_NETWORK * net_work);

/**
 * Remove all network profiles.
 *
 * \return TRUE if success.
 * \return FALSE if failure.
 */
bool wlan_ncp_remove_all_networks();

/**
 * Get Wi-Fi MAC Address in Wi-Fi firmware.
 *
 * \param[out] dest    The Wi-Fi MAC Address get from Wi-Fi firmware \n
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_get_mac_address(unsigned char * dest);

/**
 * Get Wi-Fi Statistics counter.
 *
 * \param[out] stats    The Wi-Fi Statistics counter \n
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_get_pkt_stats(NCP_CMD_PKT_STATS *stats);

/**
 * Get scan result.
 *
 * \param[in]  index    The index from the scan table \n
 * \param[out] res      Get the scan result from the scan table as the index \n
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_get_scan_result(unsigned int index, NCP_WLAN_SCAN_RESULT * res);

/**
 * Get rssi.
 *
 * \param[out] rssi     The signal strength of the beacon \n
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_get_current_rssi(short * rssi);

/**
 * Get channel number.
 *
 * \return Channel number.
 */
uint8_t wlan_ncp_get_current_channel(void);

/**
 * Get Network IP configuration.
 *
 * \param[out] ip_config     The Network IP configuration \n
 * 
 * \return TRUE if success.
 * \return FALSE if failure.
 */
int wlan_ncp_get_ip_config(NCP_CMD_IP_CONFIG * addr);

/**
 * Get Network netif flags.
 * 
 * \return netif flags.
 */
int wlan_ncp_get_netif_flags(void);

/**
 * Update Network netif configuration.
 *
 */
void wlan_ncp_netif_update(void);

/**
 * Wait ipv6 DAD complete.
 *
 */
void wlan_ncp_wait_ipv6_dad(void);
#endif /* __NCP_WIFI_API__ */
