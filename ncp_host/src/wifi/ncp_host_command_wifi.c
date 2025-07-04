/** @file ncp_host_command_wifi.c
 *
 *  Copyright 2020-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include "ncp_host_app.h"
#include "ncp_host_command.h"
#include "ncp_host_command_wifi.h"
#include "ncp_wifi_api.h"
#include "ncp_tlv_adapter.h"
#include "ncp_inet.h"
#include <sys/ioctl.h>

static uint8_t broadcast_mac[NCP_WLAN_MAC_ADDR_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static int mdns_result_num;

static bool socket_receive_res  = false;
static bool socket_recvfrom_res = false;

int cli_optind   = 0;
char *cli_optarg = NULL;
uint32_t g_udp_recv_timeout = IPERF_UDP_RECV_TIMEOUT;
extern int ping_qid;
extern ping_msg_t ping_msg;
extern sem_t ping_res_sem;
extern ping_res_t ping_res;
extern int ping_sock_handle;
extern pthread_mutex_t gpio_wakeup_mutex;

extern sem_t global_sem_dad;
extern sem_t iperf_tx_sem;
extern sem_t iperf_rx_sem;

extern uint8_t cmd_buf[NCP_COMMAND_LEN];

power_cfg_t global_power_config;

wlan_csi_config_params_t g_csi_params;

NCP_WLAN_NET_MONITOR_PARA g_net_monitor_param;

int inet_aton(const char *cp, struct in_addr *inp);
int wlan_process_wlan_uap_prov_set_uapcfg_response(uint8_t *res);

#if CONFIG_NCP_SUPP_WPS
/** Enum that indicates type of WPS session
 *   either a push button or a PIN based session is
 *   determined by value fo this enum
 */
enum wps_session_types
{
    /** WPS session is not active */
    WPS_SESSION_INACTIVE = 0xffff,
    /** WPS Push Button session active */
    WPS_SESSION_PBC = 0x0004,
    /** WPS PIN session active */
    WPS_SESSION_PIN = 0x0000,
};
#endif

NCPCmd_DS_COMMAND *mpu_host_get_wifi_command_buffer()
{
    return (NCPCmd_DS_COMMAND *)(cmd_buf);
}

/** Dump buffer in hex format on console
 *
 * This function prints the received buffer in HEX format on the console
 *
 * \param[in] data Pointer to the data buffer
 * \param[in] len Length of the data
 */
#define DUMP_WRAPAROUND 16
void dump_hex(const void *data, unsigned len)
{
    (void)printf("**** Dump @ %p Len: %d ****\n\r", data, len);

    unsigned int i;
    const char *data8 = (const char *)data;
    for (i = 0; i < len;)
    {
        (void)printf("%02x ", data8[i++]);
        if (!(i % DUMP_WRAPAROUND))
            (void)printf("\n\r");
    }

    (void)printf("\n\r******** End Dump *******\n\r");
}

/**
 * @brief This function prepares scan command
 *
 * @return Status returned
 */
int wlan_scan_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *scan_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)scan_command, 0, NCP_COMMAND_LEN);
    scan_command->header.cmd      = NCP_CMD_WLAN_STA_SCAN;
    scan_command->header.size     = NCP_CMD_HEADER_LEN;
    scan_command->header.result   = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function prepares connect command
 *
 * @return Status returned
 */
int wlan_connect_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *connect_command = mpu_host_get_wifi_command_buffer();

    if (argc > 2)
    {
        printf("invalid argument\r\n");
        return FALSE;
    }

    connect_command->header.cmd      = NCP_CMD_WLAN_STA_CONNECT;
    connect_command->header.size     = NCP_CMD_HEADER_LEN;
    connect_command->header.result   = NCP_CMD_RESULT_OK;

    if (argc == 2)
    {
        NCP_CMD_WLAN_CONN *conn = (NCP_CMD_WLAN_CONN *)&connect_command->params.wlan_connect;
        (void)memcpy(conn->name, argv[1], strlen(argv[1]) + 1);
        connect_command->header.size += sizeof(NCP_CMD_WLAN_CONN);
    }

    return TRUE;
}

/**
 * @brief  This function prepares disconnect command
 *
 * @return Status returned
 */
int wlan_disconnect_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *disconnect_command = mpu_host_get_wifi_command_buffer();
    disconnect_command->header.cmd        = NCP_CMD_WLAN_STA_DISCONNECT;
    disconnect_command->header.size       = NCP_CMD_HEADER_LEN;
    disconnect_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function prepares firmware version command
 *
 * @return Status returned
 */
int wlan_version_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *fw_ver_command = mpu_host_get_wifi_command_buffer();
    fw_ver_command->header.cmd        = NCP_CMD_WLAN_STA_VERSION;
    fw_ver_command->header.size       = NCP_CMD_HEADER_LEN;
    fw_ver_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function prepares set mac address command
 *
 * @return Status returned
 */
int wlan_set_mac_address_command(int argc, char **argv)
{
    int ret;
    uint8_t raw_mac[NCP_WLAN_MAC_ADDR_LENGTH];
    NCPCmd_DS_COMMAND *mac_addr_command = mpu_host_get_wifi_command_buffer();

    if (argc != 2)
    {
        printf("Usage: %s MAC_Address\r\n", argv[0]);
        return FALSE;
    }

    ret = get_mac(argv[1], (char *)raw_mac, ':');
    if (ret != 0)
    {
        printf("Error: invalid MAC argument\r\n");
        return FALSE;
    }

    if ((memcmp(&raw_mac[0], broadcast_mac, NCP_WLAN_MAC_ADDR_LENGTH) == 0) || (raw_mac[0] & 0x01))
    {
        printf("Error: only support unicast mac\r\n");
        return FALSE;
    }

    mac_addr_command->header.cmd      = NCP_CMD_WLAN_STA_SET_MAC;
    mac_addr_command->header.size     = NCP_CMD_HEADER_LEN;
    mac_addr_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_MAC_ADDRESS *mac_address = (NCP_CMD_MAC_ADDRESS *)&mac_addr_command->params.mac_addr;
    memcpy(mac_address->mac_addr, raw_mac, NCP_WLAN_MAC_ADDR_LENGTH);
    mac_addr_command->header.size += sizeof(NCP_CMD_MAC_ADDRESS);

    return TRUE;
}

/**
 * @brief  This function prepares get mac address command
 *
 * @return Status returned
 */
int wlan_get_mac_address_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *get_mac_command = mpu_host_get_wifi_command_buffer();
    get_mac_command->header.cmd        = NCP_CMD_WLAN_STA_GET_MAC;
    get_mac_command->header.size       = NCP_CMD_HEADER_LEN;
    get_mac_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function prepares get wlan connection state command
 *
 * @return Status returned
 */
int wlan_stat_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *conn_stat_command = mpu_host_get_wifi_command_buffer();
    conn_stat_command->header.cmd        = NCP_CMD_WLAN_STA_CONNECT_STAT;
    conn_stat_command->header.size       = NCP_CMD_HEADER_LEN;
    conn_stat_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function prepares OKC command
 *
 * @return Status returned
 */
int wlan_set_okc_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *okc_command = mpu_host_get_wifi_command_buffer();
    int enable                     = 0;

    if (argc != 2)
    {
        printf("Usage: %s <okc: 0(default)/1>\r\n", argv[0]);
        printf(
            "\tOpportunistic Key Caching (also known as Proactive Key Caching) default\r\n"
            "\tThis parameter can be used to set the default behavior for the\r\n"
            "\tBy default, OKC is disabled unless enabled with the global okc=1 parameter \r\n"
            "\tor with the per-network proactive_key_caching=1 parameter.\r\n"
            "With okc=1, OKC is enabled by default, but can be disabled with per-network proactive_key_caching=0 "
            "parameter.\r\n"
            "\t# 0 = Disable OKC (default)\r\n"
            "\t# 1 = Enable OKC\r\n");
        return FALSE;
    }

    enable = atoi(argv[1]);
    if (enable != 0 && enable != 1)
    {
        printf("Error! Invalid input of parameter <enable>\r\n");
        return FALSE;
    }

    okc_command->header.cmd      = NCP_CMD_WLAN_STA_SET_OKC;
    okc_command->header.size     = NCP_CMD_HEADER_LEN;
    okc_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_OKC *okc = (NCP_CMD_OKC *)&okc_command->params.okc_cfg;
    okc->enable      = enable;
    okc_command->header.size += sizeof(NCP_CMD_OKC);

    return TRUE;
}

static void dump_wlan_roaming_command(const char *str)
{
    printf("Usage: %s <enable> <rssi_threshold>\r\n", str);
    printf("      <enable>         : 0 - disable\r\n");
    printf("                         1 - enable\r\n");
    printf("      <rssi_threshold> : weak RSSI threshold in dBm (absolute value)\r\n");
    printf("                         default = 70\r\n");
    return;
}

/**
 * @brief  This function prepares roaming command
 *
 * @return Status returned
 */
int wlan_roaming_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *roaming_command = mpu_host_get_wifi_command_buffer();
    int enable                         = 0;

    if (argc < 2 || argc > 3)
    {
        dump_wlan_roaming_command(argv[0]);
        return FALSE;
    }

    enable = atoi(argv[1]);
    if (enable != 0 && enable != 1)
    {
        dump_wlan_roaming_command(argv[0]);
        return FALSE;
    }

    roaming_command->header.cmd      = NCP_CMD_WLAN_STA_ROAMING;
    roaming_command->header.size     = NCP_CMD_HEADER_LEN;
    roaming_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_ROAMING *roaming = (NCP_CMD_ROAMING *)&roaming_command->params.roaming;
    roaming->enable          = enable;
    if (argc == 3)
        roaming->rssi_threshold = atoi(argv[2]);
    else
        roaming->rssi_threshold = NCP_WLAN_DEFAULT_RSSI_THRESHOLD;
    roaming_command->header.size += sizeof(NCP_CMD_ROAMING);

    return TRUE;
}

static void dump_wlan_reset_command(const char *str)
{
    printf("Usage: %s <option>\r\n", str);
    printf("0 to Disable WiFi\r\n");
    printf("1 to Enable WiFi\r\n");
    printf("2 to Reset WiFi\r\n");
    return;
}
/**
 * @brief  This function prepares wlan reset command
 *
 * @return Status returned
 */
int wlan_reset_command(int argc, char **argv)
{
    int option;
    option = atoi(argv[1]);
    if (argc != 2 || (option != 0 && option != 1 && option != 2))
    {
        dump_wlan_reset_command(argv[0]);
        return FALSE;
    }

    if (option == 2)
    {
        (void)memset((void*)&g_csi_params, 0, sizeof(g_csi_params));
        (void)memset((void*)&g_net_monitor_param, 0, sizeof(g_net_monitor_param));
        (void)memset((void*)&global_power_config, 0, sizeof(global_power_config));
    }

    NCPCmd_DS_COMMAND *wlan_reset_command = mpu_host_get_wifi_command_buffer();
    wlan_reset_command->header.cmd        = NCP_CMD_WLAN_BASIC_WLAN_RESET;
    wlan_reset_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_reset_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_WLAN_RESET_CFG *wlan_reset_tlv = (NCP_CMD_WLAN_RESET_CFG *)&wlan_reset_command->params.wlan_reset_cfg;
    wlan_reset_tlv->option                 = option;
    /*cmd size*/
    wlan_reset_command->header.size += sizeof(NCP_CMD_WLAN_RESET_CFG);

    return TRUE;
}

/**
 * @brief  This function prepares wlan network info command
 *
 * @return Status returned
 */
int wlan_info_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *network_info_command = mpu_host_get_wifi_command_buffer();
    network_info_command->header.cmd        = NCP_CMD_WLAN_NETWORK_INFO;
    network_info_command->header.size       = NCP_CMD_HEADER_LEN;
    network_info_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function get wlan network ip address command
 *
 * @return Status returned
 */
int wlan_address_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *network_address_command = mpu_host_get_wifi_command_buffer();
    network_address_command->header.cmd        = NCP_CMD_WLAN_NETWORK_ADDRESS;
    network_address_command->header.size       = NCP_CMD_HEADER_LEN;
    network_address_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}


int wlan_uap_prov_start_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *uap_prov_start_command = mpu_host_get_wifi_command_buffer();
    uap_prov_start_command->header.cmd        = NCP_CMD_WLAN_BASIC_WLAN_UAP_PROV_START;
    uap_prov_start_command->header.size       = NCP_CMD_HEADER_LEN;
    uap_prov_start_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

int wlan_uap_prov_reset_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *uap_prov_reset_command = mpu_host_get_wifi_command_buffer();
    uap_prov_reset_command->header.cmd        = NCP_CMD_WLAN_BASIC_WLAN_UAP_PROV_RESET;
    uap_prov_reset_command->header.size       = NCP_CMD_HEADER_LEN;
    uap_prov_reset_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

static void dump_uap_prov_set_uapcfg_usage(void)
{
    (void)printf("Usage: wlan-uap-prov-set-uapcfg <ssid> <security> <password>\r\n");
    (void)printf("Value for <security>: \r\n");
    (void)printf("    %d - WLAN_SECURITY_NONE\r\n", WLAN_SECURITY_NONE);
    (void)printf("    %d - WLAN_SECURITY_WPA\r\n", WLAN_SECURITY_WPA);
    (void)printf("    %d - WLAN_SECURITY_WPA2\r\n", WLAN_SECURITY_WPA2);
    (void)printf("    %d - WLAN_SECURITY_WPA_WPA2_MIXED\r\n", WLAN_SECURITY_WPA_WPA2_MIXED);
    (void)printf("    %d - WLAN_SECURITY_WPA3_SAE\r\n", WLAN_SECURITY_WPA3_SAE);
    (void)printf("    %d - WLAN_SECURITY_WPA2_WPA3_SAE_MIXED\r\n", WLAN_SECURITY_WPA2_WPA3_SAE_MIXED);
    (void)printf("Usage example : \r\n");
    (void)printf("wlan-uap-prov-set-uapcfg nxp_uap\r\n");
    (void)printf("wlan-uap-prov-set-uapcfg nxp_uap 0\r\n");
    (void)printf("wlan-uap-prov-set-uapcfg nxp_uap 4 12345678\r\n");
}

int wlan_uap_prov_set_uapcfg(int argc, char **argv)
{
    int ret      = -WM_E_INVAL;

    if ((argc < 2) || (argc > 4))
    {
        (void)printf("wlan_uap_prov_reset_command: invalid number of arguments!\r\n");
		dump_uap_prov_set_uapcfg_usage();
        return ret;
    }

	if(argc >= 2 && strlen(argv[1]) > WLAN_SSID_MAX_LENGTH)
    {
       (void)printf("wlan_uap_prov_reset_command: invalid ssid length!\r\n");
	   return ret;
    }
	
	if(argc >= 4 && strlen(argv[3]) > WLAN_PASSWORD_MAX_LENGTH)
	{       
	   (void)printf("wlan_uap_prov_reset_command: invalid password length!\r\n");
	   return ret;
	}
	
	NCPCmd_DS_COMMAND *uap_prov_set_uap_cfg_command = mpu_host_get_wifi_command_buffer();
	(void)memset(uap_prov_set_uap_cfg_command, 0, sizeof(NCPCmd_DS_COMMAND));
    uap_prov_set_uap_cfg_command->header.cmd        = NCP_CMD_WLAN_BASIC_WLAN_UAP_PROV_SET_UAPCFG;
    uap_prov_set_uap_cfg_command->header.size       = NCP_CMD_HEADER_LEN;
    uap_prov_set_uap_cfg_command->header.result     = NCP_CMD_RESULT_OK;

	NCP_CMD_UAP_PROV_SET_UAPCFG *set_uap_cfg = (NCP_CMD_UAP_PROV_SET_UAPCFG *)&uap_prov_set_uap_cfg_command->params.prov_set_uap_cfg;
    if(argc >= 2)
        strncpy(set_uap_cfg->ssid, argv[1], strlen(argv[1]));
	if(argc >= 4)
	    strncpy(set_uap_cfg->uapPass, argv[3], strlen(argv[3]));
	if (argc >= 3)
        set_uap_cfg->security_type = atoi(argv[2]);
		
    /*cmd size*/
    uap_prov_set_uap_cfg_command->header.size += sizeof(NCP_CMD_UAP_PROV_SET_UAPCFG);

    return WM_SUCCESS;
}

static void dump_wlan_add_usage()
{
    printf("Usage:\r\n");
    printf("For Station interface\r\n");
    printf("  For DHCP IP Address assignment:\r\n");
    printf(
        "    wlan-add <profile_name> ssid <ssid> [wpa2 <psk> <secret>]"
        "\r\n");
    printf("      If using WPA2 security, set the PMF configuration if required.\r\n");
#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_TLS
    printf(
        "    wlan-add <profile_name> ssid <ssid> eap-tls aid <aid> key_passwd <key_passwd>"
        "\r\n");
    printf("      For WPA2 enterprise eap-tls security, only station is supported.\r\n");
#endif
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_MSCHAPV2
    printf(
        "    wlan-add <profile_name> ssid <ssid> eap-peap-mschapv2 [verify_peer_cert <0/1>] ver <0/1> aid <aid> id <id>"
        " pass <pass> key_passwd <key_passwd>"
        "\r\n");
    printf("      For WPA2 enterprise eap-peap-mschapv2 security, only station is supported.\r\n");
#endif
#endif
#endif
    printf(
        "    wlan-add <profile_name> ssid <ssid> [wpa3 sae <secret> mfpc <1> mfpr <0/1>]"
        "\r\n");
    printf("      If using WPA3 SAE security, always set the PMF configuration.\r\n");
#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_TLS
    printf(
        "    wlan-add <profile_name> ssid <ssid> wpa3-ent/wpa3-sb/wpa3-sb-192"
        " eap-tls aid <aid> key_passwd <key_passwd> mfpc <1> mfpr <0/1>"
        "\r\n");
    printf(
        "   wlan-add <profile_name> ssid <ssid> wpa3-sb-192 eap-tls [tls_cipher <ECC_P384/RSA_3K>]"
        " aid <aid> key_passwd <key_passwd> mfpc <1> mfpr <0/1>"
        "\r\n");
    printf("      For WPA3 enterprise eap-tls security, only station is supported.\r\n");
#endif
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_MSCHAPV2
    printf(
        "    wlan-add <profile_name> ssid <ssid> wpa3-ent/wpa3-sb/wpa3-sb-192 eap-peap-mschapv2 [verify_peer_cert <0/1>] ver <0/1>"
        " aid <aid> id <id> pass <pass> key_passwd <key_passwd> mfpc <1> mfpr <0/1>"
        "\r\n");
    printf("      For WPA3 enterprise eap-peap-mschapv2 security, only station is supported.\r\n");
#endif
#endif
#endif
    printf("  For static IP address assignment:\r\n");
    printf(
        "    wlan-add <profile_name> ssid <ssid>\r\n"
        "    ip:<ip_addr>,<gateway_ip>,<netmask>\r\n");
    printf(
        "    [bssid <bssid>] [channel <channel number>]\r\n"
        "    [wpa2 <psk> <secret>]"
        "\r\n");

    printf("For Micro-AP interface\r\n");
    printf(
        "    wlan-add <profile_name> ssid <ssid>\r\n"
        "    ip:<ip_addr>,<gateway_ip>,<netmask>\r\n");
    printf(
        "    role uap [bssid <bssid>]\r\n"
        "    [channel <channelnumber>]\r\n");
    printf(
        "    [wpa2 <psk> <secret>]/[wpa <secret> wpa2 <psk> <secret>]/[wpa3 sae <secret> [pwe <0/1/2>] [tr <0/1>]]/[wpa2 <secret> wpa3 sae "
        "<secret>]");
#ifdef CONFIG_WIFI_CAPA
    printf("\r\n");
    printf("    [capa <11ax/11ac/11n/legacy>]");
#endif
    printf("\r\n");
    printf("    [mfpc <0/1>] [mfpr <0/1>]\r\n");
#ifdef CONFIG_WIFI_DTIM_PERIOD
    printf("If seting dtim\r\n");
    printf(
        "    The value of dtim is an integer. The default value is 10.\r\n"
        "    The range of dtim is [1,255].\r\n");
#endif
    printf("If Set channel to 0, set acs_band to 0 1.\r\n");
    printf("0: 2.4GHz channel   1: 5GHz channel  Not support to select dual band automatically.\r\n");
}

/* Parse the 'arg' string as "ip:ipaddr,gwaddr,netmask,[dns1,dns2]" into
 * a wlan_ip_config data structure */
static int get_address(char *arg, IP_ParamSet_t *ip)
{
    char *ipaddr = NULL, *gwaddr = NULL, *netmask = NULL;
    char *dns1 = NULL, *dns2 = NULL;
    struct in_addr ip_s, gw_s, nm_s, dns1_s, dns2_s;

    ipaddr = strstr(arg, "ip:");
    if (ipaddr == NULL)
        return -1;
    ipaddr += 3;

    gwaddr = strstr(ipaddr, ",");
    if (gwaddr == NULL)
        return -1;
    *gwaddr++ = 0;

    netmask = strstr(gwaddr, ",");
    if (netmask == NULL)
        return -1;
    *netmask++ = 0;

    dns1 = strstr(netmask, ",");
    if (dns1 != NULL)
    {
        *dns1++ = 0;
        dns2    = strstr(dns1, ",");
    }

    inet_aton(ipaddr, &ip_s);
    ip->address = ip_s.s_addr;
    inet_aton(gwaddr, &gw_s);
    ip->gateway = gw_s.s_addr;
    inet_aton(netmask, &nm_s);
    ip->netmask = nm_s.s_addr;
    if (dns1 != NULL)
    {
        inet_aton(dns1, &dns1_s);
        ip->dns1 = dns1_s.s_addr;
    }
    if (dns2 != NULL)
    {
        inet_aton(dns2, &dns2_s);
        ip->dns2 = dns2_s.s_addr;
    }

    return 0;
}

static int get_security(int argc, char **argv, enum wlan_security_type type, Security_ParamSet_t *sec)
{
    if (argc < 1)
        return 1;

    switch (type)
    {
        case WLAN_SECURITY_WPA:
        case WLAN_SECURITY_WPA2:
            if (argc < 1)
                return 1;
            /* copy the PSK phrase */
            sec->password_len = strlen(argv[0]);
            if (sec->password_len < 65)
                strcpy(sec->password, argv[0]);
            else
                return 1;
            sec->type = type;
            break;
        default:
            return 1;
    }

    return 0;
}

/**
 * @brief  This function prepares wlan add network command
 *
 * @return Status returned
 */
int wlan_add_command(int argc, char **argv)
{
    int ret = 0;
    int arg = 1;
    struct
    {
        unsigned ssid : 1;
        unsigned bssid : 1;
        unsigned channel : 1;
        unsigned address : 2;
        unsigned security : 1;
        unsigned security2 : 1;
        unsigned security3 : 1;
#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
        unsigned security_eap : 1;
#endif
        unsigned role : 1;
        unsigned mfpc : 1;
        unsigned mfpr : 1;
#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
        unsigned wpa3_ent : 1;
        unsigned wpa3_sb : 1;
        unsigned wpa3_sb_192 : 1;
#ifdef CONFIG_EAP_TLS
        unsigned tls_cipher : 1;
#endif
#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
        unsigned aid : 1;
        unsigned key_passwd : 1;
        unsigned eap_ver : 1;
#ifdef CONFIG_EAP_MSCHAPV2
        unsigned verify_peer_cert : 1;
#endif
        unsigned id : 1;
        unsigned pass : 1;
#endif
#endif
        unsigned pwe: 1;
        unsigned tr : 1;
#ifdef CONFIG_WIFI_DTIM_PERIOD
        unsigned dtim : 1;
#endif
        unsigned acs_band : 1;
#ifdef CONFIG_WIFI_CAPA
        unsigned wlan_capa : 1;
#endif
    } info;

    NCPCmd_DS_COMMAND *network_add_command = mpu_host_get_wifi_command_buffer();
    NCP_CMD_NETWORK_ADD *network_add_tlv   = (NCP_CMD_NETWORK_ADD *)&network_add_command->params.network_add;
    uint8_t *ptlv_pos                      = network_add_tlv->tlv_buf;
    uint32_t tlv_buf_len                   = 0;
    SSID_ParamSet_t *ssid_tlv              = NULL;
    BSSID_ParamSet_t *bssid_tlv            = NULL;
    Channel_ParamSet_t *channel_tlv        = NULL;
    Pwe_Derivation_ParamSet_t *pwe_tlv     = NULL;
    Tr_Disable_ParamSet_t *tr_tlv          = NULL;	 
    IP_ParamSet_t *ip_tlv                  = NULL;
    Security_ParamSet_t *security_wpa_tlv = NULL, *security_wpa2_tlv = NULL, *security_wpa3_tlv = NULL;
#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
    Security_ParamSet_t *security_eap_tlv = NULL;
#endif
    PMF_ParamSet_t *pmf_tlv          = NULL;
#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
    EAP_ParamSet_t *eap_tlv          = NULL;
#endif
    BSSRole_ParamSet_t *role_tlv     = NULL;
    DTIM_ParamSet_t *dtim_tlv        = NULL;
    ACSBand_ParamSet_t *acs_band_tlv = NULL;
    CAPA_ParamSet_t *capa_tlv        = NULL;
    (void)memset(&info, 0, sizeof(info));

    if (argc < 4)
    {
        dump_wlan_add_usage();
        printf("Error: invalid number of arguments\r\n");
        return FALSE;
    }

    if (strlen(argv[arg]) >= WLAN_NETWORK_NAME_MAX_LENGTH)
    {
        printf("Error: network name too long\r\n");
        return FALSE;
    }

    (void)memcpy(network_add_tlv->name, argv[arg],
                 (strlen(argv[arg]) > WLAN_NETWORK_NAME_MAX_LENGTH - 1) ? (WLAN_NETWORK_NAME_MAX_LENGTH - 1) :
                                                                          strlen(argv[arg]) + 1);

    arg++;
    info.address = ADDR_TYPE_DHCP;
    do
    {
        if (!info.ssid && string_equal("ssid", argv[arg]))
        {
            if (strlen(argv[arg + 1]) > 32)
            {
                printf("Error: SSID is too long\r\n");
                return FALSE;
            }
            ssid_tlv = (SSID_ParamSet_t *)ptlv_pos;
            (void)memcpy(ssid_tlv->ssid, argv[arg + 1], strlen(argv[arg + 1]) + 1);
            ssid_tlv->header.type = NCP_CMD_NETWORK_SSID_TLV;
            ssid_tlv->header.size = sizeof(ssid_tlv->ssid);
            ptlv_pos += sizeof(SSID_ParamSet_t);
            tlv_buf_len += sizeof(SSID_ParamSet_t);
            arg += 2;
            info.ssid = 1;
        }
        else if (!info.bssid && string_equal("bssid", argv[arg]))
        {
            bssid_tlv = (BSSID_ParamSet_t *)ptlv_pos;
            ret       = get_mac(argv[arg + 1], bssid_tlv->bssid, ':');
            if (ret != 0)
            {
                printf(
                    "Error: invalid BSSID argument"
                    "\r\n");
                return FALSE;
            }
            bssid_tlv->header.type = NCP_CMD_NETWORK_BSSID_TLV;
            bssid_tlv->header.size = sizeof(bssid_tlv->bssid);
            ptlv_pos += sizeof(BSSID_ParamSet_t);
            tlv_buf_len += sizeof(BSSID_ParamSet_t);
            arg += 2;
            info.bssid = 1;
        }
        else if (!info.channel && string_equal("channel", argv[arg]))
        {
            channel_tlv = (Channel_ParamSet_t *)ptlv_pos;
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid channel"
                    " argument\n");
                return FALSE;
            }
            channel_tlv->channel     = atoi(argv[arg + 1]);
            channel_tlv->header.type = NCP_CMD_NETWORK_CHANNEL_TLV;
            channel_tlv->header.size = sizeof(channel_tlv->channel);
            ptlv_pos += sizeof(Channel_ParamSet_t);
            tlv_buf_len += sizeof(Channel_ParamSet_t);
            arg += 2;
            info.channel = 1;
        }
        else if (!strncmp(argv[arg], "ip:", 3))
        {
            if (ip_tlv == NULL)
            {
                ip_tlv              = (IP_ParamSet_t *)ptlv_pos;
                ret                 = get_address(argv[arg], ip_tlv);
                ip_tlv->header.type = NCP_CMD_NETWORK_IP_TLV;
                ip_tlv->header.size = sizeof(IP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += sizeof(IP_ParamSet_t);
                tlv_buf_len += sizeof(IP_ParamSet_t);
            }
            else
            {
                ret = get_address(argv[arg], ip_tlv);
            }
            ip_tlv->is_autoip = 0;
            if (ret != 0)
            {
                printf(
                    "Error: invalid address"
                    " argument\n");
                return FALSE;
            }
            arg++;
            info.address = ADDR_TYPE_STATIC;
        }
        else if (!strncmp(argv[arg], "autoip", 6))
        {
            if (ip_tlv != NULL)
            {
                ip_tlv->is_autoip = 1;
            }
            else
            {
                ip_tlv              = (IP_ParamSet_t *)ptlv_pos;
                ip_tlv->is_autoip   = 1;
                ip_tlv->header.type = NCP_CMD_NETWORK_IP_TLV;
                ip_tlv->header.size = sizeof(IP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += sizeof(IP_ParamSet_t);
                tlv_buf_len += sizeof(IP_ParamSet_t);
            }
            arg++;
            info.address = ADDR_TYPE_LLA;
        }
        else if (!info.security && string_equal("wpa", argv[arg]))
        {
            security_wpa_tlv = (Security_ParamSet_t *)ptlv_pos;
            (void)memset(security_wpa_tlv, 0, sizeof(Security_ParamSet_t));
            ret              = get_security(argc - arg - 1, argv + arg + 1, WLAN_SECURITY_WPA, security_wpa_tlv);
            if (ret != 0)
            {
                printf(
                    "Error: invalid WPA security"
                    " argument\r\n");
                return FALSE;
            }
            security_wpa_tlv->header.type = NCP_CMD_NETWORK_SECURITY_TLV;
            security_wpa_tlv->header.size = sizeof(Security_ParamSet_t) - NCP_TLV_HEADER_LEN
                                            - sizeof(security_wpa_tlv->password) + security_wpa_tlv->password_len;
            ptlv_pos += NCP_TLV_HEADER_LEN + security_wpa_tlv->header.size;
            tlv_buf_len += NCP_TLV_HEADER_LEN + security_wpa_tlv->header.size;
            arg += 2;
            info.security++;
        }
        else if (!info.security2 && string_equal("wpa2", argv[arg]))
        {
            if (string_equal(argv[arg + 1], "psk") == 0)
            {
                printf("Error: invalid WPA2 security argument, lack of psk.\r\n");
                return -WM_FAIL;
            }
            security_wpa2_tlv = (Security_ParamSet_t *)ptlv_pos;
            (void)memset(security_wpa2_tlv, 0, sizeof(Security_ParamSet_t));
            security_wpa2_tlv->type = WLAN_SECURITY_WPA2;
            security_wpa2_tlv->password_len = strlen(argv[arg + 2]);
            /* copy the PSK phrase */            
            if (security_wpa2_tlv->password_len < WLAN_PSK_MIN_LENGTH || security_wpa2_tlv->password_len >= WLAN_PSK_MAX_LENGTH)
            {
                printf("Error: Invalid passphrase length %lu (expected ASCII characters: 8..63)\r\n", strlen(argv[arg + 2]));
                return -WM_FAIL;
            }
            else
            {
                strncpy(security_wpa2_tlv->password, argv[arg + 2], strlen(argv[arg + 2]));
            }
			
            security_wpa2_tlv->header.type = NCP_CMD_NETWORK_SECURITY_TLV;
            security_wpa2_tlv->header.size = sizeof(Security_ParamSet_t) - NCP_TLV_HEADER_LEN
                                             - sizeof(security_wpa2_tlv->password) + security_wpa2_tlv->password_len;
            ptlv_pos += NCP_TLV_HEADER_LEN + security_wpa2_tlv->header.size;
            tlv_buf_len += NCP_TLV_HEADER_LEN + security_wpa2_tlv->header.size;
            arg += 3;
            info.security2++;
        }
        else if (!info.security3 && string_equal("wpa3", argv[arg]))
        {
            if (string_equal(argv[arg + 1], "sae") != 0)
            {
                security_wpa3_tlv = (Security_ParamSet_t *)ptlv_pos;
                (void)memset(security_wpa3_tlv, 0, sizeof(Security_ParamSet_t));
                security_wpa3_tlv->type = WLAN_SECURITY_WPA3_SAE;
                /* copy the PSK phrase */
                security_wpa3_tlv->password_len = strlen(argv[arg + 2]);
                if (!security_wpa3_tlv->password_len)
                {
                    printf(
                        "Error: invalid WPA3 security"
                        " argument\r\n");
                    return FALSE;
                }
                if (security_wpa3_tlv->password_len < 255)
                    strcpy(security_wpa3_tlv->password, argv[arg + 2]);
                else
                {
                    printf(
                        "Error: invalid WPA3 security"
                        " argument\r\n");
                    return FALSE;
                }

                security_wpa3_tlv->header.type = NCP_CMD_NETWORK_SECURITY_TLV;
                security_wpa3_tlv->header.size = sizeof(security_wpa3_tlv->type) +
                                                 sizeof(security_wpa3_tlv->password_len) +
                                                 security_wpa3_tlv->password_len;
                security_wpa3_tlv->header.size = sizeof(Security_ParamSet_t) - NCP_TLV_HEADER_LEN
                                                 - sizeof(security_wpa3_tlv->password) + security_wpa3_tlv->password_len;
                ptlv_pos += NCP_TLV_HEADER_LEN + security_wpa3_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + security_wpa3_tlv->header.size;
                arg += 3;
            }
            else
            {
                printf(
                    "Error: invalid WPA3 security"
                    " argument\r\n");
                return FALSE;
            }
            info.security3++;
        }
#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
        else if ((info.wpa3_ent == 0U) && string_equal("wpa3-ent", argv[arg]))
        {
            arg += 1;
            info.wpa3_ent++;
        }
        else if ((info.wpa3_sb == 0U) && string_equal("wpa3-sb", argv[arg]))
        {
            arg += 1;
            info.wpa3_sb++;
        }
        else if ((info.wpa3_sb_192 == 0U) && string_equal("wpa3-sb-192", argv[arg]))
        {
            arg += 1;
            info.wpa3_sb_192++;
        }
#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
        else if ((info.security_eap == 0U) && (
#ifdef CONFIG_EAP_TLS
                                            string_equal("eap-tls", argv[arg]) ||
#endif
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_MSCHAPV2
                                            string_equal("eap-peap-mschapv2", argv[arg]) ||
#endif
#endif
                                            false))
        {
            security_eap_tlv = (Security_ParamSet_t *)ptlv_pos;
            (void)memset(security_eap_tlv, 0, sizeof(Security_ParamSet_t));
#ifdef CONFIG_EAP_TLS
            if (string_equal("eap-tls", argv[arg]))
            {
                security_eap_tlv->type = WLAN_SECURITY_EAP_TLS;
            }
#endif
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_MSCHAPV2
            if (string_equal("eap-peap-mschapv2", argv[arg]))
            {
                security_eap_tlv->type = WLAN_SECURITY_EAP_PEAP_MSCHAPV2;
            }
#endif
#endif
            if (info.wpa3_ent == 1U)
            {
                security_eap_tlv->wpa3_ent = 1;
            }
            if (info.wpa3_sb == 1U)
            {
                security_eap_tlv->wpa3_sb = 1;
            }
            if (info.wpa3_sb_192 == 1U)
            {
                security_eap_tlv->wpa3_sb_192 = 1;
            }
            security_eap_tlv->header.type = NCP_CMD_NETWORK_SECURITY_TLV;
            security_eap_tlv->header.size = sizeof(Security_ParamSet_t) - NCP_TLV_HEADER_LEN
                                            - sizeof(security_eap_tlv->password_len) - sizeof(security_eap_tlv->password);
            ptlv_pos += NCP_TLV_HEADER_LEN + security_eap_tlv->header.size;
            tlv_buf_len += NCP_TLV_HEADER_LEN + security_eap_tlv->header.size;
            arg += 1;
            info.security_eap++;
        }
#endif
#ifdef CONFIG_EAP_TLS
        else if ((info.tls_cipher == 0U) && (string_equal("tls_cipher", argv[arg]))
                 && info.security_eap && (security_eap_tlv->type == WLAN_SECURITY_EAP_TLS)
                 && (security_eap_tlv->wpa3_sb_192 == 1))
        {
            if (eap_tlv == NULL)
            {
                eap_tlv = (EAP_ParamSet_t *)ptlv_pos;
                (void)memset(eap_tlv, 0, sizeof(EAP_ParamSet_t));
                eap_tlv->eap_ver = 1;
                eap_tlv->header.type = NCP_CMD_NETWORK_EAP_TLV;
                eap_tlv->header.size = sizeof(EAP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
            }
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid tls_cipher"
                    " argument\r\n");
                return FALSE;
            }
            if (string_equal(argv[arg + 1], "ECC_P384") != false)
            {
                eap_tlv->tls_cipher = EAP_TLS_ECC_P384;
            }
            else if (string_equal(argv[arg + 2], "RSA_3K") != false)
            {
                eap_tlv->tls_cipher = EAP_TLS_RSA_3K;
            }
            arg += 2;
            info.tls_cipher++;
        }
#endif
#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
        else if ((info.aid == 0U) && (string_equal("aid", argv[arg])))
        {
            if (eap_tlv == NULL)
            {
                eap_tlv = (EAP_ParamSet_t *)ptlv_pos;
                (void)memset(eap_tlv, 0, sizeof(EAP_ParamSet_t));
				eap_tlv->eap_ver = 1;
                eap_tlv->header.type = NCP_CMD_NETWORK_EAP_TLV;
                eap_tlv->header.size = sizeof(EAP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
            }
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid aid"
                    " argument\r\n");
                return FALSE;
            }
            /* Set Client Anonymous Identity */
            strcpy(eap_tlv->anonymous_identity, argv[arg + 1]);
            arg += 2;
            info.aid++;
        }
        else if ((info.key_passwd == 0U) && (string_equal("key_passwd", argv[arg])))
        {
            if (eap_tlv == NULL)
            {
                eap_tlv = (EAP_ParamSet_t *)ptlv_pos;
                (void)memset(eap_tlv, 0, sizeof(EAP_ParamSet_t));
				eap_tlv->eap_ver = 1;
                eap_tlv->header.type = NCP_CMD_NETWORK_EAP_TLV;
                eap_tlv->header.size = sizeof(EAP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
            }
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid aid"
                    " argument\r\n");
                return FALSE;
            }
            /* Set Client/Server Key password */
            strcpy(eap_tlv->client_key_passwd, argv[arg + 1]);
            arg += 2;
            info.key_passwd++;
        }
#ifdef CONFIG_EAP_MSCHAPV2
        else if ((info.verify_peer_cert == 0U) && (string_equal("verify_peer_cert", argv[arg])))
        {
            uint8_t verify_peer_cert = 0;
            if (eap_tlv == NULL)
            {
                eap_tlv = (EAP_ParamSet_t *)ptlv_pos;
                (void)memset(eap_tlv, 0, sizeof(EAP_ParamSet_t));
                eap_tlv->eap_ver = 1;
                eap_tlv->header.type = NCP_CMD_NETWORK_EAP_TLV;
                eap_tlv->header.size = sizeof(EAP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
            }
            verify_peer_cert = atoi(argv[arg + 1]);
            if (arg + 1 >= argc || (verify_peer_cert != 0 && verify_peer_cert != 1))
            {
                printf(
                    "Error: invalid verify_peer_cert"
                    " argument\r\n");
                return FALSE;
            }
            eap_tlv->verify_peer_cert = !!verify_peer_cert;
            arg += 2;
            info.verify_peer_cert++;
        }
#endif
        else if ((info.eap_ver == 0U) && (string_equal("ver", argv[arg])))
        {
            if (eap_tlv == NULL)
            {
                eap_tlv = (EAP_ParamSet_t *)ptlv_pos;
                (void)memset(eap_tlv, 0, sizeof(EAP_ParamSet_t));
				eap_tlv->eap_ver = 1;
                eap_tlv->header.type = NCP_CMD_NETWORK_EAP_TLV;
                eap_tlv->header.size = sizeof(EAP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
            }
            eap_tlv->eap_ver = atoi(argv[arg + 1]);
            if (arg + 1 >= argc || (eap_tlv->eap_ver != 0 && eap_tlv->eap_ver != 1))
            {
                printf(
                    "Error: invalid ver"
                    " argument\r\n");
                return FALSE;
            }
            arg += 2;
            info.eap_ver++;
        }
        else if ((info.id == 0U) && (string_equal("id", argv[arg])))
        {
            if (eap_tlv == NULL)
            {
                eap_tlv = (EAP_ParamSet_t *)ptlv_pos;
                (void)memset(eap_tlv, 0, sizeof(EAP_ParamSet_t));
				eap_tlv->eap_ver = 1;
                eap_tlv->header.type = NCP_CMD_NETWORK_EAP_TLV;
                eap_tlv->header.size = sizeof(EAP_ParamSet_t) - NCP_TLV_HEADER_LEN;
                ptlv_pos += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
                tlv_buf_len += NCP_TLV_HEADER_LEN + eap_tlv->header.size;
            }
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid id"
                    " argument\r\n");
                return FALSE;
            }
            /* Set Client Identity */
            strcpy(eap_tlv->identity, argv[arg + 1]);
            arg += 2;
            info.id++;

            if ((info.pass == 0U) && (string_equal("pass", argv[arg])))
            {
                if (arg + 1 >= argc)
                {
                    printf(
                        "Error: invalid pass"
                        " argument\r\n");
                    return FALSE;
                }
                /* Set Client Password */
                strcpy(eap_tlv->eap_password, argv[arg + 1]);
                arg += 2;
                info.pass++;
            }
        }
#endif
#endif
#ifdef CONFIG_WPA2_ENTP
        else if (!info.security2 && string_equal("eap-tls", argv[arg]))
        {
            security_wpa2_tlv              = (Security_ParamSet_t *)ptlv_pos;
            security_wpa2_tlv->type        = WLAN_SECURITY_EAP_TLS;
            security_wpa2_tlv->header.type = NCP_CMD_NETWORK_SECURITY_TLV;
            security_wpa2_tlv->header.size = sizeof(security_wpa2_tlv->type) + sizeof(security_wpa2_tlv->password_len) +
                                             security_wpa2_tlv->password_len;
            ptlv_pos += NCP_TLV_HEADER_LEN + security_wpa2_tlv->header.size;
            tlv_buf_len += NCP_TLV_HEADER_LEN + security_wpa2_tlv->header.size;
            arg += 1;
            info.security2++;
        }
#endif
        else if (!info.role && string_equal("role", argv[arg]))
        {
            role_tlv = (BSSRole_ParamSet_t *)ptlv_pos;

            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid wireless"
                    " network role\r\n");
                return FALSE;
            }

            if (strcmp(argv[arg + 1], "sta") == 0)
                role_tlv->role = WLAN_BSS_ROLE_STA;
            else if (strcmp(argv[arg + 1], "uap") == 0)
                role_tlv->role = WLAN_BSS_ROLE_UAP;
            else
            {
                printf(
                    "Error: invalid wireless"
                    " network role\r\n");
                return FALSE;
            }

            role_tlv->header.type = NCP_CMD_NETWORK_ROLE_TLV;
            role_tlv->header.size = sizeof(role_tlv->role);
            ptlv_pos += sizeof(BSSRole_ParamSet_t);
            tlv_buf_len += sizeof(BSSRole_ParamSet_t);
            arg += 2;
            info.role++;
        }
        else if (!info.mfpc && string_equal("mfpc", argv[arg]))
        {
            if (pmf_tlv == NULL)
            {
                pmf_tlv              = (PMF_ParamSet_t *)ptlv_pos;
                pmf_tlv->header.type = NCP_CMD_NETWORK_PMF_TLV;
                pmf_tlv->header.size = sizeof(pmf_tlv->mfpc) + sizeof(pmf_tlv->mfpr);
                ptlv_pos += sizeof(PMF_ParamSet_t);
                tlv_buf_len += sizeof(PMF_ParamSet_t);
            }

            pmf_tlv->mfpc = atoi(argv[arg + 1]);
            if (arg + 1 >= argc || (pmf_tlv->mfpc != 0 && pmf_tlv->mfpc != 1))
            {
                printf(
                    "Error: invalid wireless"
                    " network mfpc\r\n");
                return FALSE;
            }
            arg += 2;
            info.mfpc++;
        }
        else if (!info.mfpr && string_equal("mfpr", argv[arg]))
        {
            if (pmf_tlv == NULL)
            {
                pmf_tlv              = (PMF_ParamSet_t *)ptlv_pos;
                pmf_tlv->header.type = NCP_CMD_NETWORK_PMF_TLV;
                pmf_tlv->header.size = sizeof(pmf_tlv->mfpc) + sizeof(pmf_tlv->mfpr);
                ptlv_pos += sizeof(PMF_ParamSet_t);
                tlv_buf_len += sizeof(PMF_ParamSet_t);
            }

            pmf_tlv->mfpr = atoi(argv[arg + 1]);
            if (arg + 1 >= argc || (pmf_tlv->mfpr != 0 && pmf_tlv->mfpr != 1))
            {
                printf(
                    "Error: invalid wireless"
                    " network mfpr\r\n");
                return FALSE;
            }
            arg += 2;
            info.mfpr++;
        }
        else if (!info.pwe && string_equal("pwe", argv[arg]))
        {
            pwe_tlv = (Pwe_Derivation_ParamSet_t *)ptlv_pos;
            if (arg + 1 >= argc)
            {
                (void)printf("Error: invalid pwe argument\n");
                return -WM_FAIL;
            }
            pwe_tlv->pwe_derivation     = atoi(argv[arg + 1]);
            if(pwe_tlv->pwe_derivation > 2U)
            {
                // [pwe <0/1/2>]
                (void)printf("Error: invalid pwe value %u\n", pwe_tlv->pwe_derivation);
                 return -WM_FAIL;
            }
            pwe_tlv->header.type = NCP_CMD_NETWORK_PWE_TLV;
            pwe_tlv->header.size = sizeof(pwe_tlv->pwe_derivation);
            ptlv_pos += sizeof(Pwe_Derivation_ParamSet_t);
            tlv_buf_len += sizeof(Pwe_Derivation_ParamSet_t);
            arg += 2;
            info.pwe = 1;
        }
        else if (!info.tr && string_equal("tr", argv[arg]))
        {
            tr_tlv = (Tr_Disable_ParamSet_t *)ptlv_pos;
            if (arg + 1 >= argc)
            {
                (void)printf("Error: invalid tr argument\n");
                return -WM_FAIL;
            }
            tr_tlv->transition_disable     = atoi(argv[arg + 1]);
            if(tr_tlv->transition_disable > 1U)
            {   
                 // [tr <0/1>]]
                (void)printf("Error: invalid tr value %u\n", tr_tlv->transition_disable);
                return -WM_FAIL;
            }
            tr_tlv->header.type = NCP_CMD_NETWORK_TR_TLV;
            tr_tlv->header.size = sizeof(tr_tlv->transition_disable);
            ptlv_pos += sizeof(Tr_Disable_ParamSet_t);
            tlv_buf_len += sizeof(Tr_Disable_ParamSet_t);
            arg += 2;
            info.tr = 1;
        }

#ifdef CONFIG_WIFI_DTIM_PERIOD
        else if (!info.dtim && string_equal("dtim", argv[arg]))
        {
            dtim_tlv = (DTIM_ParamSet_t *)ptlv_pos;
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid dtim"
                    " argument\n");
                return FALSE;
            }

            dtim_tlv->dtim_period = atoi(argv[arg + 1]);
            dtim_tlv->header.type = NCP_CMD_NETWORK_DTIM_TLV;
            dtim_tlv->header.size = sizeof(dtim_tlv->dtim_period);
            ptlv_pos += sizeof(DTIM_ParamSet_t);
            tlv_buf_len += sizeof(DTIM_ParamSet_t);
            arg += 2;
            info.dtim = 1;
        }
#endif
        else if (!info.acs_band && string_equal("acs_band", argv[arg]))
        {
            acs_band_tlv = (ACSBand_ParamSet_t *)ptlv_pos;
            if (arg + 1 >= argc)
            {
                printf("Error: invalid acs_band\r\n");
                return FALSE;
            }

            acs_band_tlv->acs_band = atoi(argv[arg + 1]);
            if (acs_band_tlv->acs_band != 0 && acs_band_tlv->acs_band != 1)
            {
                printf("Pls Set acs_band to 0 or 1.\r\n");
                printf(
                    "0: 2.4GHz channel   1: 5GHz channel\r\n"
                    "Not support to select dual band automatically.\r\n");
                return FALSE;
            }

            acs_band_tlv->header.type = NCP_CMD_NETWORK_ACSBAND_TLV;
            acs_band_tlv->header.size = sizeof(acs_band_tlv->acs_band);
            ptlv_pos += sizeof(ACSBand_ParamSet_t);
            tlv_buf_len += sizeof(ACSBand_ParamSet_t);
            arg += 2;
            info.acs_band = 1;
        }
#ifdef CONFIG_WIFI_CAPA
        else if (!info.wlan_capa && (role_tlv != NULL) && (role_tlv->role == WLAN_BSS_ROLE_UAP)
                 && string_equal("capa", argv[arg]))
        {
            capa_tlv = (CAPA_ParamSet_t *)ptlv_pos;
            if (arg + 1 >= argc)
            {
                printf(
                    "Error: invalid wireless"
                    " capability\r\n");
                return FALSE;
            }

            if (strcmp(argv[arg + 1], "11ax") == 0)
                capa_tlv->capa = WIFI_SUPPORT_11AX | WIFI_SUPPORT_11AC | WIFI_SUPPORT_11N | WIFI_SUPPORT_LEGACY;
            else if (strcmp(argv[arg + 1], "11ac") == 0)
                capa_tlv->capa = WIFI_SUPPORT_11AC | WIFI_SUPPORT_11N | WIFI_SUPPORT_LEGACY;
            else if (strcmp(argv[arg + 1], "11n") == 0)
                capa_tlv->capa = WIFI_SUPPORT_11N | WIFI_SUPPORT_LEGACY;
            else if (strcmp(argv[arg + 1], "legacy") == 0)
                capa_tlv->capa = WIFI_SUPPORT_LEGACY;
            else
            {
                printf(
                    "Error: invalid wireless"
                    " capability\r\n");
                return FALSE;
            }

            capa_tlv->header.type = NCP_CMD_NETWORK_CAPA_TLV;
            capa_tlv->header.size = sizeof(capa_tlv->capa);
            ptlv_pos += sizeof(CAPA_ParamSet_t);
            tlv_buf_len += sizeof(CAPA_ParamSet_t);
            arg += 2;
            info.wlan_capa++;
        }
#endif
        else
        {
            dump_wlan_add_usage();
            printf("Error: argument %d is invalid\r\n", arg);
            return FALSE;
        }
    } while (arg < argc);

    network_add_tlv->tlv_buf_len = tlv_buf_len;

    if (!info.ssid && !info.bssid)
    {
        dump_wlan_add_usage();
        printf("Error: specify at least the SSID or BSSID\r\n");
        return FALSE;
    }

    if ((info.security && info.security2 && info.security3) ||
        ((security_wpa_tlv != NULL) &&
         ((security_wpa_tlv->type == WLAN_SECURITY_WPA) && info.security && !info.security2)))
    {
        dump_wlan_add_usage();
        printf("Error: not support WPA or WPA/WPA2/WPA3 Mixed\r\n");
        return FALSE;
    }
	
    if (((info.security2 == 0 && info.security3 == 0) || (info.mfpc == 0 && info.mfpr == 0)) && (info.pwe != 0))
    {
        dump_wlan_add_usage();
        (void)printf("Error: pwe is only configurable for wpa2/wpa3 and pmf, pwe =%d\r\n", info.pwe);
        return -WM_FAIL;
    }
	
    if (info.security3 == 0 && info.tr != 0)
    {
        dump_wlan_add_usage();
        (void)printf("Error: tr is only configurable for wpa3, tr= %d\r\n", info.tr);
        return -WM_FAIL;
    }

#if defined(CONFIG_EAP_TLS) || defined(CONFIG_EAP_PEAP)
		if (((info.security == 1) || (info.security2 == 1) || (info.security3 == 1)) && (info.security_eap == 1))
		{
			dump_wlan_add_usage();
			(void)printf("Error: not support WPA/WPA2/WPA3 and WPA2/WPA3 enterprise mixed.\r\n");
			return -WM_FAIL;
		}
		if ((info.security_eap == 1) && (role_tlv != NULL) && (role_tlv->role == WLAN_BSS_ROLE_UAP))
		{
			dump_wlan_add_usage();
			(void)printf("Error: not support uap for WPA2/WPA3 enterprise eap-tls/eap-peap-mschapv2 security, only support station.\r\n");
			return -WM_FAIL;
		}
#endif
	
    network_add_command->header.cmd = NCP_CMD_WLAN_NETWORK_ADD;
    network_add_command->header.size =
        NCP_CMD_HEADER_LEN + sizeof(network_add_tlv->name) + sizeof(network_add_tlv->tlv_buf_len) + tlv_buf_len;
    network_add_command->header.result   = NCP_CMD_RESULT_OK;
    return TRUE;
}

/**
 * @brief  This function prepares wlan start network command
 *
 * @return Status returned
 */
int wlan_start_network_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *network_start_command = mpu_host_get_wifi_command_buffer();

    if (argc > 2)
    {
        printf("invalid argument\r\n");
        return FALSE;
    }

    network_start_command->header.cmd      = NCP_CMD_WLAN_NETWORK_START;
    network_start_command->header.size     = NCP_CMD_HEADER_LEN;
    network_start_command->header.result   = NCP_CMD_RESULT_OK;

    if (argc == 2)
    {
        if (strlen(argv[1]) >= WLAN_NETWORK_NAME_MAX_LENGTH)
        {
            printf("Error: network name too long\r\n");
            return FALSE;
        }

        NCP_CMD_NETWORK_START *network_start = (NCP_CMD_NETWORK_START *)&network_start_command->params.network_start;
        (void)memcpy(network_start->name, argv[1],
                     (strlen(argv[1]) > WLAN_NETWORK_NAME_MAX_LENGTH - 1) ? (WLAN_NETWORK_NAME_MAX_LENGTH - 1) :
                                                                            strlen(argv[1]));
        network_start_command->header.size += sizeof(network_start);
    }

    return TRUE;
}

/**
 * @brief  This function prepares wlan stop network command
 *
 * @return Status returned
 */
int wlan_stop_network_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *network_stop_command = mpu_host_get_wifi_command_buffer();
    network_stop_command->header.cmd        = NCP_CMD_WLAN_NETWORK_STOP;
    network_stop_command->header.size       = NCP_CMD_HEADER_LEN;
    network_stop_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief  This function prepares get wlan uap sta list command
 *
 * @return Status returned
 */
int wlan_get_uap_sta_list_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *conn_stat_command = mpu_host_get_wifi_command_buffer();
    conn_stat_command->header.cmd        = NCP_CMD_WLAN_NETWORK_GET_UAP_STA_LIST;
    conn_stat_command->header.size       = NCP_CMD_HEADER_LEN;
    conn_stat_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

static void dump_wlan_set_monitor_filter_usage()
{
    (void)printf("Error : invalid arguments\r\n");
    (void)printf("Usage : wlan-set-monitor-filter <opt> <macaddr>\r\n");
    (void)printf("opt   : add/delete/clear/dump \r\n");
    (void)printf("add   : All options need to be filled in \r\n");
    (void)printf("delete: Delete recent mac addr \r\n");
    (void)printf("clear : Clear all mac addr \r\n");
    (void)printf("dump  : Dump monitor cfg information \r\n");

    (void)printf("\r\nUsage example : \r\n");
    (void)printf("wlan-set-monitor-filter add 64:64:4A:D6:FA:7B \r\n");
    (void)printf("wlan-set-monitor-filter delete \r\n");
    (void)printf("wlan-set-monitor-filter clear  \r\n");
    (void)printf("wlan-set-monitor-filter dump   \r\n");
}

static void dump_monitor_param()
{
    int i = 0;

    (void)printf("\r\n");
    (void)printf("current parameters: \r\n");
    (void)printf("action            : %d \r\n", g_net_monitor_param.action);
    (void)printf("monitor_activity  : %d \r\n", g_net_monitor_param.monitor_activity);
    (void)printf("filter_flags      : %d \r\n", g_net_monitor_param.filter_flags);
    (void)printf("radio_type        : %d \r\n", g_net_monitor_param.radio_type);
    (void)printf("chan_number       : %d \r\n", g_net_monitor_param.chan_number);
    (void)printf("filter_num        : %d \r\n", g_net_monitor_param.filter_num);
    (void)printf("\r\n");

    for (i = 0; i < g_net_monitor_param.filter_num; i++)
    {
        (void)printf("mac_addr      : %02X:%02X:%02X:%02X:%02X:%02X \r\n", g_net_monitor_param.mac_addr[i][0],
                     g_net_monitor_param.mac_addr[i][1], g_net_monitor_param.mac_addr[i][2],
                     g_net_monitor_param.mac_addr[i][3], g_net_monitor_param.mac_addr[i][4],
                     g_net_monitor_param.mac_addr[i][5]);
    }
}

int set_monitor_filter(int op_index, uint8_t *mac)
{
    uint8_t temp_filter_num = g_net_monitor_param.filter_num;

    switch (op_index)
    {
        case MONITOR_FILTER_OPT_ADD_MAC:
            if (temp_filter_num < MAX_MONIT_MAC_FILTER_NUM)
            {
                (void)memcpy(&g_net_monitor_param.mac_addr[temp_filter_num], mac, NCP_WLAN_MAC_ADDR_LENGTH);
                g_net_monitor_param.filter_num++;
            }
            else
            {
                (void)printf("Max filter num is 3 \r\n");
                return FALSE;
            }
            break;

        case MONITOR_FILTER_OPT_DELETE_MAC:
            if (temp_filter_num > 0)
            {
                memset(&g_net_monitor_param.mac_addr[temp_filter_num], 0, NCP_WLAN_MAC_ADDR_LENGTH);
                g_net_monitor_param.filter_num--;
            }
            else
            {
                (void)printf("Monitor filter num is 0 \r\n");
                return FALSE;
            }
            break;

        case MONITOR_FILTER_OPT_CLEAR_MAC:
            memset(&g_net_monitor_param.mac_addr[0], 0, MAX_MONIT_MAC_FILTER_NUM * NCP_WLAN_MAC_ADDR_LENGTH);
            g_net_monitor_param.filter_num = 0;
            break;

        case MONITOR_FILTER_OPT_DUMP:
            dump_monitor_param();
            break;

        default:
            (void)printf("unknown argument!\r\n");
            return FALSE;
            break;
    }

    return TRUE;
}

/**
 * @brief  This function prepares net monitor filter
 *
 * @return Status returned
 */
int wlan_set_monitor_filter_command(int argc, char **argv)
{
    int ret = 0;
    uint8_t raw_mac[NCP_WLAN_MAC_ADDR_LENGTH];
    int op_index = 0;

    if (3 == argc)
    {
        if (string_equal("add", argv[1]))
        {
            ret = get_mac(argv[2], (char *)raw_mac, ':');
            if (ret != 0)
            {
                (void)printf("Error: invalid MAC argument\r\n");
                return FALSE;
            }
            if ((memcmp(&raw_mac[0], broadcast_mac, NCP_WLAN_MAC_ADDR_LENGTH) == 0) || (raw_mac[0] & 0x01))
            {
                (void)printf("Error: only support unicast mac\r\n");
                return FALSE;
            }
            op_index = MONITOR_FILTER_OPT_ADD_MAC;
        }
        else
        {
            dump_wlan_set_monitor_filter_usage();
            return FALSE;
        }
    }
    else if (2 == argc)
    {
        if (string_equal("delete", argv[1]))
            op_index = MONITOR_FILTER_OPT_DELETE_MAC;
        else if (string_equal("clear", argv[1]))
            op_index = MONITOR_FILTER_OPT_CLEAR_MAC;
        else if (string_equal("dump", argv[1]))
            op_index = MONITOR_FILTER_OPT_DUMP;
        else
        {
            (void)printf("Unknown argument!\r\n\r\n");
            dump_wlan_set_monitor_filter_usage();
            return FALSE;
        }
    }
    else
    {
        dump_wlan_set_monitor_filter_usage();
        return FALSE;
    }

    ret = set_monitor_filter(op_index, raw_mac);

    return ret;
}

/**
 * @brief  This function set net monitor cfg parameters
 *
 * @return Status returned
 */
int wlan_set_monitor_param_command(int argc, char **argv)
{
    if (argc != 6)
    {
        (void)printf("Error             : invalid number of arguments\r\n");
        (void)printf("Usage             : %s <action> <monitor_activity> <filter_flags> <radio_type> <chan_number>\r\n",
                     argv[0]);
        (void)printf("action            : 0/1 to Action Get/Set \r\n");
        (void)printf("monitor_activity  : 1 to enable and other parameters to disable monitor activity \r\n");
        (void)printf("filter_flags      : network monitor fitler flag \r\n");
        (void)printf("chan_number       : channel to monitor \r\n");

        (void)printf("\r\nUsage example ：\r\n");
        (void)printf("wlan-set-monitor-param 1 1 7 0 1 \r\n");

        dump_monitor_param();
        return FALSE;
    }

    g_net_monitor_param.action           = (uint16_t)atoi(argv[1]);
    g_net_monitor_param.monitor_activity = (uint16_t)atoi(argv[2]);

    /*
     * filter_flags:
     * bit 0: (1/0) enable/disable management frame
     * bit 1: (1/0) enable/disable control frame
     * bit 2: (1/0) enable/disable data frame
     */
    g_net_monitor_param.filter_flags = (uint16_t)atoi(argv[3]);

    /*
     * radio_type:
     * Band Info - (00)=2.4GHz, (01)=5GHz
     * uint8_t  chanBand    : 2;
     * Channel Width - (00)=20MHz, (10)=40MHz, (11)=80MHz
     * uint8_t  chanWidth   : 2;
     * Secondary Channel Offset - (00)=None, (01)=Above, (11)=Below
     * uint8_t  chan2Offset : 2;
     * Channel Selection Mode - (00)=manual, (01)=ACS, (02)=Adoption mode
     * uint8_t  scanMode    : 2;
     */
    g_net_monitor_param.radio_type  = (uint8_t)atoi(argv[4]);
    g_net_monitor_param.chan_number = (uint8_t)atoi(argv[5]);

    dump_monitor_param();

    return TRUE;
}

/**
 * @brief  This function prepares net monitor cfg parameters
 *
 * @return Status returned
 */
int wlan_net_monitor_cfg_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *monitor_command = mpu_host_get_wifi_command_buffer();
    monitor_command->header.cmd        = NCP_CMD_WLAN_NETWORK_MONITOR;
    monitor_command->header.size       = NCP_CMD_HEADER_LEN;
    monitor_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_NET_MONITOR *monitor_cfg = (NCP_CMD_NET_MONITOR *)&monitor_command->params.monitor_cfg;
    memcpy(&monitor_cfg->monitor_para, &g_net_monitor_param, sizeof(g_net_monitor_param));
    monitor_command->header.size += sizeof(NCP_CMD_NET_MONITOR);

    return TRUE;
}

int wlan_deep_sleep_ps_command(int argc, char **argv)
{
    int deep_sleep_enable;

    if (argc != 2)
    {
        printf("Usage: %s <0/1> < 0--disable deep sleep; 1---enable deep sleep>\r\n", argv[0]);
        return FALSE;
    }

    deep_sleep_enable = atoi(argv[1]);

    NCPCmd_DS_COMMAND *wlan_deep_sleep_ps_command = mpu_host_get_wifi_command_buffer();
    wlan_deep_sleep_ps_command->header.cmd        = NCP_CMD_WLAN_POWERMGMT_DEEP_SLEEP_PS;
    wlan_deep_sleep_ps_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_deep_sleep_ps_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_DEEP_SLEEP_PS *wlan_deep_sleep_ps =
        (NCP_CMD_DEEP_SLEEP_PS *)&wlan_deep_sleep_ps_command->params.wlan_deep_sleep_ps;
    wlan_deep_sleep_ps->enable = deep_sleep_enable;
    wlan_deep_sleep_ps_command->header.size += sizeof(NCP_CMD_DEEP_SLEEP_PS);

    return TRUE;
}

int wlan_ieee_ps_command(int argc, char **argv)
{
    int ieee_enable;

    if (argc != 2)
    {
        printf("Usage: %s <0/1> < 0--disable ieee ps; 1---enable ieee ps>\r\n", argv[0]);
        return FALSE;
    }

    ieee_enable = atoi(argv[1]);

    NCPCmd_DS_COMMAND *wlan_ieee_ps_command = mpu_host_get_wifi_command_buffer();
    wlan_ieee_ps_command->header.cmd        = NCP_CMD_WLAN_POWERMGMT_IEEE_PS;
    wlan_ieee_ps_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_ieee_ps_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_IEEE_PS *wlan_ieee_ps = (NCP_CMD_IEEE_PS *)&wlan_ieee_ps_command->params.wlan_ieee_ps;
    wlan_ieee_ps->enable          = ieee_enable;
    wlan_ieee_ps_command->header.size += sizeof(NCP_CMD_IEEE_PS);

    return TRUE;
}

int wlan_process_ncp_event(uint8_t *res)
{
    int ret                  = FALSE;
    NCPCmd_DS_COMMAND *event = (NCPCmd_DS_COMMAND *)res;

    switch (event->header.cmd)
    {
        case NCP_EVENT_MDNS_QUERY_RESULT:
            ret = wlan_process_mdns_query_result_event(res);
            break;
        case NCP_EVENT_MDNS_RESOLVE_DOMAIN:
            ret = wlan_process_mdns_resolve_domain_event(res);
            break;
        case NCP_EVENT_CSI_DATA:
            ret = wlan_process_csi_data_event(res);
            break;
        case NCP_EVENT_WLAN_STA_CONNECT:
            ret = wlan_process_con_event(res);
            break;
        case NCP_EVENT_WLAN_STA_DISCONNECT:
            ret = wlan_process_discon_event(res);
            break;
        case NCP_EVENT_WLAN_STOP_NETWORK:
            ret = wlan_process_stop_network_event(res);
            break;
        case NCP_EVENT_WLAN_NCP_INET_RECV:
            ret = inet_sock_recv_event(res);
            break;
        case NCP_EVENT_WLAN_NCP_INET_SEND_FAIL:
            ret = inet_sock_send_fail_event(res);
            break;
        case NCP_EVENT_INET_DAD_DONE:
            ret = wlan_process_ipv6_dad_done_event(res);
            break;
        default:
            printf("Invaild event cmd!\r\n");
            break;
    }
    return ret;
}

iperf_msg_t iperf_msg;
#if CONFIG_USE_NEW_SOCKET
int wlan_ncp_iperf_command(int argc, char **argv)
{
    unsigned int handle      = 0;
    unsigned int type        = -1;
    unsigned int direction   = -1;

    unsigned int udp_rx_pkt_count   = 0;
    unsigned int udp_rx_rate   = 0;
    unsigned int time_per_pkt = 0;
    enum ncp_iperf_item item = FALSE_ITEM;
    memset((char *)&iperf_msg, 0, sizeof(iperf_msg));
    if (argc < 4)
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }
	iperf_msg.handle = 0;
    memcpy(iperf_msg.ip_addr, argv[1], strlen(argv[1]) + 1);
    if (!strncmp(argv[2], "tcp", 3))
    {
        type = 0;
        if (argc == 5)
        {
            if (get_uint(argv[4], (unsigned int *)&iperf_msg.iperf_set.iperf_count, strlen(argv[4])))
            {
                (void)printf("tcp packet number format is error\r\n");
                return -WM_FAIL;
            }
        }
        else
            iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
    }
    else if (!strncmp(argv[2], "udp", 3))
    {
        type = 1;
        if (argc < 3)
        {
            (void)printf("udp want ip and port, Usage: %s handle udp [tx|rx] ip port\r\n", __func__);
            return -WM_FAIL;
        }
        iperf_msg.port = NCP_IPERF_UDP_SERVER_PORT_DEFAULT;
        if (argc >= 5)
        {
            if (get_uint(argv[4], (unsigned int *)&iperf_msg.iperf_set.iperf_count, strlen(argv[4])))
            {
                printf("tcp packet number format is error\r\n");
                return -WM_FAIL;
            }
			udp_rx_pkt_count = iperf_msg.iperf_set.iperf_count;
        }
        else
            iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;

        if (argc >= 6)
        {
            if (get_uint(argv[5], &iperf_msg.iperf_set.iperf_udp_rate, strlen(argv[5])))
            {
                printf("udp rate format is error\r\n");
                return -WM_FAIL;
            }
			udp_rx_rate = iperf_msg.iperf_set.iperf_udp_rate;
        }
        else
            iperf_msg.iperf_set.iperf_udp_rate = NCP_IPERF_UDP_RATE;

        if (argc >= 7)
        {
            if (get_uint(argv[6], &iperf_msg.iperf_set.iperf_udp_time, strlen(argv[6])))
            {
                printf("udp time format is error\r\n");
                return -WM_FAIL;
            }
        }
        else
            iperf_msg.iperf_set.iperf_udp_time = NCP_IPERF_UDP_TIME;
    }
    else
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }

    if (!strncmp(argv[3], "tx", 3))
        direction = 0;
    else if (!strncmp(argv[3], "rx", 3))
        direction = 1;
    else
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }

    if (!type && direction == 0)
        item = NCP_IPERF_TCP_TX;
    else if (!type && direction == 1)
        item = NCP_IPERF_TCP_RX;
    else if (type == 1 && direction == 0)
        item = NCP_IPERF_UDP_TX;
    else if (type == 1 && direction == 1)
        item = NCP_IPERF_UDP_RX;
    switch (item)
    {
        case NCP_IPERF_TCP_TX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_TCP_TX;
            iperf_msg.per_size              = NCP_IPERF_PER_TCP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_tx_sem);
            break;
        case NCP_IPERF_TCP_RX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_TCP_RX;
            iperf_msg.per_size              = NCP_IPERF_PER_TCP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_rx_sem);
            break;
        case NCP_IPERF_UDP_TX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_UDP_TX;
            iperf_msg.per_size              = NCP_IPERF_PER_UDP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_tx_sem);
            break;
        case NCP_IPERF_UDP_RX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_UDP_RX;
            iperf_msg.per_size              = NCP_IPERF_PER_UDP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_rx_sem);
            break;
        default:
            return -WM_FAIL;
    }
    g_udp_recv_timeout = IPERF_UDP_RECV_TIMEOUT;

    if (item == NCP_IPERF_UDP_RX && udp_rx_pkt_count !=0 && udp_rx_rate)
    {
        /* calculate time for each receive packet, unit: milliseconds. */
        time_per_pkt = (1472 * 8 * udp_rx_pkt_count) / (udp_rx_rate * 1000) * 1000 / udp_rx_pkt_count;
        g_udp_recv_timeout = IPERF_UDP_RECV_TIMEOUT + time_per_pkt;
    }

    return WM_SUCCESS;
}

#else
int wlan_ncp_iperf_command(int argc, char **argv)
{
    unsigned int handle      = 0;
    unsigned int type        = -1;
    unsigned int direction   = -1;

    unsigned int udp_rx_pkt_count   = 0;
    unsigned int udp_rx_rate   = 0;
    unsigned int time_per_pkt = 0;
    enum ncp_iperf_item item = FALSE_ITEM;
    memset((char *)&iperf_msg, 0, sizeof(iperf_msg));
    if (argc < 4)
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }
    memcpy(iperf_msg.ip_addr, argv[4], strlen(argv[1]) + 1);
    if (get_uint(argv[1], &handle, strlen(argv[1])))
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }
    iperf_msg.handle = handle;
    if (!strncmp(argv[2], "tcp", 3))
    {
        type = 0;
        if (argc == 5)
        {
            if (get_uint(argv[4], (unsigned int *)&iperf_msg.iperf_set.iperf_count, strlen(argv[4])))
            {
                (void)printf("tcp packet number format is error\r\n");
                return -WM_FAIL;
            }
        }
        else
            iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
    }
    else if (!strncmp(argv[2], "udp", 3))
    {
        type = 1;
        if (argc < 5)
        {
            (void)printf("udp want ip and port, Usage: %s handle udp [tx|rx] ip port\r\n", __func__);
            return -WM_FAIL;
        }
        memcpy(iperf_msg.ip_addr, argv[4], strlen(argv[4]) + 1);

        if (argc >= 6)
        {
            if (get_uint(argv[5], &iperf_msg.port, strlen(argv[5])))
            {
                printf("udp port format is error\r\n");
                return -WM_FAIL;
            }
        }
        else
            iperf_msg.port = NCP_IPERF_UDP_SERVER_PORT_DEFAULT;

        if (argc >= 7)
        {
            if (get_uint(argv[6], (unsigned int *)&iperf_msg.iperf_set.iperf_count, strlen(argv[6])))
            {
                printf("tcp packet number format is error\r\n");
                return -WM_FAIL;
            }
			udp_rx_pkt_count = iperf_msg.iperf_set.iperf_count;
        }
        else
            iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;

        if (argc >= 8)
        {
            if (get_uint(argv[7], &iperf_msg.iperf_set.iperf_udp_rate, strlen(argv[7])))
            {
                printf("udp rate format is error\r\n");
                return -WM_FAIL;
            }
			udp_rx_rate = iperf_msg.iperf_set.iperf_udp_rate;
        }
        else
            iperf_msg.iperf_set.iperf_udp_rate = NCP_IPERF_UDP_RATE;

        if (argc >= 9)
        {
            if (get_uint(argv[8], &iperf_msg.iperf_set.iperf_udp_time, strlen(argv[8])))
            {
                printf("udp time format is error\r\n");
                return -WM_FAIL;
            }
        }
        else
            iperf_msg.iperf_set.iperf_udp_time = NCP_IPERF_UDP_TIME;
    }
    else
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }

    if (!strncmp(argv[3], "tx", 3))
        direction = 0;
    else if (!strncmp(argv[3], "rx", 3))
        direction = 1;
    else
    {
        (void)printf("Usage: %s handle [tcp|udp] [tx|rx]\r\n", __func__);
        return -WM_FAIL;
    }

    if (!type && direction == 0)
        item = NCP_IPERF_TCP_TX;
    else if (!type && direction == 1)
        item = NCP_IPERF_TCP_RX;
    else if (type == 1 && direction == 0)
        item = NCP_IPERF_UDP_TX;
    else if (type == 1 && direction == 1)
        item = NCP_IPERF_UDP_RX;
    switch (item)
    {
        case NCP_IPERF_TCP_TX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_TCP_TX;
            iperf_msg.per_size              = NCP_IPERF_PER_TCP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_tx_sem);
            break;
        case NCP_IPERF_TCP_RX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_TCP_RX;
            iperf_msg.per_size              = NCP_IPERF_PER_TCP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_rx_sem);
            break;
        case NCP_IPERF_UDP_TX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_UDP_TX;
            iperf_msg.per_size              = NCP_IPERF_PER_UDP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_tx_sem);
            break;
        case NCP_IPERF_UDP_RX:
            iperf_msg.iperf_set.iperf_type  = NCP_IPERF_UDP_RX;
            iperf_msg.per_size              = NCP_IPERF_PER_UDP_PKG_SIZE;
            if (iperf_msg.iperf_set.iperf_count == 0)
                iperf_msg.iperf_set.iperf_count = NCP_IPERF_PKG_COUNT;
            sem_post(&iperf_rx_sem);
            break;
        default:
            return -WM_FAIL;
    }
	g_udp_recv_timeout = IPERF_UDP_RECV_TIMEOUT;
	
	if (item == NCP_IPERF_UDP_RX && udp_rx_pkt_count !=0 && udp_rx_rate)
	{   
        /* calculate time for each receive packet, unit: milliseconds. */	   
        time_per_pkt = (1472 * 8 * udp_rx_pkt_count) / (udp_rx_rate * 1000) * 1000 / udp_rx_pkt_count; 
        g_udp_recv_timeout = IPERF_UDP_RECV_TIMEOUT + time_per_pkt;
	}
		
    return WM_SUCCESS;
}
#endif

/**
 * @brief       This function processes response from ncp device
 *
 * @param res   A pointer to uint8_t
 * @return      Status returned
 */
int wlan_process_response(uint8_t *res)
{
    int ret                    = FALSE;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    switch (cmd_res->header.cmd)
    {
        case NCP_RSP_WLAN_STA_SCAN:
#if !defined CONFIG_MATTER_NCP
            ret = wlan_process_scan_response(res);
#endif
            break;
        case NCP_RSP_WLAN_STA_CONNECT:
            ret = wlan_process_con_response(res);
            break;
        case NCP_RSP_WLAN_STA_DISCONNECT:
            ret = wlan_process_discon_response(res);
            break;
        case NCP_RSP_WLAN_STA_VERSION:
            ret = wlan_process_version_response(res);
            break;
        case NCP_RSP_WLAN_STA_SET_MAC:
            ret = wlan_process_set_mac_address(res);
            break;
        case NCP_RSP_WLAN_STA_GET_MAC:
            ret = wlan_process_get_mac_address(res);
            break;
        case NCP_RSP_WLAN_STA_CONNECT_STAT:
#if !defined CONFIG_MATTER_NCP
            ret = wlan_process_stat(res);
#endif
            break;
        case NCP_RSP_WLAN_STA_ROAMING:
            ret = wlan_process_roaming(res);
            break;
        case NCP_RSP_WLAN_STA_SET_OKC:
            ret = wlan_process_okc_response(res);
            break;
        case NCP_RSP_WLAN_BASIC_WLAN_RESET:
            ret = wlan_process_wlan_reset_result_response(res);
            break;
        case NCP_RSP_WLAN_BASIC_WLAN_UAP_PROV_START:
            ret = wlan_process_wlan_uap_prov_start_result_response(res);
            break;
        case NCP_RSP_WLAN_BASIC_WLAN_UAP_PROV_RESET:
            ret = wlan_process_wlan_uap_prov_reset_result_response(res);
            break;
        case NCP_RSP_WLAN_BASIC_WLAN_UAP_PROV_SET_UAPCFG:
            ret = wlan_process_wlan_uap_prov_set_uapcfg_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_INFO:
            ret = wlan_process_info(res);
            break;
        case NCP_RSP_WLAN_NETWORK_ADDRESS:
            ret = wlan_process_address(res);
            break;
        case NCP_RSP_WLAN_HTTP_CON:
            ret = wlan_process_wlan_http_con_response(res);
            break;
        case NCP_RSP_WLAN_HTTP_DISCON:
            ret = wlan_process_wlan_http_discon_response(res);
            break;
        case NCP_RSP_WLAN_HTTP_REQ:
            ret = wlan_process_wlan_http_req_response(res);
            break;
        case NCP_RSP_WLAN_HTTP_RECV:
            ret = wlan_process_wlan_http_recv_response(res);
            break;
        case NCP_RSP_WLAN_HTTP_SETH:
            ret = wlan_process_wlan_http_seth_response(res);
            break;
        case NCP_RSP_WLAN_HTTP_UNSETH:
            ret = wlan_process_wlan_http_unseth_response(res);
            break;
        case NCP_RSP_WLAN_WEBSOCKET_UPG:
            ret = wlan_process_wlan_websocket_upg_response(res);
            break;
        case NCP_RSP_WLAN_WEBSOCKET_SEND:
            ret = wlan_process_wlan_websocket_send_response(res);
            break;
        case NCP_RSP_WLAN_WEBSOCKET_RECV:
            ret = wlan_process_wlan_websocket_recv_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_OPEN:
            ret = wlan_process_wlan_socket_open_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_CON:
            ret = wlan_process_wlan_socket_con_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_BIND:
            ret = wlan_process_wlan_socket_bind_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_CLOSE:
            ret = wlan_process_wlan_socket_close_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_LISTEN:
            ret = wlan_process_wlan_socket_listen_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_ACCEPT:
            ret = wlan_process_wlan_socket_accept_response(res);
            break;
        case NCP_RSP_WLAN_SOCKET_SEND:
            ret                 = wlan_process_wlan_socket_send_response(res);
            iperf_msg.status[0] = ret;
            break;
        case NCP_RSP_WLAN_SOCKET_SENDTO:
            ret                 = wlan_process_wlan_socket_sendto_response(res);
            iperf_msg.status[0] = ret;
            break;
        case NCP_RSP_WLAN_SOCKET_RECV:
            ret                 = wlan_process_wlan_socket_receive_response(res);
            iperf_msg.status[1] = ret;
            break;
        case NCP_RSP_WLAN_SOCKET_RECVFROM:
            ret                 = wlan_process_wlan_socket_recvfrom_response(res);
            iperf_msg.status[1] = ret;
            break;
        case NCP_RSP_WLAN_NETWORK_MONITOR:
            ret = wlan_process_monitor_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_ADD:
            ret = wlan_process_add_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_START:
            ret = wlan_process_start_network_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_STOP:
            ret = wlan_process_stop_network_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_GET_UAP_STA_LIST:
            ret = wlan_process_get_uap_sta_list(res);
            break;
        case NCP_RSP_WLAN_STA_CSI:
            ret = wlan_process_csi_response(res);
            break;
        case NCP_RSP_WLAN_STA_11K_CFG:
            ret = wlan_process_11k_cfg_response(res);
            break;
        case NCP_RSP_WLAN_STA_NEIGHBOR_REQ:
            ret = wlan_process_neighbor_req_response(res);
            break;
        case NCP_RSP_WLAN_STA_SIGNAL:
            ret = wlan_process_rssi_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_MEF:
            ret = wlan_process_multi_mef_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_UAPSD:
            ret = wlan_process_wmm_uapsd_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_QOSINFO:
            ret = wlan_process_uapsd_qosinfo_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_SLEEP_PERIOD:
            ret = wlan_process_uapsd_sleep_period_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_WOWLAN_CFG:
            ret = wlan_process_wakeup_condition_response(res);
            break;
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
        case NCP_RSP_WLAN_POWERMGMT_SUSPEND:
            ret = wlan_process_suspend_response(res);
            break;
#endif
        case NCP_RSP_11AX_CFG:
            ret = wlan_process_11axcfg_response(res);
            break;
        case NCP_RSP_BTWT_CFG:
            ret = wlan_process_btwt_response(res);
            break;
        case NCP_RSP_TWT_SETUP:
            ret = wlan_process_twt_setup_response(res);
            break;
        case NCP_RSP_TWT_TEARDOWN:
            ret = wlan_process_twt_teardown_response(res);
            break;
        case NCP_RSP_TWT_GET_REPORT:
            ret = wlan_process_twt_report_response(res);
            break;
        case NCP_RSP_11D_ENABLE:
            ret = wlan_process_11d_enable_response(res);
            break;
        case NCP_RSP_REGION_CODE:
            ret = wlan_process_region_code_response(res);
            break;
        case NCP_CMD_WLAN_UAP_MAX_CLIENT_CNT:
            ret = wlan_process_client_count_response(res);
            break;
        case NCP_RSP_WLAN_STA_ANTENNA:
            ret = wlan_process_antenna_cfg_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_DEEP_SLEEP_PS:
            ret = wlan_process_deep_sleep_ps_response(res);
            break;
        case NCP_RSP_WLAN_POWERMGMT_IEEE_PS:
            ret = wlan_process_ieee_ps_response(res);
            break;
        case NCP_RSP_WLAN_DEBUG_REGISTER_ACCESS:
            ret = wlan_process_register_access_response(res);
            break;
#ifdef CONFIG_MEM_MONITOR_DEBUG
        case NCP_RSP_WLAN_MEMORY_HEAP_SIZE:
            ret = wlan_process_memory_state_response(res);
            break;
#endif
        case NCP_RSP_WLAN_REGULATORY_ED_MAC_MODE:
            ret = wlan_process_ed_mac_response(res);
            break;
#ifdef CONFIG_NCP_RF_TEST_MODE
        case NCP_RSP_WLAN_REGULATORY_SET_RF_TEST_MODE:
            ret = wlan_process_set_rf_test_mode_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_TX_ANTENNA:
            ret = wlan_process_set_rf_tx_antenna_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_RF_TX_ANTENNA:
            ret = wlan_process_get_rf_tx_antenna_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_RX_ANTENNA:
            ret = wlan_process_set_rf_rx_antenna_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_RF_RX_ANTENNA:
            ret = wlan_process_get_rf_rx_antenna_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_BAND:
            ret = wlan_process_set_rf_band_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_RF_BAND:
            ret = wlan_process_get_rf_band_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_BANDWIDTH:
            ret = wlan_process_set_rf_bandwidth_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_RF_BANDWIDTH:
            ret = wlan_process_get_rf_bandwidth_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_CHANNEL:
            ret = wlan_process_set_rf_channel_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_RF_CHANNEL:
            ret = wlan_process_get_rf_channel_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_RADIO_MODE:
            ret = wlan_process_set_rf_radio_mode_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_RF_RADIO_MODE:
            ret = wlan_process_get_rf_radio_mode_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_TX_POWER:
            ret = wlan_process_set_rf_tx_power_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_TX_CONT_MODE:
            ret = wlan_process_set_rf_tx_cont_mode_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_SET_RF_TX_FRAME:
            ret = wlan_process_set_rf_tx_frame_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_GET_AND_RESET_RF_PER:
            ret = wlan_process_set_rf_get_and_reset_rf_per_response(res);
            break;
#endif
        case NCP_RSP_WLAN_REGULATORY_EU_CRYPTO_CCMP_128:
            ret = wlan_process_eu_crypto_ccmp128_response(res);
            break;
        case NCP_RSP_WLAN_REGULATORY_EU_CRYPTO_GCMP_128:
            ret = wlan_process_eu_crypto_gcmp128_response(res);
            break;
        case NCP_RSP_DATE_TIME:
            ret = wlan_process_time_response(res);
            break;
        case NCP_RSP_GET_TEMPERATUE:
            ret = wlan_process_get_temperature_response(res);
            break;
        case NCP_RSP_WLAN_STA_WPS_PBC:
            ret = wlan_process_wps_pbc_response(res);
            break;
        case NCP_RSP_WLAN_STA_GEN_WPS_PIN:
            ret = wlan_process_wps_generate_pin_response(res);
            break;
        case NCP_RSP_WLAN_STA_WPS_PIN:
            ret = wlan_process_wps_pin_response(res);
            break;
        case NCP_RSP_INVALID_CMD:
            ret = WM_SUCCESS;
            break;
        case NCP_RSP_WLAN_NETWORK_MDNS_QUERY:
            ret = wlan_process_mdns_query_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_LIST:
            ret = wlan_process_network_list_response(res);
            break;
        case NCP_RSP_WLAN_NETWORK_REMOVE:
            ret = wlan_process_network_remove_response(res);
            break;
        default:
            break;
    }

    ncp_cmd_node_wakeup_pending_tasks((uint8_t *)cmd_res);

    return ret;
}

/**
 * @brief      This function processes monitor response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_monitor_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("Monitor cfg is success!\r\n");
        return TRUE;
    }
    else
        printf("Monitor cfg is fail!\r\n");
    return TRUE;
}

/**
 * @brief       This function processes connect response from ncp device
 *
 * @param res   A pointer to uint8_t
 * @return      Status returned
 */
int wlan_process_con_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    struct in_addr ip;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("Failed to get correct AP info!\r\n");
        printf(
            "Please input 'wlan-connect' to connect an AP or wait a few "
            "moments for the AP information.\r\n");
        return FALSE;
    }

    NCP_CMD_WLAN_CONN *connect_res_tlv = (NCP_CMD_WLAN_CONN *)&cmd_res->params.wlan_connect;
    ip.s_addr                          = connect_res_tlv->ip;
    printf("STA connected:\r\n");
    printf("SSID = [%s]\r\n", connect_res_tlv->ssid);
    printf("IPv4 Address: [%s]\r\n", inet_ntoa(ip));

    return TRUE;
}

/**
 * @brief      This function processes disconnect response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_discon_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        printf("STA disconnect.\r\n");
    else
        printf("Failed to disconnect to network.\r\n");

    return TRUE;
}

/**
 * @brief      This function processes fw version response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_version_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        NCP_CMD_FW_VERSION *fw_ver = (NCP_CMD_FW_VERSION *)&cmd_res->params.firmware_version;
        printf("WLAN Driver Version   :%s \r\n", fw_ver->driver_ver_str);
        printf("WLAN Firmware Version :%s \r\n", fw_ver->fw_ver_str);
    }
    else
    {
        printf("failed to get firmware version\r\n");
    }

    return TRUE;
}

/**
 * @brief      This function processes mac address(set) response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_mac_address(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to set mac address\r\n");
    }

    return TRUE;
}

/**
 * @brief      This function processes mac address(get) response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_mac_address(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        NCP_CMD_GET_MAC_ADDRESS *get_mac = (NCP_CMD_GET_MAC_ADDRESS *)&cmd_res->params.get_mac_addr;
        printf("MAC Address\r\n");
        printf("STA MAC Address: %02X:%02X:%02X:%02X:%02X:%02X \r\n", MAC2STR((unsigned char)get_mac->sta_mac));
        printf("UAP MAC Address: %02X:%02X:%02X:%02X:%02X:%02X \r\n", MAC2STR((unsigned char)get_mac->uap_mac));
    }
    else
    {
        printf("failed to get mac address\r\n");
    }

    return TRUE;
}

int wlan_ncp_process_get_mac(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        NCP_CMD_GET_MAC_ADDRESS *get_mac = (NCP_CMD_GET_MAC_ADDRESS *)&cmd_res->params.get_mac_addr;
        printf("MAC Address\r\n");
        printf("STA MAC Address: %02X:%02X:%02X:%02X:%02X:%02X \r\n", MAC2STR((unsigned char)get_mac->sta_mac));
        printf("UAP MAC Address: %02X:%02X:%02X:%02X:%02X:%02X \r\n", MAC2STR((unsigned char)get_mac->uap_mac));
    }
    else
    {
        printf("failed to get mac address\r\n");
    }

    return TRUE;
}

int wlan_ncp_process_get_pkt_stats(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        NCP_CMD_PKT_STATS *pkt_stats = (NCP_CMD_PKT_STATS *)&cmd_res->params.get_pkt_stats;
        printf("pkt stats\r\n");
        printf("pkt_stats: mcast_tx_frame %d \r\n", pkt_stats->mcast_tx_frame);
        //printf("UAP MAC Address: %02X:%02X:%02X:%02X:%02X:%02X \r\n", MAC2STR((unsigned char)get_mac->uap_mac));
    }
    else
    {
        printf("failed to get pkt stats\r\n");
    }

    return TRUE;
}

/**
 * @brief      This function processes wlan connection state response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_stat(uint8_t *res)
{
    char ps_mode_str[25];
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to get wlan connection state\r\n");
        return FALSE;
    }

    NCP_CMD_CONNECT_STAT *conn_stat = (NCP_CMD_CONNECT_STAT *)&cmd_res->params.conn_stat;

    switch (conn_stat->ps_mode)
    {
        case WLAN_IEEE:
            strcpy(ps_mode_str, "IEEE ps");
            break;
        case WLAN_DEEP_SLEEP:
            strcpy(ps_mode_str, "Deep sleep");
            break;
        case WLAN_IEEE_DEEP_SLEEP:
            strcpy(ps_mode_str, "IEEE ps and Deep sleep");
            break;
        case WLAN_WNM:
            strcpy(ps_mode_str, "WNM ps");
            break;
        case WLAN_WNM_DEEP_SLEEP:
            strcpy(ps_mode_str, "WNM ps and Deep sleep");
            break;
        case WLAN_ACTIVE:
        default:
            strcpy(ps_mode_str, "Active");
            break;
    }

    switch (conn_stat->sta_conn_stat)
    {
        case WLAN_DISCONNECTED:
            printf("Station disconnected (%s)\r\n", ps_mode_str);
            break;
        case WLAN_SCANNING:
            printf("Station scanning (%s)\r\n", ps_mode_str);
            break;
        case WLAN_ASSOCIATING:
            printf("Station associating (%s)\r\n", ps_mode_str);
            break;
        case WLAN_ASSOCIATED:
            printf("Station associated (%s)\r\n", ps_mode_str);
            break;
        case WLAN_CONNECTING:
            printf("Station connecting (%s)\r\n", ps_mode_str);
            break;
        case WLAN_CONNECTED:
            printf("Station connected (%s)\r\n", ps_mode_str);
            break;
        default:
            printf(
                "Error: invalid STA state"
                " %d\r\n",
                conn_stat->sta_conn_stat);
            break;
    }

    switch (conn_stat->uap_conn_stat)
    {
        case WLAN_UAP_STARTED:
            strcpy(ps_mode_str, "Active");
            printf("uAP started (%s)\r\n", ps_mode_str);
            break;
        case WLAN_UAP_STOPPED:
            printf("uAP stopped\r\n");
            break;
        default:
            printf(
                "Error: invalid uAP state"
                " %d\r\n",
                conn_stat->uap_conn_stat);
            break;
    }

    return TRUE;
}

/**
 * @brief      This function processes roaming response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */

int wlan_process_roaming(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("Set roaming successfully!\r\n");
        return TRUE;
    }
    else
        printf("Failed to set roaming!\r\n");
    return TRUE;
}

/**
 * @brief      This function processes OKC response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_okc_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        printf("Set OKC successfully!\r\n");
    else
        printf("Failed to set OKC!\r\n");
    return TRUE;
}

/**
 * @brief      This function processes scan response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_scan_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        NCP_CMD_SCAN_NETWORK_INFO *scan_result = (NCP_CMD_SCAN_NETWORK_INFO *)&cmd_res->params.scan_network_info;
        uint8_t count                          = scan_result->res_cnt;
        if (count == 0)
        {
            printf("no networks found\r\n");
        }
        else
        {
            printf("%d networks found\r\n", count);
            for (int i = 0; i < count; i++)
            {
                printf(MACSTR, MAC2STR((unsigned char)scan_result->res[i].bssid));
                printf(" [%s]\r\n", scan_result->res[i].ssid);
                printf("mode: ");
#if CONFIG_NCP_11AX
                if (scan_result->res[i].dot11ax != 0U)
                {
                    printf("802.11AX ");
                }
                else
#endif
#if CONFIG_NCP_11AC
                if (scan_result->res[i].dot11ac != 0U)
                {
                    printf("802.11AC ");
                }
                else
#endif
                if (scan_result->res[i].dot11n != 0U)
                {
                    printf("802.11N ");
                }
                else
                {
                    printf("802.11BG ");
                }
                printf("\r\n");

                printf("channel: %d\r\n", scan_result->res[i].channel);
                printf("rssi: -%d dBm\r\n", scan_result->res[i].rssi);

                printf("security: ");
                if (scan_result->res[i].wep != 0U)
                    printf("WEP ");
                if (scan_result->res[i].wpa && scan_result->res[i].wpa2)
                    printf("WPA/WPA2 Mixed ");
                else if (scan_result->res[i].wpa2 && scan_result->res[i].wpa3_sae)
                    printf("WPA2/WPA3 SAE Mixed ");
                else
                {
                    if (scan_result->res[i].wpa != 0U)
                        printf("WPA ");
                    if (scan_result->res[i].wpa2 != 0U)
                        printf("WPA2 ");
                    if (scan_result->res[i].wpa2_sha256 != 0U)
                        (void)printf("WPA2-SHA256 ");
                    if (scan_result->res[i].wpa3_sae != 0U)
                        printf("WPA3 SAE ");
                    if (scan_result->res[i].wpa2_entp != 0U)
                        printf("WPA2 Enterprise");
                    if (scan_result->res[i].wpa3_entp != 0U)
                        (void)printf("WPA3 Enterprise");
                    if (scan_result->res[i].wpa3_1x_sha256 != 0U)
                        (void)printf("WPA3-SHA256 Enterprise");
                    if (scan_result->res[i].wpa3_1x_sha384 != 0U)
                        (void)printf("WPA3-SHA384 Enterprise");
                }
                if (!(scan_result->res[i].wep || scan_result->res[i].wpa || scan_result->res[i].wpa2 ||
                      scan_result->res[i].wpa2_sha256 || scan_result->res[i].wpa3_sae || scan_result->res[i].wpa3_entp ||
                      scan_result->res[i].wpa2_entp || scan_result->res[i].wpa3_1x_sha256 || scan_result->res[i].wpa3_1x_sha384))
                {
                    printf("OPEN ");
                }
                printf("\r\n");
                printf("WMM: %s\r\n", scan_result->res[i].wmm ? "YES" : "NO");
#if CONFIG_NCP_11K
                if (scan_result->res[i].neighbor_report_supported == true)
                {
                    (void)printf("802.11K: YES\r\n");
                }
#endif
#if CONFIG_NCP_11V
                if (scan_result->res[i].bss_transition_supported == true)
                {
                    (void)printf("802.11V: YES\r\n");
                }
#endif
                if ((scan_result->res[i].ap_mfpc == true) && (scan_result->res[i].ap_mfpr == true))
                {
                    (void)printf("802.11W: Capable, Required\r\n");
                }
                if ((scan_result->res[i].ap_mfpc == true) && (scan_result->res[i].ap_mfpr == false))
                {
                    (void)printf("802.11W: Capable\r\n");
                }
                if ((scan_result->res[i].ap_mfpc == false) && (scan_result->res[i].ap_mfpr == false))
                {
                    (void)printf("802.11W: NA\r\n");
                }
#if CONFIG_NCP_SUPP_WPS
               if (scan_result->res[i].wps)
                {
                    if (scan_result->res[i].wps_session == WPS_SESSION_PBC)
                    {
                        (void)printf("WPS: %s, Session: %s\r\n", "YES", "Push Button");
                    }
                    else if (scan_result->res[i].wps_session == WPS_SESSION_PIN)
                    {
                        (void)printf("WPS: %s, Session: %s\r\n", "YES", "PIN");
                    }
                    else
                    {
                        (void)printf("WPS: %s, Session: %s\r\n", "YES", "Not active");
                    }
                }
                else
                {
                    (void)printf("WPS: %s \r\n", "NO");
                }
#endif
            }
        }
    }
    else
    {
        printf("failed to scan\r\n");
    }
    return TRUE;
}

/**
 * @brief      This function processes wlan reset response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_reset_result_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("wlan_reset is ok!\r\n");
        return TRUE;
    }
    else
        printf("Wlan reset is fail!\r\n");
    return TRUE;
}

/**
 * @brief      This function processes wlan-uap-prov-start response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_uap_prov_start_result_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("wlan-uap-prov-start is ok!\r\n");
        return TRUE;
    }
    else
        printf("wlan-uap-prov-start is fail!\r\n");
    return TRUE;
}

/**
 * @brief      This function processes wlan-uap-prov-reset response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_uap_prov_reset_result_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("wlan-uap-prov-reset is ok!\r\n");
        return TRUE;
    }
    else
        printf("wlan-uap-prov-reset is fail!\r\n");
    return TRUE;
}

/**
 * @brief      This function processes wlan_uap_prov_set_uapcfg response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_uap_prov_set_uapcfg_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("wlan_uap_prov_set_uapcfg success!\r\n");
    }
    else
        printf("wlan_uap_prov_set_uapcfg fail!\r\n");
    return TRUE;
}

static const char *print_role(uint8_t role)
{
    switch (role)
    {
        case WLAN_BSS_ROLE_STA:
            return "Infra";
        case WLAN_BSS_ROLE_UAP:
            return "uAP";
        case WLAN_BSS_ROLE_ANY:
            return "any";
    }
    return "unknown";
}

static void print_address(NCP_WLAN_NETWORK *network, uint8_t role)
{
    struct in_addr ip, gw, nm, dns1, dns2;
    char addr_type[40] = {0};

    if (role == WLAN_BSS_ROLE_STA && !network->is_sta_ipv4_connected)
        goto out;

    ip.s_addr   = network->ipv4.address;
    gw.s_addr   = network->ipv4.gw;
    nm.s_addr   = network->ipv4.netmask;
    dns1.s_addr = network->ipv4.dns1;
    dns2.s_addr = network->ipv4.dns2;
    if (network->ipv4.addr_type == ADDR_TYPE_STATIC)
        strcpy(addr_type, "STATIC");
    else if (network->ipv4.addr_type == ADDR_TYPE_STATIC)
        strcpy(addr_type, "AUTO IP");
    else
        strcpy(addr_type, "DHCP");

    printf("\r\n\tIPv4 Address\r\n");
    printf("\taddress: %s", addr_type);
    printf("\r\n\t\tIP:\t\t%s", inet_ntoa(ip));
    printf("\r\n\t\tgateway:\t%s", inet_ntoa(gw));
    printf("\r\n\t\tnetmask:\t%s", inet_ntoa(nm));
    printf("\r\n\t\tdns1:\t\t%s", inet_ntoa(dns1));
    printf("\r\n\t\tdns2:\t\t%s", inet_ntoa(dns2));
    printf("\r\n");
out:
#ifdef CONFIG_IPV6
    if (role == WLAN_BSS_ROLE_STA || role == WLAN_BSS_ROLE_UAP)
    {
        int i;
        printf("\r\n\tIPv6 Addresses\r\n");
        for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
        {
            if (strcmp((char *)network->ipv6[i].addr_state_str, "Invalid"))
            {
                inet_ntop(AF_INET6, network->ipv6[i].address, addr_type, 40);
                printf("\t%-13s:\t%s (%s)\r\n", network->ipv6[i].addr_type_str, addr_type,
                       network->ipv6[i].addr_state_str);
            }
        }
        printf("\r\n");
    }
#endif
    return;
}
static void print_mac(const unsigned char *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X ", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
static void print_network(NCP_WLAN_NETWORK *network)
{
    char *pssid = "(hidden)";
    if (network->ssid[0])
        pssid = network->ssid;
    printf("\"%s\"\r\n\tSSID: %s\r\n\tBSSID: ", network->name, pssid);
    print_mac((unsigned char *)network->bssid);
    if (network->channel != 0U)
        printf("\r\n\tchannel: %d", network->channel);
    else
        printf("\r\n\tchannel: %s", "(Auto)");
    printf("\r\n\trole: %s\r\n", print_role(network->role));

    char *sec_tag = "\tsecurity";
    if (!network->security_specific)
    {
        sec_tag = "\tsecurity [Wildcard]";
    }
    else
    {
#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
        if (
#ifdef CONFIG_EAP_TLS
            (network->security_type == WLAN_SECURITY_EAP_TLS) ||
#endif
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_MSCHAPV2
				(network->security_type == WLAN_SECURITY_EAP_PEAP_MSCHAPV2) ||
#endif
#endif
				false)
			{
				if (network->wpa3_sb_192)
				{
					sec_tag = "\tsecurity: WPA3 SuiteB(192)";
				}
				else if (network->wpa3_sb)
				{
					sec_tag = "\tsecurity: WPA3 SuiteB";
				}
				else if (network->wpa3_ent)
				{
					sec_tag = "\tsecurity: WPA3";
				}
				else
				{
					sec_tag = "\tsecurity: WPA2";
				}
			}
#endif
    }
    switch (network->security_type)
    {
        case WLAN_SECURITY_NONE:
            printf("%s: none\r\n", sec_tag);
            break;
        case WLAN_SECURITY_WEP_OPEN:
            printf("%s: WEP (open)\r\n", sec_tag);
            break;
        case WLAN_SECURITY_WEP_SHARED:
            printf("%s: WEP (shared)\r\n", sec_tag);
            break;
        case WLAN_SECURITY_WPA:
            printf("%s: WPA\r\n", sec_tag);
            break;
        case WLAN_SECURITY_WPA2:
            printf("%s: WPA2\r\n", sec_tag);
            break;
        case WLAN_SECURITY_WPA_WPA2_MIXED:
            printf("%s: WPA/WPA2 Mixed\r\n", sec_tag);
            break;
#ifdef CONFIG_WPA2_ENTP
        case WLAN_SECURITY_EAP_TLS:
            printf("%s: WPA2 Enterprise EAP-TLS\r\n", sec_tag);
            break;
#endif
        case WLAN_SECURITY_WPA3_SAE:
            printf("%s: WPA3 SAE\r\n", sec_tag);
            break;
#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_TLS
        case WLAN_SECURITY_EAP_TLS:
            printf("%s Enterprise EAP-TLS\r\n", sec_tag);
            break;
#endif
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_MSCHAPV2
        case WLAN_SECURITY_EAP_PEAP_MSCHAPV2:
            printf("%s Enterprise EAP-PEAPv%d-MSCHAPV2\r\n", sec_tag, network->eap_ver);
            break;
#endif
#endif
#endif
        case WLAN_SECURITY_WPA2_WPA3_SAE_MIXED:
            printf("%s: WPA2/WPA3 SAE Mixed\r\n", sec_tag);
            break;
        default:
            break;
    }
#ifdef CONFIG_WIFI_CAPA
    if (network->role == WLAN_BSS_ROLE_UAP)
    {
        if (network->wlan_capa & WIFI_SUPPORT_11AX)
        {
            if (!network->enable_11ax)
            {
                if (network->enable_11ac)
                    printf("\twifi capability: 11ac\r\n");
                else
                    printf("\twifi capability: 11n\r\n");
            }
            else
                printf("\twifi capability: 11ax\r\n");
            printf("\tuser configure: 11ax\r\n");
        }
        else if (network->wlan_capa & WIFI_SUPPORT_11AC)
        {
            if (!network->enable_11ac)
                printf("\twifi capability: 11n\r\n");
            else
                printf("\twifi capability: 11ac\r\n");
            printf("\tuser configure: 11ac\r\n");
        }
        else if (network->wlan_capa & WIFI_SUPPORT_11N)
        {
            if (!network->enable_11n)
                printf("\twifi capability: legacy\r\n");
            else
                printf("\twifi capability: 11n\r\n");
            printf("\tuser configure: 11n\r\n");
        }
        else
        {
            printf("\twifi capability: legacy\r\n");
            printf("\tuser configure: legacy\r\n");
        }
    }
#endif
    print_address(network, network->role);
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    printf("\r\n\trssi threshold: %d \r\n", network->rssi_threshold);
#endif
}

/**
 * @brief      This function processes wlan network info response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_info(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to get wlan info\r\n");
        return FALSE;
    }

    NCP_CMD_NETWORK_INFO *network_info = (NCP_CMD_NETWORK_INFO *)&cmd_res->params.network_info;
    if (network_info->sta_conn_stat == WLAN_CONNECTED)
    {
        printf("Station connected to:\r\n");
        print_network(&network_info->sta_network);
    }
    else
    {
        printf("Station not connected\r\n");
    }

    if (network_info->uap_conn_stat == WLAN_UAP_STARTED)
    {
        printf("uAP started as:\r\n");
        print_network(&network_info->uap_network);
    }
    else
    {
        printf("uAP not started\r\n");
    }

    return TRUE;
}

int wlan_process_address(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("failed to get wlan address\r\n");
        return -WM_FAIL;
    }

    NCP_CMD_NETWORK_ADDRESS *network_address = (NCP_CMD_NETWORK_ADDRESS *)&cmd_res->params.network_address;
    if (network_address->sta_conn_stat == WLAN_CONNECTED)
    {
        print_address(&network_address->sta_network, network_address->sta_network.role);
    }
    else
    {
        (void)printf("Station not connected\r\n");
    }

    return WM_SUCCESS;
}


/*WLAN HTTP commamd*/
/**
 * @brief      This function processes wlan http connect from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_http_con_response(uint8_t *res)
{
    int handle                 = -1;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to connect!\r\n");
        return FALSE;
    }
    else
    {
        NCP_CMD_HTTP_CON_CFG *wlan_http_connect = (NCP_CMD_HTTP_CON_CFG *)&cmd_res->params.wlan_http_connect;
        handle                                  = wlan_http_connect->opened_handle;
        printf("Handle: %d\n", handle);
        return TRUE;
    }
}

/**
 * @brief  This function prepares wlan http connect command
 *
 * @return Status returned
 */
int wlan_http_connect_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_HTTP_CON;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 2)
    {
        printf("Usage: %s host\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_CON_CFG *wlan_http_tlv = (NCP_CMD_HTTP_CON_CFG *)&wlan_http_command->params.wlan_http_connect;
    if (strlen(argv[1]) + 1 > HTTP_URI_LEN)
        return FALSE;
    memcpy(wlan_http_tlv->host, argv[1], strlen(argv[1]) + 1);
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_CON_CFG);
    wlan_http_command->header.size += strlen(wlan_http_tlv->host) + 1;
    return TRUE;
}

/**
 * @brief      This function processes wlan http disconnect from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_http_discon_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to disconnect!\r\n");
        return FALSE;
    }
    else
    {
        printf("disconnect success!\r\n");
        return TRUE;
    }
}

/**
 * @brief  This function prepares wlan http connect command
 *
 * @return Status returned
 */
int wlan_http_disconnect_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_HTTP_DISCON;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 2)
    {
        printf("Usage: %s handle\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_DISCON_CFG *wlan_http_tlv = (NCP_CMD_HTTP_DISCON_CFG *)&wlan_http_command->params.wlan_http_disconnect;
    if (get_uint(argv[1], &wlan_http_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle\r\n", __func__);
        return FALSE;
    }
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_DISCON_CFG);
    return TRUE;
}

/**
 * @brief      This function processes wlan http req from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
typedef struct
{
    char *name;
    char *value;
} http_header_pair_t;
int wlan_process_wlan_http_req_response(uint8_t *res)
{
    unsigned int header_size   = 0;
    char *recv_header          = 0;
    int header_count           = 0;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to req!\r\n");
        return FALSE;
    }
    NCP_CMD_HTTP_REQ_RESP_CFG *wlan_http_req_resp = (NCP_CMD_HTTP_REQ_RESP_CFG *)&cmd_res->params.wlan_http_req_resp;
    header_size                                   = wlan_http_req_resp->header_size;
    dump_hex(wlan_http_req_resp->recv_header, header_size);
    recv_header = wlan_http_req_resp->recv_header;
    while (strlen(recv_header))
    {
        header_count++;
        http_header_pair_t header_pair;
        header_pair.name = recv_header;
        recv_header += (strlen(recv_header) + 1);
        header_pair.value = recv_header;
        recv_header += (strlen(recv_header) + 1);
        printf("%s:%s\n", header_pair.name, header_pair.value);
    }
    return TRUE;
}

/**
 * @brief  This function prepares wlan http req command
 *
 * @return Status returned
 */
int wlan_http_req_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_HTTP_REQ;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc < 3 || argc > 6)
    {
        printf("Usage: %s handle method [uri] [req_data] [req_size]\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_REQ_CFG *wlan_http_tlv = (NCP_CMD_HTTP_REQ_CFG *)&wlan_http_command->params.wlan_http_req;

    if (get_uint(argv[1], &wlan_http_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle method [uri] [req_data] [req_size]\r\n", __func__);
        return FALSE;
    }
    if (strlen(argv[2]) + 1 > HTTP_PARA_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }

    memcpy(wlan_http_tlv->method, argv[2], strlen(argv[2]) + 1);
    if (argv[3])
    {
        if (strlen(argv[3]) + 1 > HTTP_URI_LEN)
        {
            printf("over buffer size\r\n");
            return FALSE;
        }
        memcpy(wlan_http_tlv->uri, argv[3], strlen(argv[3]) + 1);
    }

    if (argv[4])
    {
        if (!argv[5])
            wlan_http_tlv->req_size = strlen(argv[4]) + 1;
        else
        {
            if (get_uint(argv[5], &wlan_http_tlv->req_size, strlen(argv[5])))
            {
                printf("Usage: %s handle method [uri] [req_data] [req_size]\r\n", __func__);
                return FALSE;
            }
        }
        wlan_http_command->header.size += wlan_http_tlv->req_size;
    }
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_REQ_CFG);
    if (argv[4])
    {
        if (wlan_http_command->header.size > NCP_COMMAND_LEN)
        {
            printf("over buffer size\r\n");
            return FALSE;
        }
        memcpy(wlan_http_tlv->req_data, argv[4], wlan_http_tlv->req_size);
    }
    return TRUE;
}

/**
 * @brief      This function processes wlan http recv from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_http_recv_response(uint8_t *res)
{
    unsigned int recv_size     = 0;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("%s: failed to receive data!\r\n", __FUNCTION__);
        return FALSE;
    }
    NCP_CMD_HTTP_RECV_CFG *wlan_http_receive = (NCP_CMD_HTTP_RECV_CFG *)&cmd_res->params.wlan_http_recv;
    recv_size                                = wlan_http_receive->size;
    dump_hex(wlan_http_receive->recv_data, recv_size);
    printf("receive data success, %s\r\n", wlan_http_receive->recv_data);
    return TRUE;
}

/**
 * @brief  This function prepares wlan http recv command
 *
 * @return Status returned
 */
int wlan_http_recv_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_HTTP_RECV;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_RECV_CFG *wlan_http_tlv = (NCP_CMD_HTTP_RECV_CFG *)&wlan_http_command->params.wlan_http_recv;
    if (get_uint(argv[1], &wlan_http_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[2], &wlan_http_tlv->size, strlen(argv[2])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_http_tlv->timeout, strlen(argv[3])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_RECV_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan http seth from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_http_unseth_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to remove http header-name!\r\n");
        return FALSE;
    }
    printf("success to remove http header-name\n");
    return TRUE;
}

/**
 * @brief  This function prepares wlan http seth command
 *
 * @return Status returned
 */
int wlan_http_unseth_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_HTTP_UNSETH;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 2)
    {
        printf("Usage: %s header-name\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_UNSETH_CFG *wlan_http_tlv = (NCP_CMD_HTTP_UNSETH_CFG *)&wlan_http_command->params.wlan_http_unseth;
    if (strlen(argv[1]) + 1 > SETH_NAME_LENGTH)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }

    memcpy(wlan_http_tlv->name, argv[1], strlen(argv[1]) + 1);
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_UNSETH_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan http unseth from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_http_seth_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to set http header-name!\r\n");
        return FALSE;
    }
    printf("success to set http header-name\n");
    return TRUE;
}

/**
 * @brief  This function prepares wlan http unseth command
 *
 * @return Status returned
 */
int wlan_http_seth_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_HTTP_SETH;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 3)
    {
        printf("Usage: %s header-name header-value\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_SETH_CFG *wlan_http_tlv = (NCP_CMD_HTTP_SETH_CFG *)&wlan_http_command->params.wlan_http_seth;
    if (strlen(argv[1]) + 1 > SETH_NAME_LENGTH || strlen(argv[2]) + 1 > SETH_VALUE_LENGTH)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }

    memcpy(wlan_http_tlv->name, argv[1], strlen(argv[1]) + 1);
    memcpy(wlan_http_tlv->value, argv[2], strlen(argv[2]) + 1);
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_SETH_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan websocket upgrade from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_websocket_upg_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to http upgrade!\r\n");
        return FALSE;
    }
    printf("success to http upgrade\n");
    return TRUE;
}

/**
 * @brief  This function prepares wlan websocket upgrade command
 *
 * @return Status returned
 */
int wlan_websocket_upg_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_WEBSOCKET_UPG;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_HTTP_UPG_CFG *wlan_http_tlv = (NCP_CMD_HTTP_UPG_CFG *)&wlan_http_command->params.wlan_http_upg;
    if (get_uint(argv[1], (unsigned int *)&wlan_http_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (strlen(argv[2]) + 1 > HTTP_URI_LEN || strlen(argv[3]) + 1 > HTTP_PARA_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_http_tlv->uri, argv[2], strlen(argv[2]) + 1);
    memcpy(wlan_http_tlv->protocol, argv[3], strlen(argv[3]) + 1);
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_HTTP_UPG_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan websocket send from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_websocket_send_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to send data!\r\n");
        return FALSE;
    }
    // printf("send data success!\r\n");
    return TRUE;
}

/**
 * @brief  This function prepares wlan websocket send command
 *
 * @return Status returned
 */
int wlan_websocket_send_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_WEBSOCKET_SEND;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4 && argc != 5)
    {
        printf("Usage: %s handle type send_data [send_size]\r\n", __func__);
        return FALSE;
    }

    if (!argv[3])
        return FALSE;

    NCP_CMD_WEBSOCKET_SEND_CFG *wlan_http_tlv =
        (NCP_CMD_WEBSOCKET_SEND_CFG *)&wlan_http_command->params.wlan_websocket_send;
    if (get_uint(argv[1], &wlan_http_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle type send_data [send_size]\r\n", __func__);
        return FALSE;
    }
    if (strlen(argv[2]) + 1 > HTTP_PARA_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_http_tlv->type, argv[2], strlen(argv[2]) + 1);
    if (!argv[4])
        wlan_http_tlv->size = strlen(argv[3]) + 1;
    else
    {
        if (get_uint(argv[4], &wlan_http_tlv->size, strlen(argv[4])))
        {
            printf("Usage: %s handle type send_data [send_size]\r\n", __func__);
            return FALSE;
        }
    }
    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_WEBSOCKET_SEND_CFG);
    wlan_http_command->header.size += wlan_http_tlv->size;
    if (wlan_http_command->header.size > NCP_COMMAND_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_http_tlv->send_data, argv[3], wlan_http_tlv->size);

    return TRUE;
}

/**
 * @brief      This function processes wlan websocket recv from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_websocket_recv_response(uint8_t *res)
{
    unsigned int recv_size     = 0;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("%s: failed to receive data!\r\n", __FUNCTION__);
        return FALSE;
    }
    NCP_CMD_WEBSOCKET_RECV_CFG *wlan_websocket_receive =
        (NCP_CMD_WEBSOCKET_RECV_CFG *)&cmd_res->params.wlan_websocket_recv;

    recv_size = wlan_websocket_receive->size;
    dump_hex(wlan_websocket_receive->recv_data, recv_size);
    printf("receive data success, %s, fin = %d\r\n", wlan_websocket_receive->recv_data, wlan_websocket_receive->fin);
    return TRUE;
}

/**
 * @brief  This function prepares wlan websocket recv command
 *
 * @return Status returned
 */
int wlan_websocket_recv_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_http_command = mpu_host_get_wifi_command_buffer();
    wlan_http_command->header.cmd        = NCP_CMD_WLAN_WEBSOCKET_RECV;
    wlan_http_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_http_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_WEBSOCKET_RECV_CFG *wlan_http_tlv =
        (NCP_CMD_WEBSOCKET_RECV_CFG *)&wlan_http_command->params.wlan_websocket_recv;

    if (get_uint(argv[1], &wlan_http_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[2], &wlan_http_tlv->size, strlen(argv[2])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_http_tlv->timeout, strlen(argv[3])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    /*cmd size*/
    wlan_http_command->header.size += sizeof(NCP_CMD_WEBSOCKET_RECV_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket open response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_open_response(uint8_t *res)
{
    int handle                 = -1;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to open!\r\n");
        return FALSE;
    }
    NCP_CMD_SOCKET_OPEN_CFG *wlan_socket_open = (NCP_CMD_SOCKET_OPEN_CFG *)&cmd_res->params.wlan_socket_open;
    handle                                    = wlan_socket_open->opened_handle;
    if(!strcmp(wlan_socket_open->protocol, "icmp"))
        ping_sock_handle = handle;
    printf("Handle: %d\n", handle);
    return TRUE;
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket open command
 *
 * @return Status returned
 */
int wlan_socket_open_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_OPEN;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc < 2 || argc > 4)
    {
        printf("Usage: %s tcp/udp/raw [domain] [protocol]\r\n", __func__);
        return FALSE;
    }

    if (!strcmp(argv[1], "tcp") && !strcmp(argv[1], "udp") && !strcmp(argv[1], "raw"))
    {
        printf("Usage: %s tcp/udp/raw [domain] [protocol]\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_OPEN_CFG *wlan_socket_tlv = (NCP_CMD_SOCKET_OPEN_CFG *)&wlan_socket_command->params.wlan_socket_open;
    if (strlen(argv[1]) + 1 > HTTP_PARA_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_socket_tlv->socket_type, argv[1], HTTP_PARA_LEN);
    if (argv[2])
        memcpy(wlan_socket_tlv->domain_type, argv[2], sizeof(wlan_socket_tlv->domain_type));
    else
        memset(wlan_socket_tlv->domain_type, '\0', sizeof(wlan_socket_tlv->domain_type));
    if (argv[3])
        memcpy(wlan_socket_tlv->protocol, argv[3], sizeof(wlan_socket_tlv->protocol));
    else
        memset(wlan_socket_tlv->protocol, '\0', sizeof(wlan_socket_tlv->protocol));

    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_OPEN_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket connect from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_con_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to connect!\r\n");
        return FALSE;
    }
    else
    {
        printf("connect success!\r\n");
        return TRUE;
    }
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket open command
 *
 * @return Status returned
 */
int wlan_socket_con_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_CON;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_CON_CFG *wlan_socket_tlv = (NCP_CMD_SOCKET_CON_CFG *)&wlan_socket_command->params.wlan_socket_con;

    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_socket_tlv->port, strlen(argv[3])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (strlen(argv[2]) + 1 > IP_ADDR_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_socket_tlv->ip_addr, argv[2], strlen(argv[2]) + 1);
    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_CON_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket bind from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_bind_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to bind!\r\n");
        return FALSE;
    }
    else
    {
        printf("bind success!\r\n");
        return TRUE;
    }
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket bind command
 *
 * @return Status returned
 */
int wlan_socket_bind_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_BIND;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_BIND_CFG *wlan_socket_tlv = (NCP_CMD_SOCKET_BIND_CFG *)&wlan_socket_command->params.wlan_socket_bind;
    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_socket_tlv->port, strlen(argv[3])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (strlen(argv[2]) + 1 > IP_ADDR_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_socket_tlv->ip_addr, argv[2], strlen(argv[2]) + 1);
    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_BIND_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket close from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_close_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to close handle!\r\n");
        return FALSE;
    }
    else
    {
        printf("close handle success!\r\n");
        return TRUE;
    }
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket close command
 *
 * @return Status returned
 */
int wlan_socket_close_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_CLOSE;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 2)
    {
        printf("Usage: %s handle\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_CLOSE_CFG *wlan_socket_tlv =
        (NCP_CMD_SOCKET_CLOSE_CFG *)&wlan_socket_command->params.wlan_socket_close;
    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle\r\n", __func__);
        return FALSE;
    }

    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_CLOSE_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket listen from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_listen_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to listen handle!\r\n");
        return FALSE;
    }
    else
    {
        printf("listen handle success!\r\n");
        return TRUE;
    }
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket listen command
 *
 * @return Status returned
 */
int wlan_socket_listen_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_LISTEN;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 3)
    {
        printf("Usage: %s handle number\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_LISTEN_CFG *wlan_socket_tlv =
        (NCP_CMD_SOCKET_LISTEN_CFG *)&wlan_socket_command->params.wlan_socket_listen;
    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle number\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[2], &wlan_socket_tlv->number, strlen(argv[2])))
    {
        printf("Usage: %s handle number\r\n", __func__);
        return FALSE;
    }

    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_LISTEN_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket accept from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_accept_response(uint8_t *res)
{
    int handle                 = -1;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to accept handle!\r\n");
        return FALSE;
    }
    NCP_CMD_SOCKET_ACCEPT_CFG *wlan_socket_accept = (NCP_CMD_SOCKET_ACCEPT_CFG *)&cmd_res->params.wlan_socket_accept;
    handle                                        = wlan_socket_accept->accepted_handle;
    printf("accept handle %d!\r\n", handle);
    return TRUE;
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket close command
 *
 * @return Status returned
 */
int wlan_socket_accept_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_ACCEPT;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 2)
    {
        printf("Usage: %s handle\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_ACCEPT_CFG *wlan_socket_tlv =
        (NCP_CMD_SOCKET_ACCEPT_CFG *)&wlan_socket_command->params.wlan_socket_accept;
    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle\r\n", __func__);
        return FALSE;
    }
    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_ACCEPT_CFG);

    return TRUE;
}

/**
 * @brief      This function processes wlan socket send from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_send_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        // printf("failed to send data!\r\n");
        return FALSE;
    }
    // printf("send data success!\r\n");
    return TRUE;
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket send command
 *
 * @return Status returned
 */
int wlan_socket_send_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_SEND;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 3 && argc != 4)
    {
        printf("Usage: %s handle send_data [send_size]\r\n", __func__);
        return FALSE;
    }

    if (!argv[2])
        return FALSE;

    NCP_CMD_SOCKET_SEND_CFG *wlan_socket_tlv = (NCP_CMD_SOCKET_SEND_CFG *)&wlan_socket_command->params.wlan_socket_send;
    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle send_data [send_size]\r\n", __func__);
        return FALSE;
    }

    if (!argv[3])
        wlan_socket_tlv->size = (strlen(argv[2]) + 1);
    else
    {
        if (get_uint(argv[3], &wlan_socket_tlv->size, strlen(argv[3])))
        {
            printf("Usage: %s handle send_data [send_size]\r\n", __func__);
            return FALSE;
        }
    }
    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_SEND_CFG);
    wlan_socket_command->header.size += wlan_socket_tlv->size;
    if (wlan_socket_command->header.size > NCP_COMMAND_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_socket_tlv->send_data, argv[2], wlan_socket_tlv->size);
    return TRUE;
}

/**
 * @brief      This function processes wlan socket sendto from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_sendto_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        if (ping_res.seq_no < 0)
        {
            printf("failed to sendto data!\r\n");
        }
        else
        {
            /* Send ping cmd response to ping_sock_task */
            sem_post(&ping_res_sem);
        }
        return FALSE;
    }

    if (ping_res.seq_no >= 0)
    {
        /* Send ping cmd response to ping_sock_task */
        sem_post(&ping_res_sem);
    }

    return TRUE;
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket send command
 *
 * @return Status returned
 */
int wlan_socket_sendto_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_SENDTO;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 5 && argc != 6)
    {
        printf("Usage: %s handle ip_addr port send_data [send_size]\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_SENDTO_CFG *wlan_socket_tlv =
        (NCP_CMD_SOCKET_SENDTO_CFG *)&wlan_socket_command->params.wlan_socket_sendto;

    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle ip_addr port send_data [send_size]\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_socket_tlv->port, strlen(argv[3])))
    {
        printf("Usage: %s handle ip_addr port send_data [send_size]\r\n", __func__);
        return FALSE;
    }

    if (!argv[5])
        wlan_socket_tlv->size = strlen(argv[4]) + 1;
    else
    {
        if (get_uint(argv[5], &wlan_socket_tlv->size, strlen(argv[5])))
        {
            printf("Usage: %s handle ip_addr port send_data [send_size]\r\n", __func__);
            return FALSE;
        }
    }
    if (strlen(argv[2]) + 1 > IP_ADDR_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_socket_tlv->ip_addr, argv[2], strlen(argv[2]) + 1);
    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG);
    wlan_socket_command->header.size += wlan_socket_tlv->size;
    if (wlan_socket_command->header.size > NCP_COMMAND_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(wlan_socket_tlv->send_data, argv[4], wlan_socket_tlv->size);
    return TRUE;
}

extern char lwiperf_end_token[NCP_IPERF_END_TOKEN_SIZE];
/**
 * @brief      This function processes wlan socket receive from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_receive_response(uint8_t *res)
{
    unsigned int recv_size     = 0;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        if (socket_receive_res == true)
        {
            socket_receive_res = false;
        }
        printf("%s: failed to receive data!\r\n", __FUNCTION__);
        return FALSE;
    }
    NCP_CMD_SOCKET_RECEIVE_CFG *wlan_socket_receive =
        (NCP_CMD_SOCKET_RECEIVE_CFG *)&cmd_res->params.wlan_socket_receive;
    recv_size = wlan_socket_receive->size;

    if (socket_receive_res == true)
    {
        socket_receive_res = false;
        recv_size = wlan_socket_receive->size;
        printf("receive data success\r\n");
        dump_hex(wlan_socket_receive->recv_data, recv_size);
    }
    else
    {
        /*Recved end token*/
        if(memcmp(wlan_socket_receive->recv_data, &lwiperf_end_token[0], sizeof(lwiperf_end_token)) == 0)
        {
            printf("iperf finished!\r\n");
            return FALSE;
        }
    }

    return recv_size;
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket receive command
 *
 * @return Status returned
 */
int wlan_socket_receive_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_RECV;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_RECEIVE_CFG *wlan_socket_tlv =
        (NCP_CMD_SOCKET_RECEIVE_CFG *)&wlan_socket_command->params.wlan_socket_receive;
    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[2], &wlan_socket_tlv->size, strlen(argv[2])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_socket_tlv->timeout, strlen(argv[3])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_RECEIVE_CFG);

    socket_receive_res = true;

    return TRUE;
}

/* Handle the ICMP echo response and extract required parameters */
static void ping_recv(NCP_CMD_SOCKET_RECVFROM_CFG *recv)
{
    int ret = FALSE;
    struct ip_hdr *iphdr;
    struct icmp_echo_hdr *iecho;

    /* Received length should be greater than size of IP header and
     * size of ICMP header */
    if (recv->size >= (int)(sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr)))
    {
        iphdr = (struct ip_hdr *)recv->recv_data;
        /* Calculate the offset of ICMP header */
        iecho = (struct icmp_echo_hdr *)(recv->recv_data + ((iphdr->_v_hl & 0x0f) * 4));

        /* Verify that the echo response is for the echo request
         * we sent by checking PING_ID and sequence number */
        if ((iecho->id == PING_ID) && (iecho->seqno == htons(ping_res.seq_no)))
        {
            /* Increment the receive counter */
            ping_res.recvd++;
            /* To display successful ping stats, destination
             * IP address is required */
            (void)memcpy(ping_res.ip_addr, recv->peer_ip, sizeof(recv->peer_ip));

            /* Extract TTL and send back so that it can be
             * displayed in ping statistics */
            ping_res.ttl = iphdr->_ttl;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }

        ping_res.echo_resp = ret;
        ping_res.size      = ping_msg.size;
    }
}

/**
 * @brief      This function processes wlan socket recvfrom from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_wlan_socket_recvfrom_response(uint8_t *res)
{
    unsigned int recv_size     = 0;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        if (socket_recvfrom_res == true)
        {
            socket_recvfrom_res = false;
            printf("%s: failed to receive data for socket_recvfrom_res is true!\r\n", __FUNCTION__);
        }
        else if (ping_res.seq_no < 0)
        {
            printf("%s: failed to receive data!\r\n", __FUNCTION__);
        }
        else
        {
            ping_res.echo_resp = FALSE;
            /* Send ping cmd response to ping_sock_task */
            sem_post(&ping_res_sem);
        }
        return FALSE;
    }

    NCP_CMD_SOCKET_RECVFROM_CFG *wlan_socket_recvfrom =
        (NCP_CMD_SOCKET_RECVFROM_CFG *)&cmd_res->params.wlan_socket_recvfrom;
    recv_size = wlan_socket_recvfrom->size;

    if (socket_recvfrom_res == true)
    {
        socket_recvfrom_res = false;
        recv_size = wlan_socket_recvfrom->size;
        printf("recvfrom data success, peer_ip = %s, peer_port = %d\r\n", wlan_socket_recvfrom->peer_ip,
                wlan_socket_recvfrom->peer_port);
        dump_hex(wlan_socket_recvfrom->recv_data, recv_size);
    }
    else if (ping_res.seq_no < 0)
    {
        /*Recved end token*/
        if(memcmp(wlan_socket_recvfrom->recv_data, &lwiperf_end_token[0], sizeof(lwiperf_end_token)) == 0)
        {
            printf("iperf finished!\r\n");
            return FALSE;
        }
    }
    else
    {
        ping_recv(wlan_socket_recvfrom);
        /* Send ping cmd response to ping_sock_task */
        sem_post(&ping_res_sem);
    }

    return recv_size;
}

/*WLAN SOCKET commamd*/
/**
 * @brief  This function prepares wlan socket recvfrom command
 *
 * @return Status returned
 */
int wlan_socket_recvfrom_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wlan_socket_command = mpu_host_get_wifi_command_buffer();
    wlan_socket_command->header.cmd        = NCP_CMD_WLAN_SOCKET_RECVFROM;
    wlan_socket_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_socket_command->header.result     = NCP_CMD_RESULT_OK;

    if (argc != 4)
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    NCP_CMD_SOCKET_RECVFROM_CFG *wlan_socket_tlv =
        (NCP_CMD_SOCKET_RECVFROM_CFG *)&wlan_socket_command->params.wlan_socket_recvfrom;

    if (get_uint(argv[1], &wlan_socket_tlv->handle, strlen(argv[1])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[2], &wlan_socket_tlv->size, strlen(argv[2])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &wlan_socket_tlv->timeout, strlen(argv[3])))
    {
        printf("Usage: %s handle recv_size timeout\r\n", __func__);
        return FALSE;
    }

    /*cmd size*/
    wlan_socket_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);

    socket_recvfrom_res = true;

    return TRUE;
}

/**
 * @brief      This function processes wlan add network response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_add_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    switch (ret)
    {
        case WM_SUCCESS:
            printf("Added network successfully\r\n");
            break;
        case -WM_E_INVAL:
            printf("Error: network already exists or invalid arguments\r\n");
            break;
        case -WM_E_NOMEM:
            printf("Error: network list is full\r\n");
            break;
        case WLAN_ERROR_STATE:
            printf("Error: can't add networks in this state\r\n");
            break;
        default:
            printf(
                "Error: unable to add network for unknown"
                " reason\r\n");
            break;
    }

    return TRUE;
}

/**
 * @brief      This function processes wlan start network response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_start_network_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret != NCP_CMD_RESULT_OK)
    {
        printf("Error: unable to start network\r\n");
        return FALSE;
    }

    NCP_CMD_NETWORK_START *start_res_tlv = (NCP_CMD_NETWORK_START *)&cmd_res->params.network_start;
    printf("UAP started\r\n");
    printf("Soft AP \"%s\" started successfully\r\n", start_res_tlv->ssid);

    return TRUE;
}

/**
 * @brief      This function processes wlan stop network response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_stop_network_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        printf("Stop network successfully\r\n");
    }
    else
    {
        printf("Error: unable to stop network\r\n");
    }
    return TRUE;
}

/**
 * @brief      This function processes wlan get uap sta list response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_uap_sta_list(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    int i;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("failed to get wlan uap sta list\r\n");
        return FALSE;
    }

    NCP_CMD_NETWORK_UAP_STA_LIST *uap_sta_list = (NCP_CMD_NETWORK_UAP_STA_LIST *)&cmd_res->params.uap_sta_list;

    printf("Number of STA = %d \r\n\r\n", uap_sta_list->sta_count);
    for (i = 0; i < uap_sta_list->sta_count; i++)
    {
        printf("STA %d information:\r\n", i + 1);
        printf("=====================\r\n");
        printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\r\n", uap_sta_list->info[i].mac[0],
               uap_sta_list->info[i].mac[1], uap_sta_list->info[i].mac[2], uap_sta_list->info[i].mac[3],
               uap_sta_list->info[i].mac[4], uap_sta_list->info[i].mac[5]);
        printf("Power mfg status: %s\r\n", (uap_sta_list->info[i].power_mgmt_status == 0) ? "active" : "power save");
        printf("Rssi : %d dBm\r\n\r\n", (signed char)uap_sta_list->info[i].rssi);
    }

    return TRUE;
}

static void dump_wlan_csi_filter_usage()
{
    (void)printf("Error: invalid number of arguments\r\n");
    (void)printf("Usage : wlan-set-csi-filter <opt> <macaddr> <pkt_type> <type> <flag>\r\n");
    (void)printf("opt   : add/delete/clear/dump \r\n");
    (void)printf("add   : All options need to be filled in \r\n");
    (void)printf("delete: Delete recent filter information \r\n");
    (void)printf("clear : Clear all filter information \r\n");
    (void)printf("dump  : Dump csi cfg information \r\n");

    (void)printf("\r\nUsage example : \r\n");
    (void)printf("wlan-set-csi-filter add 00:18:E7:ED:2D:C1 255 255 0 \r\n");
    (void)printf("wlan-set-csi-filter delete \r\n");
    (void)printf("wlan-set-csi-filter clear \r\n");
    (void)printf("wlan-set-csi-filter dump \r\n");
}

void dump_csi_param_header()
{
    (void)printf("\r\nThe current csi_param is: \r\n");
    if(g_csi_params.bss_type == 0)
        (void)printf("bss_type      : sta\r\n");
    else
        (void)printf("bss_type      : uap\r\n");
    (void)printf("csi_enable    : %d \r\n", g_csi_params.csi_enable);
    (void)printf("head_id       : %d \r\n", g_csi_params.head_id);
    (void)printf("tail_id       : %d \r\n", g_csi_params.tail_id);
    (void)printf("csi_filter_cnt: %d \r\n", g_csi_params.csi_filter_cnt);
    (void)printf("chip_id       : %d \r\n", g_csi_params.chip_id);
    (void)printf("band_config   : %d \r\n", g_csi_params.band_config);
    (void)printf("channel       : %d \r\n", g_csi_params.channel);
    (void)printf("csi_monitor_enable : %d \r\n", g_csi_params.csi_monitor_enable);
    (void)printf("ra4us         : %d \r\n", g_csi_params.ra4us);

    (void)printf("\r\n");
}

void set_csi_param_header(uint8_t bss_type,
                          uint16_t csi_enable,
                          uint32_t head_id,
                          uint32_t tail_id,
                          uint8_t chip_id,
                          uint8_t band_config,
                          uint8_t channel,
                          uint8_t csi_monitor_enable,
                          uint8_t ra4us)
{
    g_csi_params.bss_type           = bss_type;
    g_csi_params.csi_enable         = csi_enable;
    g_csi_params.head_id            = head_id;
    g_csi_params.tail_id            = tail_id;
    g_csi_params.chip_id            = chip_id;
    g_csi_params.band_config        = band_config;
    g_csi_params.channel            = channel;
    g_csi_params.csi_monitor_enable = csi_monitor_enable;
    g_csi_params.ra4us              = ra4us;

    dump_csi_param_header();
}

int set_csi_filter(uint8_t pkt_type, uint8_t subtype, uint8_t flags, int op_index, uint8_t *mac)
{
    uint8_t temp_filter_cnt = g_csi_params.csi_filter_cnt;
    int i                   = 0;

    switch (op_index)
    {
        case CSI_FILTER_OPT_ADD:
            if (temp_filter_cnt < CSI_FILTER_MAX)
            {
                (void)memcpy(&g_csi_params.csi_filter[temp_filter_cnt].mac_addr[0], mac, NCP_WLAN_MAC_ADDR_LENGTH);
                g_csi_params.csi_filter[temp_filter_cnt].pkt_type = pkt_type;
                g_csi_params.csi_filter[temp_filter_cnt].subtype  = subtype;
                g_csi_params.csi_filter[temp_filter_cnt].flags    = flags;
                g_csi_params.csi_filter_cnt++;
            }
            else
            {
                (void)printf("max csi filter cnt is 16 \r\n");
                return FALSE;
            }
            break;

        case CSI_FILTER_OPT_DELETE:
            if (temp_filter_cnt > 0)
            {
                memset(&g_csi_params.csi_filter[temp_filter_cnt], 0, sizeof(wlan_csi_filter_t));
                g_csi_params.csi_filter_cnt--;
            }
            else
            {
                (void)printf("csi filter cnt is 0 \r\n");
                return FALSE;
            }
            break;

        case CSI_FILTER_OPT_CLEAR:
            for (i = 0; i < temp_filter_cnt; i++)
            {
                memset(&g_csi_params.csi_filter[i], 0, sizeof(wlan_csi_filter_t));
            }
            g_csi_params.csi_filter_cnt = 0;
            break;

        case CSI_FILTER_OPT_DUMP:
            dump_csi_param_header();

            for (i = 0; i < temp_filter_cnt; i++)
            {
                (void)printf("mac_addr      : %02X:%02X:%02X:%02X:%02X:%02X \r\n",
                             g_csi_params.csi_filter[i].mac_addr[0], g_csi_params.csi_filter[i].mac_addr[1],
                             g_csi_params.csi_filter[i].mac_addr[2], g_csi_params.csi_filter[i].mac_addr[3],
                             g_csi_params.csi_filter[i].mac_addr[4], g_csi_params.csi_filter[i].mac_addr[5]);

                (void)printf("pkt_type      : %d \r\n", g_csi_params.csi_filter[i].pkt_type);
                (void)printf("subtype       : %d \r\n", g_csi_params.csi_filter[i].subtype);
                (void)printf("flags         : %d \r\n", g_csi_params.csi_filter[i].flags);
                (void)printf("\r\n");
            }
            break;

        default:
            (void)printf("unknown argument!\r\n");
            break;
    }

    return TRUE;
}

int wlan_set_csi_param_header_command(int argc, char **argv)
{
    uint8_t bss_type           = 0;
    uint16_t csi_enable        = 0;
    uint32_t head_id           = 0;
    uint32_t tail_id           = 0;
    uint8_t chip_id            = 0;
    uint8_t band_config        = 0;
    uint8_t channel            = 0;
    uint8_t csi_monitor_enable = 0;
    uint8_t ra4us              = 0;

    if (argc != 10)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf(
            "Usage: %s <sta/uap> <csi_enable> <head_id> <tail_id> <chip_id> <band_config> <channel> <csi_monitor_enable> "
            "<ra4us>\r\n\r\n",
            argv[0]);

        (void)printf("[csi_enable] :1/2 to Enable/Disable CSI\r\n");
        (void)printf("[head_id, head_id, chip_id] are used to seperate CSI event records received from FW\r\n");
        (void)printf(
            "[Bandcfg] defined as below: \r\n"
            "    Band Info - (00)=2.4GHz, (01)=5GHz \r\n"
            "    uint8_t  chanBand    : 2;\r\n"
            "    Channel Width - (00)=20MHz, (10)=40MHz, (11)=80MHz\r\n"
            "    uint8_t  chanWidth   : 2;\r\n"
            "    Secondary Channel Offset - (00)=None, (01)=Above, (11)=Below\r\n"
            "    uint8_t  chan2Offset : 2;\r\n"
            "    Channel Selection Mode - (00)=manual, (01)=ACS, (02)=Adoption mode\r\n"
            "    uint8_t  scanMode    : 2;\r\n");
        (void)printf("[channel] : monitor channel number\r\n");
        (void)printf("[csi_monitor_enable] : 1-csi_monitor enable, 0-MAC filter enable\r\n");
        (void)printf(
            "[ra4us] : 1/0 to Enable/Disable CSI data received in cfg channel with mac addr filter, not only RA is "
            "us or other\r\n");

        (void)printf("\r\nUsage example : \r\n");
        (void)printf("wlan-set-csi-param-header sta 1 66051 66051 170 0 11 1 1\r\n");

        dump_csi_param_header();

        return FALSE;
    }

    /*
     * csi param header headid, tailid, chipid are used to seperate CSI event records received from FW.
     * FW adds user configured headid, chipid and tailid for each CSI event record.
     * User could configure these fields and used these fields to parse CSI event buffer and do verification.
     * All the CSI filters share the same CSI param header.
     */
    if (string_equal("sta", argv[1]))
        bss_type = 0;
    else if (string_equal("uap", argv[1]))
        bss_type = 1;
    else
    {
        (void)printf("Please put sta or uap\r\n");
        return FALSE;
    }
    csi_enable         = (uint16_t)atoi(argv[2]);
    head_id            = (uint32_t)atoi(argv[3]);
    tail_id            = (uint32_t)atoi(argv[4]);
    chip_id            = (uint8_t)atoi(argv[5]);
    band_config        = (uint8_t)atoi(argv[6]);
    channel            = (uint8_t)atoi(argv[7]);
    csi_monitor_enable = (uint8_t)atoi(argv[8]);
    ra4us              = (uint8_t)atoi(argv[9]);

    set_csi_param_header(bss_type, csi_enable, head_id, tail_id, chip_id, band_config, channel, csi_monitor_enable, ra4us);

    return TRUE;
}

int wlan_set_csi_filter_command(int argc, char **argv)
{
    int ret = TRUE;
    uint8_t raw_mac[NCP_WLAN_MAC_ADDR_LENGTH];
    uint8_t pkt_type = 0;
    uint8_t subtype  = 0;
    uint8_t flags    = 0;
    int op_index     = 0;

    if (argc < 2)
    {
        dump_wlan_csi_filter_usage();
        return FALSE;
    }

    if (string_equal("add", argv[1]))
    {
        if (6 == argc)
        {
            ret = get_mac(argv[2], (char *)raw_mac, ':');
            if (ret != 0)
            {
                (void)printf("Error: invalid MAC argument\r\n");
                return FALSE;
            }
            if ((memcmp(&raw_mac[0], broadcast_mac, NCP_WLAN_MAC_ADDR_LENGTH) == 0) || (raw_mac[0] & 0x01))
            {
                (void)printf("Error: only support unicast mac\r\n");
                return FALSE;
            }

            /*
             * pkt_type and subtype are the 802.11 framecontrol pkttype and subtype
             * flags:
             * bit0 reserved, must be 0
             * bit1 set to 1: wait for trigger
             * bit2 set to 1: send csi error event when timeout
             */
            pkt_type = (uint8_t)atoi(argv[3]);
            subtype  = (uint8_t)atoi(argv[4]);
            flags    = (uint8_t)atoi(argv[5]);

            op_index = CSI_FILTER_OPT_ADD;
        }
        else
        {
            dump_wlan_csi_filter_usage();
            return FALSE;
        }
    }
    else if (string_equal("delete", argv[1]))
        op_index = CSI_FILTER_OPT_DELETE;
    else if (string_equal("clear", argv[1]))
        op_index = CSI_FILTER_OPT_CLEAR;
    else if (string_equal("dump", argv[1]))
        op_index = CSI_FILTER_OPT_DUMP;
    else
    {
        (void)printf("Unknown argument!\r\n");
        return FALSE;
    }

    ret = set_csi_filter(pkt_type, subtype, flags, op_index, raw_mac);

    return ret;
}

int wlan_csi_cfg_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *csi_command = mpu_host_get_wifi_command_buffer();
    csi_command->header.cmd        = NCP_CMD_WLAN_STA_CSI;
    csi_command->header.size       = NCP_CMD_HEADER_LEN;
    csi_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_CSI *csi_cfg = (NCP_CMD_CSI *)&csi_command->params.csi_cfg;
    memcpy(&csi_cfg->csi_para, &g_csi_params, sizeof(g_csi_params));
    csi_command->header.size += sizeof(NCP_CMD_CSI);

    return TRUE;
}

/**
 * @brief      This function processes csi response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_csi_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("CSI cfg is success!\r\n");
        return TRUE;
    }
    else
        printf("CSI cfg is fail!\r\n");
    return TRUE;
}

int wlan_11k_cfg_command(int argc, char **argv)
{
    int enable_11k;

    if (argc != 2)
    {
        printf("Usage: %s <0/1> < 0--disable 11k; 1---enable 11k>\r\n", argv[0]);
        return FALSE;
    }

    enable_11k = atoi(argv[1]);

    NCPCmd_DS_COMMAND *wlan_11k_cfg_command = mpu_host_get_wifi_command_buffer();
    wlan_11k_cfg_command->header.cmd        = NCP_CMD_WLAN_STA_11K_CFG;
    wlan_11k_cfg_command->header.size       = NCP_CMD_HEADER_LEN;
    wlan_11k_cfg_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_11K_CFG *wlan_11k_cfg = (NCP_CMD_11K_CFG *)&wlan_11k_cfg_command->params.wlan_11k_cfg;
    wlan_11k_cfg->enable          = enable_11k;
    wlan_11k_cfg_command->header.size += sizeof(NCP_CMD_11K_CFG);

    return TRUE;
}

int wlan_11k_neighbor_req_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *neighbor_req_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)neighbor_req_command, 0, NCP_COMMAND_LEN);
    neighbor_req_command->header.cmd      = NCP_CMD_WLAN_STA_NEIGHBOR_REQ;
    neighbor_req_command->header.size     = NCP_CMD_HEADER_LEN;
    neighbor_req_command->header.result   = NCP_CMD_RESULT_OK;

    if ((argc != 1 && argc != 3) || (argc == 3 && !string_equal("ssid", argv[1])))
    {
        printf("Usage: %s\r\n", argv[0]);
        printf("or     %s ssid <ssid>\r\n", argv[0]);
        return FALSE;
    }

    if (argc == 1)
    {
        return TRUE;
    }
    else if (argc == 3)
    {
        if (strlen(argv[2]) > 32)
        {
            printf("Error: ssid too long\r\n");
            return FALSE;
        }
        else
        {
            NCP_CMD_NEIGHBOR_REQ *neighbor_req = (NCP_CMD_NEIGHBOR_REQ *)&neighbor_req_command->params.neighbor_req;
            neighbor_req->ssid_tlv.header.type = NCP_CMD_NETWORK_SSID_TLV;
            neighbor_req->ssid_tlv.header.size = strlen(argv[2]);

            neighbor_req_command->header.size += strlen(argv[2]) + NCP_TLV_HEADER_LEN;
            (void)memcpy(neighbor_req->ssid_tlv.ssid, argv[2], strlen(argv[2]));
        }
    }

    return TRUE;
}

int wlan_process_11k_cfg_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("11k cfg is success!\r\n");
        return TRUE;
    }
    else
        printf("11k cfg is fail!\r\n");
    return TRUE;
}

int wlan_process_neighbor_req_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("neighbor_req is success!\r\n");
        return TRUE;
    }
    else
        printf("neighbor_req is fail!\r\n");
    return TRUE;
}

int wlan_get_signal_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *get_signal_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)get_signal_command, 0, NCP_COMMAND_LEN);

    get_signal_command->header.cmd      = NCP_CMD_WLAN_STA_SIGNAL;
    get_signal_command->header.size     = NCP_CMD_HEADER_LEN;
    get_signal_command->header.result   = NCP_CMD_RESULT_OK;

    return TRUE;
}

int wlan_process_rssi_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("Cann't get RSSI information in disconnect state.\r\n");
        return TRUE;
    }

    NCP_CMD_RSSI *signal_rssi = (NCP_CMD_RSSI *)&cmd_res->params.signal_rssi;
    (void)printf("\tBeaconLast\tBeacon Average\tData Last\tData Average\n");
    (void)printf("RSSI\t%-10d \t%-10d \t%-10d \t%-10d\n", (int)signal_rssi->rssi_info.bcn_rssi_last,
                 (int)signal_rssi->rssi_info.bcn_rssi_avg, (int)signal_rssi->rssi_info.data_rssi_last,
                 (int)signal_rssi->rssi_info.data_rssi_avg);
    (void)printf("SNR \t%-10d \t%-10d \t%-10d \t%-10d\n", (int)signal_rssi->rssi_info.bcn_snr_last,
                 (int)signal_rssi->rssi_info.bcn_snr_avg, (int)signal_rssi->rssi_info.data_snr_last,
                 (int)signal_rssi->rssi_info.data_snr_avg);
    (void)printf("NF  \t%-10d \t%-10d \t%-10d \t%-10d\n", (int)signal_rssi->rssi_info.bcn_nf_last,
                 (int)signal_rssi->rssi_info.bcn_nf_avg, (int)signal_rssi->rssi_info.data_nf_last,
                 (int)signal_rssi->rssi_info.data_nf_avg);
    (void)printf("\r\n");
    return TRUE;
}

uint8_t ncp_device_status = NCP_DEVICE_STATUS_ACTIVE;

static void dump_wlan_multi_mef_command(const char *str)
{
    printf("Usage: %s <type> <action>\r\n", str);
    printf("      <type>   : ping/arp/multicast/ns\r\n");
    printf("                     - MEF entry type, will add one mef entry at a time\r\n");
    printf("                 del - Delete all previous MEF entries\r\n");
    printf("                       <action> is not needed for this type\r\n");
    printf("      <action> : 0 - discard and not wake host\r\n");
    printf("                 1 - discard and wake host\r\n");
    printf("                 3 - allow and wake host\r\n");
    return;
}

int wlan_multi_mef_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *mef_command = mpu_host_get_wifi_command_buffer();
    int type                       = MEF_TYPE_END;
    uint8_t action                 = 0;

    if (argc < 2 || argc > 3)
    {
        dump_wlan_multi_mef_command(argv[0]);
        return FALSE;
    }

    if (argc == 2)
    {
        if (string_equal("del", argv[1]))
            type = MEF_TYPE_DELETE;
        else
        {
            printf("Invalid type!\r\n");
            dump_wlan_multi_mef_command(argv[0]);
            return FALSE;
        }
    }
    else if (argc == 3)
    {
        if (string_equal("ping", argv[1]))
            type = MEF_TYPE_PING;
        else if (string_equal("arp", argv[1]))
            type = MEF_TYPE_ARP;
        else if (string_equal("multicast", argv[1]))
            type = MEF_TYPE_MULTICAST;
        else if (string_equal("ns", argv[1]))
            type = MEF_TYPE_IPV6_NS;
        else
        {
            printf("Invalid type!\r\n");
            dump_wlan_multi_mef_command(argv[0]);
            return FALSE;
        }
        action = (uint8_t)atoi(argv[2]);
        if (action != 0 && action != 1 && action != 3)
        {
            printf("Invalid action!\r\n");
            dump_wlan_multi_mef_command(argv[0]);
            return FALSE;
        }
    }

    mef_command->header.cmd      = NCP_CMD_WLAN_POWERMGMT_MEF;
    mef_command->header.size     = NCP_CMD_HEADER_LEN;
    mef_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_POWERMGMT_MEF *mef_config = (NCP_CMD_POWERMGMT_MEF *)&mef_command->params.mef_config;
    mef_config->type                  = type;
    if (argc == 3)
        mef_config->action = action;
    mef_command->header.size += sizeof(NCP_CMD_POWERMGMT_MEF);
    return TRUE;
}

int wlan_process_multi_mef_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    uint16_t result            = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_OK)
        printf("multi MEF cfg is success!\r\n");
    else if (result == WM_E_PERM)
        printf("Failed to get IPv4 address!\r\n");
    else if (result == WM_E_2BIG)
        printf("Number of MEF entries exceeds limit(8)\r\n");
    else
        printf("multi MEF cfg is fail!\r\n");
    return TRUE;
}

int wlan_process_wake_mode_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    uint16_t result            = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_OK)
        printf("Wake mode cfg is successful!\r\n");
    else
        printf("Wake mode cfg is failed!\r\n");

    return WM_SUCCESS;
}

int wlan_wakeup_condition_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wowlan_cfg_cmd = mpu_host_get_wifi_command_buffer();
    uint8_t is_mef                    = false;
    uint32_t wake_up_conds            = 0;

    if (argc < 2 || argc > 3)
    {
        printf("Error: invalid number of arguments\r\n");
        printf("Usage:\r\n");
        printf("    %s <wowlan [wake_up_conds]>/<mef>\r\n", argv[0]);
        printf("    wowlan -- default wowlan conditions\r\n");
        printf("    [wake_up_conds] -- value for default wowlan conditions only\r\n");
        printf("              bit 0: WAKE_ON_ALL_BROADCAST\r\n");
        printf("              bit 1: WAKE_ON_UNICAST\r\n");
        printf("              bit 2: WAKE_ON_MAC_EVENT\r\n");
        printf("              bit 3: WAKE_ON_MULTICAST\r\n");
        printf("              bit 4: WAKE_ON_ARP_BROADCAST\r\n");
        printf("              bit 6: WAKE_ON_MGMT_FRAME\r\n");
        printf("              All bit 0 discard and not wakeup host\r\n");
        printf("    mef     -- MEF wowlan condition\r\n");
        printf("Example:\r\n");
        printf("    %s mef\r\n", argv[0]);
        printf("    %s wowlan 0x1e\r\n", argv[0]);
        return -WM_FAIL;
    }
    if (string_equal("mef", argv[1]))
        is_mef = true;
    else if (string_equal("wowlan", argv[1]))
    {
        if (argc < 3)
        {
            printf("wake_up_conds need be specified\r\n");
            return -WM_FAIL;
        }
        wake_up_conds = a2hex_or_atoi(argv[2]);
    }
    else
    {
        printf("Invalid wakeup condition.\r\n");
        return -WM_FAIL;
    }
    wowlan_cfg_cmd->header.cmd                  = NCP_CMD_WLAN_POWERMGMT_WOWLAN_CFG;
    wowlan_cfg_cmd->header.size                 = NCP_CMD_HEADER_LEN;
    wowlan_cfg_cmd->header.result               = NCP_CMD_RESULT_OK;
    NCP_CMD_POWERMGMT_WOWLAN_CFG *wowlan_config = (NCP_CMD_POWERMGMT_WOWLAN_CFG *)&wowlan_cfg_cmd->params.wowlan_config;
    wowlan_config->is_mef                       = is_mef;
    wowlan_config->wake_up_conds                = wake_up_conds;
    wowlan_cfg_cmd->header.size += sizeof(NCP_CMD_POWERMGMT_WOWLAN_CFG);

    global_power_config.is_mef        = is_mef;
    global_power_config.wake_up_conds = wake_up_conds;

    return WM_SUCCESS;
}

int wlan_process_wakeup_condition_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    uint16_t result            = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_OK)
        printf("Wowlan cfg is successful!\r\n");
    else
    {
        printf("Wowlan cfg is failed!\r\n");
        /* Clear corresponding setting if failed */
        global_power_config.is_mef        = 0;
        global_power_config.wake_up_conds = 0;
    }

    return WM_SUCCESS;
}

int wlan_process_mcu_sleep_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    uint16_t result            = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_OK)
    {
        printf("mcu sleep cfg is success!\r\n");
        /* Clear previous power configs if mcu sleep is disabled */
        if (global_power_config.enable == 0)
            (void)memset(&global_power_config, 0x0, sizeof(global_power_config));
    }
    else
        printf("mcu sleep cfg is fail!\r\n");

    return WM_SUCCESS;
}

#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
int wlan_suspend_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *suspend_command = mpu_host_get_wifi_command_buffer();
    int mode                           = 0;

    if (!global_power_config.is_manual)
    {
        printf("Suspend command is not allowed because manual method is not selected\r\n");
        return -WM_FAIL;
    }
    if (argc != 2)
    {
        printf("Error: invalid number of arguments\r\n");
        printf("Usage:\r\n");
        printf("    wlan-suspend <power mode>\r\n");
        printf("    1:PM1 2:PM2\r\n");
        printf("Example:\r\n");
        printf("    wlan-suspend 2\r\n");
        return -WM_FAIL;
    }
    mode = atoi(argv[1]);
    if (mode < 1 || mode > 3)
    {
        printf("Invalid low power mode\r\n");
        printf("Only PM1/PM2 supported here\r\n");
        return -WM_FAIL;
    }

    suspend_command->header.cmd               = NCP_CMD_WLAN_POWERMGMT_SUSPEND;
    suspend_command->header.size              = NCP_CMD_HEADER_LEN;
    suspend_command->header.result            = NCP_CMD_RESULT_OK;
    NCP_CMD_POWERMGMT_SUSPEND *suspend_config = (NCP_CMD_POWERMGMT_SUSPEND *)&suspend_command->params.suspend_config;
    suspend_config->mode                      = mode;
    suspend_command->header.size += sizeof(NCP_CMD_POWERMGMT_SUSPEND);

    return WM_SUCCESS;
}

int wlan_process_suspend_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    uint16_t result            = cmd_res->header.result;

    if (result == NCP_CMD_RESULT_ERROR)
    {
        printf("suspend command is failed\r\n");
        printf("PM1/2 allowed with INTF mode\r\n");
        printf("If NCP device is RDRW612:\r\n");
        printf("    PM1/2/3 allowed with GPIO mode\r\n");
        printf("If NCP device is FRDMRW612:\r\n");
        printf("    PM1/2 allowed with GPIO mode\r\n");
        printf("    PM1/2/3 allowed with WIFI-NB mode\r\n");
    }
    else
        printf("suspend command is successful\r\n");

    return WM_SUCCESS;
}
#endif

int wlan_set_wmm_uapsd_command(int argc, char **argv)
{
    int enable_uapsd;

    if (argc != 2)
    {
        printf("Usage: %s <0/1> < 0--disable UAPSD; 1---enable UAPSD>\r\n", argv[0]);
        return FALSE;
    }

    enable_uapsd = atoi(argv[1]);

    NCPCmd_DS_COMMAND *uapsd_command = mpu_host_get_wifi_command_buffer();
    uapsd_command->header.cmd        = NCP_CMD_WLAN_POWERMGMT_UAPSD;
    uapsd_command->header.size       = NCP_CMD_HEADER_LEN;
    uapsd_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_POWERMGMT_UAPSD *wlan_uapsd_cfg = (NCP_CMD_POWERMGMT_UAPSD *)&uapsd_command->params.uapsd_cfg;
    wlan_uapsd_cfg->enable                  = enable_uapsd;
    uapsd_command->header.size += sizeof(NCP_CMD_POWERMGMT_UAPSD);

    return TRUE;
}

int wlan_process_wmm_uapsd_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        printf("UAPSD cfg is success!\r\n");
    else
        printf("UAPSD cfg is fail!\r\n");

    return TRUE;
}

int wlan_wmm_uapsd_qosinfo_command(int argc, char **argv)
{
    uint8_t qos_info = 0;

    if (argc != 1 && argc != 2)
    {
        printf("Usage: %s <null | qos_info>\r\n", argv[0]);
        printf("bit0:VO; bit1:VI; bit2:BK; bit3:BE\r\n");
        return FALSE;
    }

    if (argc == 2)
        qos_info = atoi(argv[1]);

    NCPCmd_DS_COMMAND *qosinfo_command = mpu_host_get_wifi_command_buffer();
    qosinfo_command->header.cmd        = NCP_CMD_WLAN_POWERMGMT_QOSINFO;
    qosinfo_command->header.size       = NCP_CMD_HEADER_LEN;
    qosinfo_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_POWERMGMT_QOSINFO *qosinfo_cfg = (NCP_CMD_POWERMGMT_QOSINFO *)&qosinfo_command->params.qosinfo_cfg;
    qosinfo_cfg->qos_info                  = qos_info;
    if (argc == 1)
        qosinfo_cfg->action = 0;
    else
        qosinfo_cfg->action = 1;

    qosinfo_command->header.size += sizeof(NCP_CMD_POWERMGMT_QOSINFO);

    return TRUE;
}

int wlan_process_uapsd_qosinfo_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res             = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_POWERMGMT_QOSINFO *qosinfo_cfg = (NCP_CMD_POWERMGMT_QOSINFO *)&cmd_res->params.qosinfo_cfg;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        printf("qosinfo is %u\r\n", qosinfo_cfg->qos_info);
    else
        printf("qosinfo cfg is fail!\r\n");

    return TRUE;
}

int wlan_uapsd_sleep_period_command(int argc, char **argv)
{
    uint32_t period = 0;

    if (argc != 1 && argc != 2)
    {
        printf("Usage: %s <null | period(ms)>\r\n", argv[0]);
        return FALSE;
    }

    if (argc == 2)
        period = atoi(argv[1]);

    NCPCmd_DS_COMMAND *sleep_period_command = mpu_host_get_wifi_command_buffer();
    sleep_period_command->header.cmd        = NCP_CMD_WLAN_POWERMGMT_SLEEP_PERIOD;
    sleep_period_command->header.size       = NCP_CMD_HEADER_LEN;
    sleep_period_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_POWERMGMT_SLEEP_PERIOD *sleep_period_cfg =
        (NCP_CMD_POWERMGMT_SLEEP_PERIOD *)&sleep_period_command->params.sleep_period_cfg;
    sleep_period_cfg->period = period;
    if (argc == 1)
        sleep_period_cfg->action = 0;
    else
        sleep_period_cfg->action = 1;

    sleep_period_command->header.size += sizeof(NCP_CMD_POWERMGMT_SLEEP_PERIOD);

    return TRUE;
}

int wlan_process_uapsd_sleep_period_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_POWERMGMT_SLEEP_PERIOD *sleep_period_cfg =
        (NCP_CMD_POWERMGMT_SLEEP_PERIOD *)&cmd_res->params.sleep_period_cfg;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        printf("sleep period is %u\r\n", sleep_period_cfg->period);
    else
        printf("sleep period cfg is fail!\r\n");

    return TRUE;
}

NCP_CMD_11AX_CFG_INFO g_11axcfg_params = {
    /* band */
    0x03,
    {/* tlv header */
     {0x00ff, 0x0018},
     /* extension id */
     0x23,
     /* he mac cap */
     {0x03, 0x08, 0x00, 0x82, 0x00, 0x00},
     /* he phy cap */
     {0x40, 0x50, 0x42, 0x49, 0x0d, 0x00, 0x20, 0x1e, 0x17, 0x31, 0x00},
     /* he txrx mcs support */
     {0xfd, 0xff, 0xfd, 0xff},
     /* val for txrx mcs 160Mhz or 80+80, and PPE thresholds */
     {0x88, 0x1f}}};

NCP_CMD_TWT_SETUP_CFG g_twt_setup_params = {.implicit            = 0x01,
                                        .announced           = 0x00,
                                        .trigger_enabled     = 0x00,
                                        .twt_info_disabled   = 0x01,
                                        .negotiation_type    = 0x00,
                                        .twt_wakeup_duration = 0x40,
                                        .flow_identifier     = 0x00,
                                        .hard_constraint     = 0x01,
                                        .twt_exponent        = 0x0a,
                                        .twt_mantissa        = 0x0200,
                                        .twt_request         = 0x00};

NCP_CMD_TWT_TEARDOWN_CFG g_twt_teardown_params = {
    .flow_identifier = 0x00, .negotiation_type = 0x00, .teardown_all_twt = 0x00};

/* index enum of cfgs */
enum
{
    TEST_WLAN_11AX_CFG,
    TEST_WLAN_TWT_SETUP,
    TEST_WLAN_TWT_TEARDOWN,
};

/*
 *  Structs for mutiple config data in freeRTOS, split cfg to various param modules.
 *  Modify cfg data by param index
 *  test_cfg_param_t param module of cfg
 *  test_cfg_table_t cfg table for all the param modules of a cfg
 */
typedef struct
{
    /* name of param */
    const char *name;
    /* offset in cfg data */
    int offset;
    int len;
    const char *notes;
} test_cfg_param_t;

typedef struct
{
    /* name of cfg */
    const char *name;
    /* point of stored data for sending cmd, stored in Little-Endian */
    uint8_t *data;
    /* len of data */
    int len;
    /* point of list for all the params */
    const test_cfg_param_t *param_list;
    /* total number of params */
    int param_num;
} test_cfg_table_t;

const static test_cfg_param_t g_11ax_cfg_param[] = {
    /* name                 offset  len     notes */
    {"band", 0, 1, NULL},
    {"cap_id", 1, 2, NULL},
    {"cap_len", 3, 2, NULL},
    {"he_cap_id", 5, 1, NULL},
    {"he_mac_cap_info", 6, 6, NULL},
    {"he_phy_cap_info", 12, 11, NULL},
    {"he_mcs_nss_support", 23, 4, NULL},
    {"pe", 27, 2, NULL},
};

static test_cfg_param_t g_twt_setup_cfg_param[] = {
    /* name                 offset  len  notes */
    {"implicit", 0, 1, "0: TWT session is explicit, 1: Session is implicit"},
    {"announced", 1, 1, "0: Unannounced, 1: Announced TWT"},
    {"trigger_enabled", 2, 1, "0: Non-Trigger enabled, 1: Trigger enabled TWT"},
    {"twt_info_disabled", 3, 1, "0: TWT info enabled, 1: TWT info disabled"},
    {"negotiation_type", 4, 1, "0: Individual TWT, 3: Broadcast TWT"},
    {"twt_wakeup_duration", 5, 1, "time after which the TWT requesting STA can transition to doze state"},
    {"flow_identifier", 6, 1, "Range: [0-7]"},
    {"hard_constraint", 7, 1,
     "0: FW can tweak the TWT setup parameters if it is rejected by AP, 1: FW should not tweak any parameters"},
    {"twt_exponent", 8, 1, "Range: [0-63]"},
    {"twt_mantissa", 9, 2, "Range: [0-sizeof(UINT16)]"},
    {"twt_request", 11, 1, "Type, 0: REQUEST_TWT, 1: SUGGEST_TWT"},
};

static test_cfg_param_t g_twt_teardown_cfg_param[] = {
    /* name             offset  len  notes */
    {"FlowIdentifier", 0, 1, "Range: [0-7]"},
    {"NegotiationType", 1, 1, "0: Future Individual TWT SP start time, 1: Next Wake TBTT tim"},
    {"TearDownAllTWT", 2, 1, "1: To teardown all TWT, 0 otherwise"},
};

/*
 *  Cfg table for mutiple params commands in freeRTOS.
 *  name:          cfg name
 *  data:          cfg data stored and prepared to send
 *  total_len:     len of cfg data
 *  param_list:    param list of cfg data
 *  param_num:     number of cfg param list
 */
static test_cfg_table_t g_test_cfg_table_list[] = {
    /*  name         data                          total_len param_list          param_num*/
    {"11axcfg",      (uint8_t *)&g_11axcfg_params,      29,  g_11ax_cfg_param,         8},
    {"twt_setup",    (uint8_t *)&g_twt_setup_params,    12,  g_twt_setup_cfg_param,    11},
    {"twt_teardown", (uint8_t *)&g_twt_teardown_params, 3,   g_twt_teardown_cfg_param, 3},
    {NULL}};

static int wlan_send_11axcfg_command(void)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_11AX_CFG;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    (void)memcpy((uint8_t *)&command->params.he_cfg, (uint8_t *)&g_11axcfg_params, sizeof(g_11axcfg_params));
    command->header.size += sizeof(g_11axcfg_params);

    return TRUE;
}

int wlan_process_11axcfg_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    (void)printf("11ax cfg set ret %hu\r\n", cmd_res->header.result);
    return TRUE;
}

static int wlan_send_btwt_command(uint8_t *data)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_BTWT_CFG;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    (void)memcpy((uint8_t *)&command->params.btwt_cfg, data, sizeof(NCP_CMD_BTWT_CFG_INFO));
    command->header.size += sizeof(NCP_CMD_BTWT_CFG_INFO);

    return TRUE;
}

int wlan_process_btwt_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_BTWT_CFG_INFO *btwt = (NCP_CMD_BTWT_CFG_INFO *)&cmd_res->params.btwt_cfg;
    ncp_btwt_set_t *cfg;
    int i;

    if (btwt->action == ACTION_GET && cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        (void)printf("btwt cfg count %d:\r\n", btwt->count);
        for (i = 0; i < btwt->count; i++)
        {
            cfg = &btwt->btwt_sets[i];
            (void)printf("id[%d] mantissa[%d] exponent[%d] nominal_wake[%d]\r\n",
                cfg->btwt_id, cfg->bcast_mantissa, cfg->bcast_exponent, cfg->nominal_wake);
        }
    }
    else
    {
        (void)printf("btwt cfg action %d ret %hu\r\n", btwt->action, cmd_res->header.result);
    }
    return TRUE;
}

static int wlan_send_twt_setup_command(void)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_TWT_SETUP;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    (void)memcpy((uint8_t *)&command->params.twt_setup, (uint8_t *)&g_twt_setup_params, sizeof(g_twt_setup_params));
    command->header.size += sizeof(g_twt_setup_params);

    return TRUE;
}

int wlan_process_twt_setup_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    (void)printf("twt setup set ret %hu\r\n", cmd_res->header.result);
    return TRUE;
}

static int wlan_send_twt_teardown_command(void)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_TWT_TEARDOWN;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    (void)memcpy((uint8_t *)&command->params.he_cfg, (uint8_t *)&g_twt_teardown_params, sizeof(g_twt_teardown_params));
    command->header.size += sizeof(g_twt_teardown_params);

    return TRUE;
}

int wlan_process_twt_teardown_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    (void)printf("11ax cfg set ret %hu\r\n", cmd_res->header.result);
    return TRUE;
}

int wlan_get_twt_report_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_TWT_GET_REPORT;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    return TRUE;
}

int wlan_process_twt_report_response(uint8_t *res)
{
    int i;
    NCPCmd_DS_COMMAND *cmd_res    = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_TWT_REPORT twt_report = {0};

    if (cmd_res->header.result == NCP_CMD_RESULT_OK &&
        cmd_res->header.size >= NCP_CMD_HEADER_LEN + sizeof(twt_report))
    {
        /* TODO: sensable var */
        (void)memcpy((uint8_t *)&twt_report, (uint8_t *)&cmd_res->params.twt_report, sizeof(twt_report));

        (void)printf("get twt report:\r\n");
        for (i = 0; i < 4; i++)
        {
            (void)printf(
                "twt id[%d]: type[%d] len[%d] request_type[0x%x] target_wake_time[%d]"
                " nominal_min_wake_duration[%d] wake_interval_mantissa[%d] twt_info[0x%x]\r\n",
                i, twt_report.type, twt_report.length, twt_report.info[i].request_type,
                twt_report.info[i].target_wake_time, twt_report.info[i].nominal_min_wake_duration,
                twt_report.info[i].wake_interval_mantissa, twt_report.info[i].twt_info);
        }
    }
    else
    {
        (void)printf("get twt report fail\r\n");
    }
    return TRUE;
}

static void dump_cfg_data_param(int param_id, uint8_t *data, const test_cfg_param_t *param_cfg)
{
    int i;

    (void)printf("%s ", param_cfg->name);
    if (param_cfg->notes != NULL)
        (void)printf("#### %s\r\n", param_cfg->notes);
    else
        (void)printf("\r\n");

    (void)printf("[%d]: ", param_id);
    for (i = 0; i < param_cfg->len; i++)
    {
        (void)printf("0x%02x ", data[param_cfg->offset + i]);
    }
    (void)printf("\r\n");
}

static void set_cfg_data_param(uint8_t *data, const test_cfg_param_t *param_cfg, char **argv)
{
    int i;

    for (i = 0; i < param_cfg->len; i++)
    {
        data[param_cfg->offset + i] = a2hex(argv[3 + i]);
    }
}

static void dump_cfg_data(test_cfg_table_t *cfg)
{
    int i;
    uint8_t *data = cfg->data;

    (void)printf("cfg[%s] len[%d] param_num[%d]: \r\n", cfg->name, cfg->len, cfg->param_num);
    for (i = 0; i < cfg->param_num; i++)
    {
        dump_cfg_data_param(i, data, &cfg->param_list[i]);
    }
}

static void dump_cfg_help(test_cfg_table_t *cfg)
{
    dump_cfg_data(cfg);
}

/*
 *  match param name and set data by input
 *  argv[0] "wlan-xxxx"
 *  argv[1] "set"
 *  argv[2] param_id
 *  argv[3] param_data_set
 */
static void set_cfg_data(test_cfg_table_t *cfg, int argc, char **argv)
{
    uint8_t *data                     = cfg->data;
    const test_cfg_param_t *param_cfg = NULL;
    int param_id                      = atoi(argv[2]);
    /* input data starts from argv[3] */
    int input_data_num = argc - 3;

    if (param_id < 0 || param_id >= cfg->param_num)
    {
        (void)printf("invalid param index %d\r\n", param_id);
        return;
    }

    param_cfg = &cfg->param_list[param_id];
    if (param_cfg->len != input_data_num)
    {
        (void)printf("invalid input number %d, param has %d u8 arguments\r\n", input_data_num, param_cfg->len);
        return;
    }

    set_cfg_data_param(data, param_cfg, argv);
    dump_cfg_data_param(param_id, data, param_cfg);
}

static void send_cfg_msg(test_cfg_table_t *cfg, uint32_t index)
{
    int ret;

    switch (index)
    {
        case TEST_WLAN_11AX_CFG:
            ret = wlan_send_11axcfg_command();
            break;
        case TEST_WLAN_TWT_SETUP:
            ret = wlan_send_twt_setup_command();
            break;
        case TEST_WLAN_TWT_TEARDOWN:
            ret = wlan_send_twt_teardown_command();
            break;
        default:
            ret = -1;
            break;
    }

    (void)printf("send config [%s] ret %d\r\n", cfg->name, ret);
}

static void test_wlan_cfg_process(uint32_t index, int argc, char **argv)
{
    test_cfg_table_t *cfg = NULL;

    /* last cfg table is invalid */
    if (index >= (sizeof(g_test_cfg_table_list) / sizeof(test_cfg_table_t) - 1))
    {
        (void)printf("cfg table too large index %u\r\n", index);
        return;
    }

    cfg = &g_test_cfg_table_list[index];

    if (argc < 2)
    {
        dump_cfg_help(cfg);
        return;
    }

    if (string_equal("help", argv[1]))
        dump_cfg_help(cfg);
    else if (string_equal("dump", argv[1]))
        dump_cfg_data(cfg);
    else if (string_equal("set", argv[1]))
        set_cfg_data(cfg, argc, argv);
    else if (string_equal("done", argv[1]))
        send_cfg_msg(cfg, index);
    else
        (void)printf("unknown argument\r\n");
}

int wlan_set_11axcfg_command(int argc, char **argv)
{
    test_wlan_cfg_process(TEST_WLAN_11AX_CFG, argc, argv);
    return WM_SUCCESS;
}

static void dump_wlan_btwt_usage(void)
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-bcast-twt get\r\n");
    (void)printf("wlan-bcast-twt set <sta_wait> <offset> <twtli> <session_num>\
 <id0> <mantissa0> <exponent0> <nominal_wake0> <id1> <mantissa1> <exponent1> <nominal_wake1> ...\r\n");
    (void)printf("AP BTWT setting. \r\n");
    (void)printf("Note: If set cfg, session_num, the number of TWT sessions, range: [2-5]\r\n");
}

int wlan_bcast_twt_command(int argc, char **argv)
{
    int ret = 0;
    NCP_CMD_BTWT_CFG_INFO btwt_cfg = {0};
    int i;

    if (argc < 2)
    {
        dump_wlan_btwt_usage();
        return -WM_FAIL;
    }

    if (0 == strncmp(argv[1], "get", 3))
    {
        btwt_cfg.action = ACTION_GET;
        ret = wlan_send_btwt_command((uint8_t *)(void *)&btwt_cfg);
        (void)ret;
    }
    else if (0 == strncmp(argv[1], "set", 3))
    {
        btwt_cfg.action              = ACTION_SET;
        btwt_cfg.bcast_bet_sta_wait  = a2hex_or_atoi(argv[2]);
        btwt_cfg.bcast_offset        = a2hex_or_atoi(argv[3]);
        btwt_cfg.bcast_twtli         = a2hex_or_atoi(argv[4]);
        btwt_cfg.count               = a2hex_or_atoi(argv[5]);

        if (btwt_cfg.count < 2 || argc != 6 + 4 * btwt_cfg.count)
        {
            dump_wlan_btwt_usage();
            return -WM_FAIL;
        }

        for (i = 0; i < btwt_cfg.count; ++i)
        {
            btwt_cfg.btwt_sets[i].btwt_id        = a2hex_or_atoi(argv[6 + i * 4 + 0]);
            btwt_cfg.btwt_sets[i].bcast_mantissa = a2hex_or_atoi(argv[6 + i * 4 + 1]);
            btwt_cfg.btwt_sets[i].bcast_exponent = a2hex_or_atoi(argv[6 + i * 4 + 2]);
            btwt_cfg.btwt_sets[i].nominal_wake   = a2hex_or_atoi(argv[6 + i * 4 + 3]);
        }

        ret = wlan_send_btwt_command((uint8_t *)(void *)&btwt_cfg);
        (void)ret;
    }
    return WM_SUCCESS;
}

int wlan_twt_setup_command(int argc, char **argv)
{
    test_wlan_cfg_process(TEST_WLAN_TWT_SETUP, argc, argv);
    return WM_SUCCESS;
}

int wlan_twt_teardown_command(int argc, char **argv)
{
    test_wlan_cfg_process(TEST_WLAN_TWT_TEARDOWN, argc, argv);
    return WM_SUCCESS;
}

int wlan_set_11d_enable_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    if (argc != 3)
    {
        (void)printf("set 11d invalid argument\r\n");
        return FALSE;
    }

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_11D_ENABLE;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    if (string_equal(argv[1], "sta"))
    {
        command->params.wlan_11d_cfg.role = WLAN_BSS_ROLE_STA;
    }
    else if (string_equal(argv[1], "uap"))
    {
        command->params.wlan_11d_cfg.role = WLAN_BSS_ROLE_UAP;
    }
    else
    {
        (void)printf("set 11d invalid argument, please input sta/uap\r\n");
        return FALSE;
    }
    command->params.wlan_11d_cfg.state = atoi(argv[2]);
    command->header.size += sizeof(NCP_CMD_11D_ENABLE_CFG);

    return TRUE;
}

int wlan_process_11d_enable_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if(cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        (void)printf("Config successfully!\r\n");
    }
    else
    {
        (void)printf("config failed!\r\n");
    }
	
    return TRUE;
}

int wlan_region_code_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    if (argc < 2 || argc > 3)
    {
        (void)printf("region code argument\r\n");
        return FALSE;
    }

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_REGION_CODE;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    if (string_equal(argv[1], "get"))
    {
        command->params.region_cfg.action = 0;
    }
    else if (string_equal(argv[1], "set"))
    {
        command->params.region_cfg.action      = 1;
        command->params.region_cfg.region_code = strtol(argv[2], NULL, 0);
    }
    else
    {
        (void)printf("region code invalid argument, please input set/get\r\n");
        return FALSE;
    }
    command->header.size += sizeof(NCP_CMD_REGION_CODE_CFG);

    return TRUE;
}

int wlan_process_region_code_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res  = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_REGION_CODE_CFG *region = &cmd_res->params.region_cfg;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        if (region->action == 1)
            (void)printf("region code set 0x%x success\r\n", region->region_code);
        else
            (void)printf("region code get 0x%x\r\n", region->region_code);
    }
    else
    {
        (void)printf("region code get/set fail\r\n");
    }
    return TRUE;
}

int wlan_set_max_clients_count_command(int argc, char **argv)
{
    if (argc != 2)
    {
        (void)printf("Usage: %s  max_clients_count\r\n", argv[0]);
        return FALSE;
    }

    uint16_t max_sta_count = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_client_cnt_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)set_client_cnt_command, 0, NCP_COMMAND_LEN);

    set_client_cnt_command->header.cmd      = NCP_CMD_WLAN_UAP_MAX_CLIENT_CNT;
    set_client_cnt_command->header.size     = NCP_CMD_HEADER_LEN;
    set_client_cnt_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_CLIENT_CNT *sta_count = (NCP_CMD_CLIENT_CNT *)&set_client_cnt_command->params.max_client_count;
    sta_count->max_sta_count      = max_sta_count;
    sta_count->set_status         = WLAN_SET_MAX_CLIENT_CNT_SUCCESS;
    sta_count->support_count      = 0;

    set_client_cnt_command->header.size += sizeof(NCP_CMD_CLIENT_CNT);

    return TRUE;
}

int wlan_process_client_count_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res    = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_CLIENT_CNT *sta_count = (NCP_CMD_CLIENT_CNT *)&cmd_res->params.max_client_count;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        if (sta_count->set_status == WLAN_SET_MAX_CLIENT_CNT_START)
            printf("Failed to set max client count, already started an UAP.\r\n");
        else if (sta_count->set_status == WLAN_SET_MAX_CLIENT_CNT_EXCEED)
            printf("Failed to set max client count, the maxmium supported value is %d\r\n", sta_count->support_count);
        else
            printf("Failed to set max client count, wifidriver set this config failed.\r\n");
        return TRUE;
    }

    printf("Success to set max client count.\r\n");
    return TRUE;
}

static void dump_wlan_set_antenna_cfg_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-antenna-cfg <ant mode> [evaluate_time] \r\n");
    (void)printf("\r\n");
    (void)printf("\t<ant mode>: \r\n");
    (void)printf("\t           Bit 0   -- Tx/Rx antenna 1\r\n");
    (void)printf("\t           Bit 1   -- Tx/Rx antenna 2\r\n");
    (void)printf("\t           15  -- Tx/Rx antenna diversity\r\n");
    (void)printf("\t[evaluate_time]: \r\n");
    (void)printf("\t           if ant mode = 15, SAD evaluate time interval,\r\n");
    (void)printf("\t           default value is 6s(6000)\r\n");
}

int wlan_set_antenna_cfg_command(int argc, char **argv)
{
    unsigned int value;
    uint32_t ant_mode;
    uint16_t evaluate_time = 0;
    if (argc != 2 && argc != 3)
    {
        dump_wlan_set_antenna_cfg_usage();
        return FALSE;
    }

    if (get_uint(argv[1], &value, strlen(argv[1])) || (value != 1 && value != 2 && value != 0xF))
    {
        dump_wlan_set_antenna_cfg_usage();
        return FALSE;
    }

    ant_mode = value;
    if (argc == 3 && ant_mode != 0xF)
    {
        dump_wlan_set_antenna_cfg_usage();
        return FALSE;
    }

    if (ant_mode == 0xF)
    {
        if (get_uint(argv[2], &value, strlen(argv[2])))
        {
            dump_wlan_set_antenna_cfg_usage();
            return FALSE;
        }
        evaluate_time = value & 0XFF;
    }

    NCPCmd_DS_COMMAND *set_antenna_cfg_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)set_antenna_cfg_command, 0, NCP_COMMAND_LEN);

    set_antenna_cfg_command->header.cmd      = NCP_CMD_WLAN_STA_ANTENNA;
    set_antenna_cfg_command->header.size     = NCP_CMD_HEADER_LEN;
    set_antenna_cfg_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_ANTENNA_CFG *antenna_cfg = (NCP_CMD_ANTENNA_CFG *)&set_antenna_cfg_command->params.antenna_cfg;
    antenna_cfg->action              = ACTION_SET;
    if (ant_mode != 0xF)
        antenna_cfg->antenna_mode = ant_mode;
    else
        antenna_cfg->antenna_mode = 0xFFFF;
    antenna_cfg->evaluate_time = evaluate_time;

    set_antenna_cfg_command->header.size += sizeof(NCP_CMD_ANTENNA_CFG);

    return TRUE;
}

int wlan_get_antenna_cfg_command(int argc, char **argv)
{
    if (argc != 1)
    {
        (void)printf("Usage:\r\n");
        (void)printf("wlan-get-antcfg \r\n");
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_antenna_cfg_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)get_antenna_cfg_command, 0, NCP_COMMAND_LEN);

    get_antenna_cfg_command->header.cmd      = NCP_CMD_WLAN_STA_ANTENNA;
    get_antenna_cfg_command->header.size     = NCP_CMD_HEADER_LEN;
    get_antenna_cfg_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_ANTENNA_CFG *antenna_cfg = (NCP_CMD_ANTENNA_CFG *)&get_antenna_cfg_command->params.antenna_cfg;
    antenna_cfg->action              = ACTION_GET;
    antenna_cfg->antenna_mode        = 0;
    antenna_cfg->evaluate_time       = 0;

    get_antenna_cfg_command->header.size += sizeof(NCP_CMD_ANTENNA_CFG);

    return TRUE;
}

int wlan_process_antenna_cfg_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res       = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_ANTENNA_CFG *antenna_cfg = (NCP_CMD_ANTENNA_CFG *)&cmd_res->params.antenna_cfg;
    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        if (antenna_cfg->action == ACTION_SET)
            printf("Failed to set antenna config.\r\n");
        else
            printf("Failed to get antenna config.\r\n");
    }
    else
    {
        if (antenna_cfg->action == ACTION_SET)
            printf("Sucess to set antenna config.\r\n");
        else
        {
            printf("Mode of Tx/Rx path is : %x\r\n", antenna_cfg->antenna_mode);
            if (antenna_cfg->antenna_mode == 0xFFFF)
                printf("Evaluate time : %x\r\n", antenna_cfg->evaluate_time);
        }
    }
    return TRUE;
}

int wlan_process_deep_sleep_ps_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("Deep sleep ps is success!\r\n");
    }
    else
    {
        printf("Deep sleep ps is fail!\r\n");
    }
    return TRUE;
}

int wlan_process_ieee_ps_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        printf("IEEE ps is success!\r\n");
    }
    else
    {
        printf("IEEE ps is fail!\r\n");
    }
    return TRUE;
}

static void dump_wlan_reg_access_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("Read the register:\r\n");
    (void)printf("    wlan-reg-access <type> <offset>\r\n");
    (void)printf("Write the regiset:\r\n");
    (void)printf("    wlan-reg-access <type> <offset> <value>\r\n");
    (void)printf("Options: \r\n");
    (void)printf("    <type>  : 1:MAC, 2:BBP, 3:RF, 4:CAU\r\n");
    (void)printf("    <offset>: offset of register\r\n");
    (void)printf("For example:\r\n");
    (void)printf("    wlan-reg-access 1 0x9b8             : Read the MAC register\r\n");
    (void)printf("    wlan-reg-access 1 0x9b8 0x80000000 : Write 0x80000000 to MAC register\r\n");
}

int wlan_register_access_command(int argc, char **argv)
{
    uint16_t action;
    uint32_t type   = 0;
    uint32_t value  = 0;
    uint32_t offset = 0;
    if (argc < 3 || argc > 4)
    {
        dump_wlan_reg_access_usage();
        return FALSE;
    }

    if ((a2hex_or_atoi(argv[1]) != 1 && a2hex_or_atoi(argv[1]) != 2 && a2hex_or_atoi(argv[1]) != 3 &&
         a2hex_or_atoi(argv[1]) != 4))
    {
        dump_wlan_reg_access_usage();
        (void)printf("Error: Illegal register type %s. Must be either '1','2','3' or '4'.\r\n", argv[1]);
        return FALSE;
    }

    type = a2hex_or_atoi(argv[1]);
    if (argv[2][0] == '0' && (argv[2][1] == 'x' || argv[2][1] == 'X'))
        offset = a2hex_or_atoi(argv[2]);
    else
    {
        dump_wlan_reg_access_usage();
        (void)printf("Error: invalid offset argument\r\n");
        return FALSE;
    }

    if (argc == 3)
        action = ACTION_GET;
    else
    {
        action = ACTION_SET;
        if (argv[3][0] == '0' && (argv[3][1] == 'x' || argv[3][1] == 'X'))
            value = a2hex_or_atoi(argv[3]);
        else
        {
            dump_wlan_reg_access_usage();
            (void)printf("Error: invalid value argument\r\n");
            return FALSE;
        }
    }

    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_WLAN_DEBUG_REGISTER_ACCESS;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_REGISTER_ACCESS *register_access = (NCP_CMD_REGISTER_ACCESS *)&command->params.register_access;

    register_access->action = action;
    register_access->type   = type & 0xFF;
    register_access->offset = offset;
    register_access->value  = value;

    command->header.size += sizeof(NCP_CMD_REGISTER_ACCESS);

    return TRUE;
}

int wlan_process_register_access_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res               = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_REGISTER_ACCESS *register_access = (NCP_CMD_REGISTER_ACCESS *)&cmd_res->params.register_access;

    char type[4][4] = {"MAC", "BBP", "RF", "CAU"};
    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        if (register_access->action == ACTION_GET)
            (void)printf("Register: %s  offset = 0x%08x    value = 0x%08x\r\n", type[register_access->type - 1],
                         register_access->offset, register_access->value);
        else
            (void)printf("Set the register successfully\r\n");
    }
    else
    {
        if (register_access->action == ACTION_GET)
            (void)printf("Read Register failed\r\n");
        else
            (void)printf("Write Register failed\r\n");
    }

    (void)printf("\r\n");

    return TRUE;
}

#ifdef CONFIG_MEM_MONITOR_DEBUG
int wlan_memory_state_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_WLAN_MEMORY_HEAP_SIZE;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    return TRUE;
}

int wlan_process_memory_state_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res  = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_MEM_STAT *mem_state = (NCP_CMD_MEM_STAT *)&cmd_res->params.register_access;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        (void)printf("FreeHeapSize    : %d \r\n", mem_state->free_heap_size);
        (void)printf("MinFreeHeapSize : %d \r\n\r\n", mem_state->minimun_ever_free_heap_size);
    }
    else
    {
        (void)printf("Failed to get heap size.\r\n");
    }

    (void)printf("\r\n");

    return TRUE;
}
#endif

static void dump_wlan_set_ed_mac_mode_usage()
{
    (void)printf("Usage:\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)printf("wlan-set-ed-mac-mode <ed_ctrl_2g> <ed_offset_2g> <ed_ctrl_5g> <ed_offset_5g>\r\n");
#else
    (void)printf("wlan-set-ed-mac-mode <ed_ctrl_2g> <ed_offset_2g>\r\n");
#endif
    (void)printf("\r\n");
    (void)printf("\ted_ctrl_2g \r\n");
    (void)printf("\t    # 0       - disable EU adaptivity for 2.4GHz band\r\n");
    (void)printf("\t    # 1       - enable EU adaptivity for 2.4GHz band\r\n");
    (void)printf("\ted_offset_2g \r\n");
    (void)printf("\t    # 0       - Default Energy Detect threshold\r\n");
    (void)printf("\t    #offset value range: 0x80 to 0x7F\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)printf("\ted_ctrl_5g \r\n");
    (void)printf("\t    # 0       - disable EU adaptivity for 5GHz band\r\n");
    (void)printf("\t    # 1       - enable EU adaptivity for 5GHz band\r\n");
    (void)printf("\ted_offset_2g \r\n");
    (void)printf("\t    # 0       - Default Energy Detect threshold\r\n");
    (void)printf("\t    #offset value range: 0x80 to 0x7F\r\n");
#endif
}

int wlan_ed_mac_mode_set_command(int argc, char **argv)
{
    unsigned int value;
#ifdef CONFIG_5GHz_SUPPORT
    if (argc != 5)
#else
    if (argc != 3)
#endif
    {
        dump_wlan_set_ed_mac_mode_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_WLAN_REGULATORY_ED_MAC_MODE;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_ED_MAC *ed_mac_mode = (NCP_CMD_ED_MAC *)&command->params.ed_mac_mode;
    ed_mac_mode->action         = ACTION_SET;

    if (get_uint(argv[1], &value, strlen(argv[1])) || (value != 0 && value != 1))
    {
        (void)printf("Error: invalid ed_ctrl_2g value\r\n");
        dump_wlan_set_ed_mac_mode_usage();
        return FALSE;
    }

    ed_mac_mode->ed_ctrl_2g = value & 0xFF;

    if (argv[2][0] == '0' && (argv[2][1] == 'x' || argv[2][1] == 'X'))
        value = a2hex_or_atoi(argv[2]);
    else
    {
        (void)printf("Error: invalid ed_offset_2g value\r\n");
        dump_wlan_set_ed_mac_mode_usage();
        return FALSE;
    }

    ed_mac_mode->ed_offset_2g = value & 0xFF;

#ifdef CONFIG_5GHz_SUPPORT
    if (get_uint(argv[3], &value, strlen(argv[3])) || (value != 0 && value != 1))
    {
        (void)printf("Error: invalid ed_ctrl_5g value\r\n");
        dump_wlan_set_ed_mac_mode_usage();
        return FALSE;
    }

    ed_mac_mode->ed_ctrl_5g = value & 0xFF;

    if (argv[4][0] == '0' && (argv[4][1] == 'x' || argv[4][1] == 'X'))
        value = a2hex_or_atoi(argv[4]);
    else
    {
        (void)printf("Error: invalid ed_offset_5g value\r\n");
        dump_wlan_set_ed_mac_mode_usage();
        return FALSE;
    }

    ed_mac_mode->ed_offset_5g = value & 0xFF;
#endif

    command->header.size += sizeof(NCP_CMD_ED_MAC);

    return TRUE;
}

static void dump_wlan_get_ed_mac_mode_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-ed-mac-mode \r\n");
}

int wlan_ed_mac_mode_get_command(int argc, char **argv)
{
    if (argc != 1)
    {
        dump_wlan_get_ed_mac_mode_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_WLAN_REGULATORY_ED_MAC_MODE;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_ED_MAC *ed_mac_mode = (NCP_CMD_ED_MAC *)&command->params.ed_mac_mode;
    ed_mac_mode->action         = ACTION_GET;

    command->header.size += sizeof(NCP_CMD_ED_MAC);

    return TRUE;
}

int wlan_process_ed_mac_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res  = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_ED_MAC *ed_mac_mode = (NCP_CMD_ED_MAC *)&cmd_res->params.ed_mac_mode;

    if (ed_mac_mode->action == ACTION_SET)
    {
        if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        {
            (void)printf("ED MAC MODE settings configuration successful\r\n");
        }
        else
        {
            (void)printf("ED MAC MODE settings configuration failed\r\n");
        }
    }
    else
    {
        if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        {
            (void)printf("EU adaptivity for 2.4GHz band : %s\r\n",
                         ed_mac_mode->ed_ctrl_2g == 1 ? "Enabled" : "Disabled");
            if (ed_mac_mode->ed_offset_2g != 0)
            {
                (void)printf("Energy Detect threshold offset : 0X%x\r\n", ed_mac_mode->ed_offset_2g);
            }
#ifdef CONFIG_5GHz_SUPPORT
            (void)printf("EU adaptivity for 5GHz band : %s\r\n", ed_mac_mode->ed_ctrl_5g == 1 ? "Enabled" : "Disabled");
            if (ed_mac_mode->ed_offset_5g != 0)
            {
                (void)printf("Energy Detect threshold offset : 0X%x\r\n", ed_mac_mode->ed_offset_5g);
            }
#endif
        }
        else
        {
            (void)printf("ED MAC MODE read failed\r\n");
        }
    }
    (void)printf("\r\n");

    return TRUE;
}

#ifdef CONFIG_NCP_RF_TEST_MODE
static bool ncp_rf_test_mode = false;

static void dump_wlan_set_rf_test_mode_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-test-mode \r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf test mode command
 *
 * @return Status returned
 */
int wlan_set_rf_test_mode_command(int argc, char **argv)
{
    if (argc != 1)
    {
        dump_wlan_set_rf_test_mode_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *set_rf_test_mode_command = mpu_host_get_wifi_command_buffer();
    set_rf_test_mode_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_TEST_MODE;
    set_rf_test_mode_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_test_mode_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf test mode response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_test_mode_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        ncp_rf_test_mode = true;
        (void)printf("RF Test Mode configuration successful\r\n");
    }
    else
    {
        (void)printf("RF Test Mode configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_set_rf_test_mode()
{
    (void)printf("RF Test Mode is not set\r\n");
    dump_wlan_set_rf_test_mode_usage();
}

static void dump_wlan_set_rf_tx_antenna_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-tx-antenna <antenna> \r\n");
    (void)printf("antenna: 1=Main, 2=Aux \r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf tx antenna command
 *
 * @return Status returned
 */
int wlan_set_rf_tx_antenna_command(int argc, char **argv)
{
    uint8_t ant;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 2)
    {
        dump_wlan_set_rf_tx_antenna_usage();
        return FALSE;
    }

    ant = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_rf_tx_antenna_command = mpu_host_get_wifi_command_buffer();
    set_rf_tx_antenna_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_TX_ANTENNA;
    set_rf_tx_antenna_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_tx_antenna_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_TX_ANTENNA *tx_antenna = (NCP_CMD_RF_TX_ANTENNA *)&set_rf_tx_antenna_command->params.rf_tx_antenna;
    tx_antenna->ant                   = ant;
    set_rf_tx_antenna_command->header.size += sizeof(NCP_CMD_RF_TX_ANTENNA);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf tx antenna response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_tx_antenna_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("RF Tx Antenna configuration successful\r\n");
    }
    else
    {
        (void)printf("RF Tx Antenna configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_rf_tx_antenna_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-rf-tx-antenna \r\n");
}

/**
 * @brief      This function prepares wlan get rf tx antenna command
 *
 * @return Status returned
 */
int wlan_get_rf_tx_antenna_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_rf_tx_antenna_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_rf_tx_antenna_command = mpu_host_get_wifi_command_buffer();
    get_rf_tx_antenna_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_RF_TX_ANTENNA;
    get_rf_tx_antenna_command->header.size       = NCP_CMD_HEADER_LEN;
    get_rf_tx_antenna_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get rf tx antenna response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_rf_tx_antenna_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("RF Tx Antenna configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_TX_ANTENNA *tx_antenna = (NCP_CMD_RF_TX_ANTENNA *)&cmd_res->params.rf_tx_antenna;
    (void)printf("Configured RF Tx Antenna is: %s\r\n", tx_antenna->ant == 1 ? "Main" : "Aux");

    return TRUE;
}

static void dump_wlan_set_rf_rx_antenna_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-rx-antenna <antenna> \r\n");
    (void)printf("antenna: 1=Main, 2=Aux \r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf rx antenna command
 *
 * @return Status returned
 */
int wlan_set_rf_rx_antenna_command(int argc, char **argv)
{
    uint8_t ant;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 2)
    {
        dump_wlan_set_rf_rx_antenna_usage();
        return FALSE;
    }

    ant = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_rf_rx_antenna_command = mpu_host_get_wifi_command_buffer();
    set_rf_rx_antenna_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_RX_ANTENNA;
    set_rf_rx_antenna_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_rx_antenna_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_RX_ANTENNA *rx_antenna = (NCP_CMD_RF_RX_ANTENNA *)&set_rf_rx_antenna_command->params.rf_rx_antenna;
    rx_antenna->ant                   = ant;
    set_rf_rx_antenna_command->header.size += sizeof(NCP_CMD_RF_RX_ANTENNA);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf rx antenna response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_rx_antenna_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("RF Rx Antenna configuration successful\r\n");
    }
    else
    {
        (void)printf("RF Rx Antenna configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_rf_rx_antenna_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-rf-rx-antenna \r\n");
}

/**
 * @brief      This function prepares wlan get rf rx antenna command
 *
 * @return Status returned
 */
int wlan_get_rf_rx_antenna_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_rf_rx_antenna_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_rf_rx_antenna_command = mpu_host_get_wifi_command_buffer();
    get_rf_rx_antenna_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_RF_RX_ANTENNA;
    get_rf_rx_antenna_command->header.size       = NCP_CMD_HEADER_LEN;
    get_rf_rx_antenna_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get rf rx antenna response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_rf_rx_antenna_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("RF Rx Antenna configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_RX_ANTENNA *rx_antenna = (NCP_CMD_RF_RX_ANTENNA *)&cmd_res->params.rf_rx_antenna;
    (void)printf("Configured RF Rx Antenna is: %s\r\n", rx_antenna->ant == 1 ? "Main" : "Aux");

    return TRUE;
}

static void dump_wlan_set_rf_band_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-band <band> \r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)printf("band: 0=2.4G, 1=5G \r\n");
#else
    (void)printf("band: 0=2.4G \r\n");
#endif
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf band command
 *
 * @return Status returned
 */
int wlan_set_rf_band_command(int argc, char **argv)
{
    uint8_t band;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 2)
    {
        dump_wlan_set_rf_band_usage();
        return FALSE;
    }

    band = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_rf_band_command = mpu_host_get_wifi_command_buffer();
    set_rf_band_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_BAND;
    set_rf_band_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_band_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_BAND *rf_band = (NCP_CMD_RF_BAND *)&set_rf_band_command->params.rf_band;
    rf_band->band            = band;
    set_rf_band_command->header.size += sizeof(NCP_CMD_RF_BAND);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf band response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_band_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("RF Band configuration successful\r\n");
    }
    else
    {
        (void)printf("RF Band configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_rf_band_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-rf-band \r\n");
}

/**
 * @brief      This function prepares wlan get rf band command
 *
 * @return Status returned
 */
int wlan_get_rf_band_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_rf_band_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_rf_band_command = mpu_host_get_wifi_command_buffer();
    get_rf_band_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_RF_BAND;
    get_rf_band_command->header.size       = NCP_CMD_HEADER_LEN;
    get_rf_band_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get rf band response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_rf_band_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("RF Band configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_BAND *rf_band = (NCP_CMD_RF_BAND *)&cmd_res->params.rf_band;
    (void)printf("Configured RF Band is: %s\r\n", rf_band->band ? "5G" : "2.4G");

    return TRUE;
}

static void dump_wlan_set_rf_bandwidth_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-bandwidth <bandwidth> \r\n");
    (void)printf("\r\n");
    (void)printf("\t<bandwidth>: \r\n");
    (void)printf("\t		0: 20MHz\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)printf("\t		1: 40MHz\r\n");
#endif
#ifdef CONFIG_11AC
    (void)printf("\t		4: 80MHz\r\n");
#endif
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf bandwidth command
 *
 * @return Status returned
 */
int wlan_set_rf_bandwidth_command(int argc, char **argv)
{
    uint8_t bandwidth;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 2)
    {
        dump_wlan_set_rf_bandwidth_usage();
        return FALSE;
    }

    bandwidth = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_rf_bandwidth_command = mpu_host_get_wifi_command_buffer();
    set_rf_bandwidth_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_BANDWIDTH;
    set_rf_bandwidth_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_bandwidth_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_BANDWIDTH *rf_bandwidth = (NCP_CMD_RF_BANDWIDTH *)&set_rf_bandwidth_command->params.rf_bandwidth;
    rf_bandwidth->bandwidth            = bandwidth;
    set_rf_bandwidth_command->header.size += sizeof(NCP_CMD_RF_BANDWIDTH);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf bandwidth response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_bandwidth_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("RF Bandwidth configuration successful\r\n");
    }
    else
    {
        (void)printf("RF Bandwidth configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_rf_bandwidth_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-rf-bandwidth \r\n");
}

/**
 * @brief      This function prepares wlan get rf bandwidth command
 *
 * @return Status returned
 */
int wlan_get_rf_bandwidth_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_rf_bandwidth_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_rf_bandwidth_command = mpu_host_get_wifi_command_buffer();
    get_rf_bandwidth_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_RF_BANDWIDTH;
    get_rf_bandwidth_command->header.size       = NCP_CMD_HEADER_LEN;
    get_rf_bandwidth_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get rf bandwidth response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_rf_bandwidth_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("RF Bandwidth configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_BANDWIDTH *rf_bandwidth = (NCP_CMD_RF_BANDWIDTH *)&cmd_res->params.rf_bandwidth;
    (void)printf("Configured RF bandwidth is: %s\r\n",
                 rf_bandwidth->bandwidth == 0 ? "20MHz" : rf_bandwidth->bandwidth == 1 ? "40MHz" : "80MHz");

    return TRUE;
}

static void dump_wlan_set_rf_channel_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-channel <channel> \r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf channel command
 *
 * @return Status returned
 */
int wlan_set_rf_channel_command(int argc, char **argv)
{
    uint8_t channel;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 2)
    {
        dump_wlan_set_rf_channel_usage();
        return FALSE;
    }

    channel = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_rf_channel_command = mpu_host_get_wifi_command_buffer();
    set_rf_channel_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_CHANNEL;
    set_rf_channel_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_channel_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_CHANNEL *rf_channel = (NCP_CMD_RF_CHANNEL *)&set_rf_channel_command->params.rf_channel;
    rf_channel->channel            = channel;
    set_rf_channel_command->header.size += sizeof(NCP_CMD_RF_CHANNEL);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf channel response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_channel_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("RF channel configuration successful\r\n");
    }
    else
    {
        (void)printf("RF channel configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_rf_channel_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-rf-channel \r\n");
}

/**
 * @brief      This function prepares wlan get rf channel command
 *
 * @return Status returned
 */
int wlan_get_rf_channel_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_rf_channel_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_rf_channel_command = mpu_host_get_wifi_command_buffer();
    get_rf_channel_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_RF_CHANNEL;
    get_rf_channel_command->header.size       = NCP_CMD_HEADER_LEN;
    get_rf_channel_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get rf channel response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_rf_channel_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("RF channel configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_CHANNEL *rf_channel = (NCP_CMD_RF_CHANNEL *)&cmd_res->params.rf_channel;
    (void)printf("Configured channel is: %d\r\n\r\n", rf_channel->channel);

    return TRUE;
}

static void dump_wlan_set_rf_radio_mode_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-radio-mode <radio_mode> \r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf radio mode command
 *
 * @return Status returned
 */
int wlan_set_rf_radio_mode_command(int argc, char **argv)
{
    uint8_t radio_mode;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 2)
    {
        dump_wlan_set_rf_radio_mode_usage();
        return FALSE;
    }

    radio_mode = atoi(argv[1]);

    NCPCmd_DS_COMMAND *set_rf_radio_mode_command = mpu_host_get_wifi_command_buffer();
    set_rf_radio_mode_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_RADIO_MODE;
    set_rf_radio_mode_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_radio_mode_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_RADIO_MODE *rf_radio_mode = (NCP_CMD_RF_RADIO_MODE *)&set_rf_radio_mode_command->params.rf_radio_mode;
    rf_radio_mode->radio_mode            = radio_mode;
    set_rf_radio_mode_command->header.size += sizeof(NCP_CMD_RF_RADIO_MODE);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf radio mode response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_radio_mode_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("Set RF radio mode successful\r\n");
    }
    else
    {
        (void)printf("Set RF radio mode failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_rf_radio_mode_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-rf-radio-mode \r\n");
}

/**
 * @brief      This function prepares wlan get rf radio mode command
 *
 * @return Status returned
 */
int wlan_get_rf_radio_mode_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_rf_radio_mode_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_rf_radio_mode_command = mpu_host_get_wifi_command_buffer();
    get_rf_radio_mode_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_RF_RADIO_MODE;
    get_rf_radio_mode_command->header.size       = NCP_CMD_HEADER_LEN;
    get_rf_radio_mode_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get rf radio mode response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_get_rf_radio_mode_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("RF radio mode configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_RADIO_MODE *rf_radio_mode = (NCP_CMD_RF_RADIO_MODE *)&cmd_res->params.rf_radio_mode;
    (void)printf("Configured RF radio mode is: %d\r\n\r\n\r\n", rf_radio_mode->radio_mode);

    return TRUE;
}

static void dump_wlan_set_rf_tx_power_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-set-rf-tx-power <tx_power> <modulation> <path_id> \r\n");
    (void)printf("Power       (0 to 24 dBm)\r\n");
    (void)printf("Modulation  (0: CCK, 1:OFDM, 2:MCS)\r\n");
    (void)printf("Path ID     (0: PathA, 1:PathB, 2:PathA+B)\r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf tx power command
 *
 * @return Status returned
 */
int wlan_ncp_set_rf_tx_power_command(int argc, char **argv)
{
    uint8_t power;
    uint8_t mod;
    uint8_t path_id;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 4)
    {
        dump_wlan_set_rf_tx_power_usage();
        return FALSE;
    }

    power   = atoi(argv[1]);
    mod     = atoi(argv[2]);
    path_id = atoi(argv[3]);

    if (power > 24)
    {
        dump_wlan_set_rf_tx_power_usage();
        return FALSE;
    }

    if (mod != 0 && mod != 1 && mod != 2)
    {
        dump_wlan_set_rf_tx_power_usage();
        return FALSE;
    }

    if (path_id != 0 && path_id != 1 && path_id != 2)
    {
        dump_wlan_set_rf_tx_power_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *set_rf_tx_power_command = mpu_host_get_wifi_command_buffer();
    set_rf_tx_power_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_TX_POWER;
    set_rf_tx_power_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_tx_power_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_TX_POWER *rf_tx_power = (NCP_CMD_RF_TX_POWER *)&set_rf_tx_power_command->params.rf_tx_power;
    rf_tx_power->power               = power;
    rf_tx_power->mod                 = mod;
    rf_tx_power->path_id             = path_id;
    set_rf_tx_power_command->header.size += sizeof(NCP_CMD_RF_TX_POWER);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf tx power response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_tx_power_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("Set RF tx power configuration successful\r\n");
    }
    else
    {
        (void)printf("Set RF tx power configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_set_tx_cont_mode_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf(
        "wlan-set-rf-tx-cont-mode <enable_tx> <cw_mode> <payload_pattern> <cs_mode> <act_sub_ch> <tx_rate> \r\n");
    (void)printf("Enable                (0:disable, 1:enable)\r\n");
    (void)printf("Continuous Wave Mode  (0:disable, 1:enable)\r\n");
    (void)printf("Payload Pattern       (0 to 0xFFFFFFFF) (Enter hexadecimal value)\r\n");
    (void)printf("CS Mode               (Applicable only when continuous wave is disabled) (0:disable, 1:enable)\r\n");
    (void)printf("Active SubChannel     (0:low, 1:upper, 3:both)\r\n");
    (void)printf("Tx Data Rate          (Rate Index corresponding to legacy/HT/VHT rates)\r\n");
    (void)printf("\r\n");
    (void)printf("To Disable:\r\n");
    (void)printf("wlan-set-rf-tx-cont-mode 0\r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf tx cont mode command
 *
 * @return Status returned
 */
int wlan_ncp_set_rf_tx_cont_mode_command(int argc, char **argv)
{
    uint32_t enable_tx, cw_mode, payload_pattern, cs_mode, act_sub_ch, tx_rate;

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc == 2 && atoi(argv[1]) == 0)
    {
        enable_tx       = 0;
        cw_mode         = 0;
        payload_pattern = 0;
        cs_mode         = 0;
        act_sub_ch      = 0;
        tx_rate         = 0;
    }
    else if (argc != 7)
    {
        dump_wlan_set_tx_cont_mode_usage();
        return FALSE;
    }
    else
    {
        enable_tx       = atoi(argv[1]);
        cw_mode         = atoi(argv[2]);
        payload_pattern = strtol(argv[3], NULL, 16);
        cs_mode         = atoi(argv[4]);
        act_sub_ch      = atoi(argv[5]);
        tx_rate         = atoi(argv[6]);
    }

    NCPCmd_DS_COMMAND *set_rf_tx_cont_mode_command = mpu_host_get_wifi_command_buffer();
    set_rf_tx_cont_mode_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_TX_CONT_MODE;
    set_rf_tx_cont_mode_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_tx_cont_mode_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_TX_CONT_MODE *rf_tx_power =
        (NCP_CMD_RF_TX_CONT_MODE *)&set_rf_tx_cont_mode_command->params.rf_tx_cont_mode;
    rf_tx_power->enable_tx       = enable_tx;
    rf_tx_power->cw_mode         = cw_mode;
    rf_tx_power->payload_pattern = payload_pattern;
    rf_tx_power->cs_mode         = cs_mode;
    rf_tx_power->act_sub_ch      = act_sub_ch;
    rf_tx_power->tx_rate         = tx_rate;
    set_rf_tx_cont_mode_command->header.size += sizeof(NCP_CMD_RF_TX_CONT_MODE);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf tx cont mode response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_tx_cont_mode_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("Set RF tx continuous configuration successful\r\n");
    }
    else
    {
        (void)printf("Set RF tx continuous configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_set_tx_frame_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf(
        "wlan-set-rf-tx-frame <start> <data_rate> <frame_pattern> <frame_len> <adjust_burst_sifs> <burst_sifs_in_us> "
        "<short_preamble> <act_sub_ch> <short_gi> <adv_coding> <tx_bf> <gf_mode> <stbc> <bssid>\r\n");
    (void)printf("Enable                 (0:disable, 1:enable)\r\n");
    (void)printf("Tx Data Rate           (Rate Index corresponding to legacy/HT/VHT rates)\r\n");
    (void)printf("Payload Pattern        (0 to 0xFFFFFFFF) (Enter hexadecimal value)\r\n");
    (void)printf("Payload Length         (1 to 0x400) (Enter hexadecimal value)\r\n");
    (void)printf("Adjust Burst SIFS3 Gap (0:disable, 1:enable)\r\n");
    (void)printf("Burst SIFS in us       (0 to 255us)\r\n");
    (void)printf("Short Preamble         (0:disable, 1:enable)\r\n");
    (void)printf("Active SubChannel      (0:low, 1:upper, 3:both)\r\n");
    (void)printf("Short GI               (0:disable, 1:enable)\r\n");
    (void)printf("Adv Coding             (0:disable, 1:enable)\r\n");
    (void)printf("Beamforming            (0:disable, 1:enable)\r\n");
    (void)printf("GreenField Mode        (0:disable, 1:enable)\r\n");
    (void)printf("STBC                   (0:disable, 1:enable)\r\n");
    (void)printf("BSSID                  (xx:xx:xx:xx:xx:xx)\r\n");
    (void)printf("\r\n");
    (void)printf("To Disable:\r\n");
    (void)printf("wlan-set-rf-tx-frame 0\r\n");
    (void)printf("\r\n");
}

/**
 * @brief  This function prepares wlan set rf tx frame command
 *
 * @return Status returned
 */
int wlan_ncp_set_rf_tx_frame_command(int argc, char **argv)
{
    int ret;
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

    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc == 2 && atoi(argv[1]) == 0)
    {
        enable            = 0;
        data_rate         = 0;
        frame_pattern     = 0;
        frame_length      = 1;
        adjust_burst_sifs = 0;
        burst_sifs_in_us  = 0;
        short_preamble    = 0;
        act_sub_ch        = 0;
        short_gi          = 0;
        adv_coding        = 0;
        tx_bf             = 0;
        gf_mode           = 0;
        stbc              = 0;
        (void)memset(bssid, 0, sizeof(bssid));
    }
    else if (argc != 15)
    {
        dump_wlan_set_tx_frame_usage();
        return FALSE;
    }
    else
    {
        enable            = atoi(argv[1]);
        data_rate         = atoi(argv[2]);
        frame_pattern     = strtol(argv[3], NULL, 16);
        frame_length      = strtol(argv[4], NULL, 16);
        adjust_burst_sifs = atoi(argv[5]);
        burst_sifs_in_us  = atoi(argv[6]);
        short_preamble    = atoi(argv[7]);
        act_sub_ch        = atoi(argv[8]);
        short_gi          = atoi(argv[9]);
        adv_coding        = atoi(argv[10]);
        tx_bf             = atoi(argv[11]);
        gf_mode           = atoi(argv[12]);
        stbc              = atoi(argv[13]);
        ret               = get_mac((const char *)argv[14], (char *)bssid, ':');
        if (ret)
        {
            dump_wlan_set_tx_frame_usage();
            return FALSE;
        }

        if (enable > 1 || frame_length < 1 || frame_length > 0x400 || burst_sifs_in_us > 255 || short_preamble > 1 ||
            act_sub_ch == 2 || act_sub_ch > 3 || short_gi > 1 || adv_coding > 1 || tx_bf > 1 || gf_mode > 1 || stbc > 1)
        {
            dump_wlan_set_tx_frame_usage();
            return FALSE;
        }
    }

    NCPCmd_DS_COMMAND *set_rf_tx_frame_command = mpu_host_get_wifi_command_buffer();
    set_rf_tx_frame_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_SET_RF_TX_FRAME;
    set_rf_tx_frame_command->header.size       = NCP_CMD_HEADER_LEN;
    set_rf_tx_frame_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_RF_TX_FRAME *rf_tx_frame = (NCP_CMD_RF_TX_FRAME *)&set_rf_tx_frame_command->params.rf_tx_frame;
    rf_tx_frame->enable              = enable;
    rf_tx_frame->data_rate           = data_rate;
    rf_tx_frame->frame_pattern       = frame_pattern;
    rf_tx_frame->frame_length        = frame_length;
    rf_tx_frame->adjust_burst_sifs   = adjust_burst_sifs;
    rf_tx_frame->burst_sifs_in_us    = burst_sifs_in_us;
    rf_tx_frame->short_preamble      = short_preamble;
    rf_tx_frame->act_sub_ch          = act_sub_ch;
    rf_tx_frame->short_gi            = short_gi;
    rf_tx_frame->adv_coding          = adv_coding;
    rf_tx_frame->tx_bf               = tx_bf;
    rf_tx_frame->gf_mode             = gf_mode;
    rf_tx_frame->stbc                = stbc;
    memcpy(rf_tx_frame->bssid, bssid, sizeof(bssid));
    set_rf_tx_frame_command->header.size += sizeof(NCP_CMD_RF_TX_FRAME);

    return TRUE;
}

/**
 * @brief      This function processes wlan set rf tx frame response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_tx_frame_response(uint8_t *res)
{
    int ret;
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    ret                        = cmd_res->header.result;

    if (ret == NCP_CMD_RESULT_OK)
    {
        (void)printf("Set RF tx frame configuration successful\r\n");
    }
    else
    {
        (void)printf("Set RF tx frame configuration failed\r\n");
    }
    return TRUE;
}

static void dump_wlan_get_and_reset_rf_per_usage()
{
    (void)printf("Usage:\r\n");
    (void)printf("wlan-get-and-reset-rf-per \r\n");
}

/**
 * @brief  This function prepares wlan get and reset rf per command
 *
 * @return Status returned
 */
int wlan_ncp_set_rf_get_and_reset_rf_per_command(int argc, char **argv)
{
    if (!ncp_rf_test_mode)
    {
        dump_wlan_set_rf_test_mode();
        return FALSE;
    }

    if (argc != 1)
    {
        dump_wlan_get_and_reset_rf_per_usage();
        return FALSE;
    }

    NCPCmd_DS_COMMAND *get_and_reset_rf_per_command = mpu_host_get_wifi_command_buffer();
    get_and_reset_rf_per_command->header.cmd        = NCP_CMD_WLAN_REGULATORY_GET_AND_RESET_RF_PER;
    get_and_reset_rf_per_command->header.size       = NCP_CMD_HEADER_LEN;
    get_and_reset_rf_per_command->header.result     = NCP_CMD_RESULT_OK;

    return TRUE;
}

/**
 * @brief      This function processes wlan get and reset rf per response from ncp device
 *
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_set_rf_get_and_reset_rf_per_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("RF PER configuration read failed\r\n");
        return FALSE;
    }

    NCP_CMD_RF_PER *rf_per = (NCP_CMD_RF_PER *)&cmd_res->params.rf_per;
    (void)printf("PER is as below: \r\n");
    (void)printf("Total Rx Packet Count: %d\r\n", rf_per->rx_tot_pkt_count);
    (void)printf("Total Rx Multicast/Broadcast Packet Count: %d\r\n", rf_per->rx_mcast_bcast_count);
    (void)printf("Total Rx Packets with FCS error: %d\r\n", rf_per->rx_pkt_fcs_error);

    return TRUE;
}
#endif

static void dump_wlan_eu_crypto_ccmp_128(void)
{
    (void)printf("Usage:\r\n");
    (void)printf("Algorithm AES-CCMP-128 encryption and decryption verification\r\n");
    (void)printf("wlan-eu-crypto-ccmp-128 <EncDec>\r\n");
    (void)printf("EncDec: 0-Decrypt, 1-Encrypt\r\n");
}

int wlan_eu_crypto_ccmp128_command(int argc, char **argv)
{
    unsigned int EncDec = 0;

    if (argc != 2)
    {
        dump_wlan_eu_crypto_ccmp_128();
        (void)printf("Error: invalid number of arguments\r\n");
        return FALSE;
    }

    EncDec = atoi(argv[1]);
    if (EncDec != 0 && EncDec != 1)
    {
        dump_wlan_eu_crypto_ccmp_128();
        (void)printf("Error: invalid EncDec\r\n");
        return FALSE;
    }

    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_WLAN_REGULATORY_EU_CRYPTO_CCMP_128;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_EU_CRYPRTO *eu_crypto = (NCP_CMD_EU_CRYPRTO *)&command->params.eu_crypto;
    eu_crypto->enc = EncDec;
    command->header.size += sizeof(NCP_CMD_EU_CRYPRTO);

    return TRUE;
}

int wlan_process_eu_crypto_ccmp128_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        (void)printf("EU Crypto CCMP 128 verified successfully.\r\n");
    }
    else
    {
        (void)printf("EU Crypto CCMP 128 verified failed.\r\n");
    }

    return TRUE;
}

static void dump_wlan_eu_crypto_gcmp_128(void)
{
    (void)printf("Usage:\r\n");
    (void)printf("Algorithm AES-GCMP-128 encryption and decryption verification\r\n");
    (void)printf("wlan-eu-crypto-gcmp-128 <EncDec>\r\n");
    (void)printf("EncDec: 0-Decrypt, 1-Encrypt\r\n");
}

int wlan_eu_crypto_gcmp128_command(int argc, char **argv)
{
    unsigned int EncDec = 0;

    if (argc != 2)
    {
        dump_wlan_eu_crypto_gcmp_128();
        (void)printf("Error: invalid number of arguments\r\n");
        return FALSE;
    }

    EncDec = atoi(argv[1]);
    if (EncDec != 0U && EncDec != 1U)
    {
        dump_wlan_eu_crypto_gcmp_128();
        (void)printf("Error: invalid EncDec\r\n");
        return FALSE;
    }

    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_WLAN_REGULATORY_EU_CRYPTO_GCMP_128;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_EU_CRYPRTO *eu_crypto = (NCP_CMD_EU_CRYPRTO *)&command->params.eu_crypto;
    eu_crypto->enc = EncDec;
    command->header.size += sizeof(NCP_CMD_EU_CRYPRTO);

    return TRUE;
}

int wlan_process_eu_crypto_gcmp128_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res       = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        (void)printf("EU Crypto GCMP 128 verified successfully.\r\n");
    }
    else
    {
        (void)printf("EU Crypto GCMP 128 verified failed.\r\n");
    }

    return TRUE;
}

static bool is_timestr_valid(int argc, char **argv)
{
    char *str = NULL;

    if (argv == NULL)
        return false;
    
    for (int i = 1; i < argc; i++)
    {
        str = argv[i];
        while (*str != '\0')
        {
            if (!isdigit((unsigned char)*str))
            {
                return false; 
            }
            str++;
        }
    }
    
    return true; 
}

/* Display the usage of ping */
static void display_set_time_usage(void)
{
    (void)printf("Usage:\r\n");
    (void)printf(
        "\twlan-set-time <year><month><day><hour><minute><second>\r\n");
    (void)printf("\r\n");
    (void)printf("\tyear: range from 1970 to 2099\r\n");
    (void)printf("\tmonth: range from 1 to 12\r\n");
    (void)printf("\tday: range from 1 to 31\r\n");
    (void)printf("\thour: range from 0 to 23\r\n");
    (void)printf("\tminute: range from 0 to 59\r\n");
    (void)printf("\tsecond: range from 0 to 59\r\n");
    (void)printf("\r\n");
}

int wlan_set_time_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();
    NCP_CMD_DATE_TIME_CFG *time    = &command->params.date_time;

    if (argc != 7)
    {
        (void)printf("set time invalid argument, please input <year> <month> <day> <hour> <minute> <second>\r\n");
        return FALSE;
    }
	
    if (!is_timestr_valid(argc, argv))
    {
        (void)printf("set time invalid argument, please enter an integer string\r\n");
        display_set_time_usage();
        return FALSE;
    }

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_DATE_TIME;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    time->action           = 1;
    time->date_time.year   = atoi(argv[1]);
    time->date_time.month  = atoi(argv[2]);
    time->date_time.day    = atoi(argv[3]);
    time->date_time.hour   = atoi(argv[4]);
    time->date_time.minute = atoi(argv[5]);
    time->date_time.second = atoi(argv[6]);

    command->header.size += sizeof(NCP_CMD_DATE_TIME_CFG);

    return TRUE;
}

int wlan_get_time_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_DATE_TIME;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    command->params.date_time.action = 0;
    command->header.size += sizeof(NCP_CMD_DATE_TIME_CFG);

    return TRUE;
}

int wlan_process_time_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_DATE_TIME_CFG *time    = &cmd_res->params.date_time;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
    {
        if (time->action == 1)
        {
            (void)printf("time set success\r\n");
        }
        else
        {
            wlan_date_time_t *t = &time->date_time;
            (void)printf("time: %d:%d:%d %d:%d:%d\r\n", t->year, t->month, t->day, t->hour, t->minute, t->second);
        }
    }
    else
    {
        (void)printf("time get/set fail\r\n");
    }
    return TRUE;
}

int wlan_get_temperature_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *command = mpu_host_get_wifi_command_buffer();

    (void)memset((uint8_t *)command, 0, NCP_COMMAND_LEN);
    command->header.cmd      = NCP_CMD_GET_TEMPERATUE;
    command->header.size     = NCP_CMD_HEADER_LEN;
    command->header.result   = NCP_CMD_RESULT_OK;

    command->header.size += sizeof(NCP_CMD_TEMPERATURE);

    return TRUE;
}

int wlan_process_get_temperature_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        (void)printf("temperature %dC\r\n", cmd_res->params.temperature.temp);
    else
        (void)printf("temperature get fail\r\n");
    return TRUE;
}

int wlan_start_wps_pbc_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wpspbc_command = mpu_host_get_wifi_command_buffer();
    wpspbc_command->header.cmd        = NCP_CMD_WLAN_STA_WPS_PBC;
    wpspbc_command->header.size       = NCP_CMD_HEADER_LEN;
    wpspbc_command->header.result     = NCP_CMD_RESULT_OK;

    return WM_SUCCESS;
}

int wlan_process_wps_pbc_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        (void)printf("start wps pbc is successful!\r\n");
    else
        (void)printf("start wps pbc is fail!\r\n");

    return WM_SUCCESS;
}

int wlan_wps_generate_pin_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *wps_gen_pin_command = mpu_host_get_wifi_command_buffer();
    wps_gen_pin_command->header.cmd        = NCP_CMD_WLAN_STA_GEN_WPS_PIN;
    wps_gen_pin_command->header.size       = NCP_CMD_HEADER_LEN;
    wps_gen_pin_command->header.result     = NCP_CMD_RESULT_OK;
    wps_gen_pin_command->header.size += sizeof(NCP_CMD_WPS_GEN_PIN);

    return WM_SUCCESS;
}

int wlan_process_wps_generate_pin_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res    = (NCPCmd_DS_COMMAND *)res;
    NCP_CMD_WPS_GEN_PIN *pin_info = (NCP_CMD_WPS_GEN_PIN *)&cmd_res->params.wps_gen_pin_info;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        (void)printf("WPS PIN is %u\r\n", pin_info->pin);
    else
        (void)printf("WPS PIN generation is fail!\r\n");

    return WM_SUCCESS;
}

int wlan_start_wps_pin_command(int argc, char **argv)
{
    uint32_t pin = 0;

    if (argc != 2)
    {
        (void)printf("Usage: %s <8 digit pin>\r\n", argv[0]);
        return -WM_FAIL;
    }

    pin = atoi(argv[1]);

    NCPCmd_DS_COMMAND *wps_pin_command = mpu_host_get_wifi_command_buffer();
    wps_pin_command->header.cmd        = NCP_CMD_WLAN_STA_WPS_PIN;
    wps_pin_command->header.size       = NCP_CMD_HEADER_LEN;
    wps_pin_command->header.result     = NCP_CMD_RESULT_OK;

    NCP_CMD_WPS_PIN *wps_pin_cfg = (NCP_CMD_WPS_PIN *)&wps_pin_command->params.wps_pin_cfg;
    wps_pin_cfg->pin             = pin;
    wps_pin_command->header.size += sizeof(NCP_CMD_WPS_PIN);

    return WM_SUCCESS;
}

int wlan_process_wps_pin_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result == NCP_CMD_RESULT_OK)
        (void)printf("start wps pin is successful!\r\n");
    else
        (void)printf("start wps pin is fail!\r\n");

    return WM_SUCCESS;
}

int wlan_mdns_query_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *mdns_command = mpu_host_get_wifi_command_buffer();

    if (!(argc == 3 || argc == 2))
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("      wlan-mdns-query <service> <protocol>\r\n");
        (void)printf("For example:\r\n");
        (void)printf("      wlan-mdns-query _http tcp\r\n");
        return FALSE;
    }

    mdns_result_num = 0;

    mdns_command->header.cmd      = NCP_CMD_WLAN_NETWORK_MDNS_QUERY;
    mdns_command->header.size     = NCP_CMD_HEADER_LEN;
    mdns_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_MDNS_QUERY *mdns_query = (NCP_CMD_MDNS_QUERY *)&mdns_command->params.mdns_query;

    if (argc == 3)
    {
        mdns_query->qtype = DNS_RRTYPE_PTR;
        memcpy(mdns_query->Q.ptr_cfg.service, argv[1], strlen(argv[1]) + 1);
        if (!strcmp(argv[2], "udp"))
        {
            mdns_query->Q.ptr_cfg.proto = DNSSD_PROTO_UDP;
        }
        else if (!strcmp(argv[2], "tcp"))
        {
            mdns_query->Q.ptr_cfg.proto = DNSSD_PROTO_TCP;
        }
        else
        {
            (void)printf("Invalid protocol value\r\n");
            return FALSE;
        }
    }

    if (argc == 2)
    {
        mdns_query->qtype = DNS_RRTYPE_A;
        memcpy(mdns_query->Q.a_cfg.name, argv[1], strlen(argv[1]) + 1);
    }

    mdns_command->header.size += sizeof(NCP_CMD_MDNS_QUERY);

    return TRUE;
}

int wlan_process_mdns_query_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("failed to mDNS query!\r\n");
        return FALSE;
    }

    (void)printf("mDNS query successed!\r\n");
    return TRUE;
}

int wlan_process_mdns_query_result_event(uint8_t *res)
{
    uint32_t tlv_buf_len               = 0;
    uint8_t *ptlv_pos                  = NULL;
    NCP_TLV_HEADER *ptlv_header = NULL;
    PTR_ParamSet_t *ptr_tlv            = NULL;
    SRV_ParamSet_t *srv_tlv            = NULL;
    TXT_ParamSet_t *txt_tlv            = NULL;
    IP_ADDR_ParamSet_t *ip_addr_tlv    = NULL;
    char addr_type[40]                 = {0};

    NCPCmd_DS_COMMAND *evt_res = (NCPCmd_DS_COMMAND *)res;

    if (evt_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("Unknown mDNS result!\r\n");
        return FALSE;
    }

    NCP_EVT_MDNS_RESULT *mdns_result_tlv = (NCP_EVT_MDNS_RESULT *)&evt_res->params.mdns_result;

    (void)printf("Answers: %d\r\n", mdns_result_num++);
    ptlv_pos    = mdns_result_tlv->tlv_buf;
    tlv_buf_len = mdns_result_tlv->tlv_buf_len;

    do
    {
        ptlv_header = (NCP_TLV_HEADER *)ptlv_pos;

        switch (ptlv_header->type)
        {
            case NCP_CMD_NETWORK_MDNS_RESULT_PTR:
                ptr_tlv = (PTR_ParamSet_t *)ptlv_pos;
                if (ptr_tlv->instance_name[0] != '\0')
                    (void)printf("PTR : %s\r\n", ptr_tlv->instance_name);
                else
                    (void)printf("PTR : %s.%s.local\r\n", ptr_tlv->service_type, ptr_tlv->proto);
                break;
            case NCP_CMD_NETWORK_MDNS_RESULT_SRV:
                srv_tlv = (SRV_ParamSet_t *)ptlv_pos;
                (void)printf("SRV : %s:%d\r\n", srv_tlv->target, srv_tlv->port);
                break;
            case NCP_CMD_NETWORK_MDNS_RESULT_TXT:
                txt_tlv = (TXT_ParamSet_t *)ptlv_pos;
                (void)printf("TXT : %s\r\n", txt_tlv->txt);
                break;
            case NCP_CMD_NETWORK_MDNS_RESULT_IP_ADDR:
                ip_addr_tlv = (IP_ADDR_ParamSet_t *)ptlv_pos;
                if (ip_addr_tlv->addr_type == 4)
                {
                    struct in_addr ip;
                    ip.s_addr = ip_addr_tlv->ip.ip_v4;
                    (void)printf("A   : %s\r\n", inet_ntoa(ip));
                }
                else
                {
                    inet_ntop(AF_INET6, ip_addr_tlv->ip.ip_v6, addr_type, 40);
                    (void)printf("AAAA: %s\r\n", addr_type);
                }
                break;
            default:
                (void)printf("Invaild TLV\r\n");
                return FALSE;
        }
        ptlv_pos += NCP_TLV_HEADER_LEN + ptlv_header->size;
        tlv_buf_len -= NCP_TLV_HEADER_LEN + ptlv_header->size;
    } while (tlv_buf_len > 0);

    (void)printf("TTL : %d\r\n", mdns_result_tlv->ttl);
    return TRUE;
}

int wlan_process_mdns_resolve_domain_event(uint8_t *res)
{
    NCPCmd_DS_COMMAND *evt_res             = (NCPCmd_DS_COMMAND *)res;
    NCP_EVT_MDNS_RESOLVE *mdns_resolve_tlv = (NCP_EVT_MDNS_RESOLVE *)&evt_res->params.mdns_resolve;
    struct in_addr ip;
    char addr_type[40] = {0};

    if (evt_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("Unknown IP address!\r\n");
        return FALSE;
    }

    switch (mdns_resolve_tlv->ip_type)
    {
        case MDNS_ADDRTYPE_IPV4:
            ip.s_addr = mdns_resolve_tlv->u_addr.ip4_addr;
            (void)printf("IPv4 address: %s\r\n", inet_ntoa(ip));
            break;
        case MDNS_ADDRTYPE_IPV6:
            inet_ntop(AF_INET6, mdns_resolve_tlv->u_addr.ip6_addr, addr_type, 40);
            (void)printf("IPv6 address: %s\r\n", addr_type);
            break;
        default:
            (void)printf("Not found ip address\r\n");
            break;
    }

    return TRUE;
}

/* Display the usage of ping */
static void display_ping_usage()
{
    printf("Usage:\r\n");
    printf(
        "\tping [-s <packet_size>] [-c <packet_count>] "
        "[-W <timeout in sec>] <ipv4 address>\r\n");
    printf("Default values:\r\n");
    printf(
        "\tpacket_size: %u\r\n\tpacket_count: %u"
        "\r\n\ttimeout: %u sec\r\n",
        PING_DEFAULT_SIZE, PING_DEFAULT_COUNT, PING_DEFAULT_TIMEOUT_SEC);
}

int ncp_ping_command(int argc, char **argv)
{
    ping_msg_t ping_cmd;
    int c;
    int ret = WM_SUCCESS, err = 0;
    uint16_t size    = PING_DEFAULT_SIZE;
    uint32_t count   = PING_DEFAULT_COUNT, temp;
    uint32_t timeout = PING_DEFAULT_TIMEOUT_SEC;
	
    /* If number of arguments is not even then print error */
    if ((argc % 2) != 0)
    {
        ret = FALSE;
        goto end;
    }

    cli_optind = 1;
    while ((c = cli_getopt(argc, argv, "c:s:W:")) != -1)
    {
        err = 0;
        switch (c)
        {
            case 'c':
                count = strtoul(cli_optarg, NULL, 10);
                break;
            case 's':
                temp = strtoul(cli_optarg, NULL, 10);
                if (temp > PING_MAX_SIZE)
                {
                    if (err != 0)
                        printf("Error during strtoul errno:%d", err);
                    printf(
                        "ping: packet size too large: %u."
                        " Maximum is %u\r\n",
                        temp, PING_MAX_SIZE);
                    return FALSE;
                }
                size = temp;
                break;
            case 'W':
                timeout = strtoul(cli_optarg, NULL, 10);
                break;
            default:
                goto end;
        }
        if (err != 0)
            printf("Error during strtoul errno:%d", err);
    }
    if (cli_optind == argc)
        goto end;

    (void)memset(&ping_cmd, 0, sizeof(ping_msg_t));
    ping_cmd.count   = count;
    ping_cmd.size    = size;
    ping_cmd.timeout = timeout;
    ping_cmd.port    = 0;
    strcpy(ping_cmd.ip_addr, argv[cli_optind++]);

    /* Send message to ping_sock_task to handle ping command*/
    if ((msgsnd(ping_qid, &ping_cmd, sizeof(ping_msg_t), 0)) < 0)
    {
        printf("Send message error!\r\n");
        return FALSE;
    }

    return TRUE;

end:
    printf("Incorrect usage\r\n");
    display_ping_usage();

    return ret;
}

int wlan_process_csi_data_event(uint8_t *res)
{
    // NCPCmd_DS_COMMAND *evt_res = (NCPCmd_DS_COMMAND *)res;
    // NCP_EVT_CSI_DATA *p_csi_data = (NCP_EVT_CSI_DATA *)&evt_res->params.csi_data;
    // printf("CSI user callback: Event CSI data\r\n");
    // The real CSI data length is p_csi_data->Len*4 bytes,
    // print 1/4 to avoid USB rx buffer overflow.
    // dump_hex((void *)p_csi_data, p_csi_data->Len*4);
    // dump_hex((void *)p_csi_data, p_csi_data->Len);
    return WM_SUCCESS;
}

int wlan_process_con_event(uint8_t *res)
{
    NCPCmd_DS_COMMAND *evt_res = (NCPCmd_DS_COMMAND *)res;
    struct in_addr ip;

    if (evt_res->header.result != NCP_CMD_RESULT_OK)
    {
        printf("Failed to get correct AP info!\r\n");
        printf("Please input 'wlan-connect' to connect an AP or wait a few moments for the AP information.\r\n");
        return -WM_FAIL;
    }

    NCP_CMD_WLAN_CONN *connect_res_tlv = (NCP_CMD_WLAN_CONN *)&evt_res->params.wlan_connect;
    ip.s_addr                          = connect_res_tlv->ip;
    printf("STA connected:\r\n");
    printf("SSID = [%s]\r\n", connect_res_tlv->ssid);
    printf("IPv4 Address: [%s]\r\n", inet_ntoa(ip));

    return WM_SUCCESS;
}

int wlan_process_discon_event(uint8_t *res)
{
    NCPCmd_DS_COMMAND *evt_res = (NCPCmd_DS_COMMAND *)res;

    printf("STA disconnect, result %d\r\n",evt_res->header.result);

    return WM_SUCCESS;
}

int wlan_process_stop_network_event(uint8_t *res)
{
    NCPCmd_DS_COMMAND *evt_res = (NCPCmd_DS_COMMAND *)res;

    printf("Stop network, result %d\r\n",evt_res->header.result);

    return WM_SUCCESS;
}

int wlan_process_ipv6_dad_done_event(uint8_t *res)
{
    sem_post(&global_sem_dad);
    return WM_SUCCESS;
}

int wlan_list_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *network_list_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)network_list_command, 0, NCP_COMMAND_LEN);

    if (argc != 1)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("wlan-list\r\n");
        return -WM_FAIL;
    }

    network_list_command->header.cmd      = NCP_CMD_WLAN_NETWORK_LIST;
    network_list_command->header.size     = NCP_CMD_HEADER_LEN;
    network_list_command->header.result   = NCP_CMD_RESULT_OK;

    return WM_SUCCESS;
}

int wlan_process_network_list_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("Failed to get network list!\r\n");
        return -WM_FAIL;
    }

    NCP_CMD_NETWORK_LIST *network_list = (NCP_CMD_NETWORK_LIST *)&cmd_res->params.network_list;

    (void)printf(" %d networks %s\r\n", network_list->count, network_list->count == 0 ? "" : ":");

    for (int i = 0; i < network_list->count; i++)
    {
        print_network(&network_list->net_list[i]);
    }

    return WM_SUCCESS;
}

int wlan_remove_command(int argc, char **argv)
{
    NCPCmd_DS_COMMAND *network_remove_command = mpu_host_get_wifi_command_buffer();
    (void)memset((uint8_t *)network_remove_command, 0, NCP_COMMAND_LEN);

    if (argc != 2)
    {
        (void)printf("Error: invalid number of arguments\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("wlan-remove <profile_name>\r\n");
        return -WM_FAIL;
    }

    if (strlen(argv[1]) > WLAN_NETWORK_NAME_MAX_LENGTH)
    {
        (void)printf("Error: The length of profile_name is too log.\r\n");
        (void)printf("Usage:\r\n");
        (void)printf("wlan-remove <profile_name>\r\n");
        return -WM_FAIL;
    }

    network_remove_command->header.cmd      = NCP_CMD_WLAN_NETWORK_REMOVE;
    network_remove_command->header.size     = NCP_CMD_HEADER_LEN;
    network_remove_command->header.result   = NCP_CMD_RESULT_OK;

    NCP_CMD_NETWORK_REMOVE *network_remove = (NCP_CMD_NETWORK_REMOVE *)&network_remove_command->params.network_remove;

    (void)memcpy(network_remove->name, argv[1], strlen(argv[1]));
    network_remove->remove_state = WM_SUCCESS;

    network_remove_command->header.size += sizeof(NCP_CMD_NETWORK_REMOVE);

    return WM_SUCCESS;
}

int wlan_process_network_remove_response(uint8_t *res)
{
    NCPCmd_DS_COMMAND *cmd_res = (NCPCmd_DS_COMMAND *)res;

    if (cmd_res->header.result != NCP_CMD_RESULT_OK)
    {
        (void)printf("Failed to remove network!\r\n");
        return -WM_FAIL;
    }

    NCP_CMD_NETWORK_REMOVE *network_remove = (NCP_CMD_NETWORK_REMOVE *)&cmd_res->params.network_remove;

    switch (network_remove->remove_state)
    {
        case WM_SUCCESS:
            (void)printf("Removed \"%s\"\r\n", network_remove->name);
            break;
        case -WM_E_INVAL:
            (void)printf("Error: network not found\r\n");
            break;
        case WLAN_ERROR_STATE:
            (void)printf("Error: can't remove network in this state\r\n");
            break;
        default:
            (void)printf("Error: unable to remove network\r\n");
            break;
    }

    return WM_SUCCESS;
}


/*
 * @brief: ncp inet socket tcp/udp server/client test APIs, only for internal debug using
 */
typedef enum inet_test_type
{
    TCP_SERVER = 0,
	TCP_CLIENT,
	UDP_SERVER,
	UDP_CLIENT,
} INET_TEST_TYPE;


#ifdef NET_IPV6
#define OPT_NUM_ARGS 4
// IPv6 Specifics
#define NET_IN_ADDR in6_addr
#define NET_SOCKADDR_IN sockaddr_in6
#define NET_PF_INET PF_INET6 /* IPv6 Internet Namespace also called Protocol Family (PF) */
#define NET_AF_INET AF_INET6 /* Address Format (AF) for that namespace                   */
#define NET_ADDRSTRLEN INET6_ADDRSTRLEN
static int IF_num; // Network Interface number (check with 'ip a')
#else
#define OPT_NUM_ARGS 3
// IPv4 Specifics
#define NET_IN_ADDR in_addr
#define NET_SOCKADDR_IN sockaddr_in
#define NET_PF_INET PF_INET /* IPv4 Internet Namespace also called Protocol Family (PF) */
#define NET_AF_INET AF_INET /* Address Format (AF) for that namespace                   */
#define NET_ADDRSTRLEN INET_ADDRSTRLEN
#endif
typedef struct ncp_inet_test
{
	unsigned int type;
	unsigned int port;
	char addr[64];
} NCP_INET_TEST;

static void ncp_inet_tcp_server_test(char *addr, int port)
{
	/*
	** Done with options.
	** OPTIND points to first non-option argument.
	*/

	char	buffer[1024] = {0};
	ssize_t nBytesRX;

	struct NET_IN_ADDR dest_addr;		 // argv[1]

	int 				   server_sockfd;
	struct NET_SOCKADDR_IN server_addr = {0};

	int 				   client_sockfd;
	struct NET_SOCKADDR_IN client_addr = {0};
	socklen_t			   client_addr_size;

	int status = 0;

	// converts an Internet address (either IPv4 or IPv6) from presentation (textual) to network (binary) format.
	if (inet_pton(NET_AF_INET, addr, &dest_addr) == 0)
	{
		ncp_adap_e( "Invalid <dest_addr>");
	}


	//....................Main Processing Loop..........>>>

	//__________________________________________________
	//
	// Now open a TCP server socket
	//__________________________________________________

	// Function: int socket (int family, int style, int protocol)  (see <sys/socket.h>)
	//	   Protocol Family: 	PF_INET for IPv4 ; PF_INET6 for IPv6
	//	   Communication Style: SOCK_DGRAM for udp ; SOCK_STREAM for tcp
	//	   Specific Protocol:	zero is usually right for protocol. (i.e. IPPROTO_TCP=6 see <netinet/in.h>)

	/*
	 * REF: https://stackoverflow.com/questions/22304631/what-is-the-purpose-to-set-sock-cloexec-flag-with-accept4-same-as-o-cloexec
	 *
	 *		The reason for SOCK_CLOEXEC to exist is to avoid a race condition between getting a new
	 * socket from accept and setting the FD_CLOEXEC flag afterwards.
	 *
	 *		Normally if you want the file descriptor to be close-on-exec you'd first obtain the file
	 * descriptor in some way, then call fcntl(fd, F_SETFD, FD_CLOEXEC). But in a threaded program 
	 * there is a possibility for a race condition between getting that file descriptor (in this 
	 * case from accept) and setting the CLOEXEC flag. 
	 *		Therefore Linux has recently changed most (if not all) system calls that return new file
	 * descriptors to also accept flags that tell the kernel to atomically set the close-on-exec flag
	 * before making the file descriptor valid. That way the race condition is closed.
	 *
	 * If you wonder why close on exec exists, it's because in some cases, especially when you're 
	 * executing non-privileged programs from a privileged one, you don't want some file descriptors 
	 * to leak to that program. 
	 *
	 */

	server_sockfd = ncp_socket(NET_PF_INET, (SOCK_STREAM | SOCK_CLOEXEC), IPPROTO_TCP);
	if (server_sockfd <0)
	{
		ncp_adap_e("socket() -- socket creation failed! -- errno=%d => '%s'", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	else
	{
	    ncp_adap_w("[OK] socket Created");
	}

	// Structure describing an Internet socket address. (see <netinet/in.h>)
#ifdef NET_IPV6
	server_addr.sin6_family 	= NET_AF_INET;
	server_addr.sin6_port		= htons(port);		  // converts the uint16_t integer hostshort from host byte order to network byte order
	memcpy(server_addr.sin6_addr.s6_addr, dest_addr.s6_addr, sizeof(dest_addr.s6_addr)); // see inet_pton (int af, const char *cp, void *buf) function above
	//server_addr.sin6_addr 	  = in6addr_any;
	server_addr.sin6_scope_id	= IF_num;			  // Specify INET interface number
#else
	server_addr.sin_family		= NET_AF_INET;
	server_addr.sin_port		= htons(port);		  // converts the uint16_t integer hostshort from host byte order to network byte order
	server_addr.sin_addr.s_addr = dest_addr.s_addr;   // see inet_pton (int af, const char *cp, void *buf) function above
	//server_addr.sin_addr.s_addr = htonl(INADDR_ANY);	// see inet_pton (int af, const char *cp, void *buf) function above
    //server_addr.sin_addr.s_addr = INADDR_ANY;
#endif

	// Function:	int bind (int socket, struct sockaddr *addr, socklen_t length)
	// Description: assigns an address to the created socket. 'addr' and 'length' arguments specify the address.
	if (ncp_bind(server_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
	{
		ncp_adap_e("bind() -- Can't assign an address to the socket! -- errno=%d => '%s'", errno, strerror(errno));
		ncp_close(server_sockfd);
		exit(EXIT_FAILURE);
	}
	else
	{
	    ncp_adap_w("[OK] bind");
	}

	// Function: int listen (int socket, int n)
	if (ncp_listen(server_sockfd, 1))
	{
		ncp_adap_e("listen() -- listen failed!\nCan't enable socket to accept connections! -- errno=%d => '%s'", errno, strerror(errno));
		ncp_close(server_sockfd);
		exit(EXIT_FAILURE);
	}
	else
	{
	    ncp_adap_w("[OK] Listen"); }
        ncp_adap_w("[...Blocked--Waiting for Connection Request...]");

	// Function: int accept (int socket, struct sockaddr *addr, socklen_t *length_ptr)
	client_addr_size = sizeof(client_addr);
	client_sockfd = ncp_accept(server_sockfd, (struct sockaddr *) &client_addr, &client_addr_size);
	if (client_sockfd  < 0)
	{
		ncp_adap_e("accept() -- accept failed!\nCan't accept the connection request! -- errno=%d => '%s'", errno, strerror(errno));
		ncp_close(server_sockfd);
		exit(EXIT_FAILURE);
	}
	else
	{
	    ncp_adap_w("[OK] Client Connected");
	}

	ncp_adap_w("[...Blocked--Waiting for RX data...]");

    fd_set readfds;
    for (int i = 0; i < 2; i++)
    {
        FD_ZERO(&readfds);
        FD_SET(client_sockfd, &readfds);

        if (ncp_select(client_sockfd + 1, &readfds, NULL, NULL, NULL) < 0)
        {
            ncp_adap_e("select failed!");
        }

        // Function: ssize_t recv (int socket, void *buffer, size_t size, int flags)
        if ((nBytesRX = ncp_recv(client_sockfd, buffer, sizeof(buffer), 0)) < 0)
        {
            ncp_adap_e("recv() -- data received failed! -- errno=%d => '%s'", errno, strerror(errno));
            ncp_close(client_sockfd);
            ncp_close(server_sockfd);
            exit(EXIT_FAILURE);
        }
        else
        {
            char		  theClientIP[NET_ADDRSTRLEN];
            unsigned int  theClientPort;

#ifdef NET_IPV6
            inet_ntop(NET_AF_INET, &client_addr.sin6_addr, theClientIP, sizeof(theClientIP));
            theClientPort = ntohs(client_addr.sin6_port); // converts the uint16_t integer hostshort from network byte order to host byte order
#else
            inet_ntop(NET_AF_INET, &client_addr.sin_addr,  theClientIP, sizeof(theClientIP));
            theClientPort = ntohs(client_addr.sin_port); // converts the uint16_t integer hostshort from network byte order to host byte order
#endif

            ncp_adap_w("[OK] Data Received: (%ld Bytes) '%s' from @ '[%s]:%d'", nBytesRX, buffer, theClientIP, theClientPort);
        }
    }
	//__________________________________________________
	//
	// Now close both the TCP server & client sockets
	//__________________________________________________

	// Function: int close (int socket)
	if (ncp_close(client_sockfd) < 0)
	{
		ncp_adap_e("close() -- client socket closing failed! -- 'errno'=%d", errno);
		exit(EXIT_FAILURE);
	}
	else
	{
		ncp_adap_w("[OK] client socket Closed");
	}

	// Function: int close (int socket)
	if (ncp_close(server_sockfd) < 0)
	{
		ncp_adap_e("close() -- server socket closing failed! -- 'errno'=%d", errno);
		exit(EXIT_FAILURE);
	}
	else
	{
		ncp_adap_w("[OK] server socket Closed");
	}
}

static void ncp_inet_tcp_client_test(char *addr, int port)
{
    struct NET_IN_ADDR dest_addr;
    int                client_sockfd;
	struct NET_SOCKADDR_IN server_addr = {0};
    char    buffer[1024] = "Hello TCP Server";
    ssize_t nBytesTX;

	inet_pton(NET_AF_INET, addr, &dest_addr);

	client_sockfd = ncp_socket(NET_PF_INET, (SOCK_STREAM | SOCK_CLOEXEC), IPPROTO_TCP);
	if (client_sockfd < 0)
	    ncp_adap_e("socket creation failed!");
	else
	    ncp_adap_w("[OK] socket Created");

	
	// Structure describing an Internet socket address. (see <netinet/in.h>)
#ifdef NET_IPV6
	server_addr.sin6_family 	= NET_AF_INET;
	server_addr.sin6_port		= htons(port);		  // converts the uint16_t integer hostshort from host byte order to network byte order
	memcpy(server_addr.sin6_addr.s6_addr, dest_addr.s6_addr, sizeof(dest_addr.s6_addr)); // see inet_pton (int af, const char *cp, void *buf) function above
	server_addr.sin6_scope_id	= IF_num;			  // Specify INET interface number
#else
	server_addr.sin_family		= NET_AF_INET;
	server_addr.sin_port		= htons(port);		  // converts the uint16_t integer hostshort from host byte order to network byte order
	server_addr.sin_addr.s_addr = dest_addr.s_addr;   // see inet_pton (int af, const char *cp, void *buf) function above
#endif

	
	// Function: int connect (int socket, struct sockaddr *addr, socklen_t length)
	if (ncp_connect(client_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
	{
	    ncp_adap_e("connect to server failed!");
	    ncp_close(client_sockfd);
	}
	else
        ncp_adap_w("[OK] Connected to Server");
    char ioctl_example_buffer[128];
	if (ncp_ioctl(client_sockfd, SIOCGIFADDR, ioctl_example_buffer) < 0)
	{
	    ncp_adap_e("ioctl failed!");
	}
	if (ncp_fcntl(client_sockfd, F_GETFL, 0) < 0)
	{
	    ncp_adap_e("fcntl failed!");
	}

	// Function: ssize_t send (int socket, const void *buffer, size_t size, int flags)
	if ((nBytesTX = ncp_send(client_sockfd, buffer, strlen(buffer), 0)) < 0)
	{
	    ncp_adap_e("data send failed!");
		ncp_close(client_sockfd);
	}
	else
	{
		struct NET_SOCKADDR_IN myAddr  = {0};
		socklen_t			   lenAddr = sizeof(myAddr);
		
		// Reading the Address of the client Socket
		if (ncp_getsockname(client_sockfd, (struct sockaddr *) &myAddr, &lenAddr))
		{
			ncp_adap_e("getsockname() -- Reading the Address of a Socket failed! -- errno=%d => '%s'", errno, strerror(errno));
			ncp_close(client_sockfd);

		}
		else
		{
			char		  myIP[NET_ADDRSTRLEN];
			unsigned int  myPort;
		
#ifdef NET_IPV6
			inet_ntop(NET_AF_INET, &myAddr.sin6_addr.s6_addr, myIP, sizeof(myIP));
			myPort = ntohs(myAddr.sin6_port); // converts the uint16_t integer hostshort from network byte order to host byte order
#else
			inet_ntop(NET_AF_INET, &myAddr.sin_addr.s_addr,   myIP, sizeof(myIP));
			myPort = ntohs(myAddr.sin_port); // converts the uint16_t integer hostshort from network byte order to host byte order
#endif

			ncp_adap_w("[OK] Data Sent: (%ld Bytes) '%s' to @ '[%s]:%d'", nBytesTX, buffer, myIP, myPort);
		}
	}
	
	// Function: int close (int socket)
	if (ncp_close(client_sockfd) < 0)
	{
		ncp_adap_e("close() -- Client socket closing failed! -- errno=%d => '%s'", errno, strerror(errno));
	} 
}

static int ncp_inet_udp_client_test(char *addr, int port)
{
	char buffer[1024] = "Hello UDP Client";
	ssize_t nBytesTX;

	struct NET_IN_ADDR dest_addr; // argv[1]

	int client_sockfd;

	struct NET_SOCKADDR_IN server_addr = {0};

	int status = 0;
	

	if (inet_pton(NET_AF_INET, addr, &dest_addr) == 0)
	{
		ncp_adap_e( "Invalid <dest_addr>");
	}

	//....................Main Processing Loop..........>>>

	//__________________________________________________
	//
	// Now open a UDP socket
	//__________________________________________________

	// Function: int socket (int family, int style, int protocol)  (see <sys/socket.h>)
	//	   Protocol Family: 	PF_INET for IPv4 ; PF_INET6 for IPv6
	//	   Communication Style: SOCK_DGRAM for udp ; SOCK_STREAM for tcp
	//	   Specific Protocol:	zero is usually right for protocol. (i.e. IPPROTO_UDP=17 see <netinet/in.h>)

	/*
	 * REF: https://stackoverflow.com/questions/22304631/what-is-the-purpose-to-set-sock-cloexec-flag-with-accept4-same-as-o-cloexec
	 *
	 *		The reason for SOCK_CLOEXEC to exist is to avoid a race condition between getting a new
	 * socket from accept and setting the FD_CLOEXEC flag afterwards.
	 *
	 *		Normally if you want the file descriptor to be close-on-exec you'd first obtain the file
	 * descriptor in some way, then call fcntl(fd, F_SETFD, FD_CLOEXEC). But in a threaded program 
	 * there is a possibility for a race condition between getting that file descriptor (in this 
	 * case from accept) and setting the CLOEXEC flag. 
	 *		Therefore Linux has recently changed most (if not all) system calls that return new file
	 * descriptors to also accept flags that tell the kernel to atomically set the close-on-exec flag
	 * before making the file descriptor valid. That way the race condition is closed.
	 *
	 * If you wonder why close on exec exists, it's because in some cases, especially when you're 
	 * executing non-privileged programs from a privileged one, you don't want some file descriptors 
	 * to leak to that program. 
	 *
	 */
	
	client_sockfd = ncp_socket(NET_PF_INET, (SOCK_DGRAM | SOCK_CLOEXEC), IPPROTO_UDP);
	if (client_sockfd < 0)
	{
		ncp_adap_e("socket creation failed! -- errno=%d => '%s'", errno, strerror(errno));
	}
	else
	{
		ncp_adap_w("\t[OK] socket Created: client_sockfd=%d", client_sockfd);
	}

	
	//__________________________________________________
	//
	// GET / SET Socket Options
	//
	//__________________________________________________

	int 	  sendbuf_sz;
	int 	  recvbuf_sz;
	socklen_t optlen;
	//__________________________________________________
	//
	// send INET data to server
	//__________________________________________________

	// Structure describing an Internet socket address. (see <netinet/in.h>)
#ifdef NET_IPV6
	server_addr.sin6_family = NET_AF_INET;
	server_addr.sin6_port = htons(port);												 // converts the uint16_t integer hostshort from host byte order to network byte order
	memcpy(server_addr.sin6_addr.s6_addr, dest_addr.s6_addr, sizeof(dest_addr.s6_addr)); // see inet_pton (int af, const char *cp, void *buf) function above
	server_addr.sin6_scope_id = IF_num; 												 // Specify INET interface number
#else
	server_addr.sin_family = NET_AF_INET;
	server_addr.sin_port = htons(port); 			// converts the uint16_t integer hostshort from host byte order to network byte order
	server_addr.sin_addr.s_addr = dest_addr.s_addr; // see inet_aton(const char *name, struct in_addr *addr) function above
#endif

	// Function:	ssize_t sendto (int socket, const void *buffer, size_t size, int flags, struct sockaddr *addr, socklen_t length)
	// Description: send data on a datagram socket to the specified destination address
	if ((nBytesTX = ncp_sendto(client_sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0)
	{
		ncp_adap_e("sendto() -- data send failed! -- errno=%d => '%s'", errno, strerror(errno));
		ncp_close(client_sockfd);
	}
	else
	{
		char str_addr[NET_ADDRSTRLEN];
		int  s_port;
		//		  inet_ntop (NET_AF_INET, &dest_addr, str_addr, NET_ADDRSTRLEN);
#ifdef NET_IPV6
		inet_ntop (NET_AF_INET, &server_addr.sin6_addr, str_addr, NET_ADDRSTRLEN);
		s_port = ntohs(server_addr.sin6_port);
#else
		inet_ntop (NET_AF_INET, &server_addr.sin_addr, str_addr, NET_ADDRSTRLEN);
		s_port = ntohs(server_addr.sin_port);
#endif
		ncp_adap_w("[OK] Data Sent: (%ld Bytes) '%s' to @ '[%s]:%d'", nBytesTX, buffer, str_addr, s_port);
	}

	//__________________________________________________
	//
	// wait for ACK response from server
	//__________________________________________________


	//__________________________________________________
	//
	// Now close the UDP socket
	//__________________________________________________

	// Function: int close (int socket)
	if (ncp_close(client_sockfd) < 0)
	{
		printf("close() -- socket closing failed! -- errno=%d => '%s'", errno, strerror(errno));
	}
	else
	{
		printf("\t[OK] socket Closed");
	}
	return WM_SUCCESS;
}

static int ncp_inet_udp_server_test(char *addr, int port)
{	
	char buffer[1024] = "Hello UDP Server";
	ssize_t nBytesRX;

	struct NET_IN_ADDR dest_addr; // argv[1]

	int server_sockfd;
	struct NET_SOCKADDR_IN server_addr = {0};

	struct NET_SOCKADDR_IN client_addr = {0};
	socklen_t client_addr_size;

	int status = 0;

	if (inet_pton(NET_AF_INET, addr, &dest_addr) == 0)
	{
		ncp_adap_e( "Invalid <dest_addr>");
	}


	// Structure describing an Internet socket address. (see <netinet/in.h>)
    server_sockfd = ncp_socket(NET_PF_INET, (SOCK_DGRAM | SOCK_CLOEXEC), IPPROTO_UDP);
    if (server_sockfd < 0)
    {
        ncp_adap_e("socket creation failed! -- errno=%d => '%s'", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    else
    {
        ncp_adap_w("[OK] socket Created: server_sockfd=%d", server_sockfd);
    }

#ifdef NET_IPV6
	server_addr.sin6_family = NET_AF_INET;
	server_addr.sin6_port = htons(port);												 // converts the uint16_t integer hostshort from host byte order to network byte order
	memcpy(server_addr.sin6_addr.s6_addr, dest_addr.s6_addr, sizeof(dest_addr.s6_addr)); // see inet_pton (int af, const char *cp, void *buf) function above
	// server_addr.sin6_addr	   = in6addr_any;
	server_addr.sin6_scope_id = IF_num; // Specify INET interface number
#else
	server_addr.sin_family = NET_AF_INET;
	server_addr.sin_port = htons(port); 			// converts the uint16_t integer hostshort from host byte order to network byte order
	server_addr.sin_addr.s_addr = dest_addr.s_addr; // see inet_pton (int af, const char *cp, void *buf) function above
	// server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // see inet_pton (int af, const char *cp, void *buf) function above
#endif

	// Function:	int bind (int socket, struct sockaddr *addr, socklen_t length)
	// Description: assigns an address to the created socket. 'server_addr' specifies the address.
	if (ncp_bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)))
	{
		ncp_adap_e("bind() -- Can't assign an address to the socket! -- errno=%d => '%s'", errno, strerror(errno));
		ncp_close(server_sockfd);
		exit(EXIT_FAILURE);
	}
	else
	{
		ncp_adap_w("[OK] bind");
	}

	ncp_adap_w("[...Blocked--Waiting for RX data...]");

	// Function:	ssize_t recvfrom (int socket, void *buffer, size_t size, int flags, struct sockaddr *addr, socklen_t *length-ptr)
	// Description: reads a packet from a datagram socket and also tells you where it was sent from
    for (int i = 0; i < 2; i++)
    {
        client_addr_size = sizeof(client_addr);
        memset(buffer, 0, sizeof(buffer));
        if ((nBytesRX = ncp_recvfrom(server_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_size)) < 0)
        {
            ncp_adap_e("recvfrom() -- data received failed! -- errno=%d => '%s'", errno, strerror(errno));
            ncp_close(server_sockfd);
            sleep(1);
            exit(EXIT_FAILURE);
        }
        else
        {
            char str_addr[NET_ADDRSTRLEN];
            int  r_port;
#ifdef NET_IPV6
            inet_ntop (NET_AF_INET, &client_addr.sin6_addr, str_addr, NET_ADDRSTRLEN);
            r_port = ntohs(server_addr.sin6_port);
#else
            inet_ntop (NET_AF_INET, &client_addr.sin_addr, str_addr, NET_ADDRSTRLEN);
            r_port = ntohs(server_addr.sin_port);
#endif
            ncp_adap_w("[OK] Data Received: (%ld Bytes) '%s' from @ '[%s]:%d'", nBytesRX, buffer, str_addr, r_port);
        }
    }
	//__________________________________________________
	//
	// Now close the UDP socket
	//__________________________________________________

	// Function: int close (int socket)
	if (ncp_close(server_sockfd) < 0)
	{
		ncp_adap_e("close() -- socket closing failed! -- errno=%d => '%s'", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	else
	{
		ncp_adap_w("[OK] socket Closed");
	}

	sleep(1);
    return WM_SUCCESS;
	//..................................................<<<
}


static pthread_t ncp_inet_test_thread;
static void ncp_inet_test_task(void *data)
{
    NCP_INET_TEST *arg = (NCP_INET_TEST *)data;
    switch (arg->type)
    {
        case TCP_SERVER:
			ncp_inet_tcp_server_test(arg->addr, arg->port);
		break;
	    case TCP_CLIENT:
			ncp_inet_tcp_client_test(arg->addr, arg->port);
	    break;
		case UDP_SERVER:
			ncp_inet_udp_server_test(arg->addr, arg->port);
		break;
		case UDP_CLIENT:
			ncp_inet_udp_client_test(arg->addr, arg->port);
		break;
    }
	free(arg);
    pthread_exit(NULL);
}

static int ncp_inet_test_command(int argc, char **argv)
{
    NCP_INET_TEST *arg = (NCP_INET_TEST *)malloc(sizeof(NCP_INET_TEST));
	

    unsigned int type;
	unsigned int port;
	char addr[64];
    if (get_uint(argv[1], &arg->type, strlen(argv[1])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (get_uint(argv[3], &arg->port, strlen(argv[3])))
    {
        printf("Usage: %s handle ip_addr port\r\n", __func__);
        return FALSE;
    }
    if (strlen(argv[2]) + 1 > IP_ADDR_LEN)
    {
        printf("over buffer size\r\n");
        return FALSE;
    }
    memcpy(arg->addr, argv[2], strlen(argv[2]) + 1);
	pthread_create(&ncp_inet_test_thread, NULL, (void *)ncp_inet_test_task, (void *)arg);
	pthread_detach(ncp_inet_test_thread);
	return TRUE;
}

#ifdef CONFIG_SDIO_TEST_LOOPBACK
static struct mpu_host_cli_command mpu_host_app_cli_commands_loopback[] = {
    {"test-loopback", NULL, ncp_test_loopback_command},
};
#else
static struct mpu_host_cli_command mpu_host_app_cli_commands[] = {
    {"wlan-scan", NULL, wlan_scan_command},
    {"wlan-connect", NULL, wlan_connect_command},
    {"wlan-disconnect", NULL, wlan_disconnect_command},
    {"wlan-version", NULL, wlan_version_command},
    {"wlan-set-mac", "<mac_address>", wlan_set_mac_address_command},
    {"wlan-get-mac", NULL, wlan_get_mac_address_command},
    {"wlan-stat", NULL, wlan_stat_command},
    {"wlan-roaming", NULL, wlan_roaming_command},
    {"wlan-reset", NULL, wlan_reset_command},
    {"wlan-info", NULL, wlan_info_command},
    {"wlan-address", NULL, wlan_address_command},
    {"wlan-socket-open", NULL, wlan_socket_open_command},
    {"wlan-socket-connect", NULL, wlan_socket_con_command},
    {"wlan-socket-bind", NULL, wlan_socket_bind_command},
    {"wlan-socket-close", NULL, wlan_socket_close_command},
    {"wlan-socket-listen", NULL, wlan_socket_listen_command},
    {"wlan-socket-accept", NULL, wlan_socket_accept_command},
    {"wlan-socket-send", NULL, wlan_socket_send_command},
    {"wlan-socket-sendto", NULL, wlan_socket_sendto_command},
    {"wlan-socket-receive", NULL, wlan_socket_receive_command},
    {"wlan-socket-recvfrom", NULL, wlan_socket_recvfrom_command},
    {"wlan-ncp-inet-test", NULL, ncp_inet_test_command},
    {"wlan-http-connect", NULL, wlan_http_connect_command},
    {"wlan-http-disconnect", NULL, wlan_http_disconnect_command},
    {"wlan-http-req", NULL, wlan_http_req_command},
    {"wlan-http-recv", NULL, wlan_http_recv_command},
    {"wlan-http-seth", NULL, wlan_http_seth_command},
    {"wlan-http-unseth", NULL, wlan_http_unseth_command},
    {"wlan-websocket-upg", NULL, wlan_websocket_upg_command},
    {"wlan-websocket-send", NULL, wlan_websocket_send_command},
    {"wlan-websocket-recv", NULL, wlan_websocket_recv_command},
    {"wlan-net-monitor-cfg", NULL, wlan_net_monitor_cfg_command},
    {"wlan-set-monitor-filter", "<opt> <macaddr>", wlan_set_monitor_filter_command},
    {"wlan-set-monitor-param", "<action> <monitor_activity> <filter_flags> <radio_type> <chan_number>",
     wlan_set_monitor_param_command},
    {"wlan-uap-prov-start", NULL, wlan_uap_prov_start_command},
    {"wlan-uap-prov-reset", NULL, wlan_uap_prov_reset_command},
    {"wlan-uap-prov-set-uapcfg", "<ssid> [<sec> <password>]", wlan_uap_prov_set_uapcfg},
    {"wlan-add", NULL, wlan_add_command},
    {"wlan-start-network", "<profile_name>", wlan_start_network_command},
    {"wlan-stop-network", NULL, wlan_stop_network_command},
    {"wlan-get-uap-sta-list", NULL, wlan_get_uap_sta_list_command},
    {"wlan-csi-cfg", NULL, wlan_csi_cfg_command},
    {"wlan-set-csi-param-header",
     " <sta/uap> <csi_enable> <head_id> <tail_id> <chip_id> <band_config> <channel> <csi_monitor_enable> <ra4us>",
     wlan_set_csi_param_header_command},
    {"wlan-set-csi-filter", "<opt> <macaddr> <pkt_type> <type> <flag>", wlan_set_csi_filter_command},
    {"wlan-11k-enable", "<0/1>", wlan_11k_cfg_command},
    {"wlan-11k-neigbor-req", "[ssid <ssid>]", wlan_11k_neighbor_req_command},
    {"wlan-get-signal", NULL, wlan_get_signal_command},
    {"wlan-multi-mef", NULL, wlan_multi_mef_command},
    {"wlan-uapsd-enable", NULL, wlan_set_wmm_uapsd_command},
    {"wlan-uapsd-qosinfo", NULL, wlan_wmm_uapsd_qosinfo_command},
    {"wlan-uapsd-sleep-period", NULL, wlan_uapsd_sleep_period_command},
    {"wlan-wakeup-condition", NULL, wlan_wakeup_condition_command},
#if (defined CONFIG_NCP_WIFI) && (!defined CONFIG_NCP_BLE) && (!defined CONFIG_NCP_OT)
    {"wlan-suspend", NULL, wlan_suspend_command},
#endif
    {"wlan-set-11axcfg", NULL, wlan_set_11axcfg_command},
    {"wlan-bcast-twt", "<set/get>", wlan_bcast_twt_command},
    {"wlan-twt-setup", NULL, wlan_twt_setup_command},
    {"wlan-twt-teardown", NULL, wlan_twt_teardown_command},
    {"wlan-get-twt-report", NULL, wlan_get_twt_report_command},
    {"wlan-set-11d-enable", "sta/uap <state>", wlan_set_11d_enable_command},
    {"wlan-region-code", "get/set <region_code hex>", wlan_region_code_command},
    {"wlan-set-max-clients-count", "<max clients count>", wlan_set_max_clients_count_command},
    {"wlan-set-antenna-cfg", "<antenna mode> <evaluate_time>", wlan_set_antenna_cfg_command},
    {"wlan-get-antenna-cfg", NULL, wlan_get_antenna_cfg_command},
    {"wlan-deep-sleep-ps", "<0/1>", wlan_deep_sleep_ps_command},
    {"wlan-ieee-ps", "<0/1>", wlan_ieee_ps_command},
    {"wlan-reg-access", "<type> <offset> <value>", wlan_register_access_command},
#ifdef CONFIG_MEM_MONITOR_DEBUG
    {"wlan-mem-stat", NULL, wlan_memory_state_command},
#endif
#ifdef CONFIG_5GHz_SUPPORT
    {"wlan-set-ed-mac-mode", "<ed_ctrl_2g> <ed_offset_2g> <ed_ctrl_5g> <ed_offset_5g>", wlan_ed_mac_mode_set_command},
#else
    {"wlan-set-ed-mac-mode", "<ed_ctrl_2g> <ed_offset_2g>", wlan_ed_mac_mode_set_command},
#endif
    {"wlan-get-ed-mac-mode", NULL, wlan_ed_mac_mode_get_command},
#ifdef CONFIG_NCP_RF_TEST_MODE
    {"wlan-set-rf-test-mode", NULL, wlan_set_rf_test_mode_command},
    {"wlan-set-rf-tx-antenna", "<antenna>", wlan_set_rf_tx_antenna_command},
    {"wlan-get-rf-tx-antenna", NULL, wlan_get_rf_tx_antenna_command},
    {"wlan-set-rf-rx-antenna", "<antenna>", wlan_set_rf_rx_antenna_command},
    {"wlan-get-rf-rx-antenna", NULL, wlan_get_rf_rx_antenna_command},
    {"wlan-set-rf-band", "<band>", wlan_set_rf_band_command},
    {"wlan-get-rf-band", NULL, wlan_get_rf_band_command},
    {"wlan-set-rf-bandwidth", "<bandwidth>", wlan_set_rf_bandwidth_command},
    {"wlan-get-rf-bandwidth", NULL, wlan_get_rf_bandwidth_command},
    {"wlan-set-rf-channel", "<channel>", wlan_set_rf_channel_command},
    {"wlan-get-rf-channel", NULL, wlan_get_rf_channel_command},
    {"wlan-set-rf-radio-mode", "<radio_mode>", wlan_set_rf_radio_mode_command},
    {"wlan-get-rf-radio-mode", NULL, wlan_get_rf_radio_mode_command},
    {"wlan-set-rf-tx-power", "<tx_power> <modulation> <path_id>", wlan_ncp_set_rf_tx_power_command},
    {"wlan-set-rf-tx-cont-mode", "<enable_tx> <cw_mode> <payload_pattern> <cs_mode> <act_sub_ch> <tx_rate>",
     wlan_ncp_set_rf_tx_cont_mode_command},
    {"wlan-set-rf-tx-frame",
     "<start> <data_rate> <frame_pattern> <frame_len> <adjust_burst_sifs> <burst_sifs_in_us> <short_preamble> "
     "<act_sub_ch> <short_gi> <adv_coding> <tx_bf> <gf_mode> <stbc> <bssid>",
     wlan_ncp_set_rf_tx_frame_command},
    {"wlan-get-and-reset-rf-per", NULL, wlan_ncp_set_rf_get_and_reset_rf_per_command},
#endif
    {"wlan-eu-crypto-ccmp-128", "<EncDec>", wlan_eu_crypto_ccmp128_command},
    {"wlan-eu-crypto-gcmp-128", "<EncDec>", wlan_eu_crypto_gcmp128_command},
    {"wlan-get-time", NULL, wlan_get_time_command},
    {"wlan-set-time", "<year> <month> <day> <hour> <minute> <second>", wlan_set_time_command},
    {"wlan-get-temp", NULL, wlan_get_temperature_command},
    {"wlan-start-wps-pbc", NULL, wlan_start_wps_pbc_command},
    {"wlan-generate-wps-pin", NULL, wlan_wps_generate_pin_command},
    {"wlan-start-wps-pin", "<8 digit pin>", wlan_start_wps_pin_command},
    {"wlan-mdns-query", "<service> <protocol>", wlan_mdns_query_command},
    {"ping", "[-s <packet_size>] [-c <packet_count>] [-W <timeout in sec>] <ipv4 address>", ncp_ping_command},
    {"wlan-list", NULL, wlan_list_command},
    {"wlan-remove", "<profile_name>", wlan_remove_command},
    {"wlan-ncp-iperf", NULL, wlan_ncp_iperf_command},
#ifdef CONFIG_NCP_SUPP
    {"wlan-set-okc", "<okc: 0(default)/1>", wlan_set_okc_command},
#endif
};
#endif

int mpu_host_init_cli_commands_wifi()
{
#ifdef CONFIG_SDIO_TEST_LOOPBACK
    if (mpu_host_register_commands(mpu_host_app_cli_commands_loopback,
                                     sizeof(mpu_host_app_cli_commands_loopback) / sizeof(struct mpu_host_cli_command)) != 0)
        return FALSE;
#else
    if (mpu_host_register_commands(mpu_host_app_cli_commands,
                                     sizeof(mpu_host_app_cli_commands) / sizeof(struct mpu_host_cli_command)) != 0)
        return FALSE;
#endif

    return TRUE;
}

int mpu_host_deinit_cli_commands_wifi()
{
#ifdef CONFIG_SDIO_TEST_LOOPBACK
    if (mpu_host_unregister_commands(mpu_host_app_cli_commands_loopback,
                                     sizeof(mpu_host_app_cli_commands_loopback) / sizeof(struct mpu_host_cli_command)) != 0)
        return FALSE;
#else
    if (mpu_host_unregister_commands(mpu_host_app_cli_commands,
                                     sizeof(mpu_host_app_cli_commands) / sizeof(struct mpu_host_cli_command)) != 0)
        return FALSE;
#endif

    return TRUE;
}
