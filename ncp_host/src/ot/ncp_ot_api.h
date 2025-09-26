
/** @file ncp_ot_api.h
 *
 *  @brief This file provides OT APIs implementation
 *
 *  Copyright 2025 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <openthread/border_agent.h>
#include <openthread/dataset.h>
#include <openthread/dns.h>
#include <openthread/dns_client.h>
#include <openthread/error.h>
#include <openthread/icmp6.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/message.h>
#include <openthread/netdata.h>
#include <openthread/srp_client.h>
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/udp.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#ifdef __GNUC__
/** Structure packing begins */
#define NCP_OT_PACK_START
/** Structure packeing end */
#define NCP_OT_PACK_END __attribute__((packed))
#else /* !__GNUC__ */
#ifdef PRAGMA_PACK
/** Structure packing begins */
#define NCP_OT_PACK_START
/** Structure packeing end */
#define NCP_OT_PACK_END
#else /* !PRAGMA_PACK */
/** Structure packing begins */
#define NCP_OT_PACK_START __packed
/** Structure packing end */
#define NCP_OT_PACK_END
#endif /* PRAGMA_PACK */
#endif /* __GNUC__ */

#define NCP_CMD_OPCODE_DoInit 0x1           // DoInit
#define NCP_CMD_OPCODE_SetThreadEnabled 0x2 // thread start/stop
#define NCP_CMD_OPCODE_GET_IPADDR 0x3       // getipaddr
#define NCP_CMD_OPCODE_GET_ROLE 0x4         // device role
#define NCP_CMD_OPCODE_IsThreadEnabled 0x5  // check if ThreadEnabled
#define NCP_CMD_OPCODE_otUdpOpen 0x6        // to open udp socket
#define NCP_CMD_OPCODE_otUdpBind 0x7        // udp bind
#define NCP_CMD_OPCODE_otUdpClose 0x8       // otUdpClose
#define NCP_CMD_OPCODE_otUdpSend 0x9        // otUdpSend
#define NCP_CMD_OPCODE_otdatasetinit 0xA    // "dataset init new"
#define NCP_CMD_OPCODE_otdataset_val_set                                       \
  0xB // "set value for specific dataset member
#define NCP_CMD_OPCODE_otIp6SetEnabled 0xC          // ifconfig
#define NCP_CMD_OPCODE_otIp6IsEnabled 0xD           // otIp6IsEnabled
#define NCP_CMD_OPCODE_otSysInit 0xE                // otSysInit
#define NCP_CMD_OPCODE_otInstanceInitSingle 0xF     // otInstanceInitSingle
#define NCP_CMD_OPCODE_otUdpNewMessage 0x10         // otUdpNewMessage
#define NCP_CMD_OPCODE_otMessageFree 0x11           // otMessageFree
#define NCP_CMD_OPCODE_otMessageAppend 0x12         // otMessageAppend
#define NCP_CMD_OPCODE_otUdpIsOpen 0x13             // otUdpIsOpen
#define NCP_CMD_OPCODE_otMessageGetLength 0x14      // otMessageGetLength
#define NCP_CMD_OPCODE_otMessageRead 0x15           // otMessageRead
#define NCP_CMD_OPCODE_otDatasetSetActiveTlvs 0x16  // set tlvs received
#define NCP_CMD_OPCODE_otDatasetIsCommissioned 0x17 // otDatasetIsCommissioned
#define NCP_CMD_OPCODE_otDatasetGetActiveTlvs 0x18  // otDatasetGetActiveTlvs
#define NCP_CMD_OPCODE_otDatasetGetActive 0x19      // otDatasetGetActive
#define NCP_CMD_OPCODE_otDatasetGetPendingTlvs 0x1A // otDatasetGetPendingTlvs
#define NCP_CMD_OPCODE_otDatasetSetPendingTlvs 0x1B // otDatasetSetPendingTlvs
#define NCP_CMD_OPCODE_otInstanceErasePersistentInfo                           \
  0x1C // otInstanceErasePersistentInfo
#define NCP_CMD_OPCODE_otThreadIsRouterEligible 0x1D // otThreadIsRouterEligible
#define NCP_CMD_OPCODE_otLinkGetCslPeriod 0x1E       // otLinkGetCslPeriod
#define NCP_CMD_OPCODE_otThreadSetRouterEligible                               \
  0x1F                                        // otThreadSetRouterEligible
#define NCP_CMD_OPCODE_otThreadGetRloc16 0x20 // otThreadGetRloc16
#define NCP_CMD_OPCODE_otThreadGetLeaderRouterId                               \
  0x21                                              // otThreadGetLeaderRouterId
#define NCP_CMD_OPCODE_otThreadGetPartitionId 0x22  // otThreadGetPartitionId
#define NCP_CMD_OPCODE_otPlatRadioGetRssi 0x23      // otPlatRadioGetRssi
#define NCP_CMD_OPCODE_otThreadGetLeaderWeight 0x24 // otThreadGetLeaderWeight
#define NCP_CMD_OPCODE_otThreadGetLocalLeaderWeight                            \
  0x25                                          // otThreadGetLocalLeaderWeight
#define NCP_CMD_OPCODE_otThreadGetVersion 0x26  // otThreadGetVersion
#define NCP_CMD_OPCODE_otLinkGetPollPeriod 0x27 // otLinkGetPollPeriod
#define NCP_CMD_OPCODE_otLinkSetCslPeriod 0x28  // otLinkSetCslPeriod
#define NCP_CMD_OPCODE_otLinkSetPollPeriod 0x29 // otLinkSetPollPeriod
#define NCP_CMD_OPCODE_otLinkGetPanId 0x2A      // otLinkGetPanId
#define NCP_CMD_OPCODE_otNetDataGetStableVersion                               \
  0x2B // otNetDataGetStableVersion
#define NCP_CMD_OPCODE_otSrpClientSetLeaseInterval                             \
  0x2C // otSrpClientSetLeaseInterval
#define NCP_CMD_OPCODE_otSrpClientSetKeyLeaseInterval                          \
  0x2D // otSrpClientSetKeyLeaseInterval
#define NCP_CMD_OPCODE_otSrpClientRemoveHostAndServices                        \
  0x2E // otSrpClientRemoveHostAndServices
#define NCP_CMD_OPCODE_otSrpClientEnableAutoHostAddress                        \
  0x2F                                   // otSrpClientEnableAutoHostAddress
#define NCP_CMD_OPCODE_otAppCliInit 0x30 // otAppCliInit
#define NCP_CMD_OPCODE_otThreadSetLinkMode 0x31 // otThreadSetLinkMode
#define NCP_CMD_OPCODE_otThreadGetLinkMode 0x32 // otThreadGetLinkMode
#define NCP_CMD_OPCODE_otThreadGetParentAverageRssi                            \
  0x33 // otThreadGetParentAverageRssi
#define NCP_CMD_OPCODE_otThreadGetParentLastRssi                               \
  0x34                                             // otThreadGetParentLastRssi
#define NCP_CMD_OPCODE_otThreadGetNetworkKey 0x35  // otThreadGetNetworkKey
#define NCP_CMD_OPCODE_otThreadErrorToString 0x36  // otThreadErrorToString
#define NCP_CMD_OPCODE_otBorderAgentGetId 0x37     // otBorderAgentGetId
#define NCP_CMD_OPCODE_otThreadGetNetworkName 0x38 // otThreadGetNetworkName
#define NCP_CMD_OPCODE_otLinkGetExtendedAddress 0x39 // otLinkGetExtendedAddress
#define NCP_CMD_OPCODE_otThreadGetExtendedPanId 0x3A // otThreadGetExtendedPanId
#define NCP_CMD_OPCODE_otThreadGetMeshLocalPrefix                              \
  0x3B                                            // otThreadGetMeshLocalPrefix
#define NCP_CMD_OPCODE_otThreadGetLeaderRloc 0x3C // otThreadGetLeaderRloc
#define NCP_CMD_OPCODE_otNetDataGet 0x3D          // otNetDataGet
#define NCP_CMD_OPCODE_otIp6SubscribeMulticastAddress                          \
  0x3E // otIp6SubscribeMulticastAddress
#define NCP_CMD_OPCODE_otIp6UnsubscribeMulticastAddress                        \
  0x3F // otIp6UnsubscribeMulticastAddress
#define NCP_CMD_OPCODE_otThreadGetNextNeighborInfo                             \
  0x40                                            // otThreadGetNextNeighborInfo
#define NCP_CMD_OPCODE_otNetDataGetNextRoute 0x41 // otNetDataGetNextRoute
#define NCP_CMD_OPCODE_otLinkGetCounters 0x42     // otLinkGetCounters
#define NCP_CMD_OPCODE_otThreadGetIp6Counters 0x43 // otThreadGetIp6Counters
#define NCP_CMD_OPCODE_otSetStateChangedCallback                               \
  0x44                                             // otSetStateChangedCallback
#define NCP_CMD_OPCODE_otIp6AddressFromString 0x45 // otIp6AddressFromString
#define NCP_CMD_OPCODE_otIp6AddressToString 0x46   // otIp6AddressToString
#define NCP_CMD_OPCODE_otNetDataGetVersion 0x47    // otNetDataGetVersion
#define NCP_CMD_OPCODE_otSysProcessDrivers 0x48    // otSysProcessDrivers
#define NCP_CMD_OPCODE_otTaskletsProcess 0x49      // otTaskletsProcess
#define NCP_CMD_OPCODE_otThreadGetChildInfoById 0x4A // otThreadGetChildInfoById
#define NCP_CMD_OPCODE_otIp6GetMulticastAddresses                              \
  0x4B                                             // otIp6GetMulticastAddresses
#define NCP_CMD_OPCODE_otThreadDiscover 0x4C       // otThreadDiscover
#define NCP_CMD_OPCODE_otSrpClientSetHostName 0x4D // otSrpClientSetHostName
#define NCP_CMD_OPCODE_otSrpClientAddService 0x4E  // otSrpClientAddService
#define NCP_CMD_OPCODE_otSrpClientRemoveService 0x4F // otSrpClientRemoveService
#define NCP_CMD_OPCODE_otSrpClientClearService 0x50  // otSrpClientClearService
#define NCP_CMD_OPCODE_otSrpClientEnableAutoStartMode                          \
  0x51 // otSrpClientEnableAutoStartMode
#define NCP_CMD_OPCODE_otSrpClientSetCallback 0x52 // otSrpClientSetCallback
#define NCP_CMD_OPCODE_otDnsBrowseResponseGetServiceName                       \
  0x53 // otDnsBrowseResponseGetServiceName
#define NCP_CMD_OPCODE_otDnsClientBrowse 0x54 // otDnsClientBrowse
#define NCP_CMD_OPCODE_otDnsClientGetDefaultConfig                             \
  0x55 // otDnsClientGetDefaultConfig
#define NCP_CMD_OPCODE_otDnsClientSetDefaultConfig                             \
  0x56 // otDnsClientSetDefaultConfig
#define NCP_CMD_OPCODE_otDnsInitTxtEntryIterator                               \
  0x57                                           // otDnsInitTxtEntryIterator
#define NCP_CMD_OPCODE_otDnsGetNextTxtEntry 0x58 // otDnsGetNextTxtEntry
#define NCP_CMD_OPCODE_otDnsClientResolveService                               \
  0x59 // OtDnsClientResolveService
#define NCP_CMD_OPCODE_otDnsServiceResponseGetServiceName                      \
  0x5A // otDnsServiceResponseGetServiceName
#define NCP_CMD_OPCODE_otDnsServiceResponseGetServiceInfo                      \
  0x5B // otDnsServiceResponseGetServiceInfo

#define NCP_CMD_OPCODE_otIp6IsAddressUnspecified                               \
  0x5C // otIp6IsAddressUnspecified
#define NCP_CMD_OPCODE_otDnsClientResolveAddress                               \
  0x5D                                         // otDnsClientResolveAddress
#define NCP_CMD_OPCODE_otIcmp6SetEchoMode 0x5E // otIcmp6SetEchoMode
#define NCP_CMD_OPCODE_otIp6SetReceiveFilterEnabled                            \
  0x5F                                           // otIp6SetReceiveFilterEnabled
#define NCP_CMD_OPCODE_otIp6SetSlaacEnabled 0x60 // otIp6SetSlaacEnabled
#define NCP_CMD_OPCODE_otIp6SetReceiveCallback 0x61 // otIp6SetReceiveCallback
#define NCP_CMD_OPCODE_otIp6NewMessage 0x62         // otIp6NewMessage
#define NCP_CMD_OPCODE_otIp6Send 0x63               // otIp6Send
#define NCP_CMD_OPCODE_otLinkGetChannel 0x64        // otLinkGetChannel

// defines
#define NCP_EVENT_ID_UDP_RECEIVE 0x1        // UDP_RECEIVE
#define NCP_EVENT_ID_OT_STATE_CHANGE 0x2    // OT_STATE_CHANGE
#define NCP_EVENT_ID_OT_THREAD_DISCOVER 0x3 // otThreadDiscover
#define NCP_EVENT_ID_OT_SRP_CLIENT_STATE_CHANGE                                \
  0x4 // otSrpClientEnableAutoStartMode
#define NCP_EVENT_ID_OT_SRP_CLIENT_SET_CALLBACK 0x5 // otSrpClientSetCallback
#define NCP_EVENT_ID_OT_DNS_CLIENT_BROWSE 0x6       // otDnsClientBrowse
#define NCP_EVENT_ID_OT_DNS_CLIENT_RESOLVE_SERVICE                             \
  0x7 // OtDnsClientResolveService
#define NCP_EVENT_ID_OT_DNS_CLIENT_RESOLVE_ADDRESS                             \
  0x8 // otDnsClientResolveAddress

#define NCP_EVENT_ID_OT_SET_RECEIVE_CB 0x9 // otIp6SetReceiveCallback

#define OT_DATASET_MEMBERS_COUNT 13 // otdataset_members count
#define NCP_CALLBACK_TO_EVENTID_ARRAY_SZ                                       \
  13 // Maximum number of members in callback function to eventid mapping array
#define MAX_32_TO_64_ARRAY_LEN                                                 \
  256 // Maximum size of array to hold 32 to 64 addr mapping

#define MaX_BR_INSTANCE_RECORDS 5

#define MAX_TXTBUFFER_LEN 512 // refer to kMaxTxtDataSize

// ot dataset
struct otdataset {
  const char *member;
  uint8_t index;
};

static struct otdataset otdataset_array[] = {

    {"activetimestamp", 0}, {"pendingtimestamp", 1},
    {"networkkey", 2},      {"networkname", 3},
    {"extendedpanid", 4},   {"meshlocalprefix", 5},
    {"delay", 6},           {"panid", 7},
    {"channel", 8},         {"pskc", 9},
    {"securitypolicy", 10}, {"channelmask", 11},
    {"components", 12},
};

struct address_mapping_32_to_64 {
  uint32_t addr32; // address used at ncp device
  uint64_t addr64; // address from imx
};

typedef struct otInstance {
} otInstance;

struct ptr_to_eventid_mapping {
  /** The name of the CLI command */
  int eventid;
  /** The function that should be invoked for this eventid. */
  int (*ptr_val)();
};

/* OT callback element structure*/
typedef NCP_OT_PACK_START struct {
  uint32_t pld_sz;
  uint8_t *cb_pld_buf;
} NCP_OT_PACK_END ncp_ot_cb_qelem_t;

int cli_test_otInstanceInitSingle(int argc, char *argv[]);
int cli_test_otSysInit(int argc, char *argv[]);          // USER API
int cli_test_DoInit(int argc, char *argv[]);             // USER API
int cli_test_otThreadSetEnabled(int argc, char *argv[]); // SetThreadEnabled
int cli_test_otIp6SetEnabled(int argc, char *argv[]);    // otIp6SetEnabled
int cli_test_otIp6IsEnabled(int argc, char *argv[]);     // otIp6IsEnabled
int cli_test_otIp6GetUnicastAddresses(int argc, char *argv[]);
int cli_test_otThreadGetDeviceRole(int argc, char *argv[]);
int cli_test_IsThreadEnabled(int argc, char *argv[]); // USER API
int cli_test_otUdpOpen(int argc, char *argv[]);
int cli_test_otUdpClose(int argc, char *argv[]);
int cli_test_otUdpIsOpen(int argc, char *argv[]);
int cli_test_otUdpBind(int argc, char *argv[]);
int cli_test_otUdpSend(int argc, char *argv[]);
int cli_test_otUdpNewMessage(int argc, char *argv[]);
int cli_test_otMessageFree(int argc, char *argv[]);
int cli_test_otMessageAppend(int argc, char *argv[]);
int cli_test_datasetinit(int argc, char *argv[]);
int cli_test_dataset_val_set(int argc, char *argv[]);
int cli_test_otDatasetSetActiveTlvs(int argc, char *argv[]);
int cli_test_otDatasetIsCommissioned(int argc, char *argv[]);
int cli_test_otDatasetGetActiveTlvs(int argc, char *argv[]);
int cli_test_otDatasetGetActive(int argc, char *argv[]);
int cli_test_otDatasetGetPendingTlvs(int argc, char *argv[]);
int cli_test_otDatasetSetPendingTlvs(int argc, char *argv[]);
int cli_test_otInstanceErasePersistentInfo(int argc, char *argv[]);
int cli_test_otThreadIsRouterEligible(int argc, char *argv[]);
int cli_test_otLinkGetCslPeriod(int argc, char *argv[]);
int cli_test_otThreadSetRouterEligible(int argc, char *argv[]);
int cli_test_otThreadGetRloc16(int argc, char *argv[]);
int cli_test_otThreadGetLeaderRouterId(int argc, char *argv[]);
int cli_test_otThreadGetPartitionId(int argc, char *argv[]);
int cli_test_otPlatRadioGetRssi(int argc, char *argv[]);
int cli_test_otThreadGetLeaderWeight(int argc, char *argv[]);
int cli_test_otThreadGetLocalLeaderWeight(int argc, char *argv[]);
int cli_test_otThreadGetVersion(int argc, char *argv[]);
int cli_test_otLinkGetPollPeriod(int argc, char *argv[]);
int cli_test_otLinkSetCslPeriod(int argc, char *argv[]);
int cli_test_otLinkSetPollPeriod(int argc, char *argv[]);
int cli_test_otLinkGetPanId(int argc, char *argv[]);
int cli_test_otNetDataGetStableVersion(int argc, char *argv[]);
int cli_test_otSrpClientSetLeaseInterval(int argc, char *argv[]);
int cli_test_otSrpClientSetKeyLeaseInterval(int argc, char *argv[]);
int cli_test_otSrpClientRemoveHostAndServices(int argc, char *argv[]);
int cli_test_otSrpClientEnableAutoHostAddress(int argc, char *argv[]);
int cli_test_otAppCliInit(int argc, char *argv[]);
int cli_test_otThreadSetLinkMode(int argc, char *argv[]);
int cli_test_otThreadGetLinkMode(int argc, char *argv[]);
int cli_test_otThreadGetParentAverageRssi(int argc, char *argv[]);
int cli_test_otThreadGetParentLastRssi(int argc, char *argv[]);
int cli_test_otThreadGetNetworkKey(int argc, char *argv[]);
int cli_test_otThreadErrorToString(int argc, char *argv[]);
int cli_test_otBorderAgentGetId(int argc, char *argv[]);
int cli_test_otThreadGetNetworkName(int argc, char *argv[]);
int cli_test_otLinkGetExtendedAddress(int argc, char *argv[]);
int cli_test_otThreadGetExtendedPanId(int argc, char *argv[]);
int cli_test_otThreadGetMeshLocalPrefix(int argc, char *argv[]);
int cli_test_otThreadGetLeaderRloc(int argc, char *argv[]);
int cli_test_otNetDataGet(int argc, char *argv[]);
int cli_test_otIp6SubscribeMulticastAddress(int argc, char *argv[]);
int cli_test_otIp6UnsubscribeMulticastAddress(int argc, char *argv[]);
int cli_test_otThreadGetNextNeighborInfo(int argc, char *argv[]);
int cli_test_otNetDataGetNextRoute(int argc, char *argv[]);
int cli_test_otLinkGetCounters(int argc, char *argv[]);
int cli_test_otThreadGetIp6Counters(int argc, char *argv[]);
int cli_test_otSetStateChangedCallback(int argc, char *argv[]);
int cli_test_otIp6AddressFromString(int argc, char *argv[]);
int cli_test_otIp6AddressToString(int argc, char *argv[]);
int cli_test_otNetDataGetVersion(int argc, char *argv[]);
int cli_test_otSysProcessDrivers(int argc, char *argv[]);
int cli_test_otTaskletsProcess(int argc, char *argv[]);
int cli_test_otThreadGetChildInfoById(int argc, char *argv[]);
int cli_test_otIp6GetMulticastAddresses(int argc, char *argv[]);
int cli_test_otThreadDiscover(int argc, char *argv[]);
int cli_test_otSrpClientSetHostName(int argc, char *argv[]);
int cli_test_otSrpClientAddService(int argc, char *argv[]);
int cli_test_otSrpClientRemoveService(int argc, char *argv[]);
int cli_test_otSrpClientClearService(int argc, char *argv[]);
int cli_test_otSrpClientEnableAutoStartMode(int argc, char *argv[]);
int cli_test_otSrpClientSetCallback(int argc, char *argv[]);
int cli_test_otDnsBrowseResponseGetServiceName(
    const otDnsBrowseResponse *aResponse);
int cli_test_otDnsClientBrowse(int argc, char *argv[]);
int cli_test_otDnsBrowseResponseGetServiceInstance(
    const otDnsBrowseResponse *aResponse);
int cli_test_otDnsBrowseResponseGetServiceInfo(
    const otDnsBrowseResponse *aResponse, const char *aInstanceLabel,
    otDnsServiceInfo *aServiceInfo);
int cli_test_otDnsClientGetDefaultConfig(int argc, char *argv[]);
int cli_test_otDnsClientSetDefaultConfig(int argc, char *argv[]);
int cli_test_otDnsInitTxtEntryIterator(int argc, char *argv[]);
int cli_test_otDnsGetNextTxtEntry(int argc, char *argv[]);

int cli_test_otDnsClientResolveService(int argc, char *argv[]);
int cli_test_otDnsServiceResponseGetServiceName(
    const otDnsServiceResponse *aResponse);
int cli_test_otDnsServiceResponseGetServiceInfo(
    const otDnsServiceResponse *aResponse);
int cli_test_otIp6IsAddressUnspecified(int argc, char *argv[]);
int cli_test_otDnsClientResolveAddress(int argc, char *argv[]);
int cli_test_otDnsAddressResponseGetAddress(
    const otDnsAddressResponse *aResponse);
int cli_test_otIcmp6SetEchoMode(int argc, char *argv[]);
int cli_test_otIp6SetReceiveFilterEnabled(int argc, char *argv[]);
int cli_test_otIp6SetSlaacEnabled(int argc, char *argv[]);
int cli_test_otIp6SetReceiveCallback(int argc, char *argv[]);
int cli_test_otIp6NewMessage(int argc, char *argv[]);
int cli_test_otIp6Send(int argc, char *argv[]);

int cli_test_otLinkGetChannel(int argc, char *argv[]);

/*NCP functions are those that will be called by MATTER.
 *These functions have same signature as on OT*/
otInstance *otInstanceInitSingle(void);
int otSysInit(void);
otError otThreadSetEnabled(otInstance *aInstance, bool val);
otError otIp6SetEnabled(otInstance *aInstance, bool val);
bool otIp6IsEnabled(otInstance *aInstance);
const otNetifAddress *otIp6GetUnicastAddresses(otInstance *aInstance);
otDeviceRole otThreadGetDeviceRole(otInstance *aInstance);
bool IsThreadEnabled(); //_IsThreadEnabled nxp
otError otUdpClose(otInstance *aInstance, otUdpSocket *aSocket);
bool otUdpIsOpen(otInstance *aInstance, const otUdpSocket *aSocket);
otError otUdpOpen(otInstance *aInstance, otUdpSocket *aSocket,
                  otUdpReceive aCallback, void *aContext);
otError otUdpBind(otInstance *aInstance, otUdpSocket *aSocket,
                  const otSockAddr *aSockName, otNetifIdentifier aNetif);
otError otUdpSend(otInstance *aInstance, otUdpSocket *aSocket,
                  otMessage *aMessage, const otMessageInfo *aMessageInfo);
otMessage *otUdpNewMessage(otInstance *aInstance,
                           const otMessageSettings *aSettings);
void otMessageFree(otMessage *aMessage);
otError otMessageAppend(otMessage *aMessage, const void *aBuf,
                        uint16_t aLength);
uint16_t otMessageRead(const otMessage *aMessage, uint16_t aOffset, void *aBuf,
                       uint16_t aLength);
uint16_t otMessageGetLength(const otMessage *aMessage);
otError otDatasetSetActiveTlvs(otInstance *aInstance,
                               const otOperationalDatasetTlvs *aDataset);
bool otDatasetIsCommissioned(otInstance *aInstance);
otError otDatasetGetActiveTlvs(otInstance *aInstance,
                               otOperationalDatasetTlvs *aDataset);
otError otDatasetGetActive(otInstance *aInstance,
                           otOperationalDataset *aDataset);
otError otDatasetGetPendingTlvs(otInstance *aInstance,
                                otOperationalDatasetTlvs *aDataset);
otError otDatasetSetPendingTlvs(otInstance *aInstance,
                                const otOperationalDatasetTlvs *aDataset);
otError otInstanceErasePersistentInfo(otInstance *aInstance);
bool otThreadIsRouterEligible(otInstance *aInstance);
uint32_t otLinkGetCslPeriod(otInstance *aInstance);
otError otThreadSetRouterEligible(otInstance *aInstance, bool aEligible);
uint16_t otThreadGetRloc16(otInstance *aInstance);
uint8_t otThreadGetLeaderRouterId(otInstance *aInstance);
uint32_t otThreadGetPartitionId(otInstance *aInstance);
int8_t otPlatRadioGetRssi(otInstance *aInstance);
uint8_t otThreadGetLeaderWeight(otInstance *aInstance);
uint8_t otThreadGetLocalLeaderWeight(otInstance *aInstance);
uint16_t otThreadGetVersion(void);
uint32_t otLinkGetPollPeriod(otInstance *aInstance);
otError otLinkSetCslPeriod(otInstance *aInstance, uint32_t aPeriod);
otError otLinkSetPollPeriod(otInstance *aInstance, uint32_t aPollPeriod);
otPanId otLinkGetPanId(otInstance *aInstance);
uint8_t otNetDataGetStableVersion(otInstance *aInstance);
void otSrpClientSetLeaseInterval(otInstance *aInstance, uint32_t aInterval);
void otSrpClientSetKeyLeaseInterval(otInstance *aInstance, uint32_t aInterval);
otError otSrpClientRemoveHostAndServices(otInstance *aInstance,
                                         bool aRemoveKeyLease,
                                         bool aSendUnregToServer);
otError otSrpClientEnableAutoHostAddress(otInstance *aInstance);
void otAppCliInit(otInstance *aInstance);
otError otThreadSetLinkMode(otInstance *aInstance, otLinkModeConfig aConfig);
otLinkModeConfig otThreadGetLinkMode(otInstance *aInstance);
otError otThreadGetParentAverageRssi(otInstance *aInstance,
                                     int8_t *aParentRssi);
otError otThreadGetParentLastRssi(otInstance *aInstance, int8_t *aLastRssi);
void otThreadGetNetworkKey(otInstance *aInstance, otNetworkKey *aNetworkKey);
const char *otThreadErrorToString(otError aError);
otError otBorderAgentGetId(otInstance *aInstance, otBorderAgentId *aId);
const char *otThreadGetNetworkName(otInstance *aInstance);
const otExtAddress *otLinkGetExtendedAddress(otInstance *aInstance);
const otExtendedPanId *otThreadGetExtendedPanId(otInstance *aInstance);
const otMeshLocalPrefix *otThreadGetMeshLocalPrefix(otInstance *aInstance);
otError otThreadGetLeaderRloc(otInstance *aInstance, otIp6Address *aLeaderRloc);
otError otNetDataGet(otInstance *aInstance, bool aStable, uint8_t *aData,
                     uint8_t *aDataLength);
otError otIp6SubscribeMulticastAddress(otInstance *aInstance,
                                       const otIp6Address *aAddress);
otError otIp6UnsubscribeMulticastAddress(otInstance *aInstance,
                                         const otIp6Address *aAddress);
otError otThreadGetNextNeighborInfo(otInstance *aInstance,
                                    otNeighborInfoIterator *aIterator,
                                    otNeighborInfo *aInfo);
otError otNetDataGetNextRoute(otInstance *aInstance,
                              otNetworkDataIterator *aIterator,
                              otExternalRouteConfig *aConfig);
const otMacCounters *otLinkGetCounters(otInstance *aInstance);
const otIpCounters *otThreadGetIp6Counters(otInstance *aInstance);
otError otSetStateChangedCallback(otInstance *aInstance,
                                  otStateChangedCallback aCallback,
                                  void *aContext);
otError otIp6AddressFromString(const char *aString, otIp6Address *aAddress);
void otIp6AddressToString(const otIp6Address *aAddress, char *aBuffer,
                          uint16_t aSize);
uint8_t otNetDataGetVersion(otInstance *aInstance);
void otSysProcessDrivers(otInstance *aInstance);
void otTaskletsProcess(otInstance *aInstance);
otError otThreadGetChildInfoById(otInstance *aInstance, uint16_t aChildId,
                                 otChildInfo *aChildInfo);
const otNetifMulticastAddress *
otIp6GetMulticastAddresses(otInstance *aInstance);
otError otThreadDiscover(otInstance *aInstance, uint32_t aScanChannels,
                         uint16_t aPanId, bool aJoiner,
                         bool aEnableEui64Filtering,
                         otHandleActiveScanResult aCallback,
                         void *aCallbackContext);
otError otSrpClientSetHostName(otInstance *aInstance, const char *aName);
otError otSrpClientAddService(otInstance *aInstance,
                              otSrpClientService *aService);
otError otSrpClientRemoveService(otInstance *aInstance,
                                 otSrpClientService *aService);
otError otSrpClientClearService(otInstance *aInstance,
                                otSrpClientService *aService);
void otSrpClientEnableAutoStartMode(otInstance *aInstance,
                                    otSrpClientAutoStartCallback aCallback,
                                    void *aContext);
void otSrpClientSetCallback(otInstance *aInstance,
                            otSrpClientCallback aCallback, void *aContext);
otError otDnsBrowseResponseGetServiceName(const otDnsBrowseResponse *aResponse,
                                          char *aNameBuffer,
                                          uint16_t aNameBufferSize);
otError otDnsClientBrowse(otInstance *aInstance, const char *aServiceName,
                          otDnsBrowseCallback aCallback, void *aContext,
                          const otDnsQueryConfig *aConfig);
otError
otDnsBrowseResponseGetServiceInstance(const otDnsBrowseResponse *aResponse,
                                      uint16_t aIndex, char *aLabelBuffer,
                                      uint8_t aLabelBufferSize);

otError otDnsBrowseResponseGetServiceInfo(const otDnsBrowseResponse *aResponse,
                                          const char *aInstanceLabel,
                                          otDnsServiceInfo *aServiceInfo);

void otDnsClientSetDefaultConfig(otInstance *aInstance,
                                 const otDnsQueryConfig *aConfig);

const otDnsQueryConfig *otDnsClientGetDefaultConfig(otInstance *aInstance);

void otDnsInitTxtEntryIterator(otDnsTxtEntryIterator *aIterator,
                               const uint8_t *aTxtData,
                               uint16_t aTxtDataLength);

otError otDnsGetNextTxtEntry(otDnsTxtEntryIterator *aIterator,
                             otDnsTxtEntry *aEntry);

otError otDnsClientResolveService(otInstance *aInstance,
                                  const char *aInstanceLabel,
                                  const char *aServiceName,
                                  otDnsServiceCallback aCallback,
                                  void *aContext,
                                  const otDnsQueryConfig *aConfig);
otError
otDnsServiceResponseGetServiceName(const otDnsServiceResponse *aResponse,
                                   char *aLabelBuffer, uint8_t aLabelBufferSize,
                                   char *aNameBuffer, uint16_t aNameBufferSize);

otError
otDnsServiceResponseGetServiceInfo(const otDnsServiceResponse *aResponse,
                                   otDnsServiceInfo *aServiceInfo);

bool otIp6IsAddressUnspecified(const otIp6Address *aAddress);

otError otDnsClientResolveAddress(otInstance *aInstance, const char *aHostName,
                                  otDnsAddressCallback aCallback,
                                  void *aContext,
                                  const otDnsQueryConfig *aConfig);

otError otDnsAddressResponseGetAddress(const otDnsAddressResponse *aResponse,
                                       uint16_t aIndex, otIp6Address *aAddress,
                                       uint32_t *aTtl);

void otIcmp6SetEchoMode(otInstance *aInstance, otIcmp6EchoMode aMode);
void otIp6SetReceiveFilterEnabled(otInstance *aInstance, bool aEnabled);
void otIp6SetSlaacEnabled(otInstance *aInstance, bool aEnabled);
void otIp6SetReceiveCallback(otInstance *aInstance,
                             otIp6ReceiveCallback aCallback,
                             void *aCallbackContext);
otMessage *otIp6NewMessage(otInstance *aInstance,
                           const otMessageSettings *aSettings);
otError otIp6Send(otInstance *aInstance, otMessage *aMessage);

uint8_t otLinkGetChannel(otInstance *aInstance);

/*Helping or test related functions*/
void process_udpreceive(char *response, int len, int eventid);
void process_otstatechange(char *response_index, int len, int eventid);
void process_otthreaddiscover(char *response_index, int len, int eventid);
void process_otsrpclientstatechange(char *response_index, int len, int eventid);
void process_otsrpclientsetcallback(char *response_index, int len, int eventid);
void process_otDnsClientBrowse(char *response_index, int len, int eventid);
void process_otDnsClientResolveService(char *response_index, int len,
                                       int eventid);
void process_otDnsClientResolveAddress(char *response_index, int len,
                                       int eventid);
void process_otIp6SetReceiveCallback(char *response_index, int len,
                                     int eventid);
void ParseAsHexString(char *arraytochange, char *arraytoreturn);

void handle_response(void *arg);
void ot_ncp_callback(void *tlv, size_t tlv_sz, int status);
static void process_event(int eventid, char *response, int len);
void ot_api_init(char *dev_name);
void ot_ncp_send_command(uint8_t *userinputcmd, uint16_t userinputcmd_len);
void map_32_to_64_addr(uint32_t addr32bit, void *addr64bit);
uint64_t get_64_mapped_addr(uint32_t addr32bit);
uint32_t get_32_mapped_addr(void *addr64bit);
void remove_32_mapped_addr(void *addr64bit);
void ncp_memcpy(char *dest, char *src, int bytes_to_copy, int *totalsize);
void ncp_val_mem_copy(char *dest, char src, int *totalsize);

/*DEbug functions*/
#ifdef DEBUG_NCP_OT
void displaychar(char *char_addr, int NoOfChar);
#endif
