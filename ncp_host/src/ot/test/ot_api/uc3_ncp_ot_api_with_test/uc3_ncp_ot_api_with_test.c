/** @file uc3_ncp_ot_api_with_test.c
 *
 *  @brief This file provides OT APIs testig interface
 *
 *  Copyright 2025 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

/*NCP include */
#include <ncp_ot_api.h>
#include <ncp_adapter.h>
#include <ncp_tlv_adapter.h>
#include <uart.h>

/** Structure for registering commands */
struct mpu_host_cli_command_ncp {
  /** The name of the CLI command */
  const char *name;
  /** The help text associated with the command */
  const char *help;
  /** The function that should be invoked for this command. */
  int (*function)(int argc, char *argv[]);
};

static struct mpu_host_cli_command_ncp mpu_host_app_ot_cli_commands[] = {

    {"cli_test_otInstanceInitSingle", "otSysInit",
     cli_test_otInstanceInitSingle},
    {"cli_test_otSysInit", "otSysInit", cli_test_otSysInit},
    {"cli_test_DoInit", " initialize otSysInit and get otinstance",
     cli_test_DoInit},
    {"cli_test_otThreadSetEnabled", "ifconfig up/down",
      cli_test_otThreadSetEnabled},
    {"cli_test_otIp6SetEnabled", "thread start/stop", cli_test_otIp6SetEnabled},
    {"cli_test_otIp6IsEnabled", "check otIp6IsEnabled",
     cli_test_otIp6IsEnabled},
    {"cli_test_otIp6GetUnicastAddresses", "get ip address",
     cli_test_otIp6GetUnicastAddresses},
    {"cli_test_otThreadGetDeviceRole", "get thread device role",
     cli_test_otThreadGetDeviceRole},
    {"cli_test_IsThreadEnabled", "IsThreadEnabled ?", cli_test_IsThreadEnabled},
    {"cli_test_otUdpOpen", "open udp socket", cli_test_otUdpOpen},
    {"cli_test_otUdpBind", "open udp socket", cli_test_otUdpBind},
    {"cli_test_otUdpClose", "close udp socket", cli_test_otUdpClose},
    {"cli_test_otUdpIsOpen", "close udp socket", cli_test_otUdpIsOpen},
    {"cli_test_otUdpSend", "udp send", cli_test_otUdpSend},
    {"cli_test_otUdpNewMessage", "get pointer to buffer for otmesssage",
     cli_test_otUdpNewMessage},
    {"cli_test_otMessageFree", "free message buffer", cli_test_otMessageFree},
    {"cli_test_otMessageAppend", "free message buffer",
     cli_test_otMessageAppend},
    {"cli_test_datasetinit", "dataset init new", cli_test_datasetinit},
    {"cli_test_dataset_val_set", "dataset property set",
     cli_test_dataset_val_set},
    {"cli_test_otDatasetSetActiveTlvs", "dataset init new",
     cli_test_otDatasetSetActiveTlvs},
    {"cli_test_otDatasetIsCommissioned",
     "whether a valid network is present in the Active Operational Dataset",
     cli_test_otDatasetIsCommissioned},
    {"cli_test_otDatasetGetActiveTlvs", "get active TLVs",
     cli_test_otDatasetGetActiveTlvs},
    {"cli_test_otDatasetGetActive", "get active dataset",
     cli_test_otDatasetGetActive},
    {"cli_test_otDatasetGetPendingTlvs", "get pending TLVs",
     cli_test_otDatasetGetPendingTlvs},
    {"cli_test_otDatasetSetPendingTlvs", "dataset commit pending",
     cli_test_otDatasetSetPendingTlvs},
    {"cli_test_otInstanceErasePersistentInfo",
     "erase dataset info from non-volatile",
     cli_test_otInstanceErasePersistentInfo},
    {"cli_test_otThreadIsRouterEligible", "otThreadIsRouterEligible",
     cli_test_otThreadIsRouterEligible},
    {"cli_test_otLinkGetCslPeriod", "otLinkGetCslPeriod",
     cli_test_otLinkGetCslPeriod},
    {"cli_test_otThreadSetRouterEligible", "otThreadSetRouterEligible",
     cli_test_otThreadSetRouterEligible},
    {"cli_test_otThreadGetRloc16", "otThreadGetRloc16",
     cli_test_otThreadGetRloc16},
    {"cli_test_otThreadGetLeaderRouterId", "otThreadGetLeaderRouterId",
     cli_test_otThreadGetLeaderRouterId},
    {"cli_test_otThreadGetPartitionId", "otThreadGetLeaderRouterId",
     cli_test_otThreadGetPartitionId},
    {"cli_test_otPlatRadioGetRssi", "otPlatRadioGetRssi",
     cli_test_otPlatRadioGetRssi},
    {"cli_test_otThreadGetLeaderWeight", "otPlatRadioGetRssi",
     cli_test_otThreadGetLeaderWeight},
    {"cli_test_otThreadGetLocalLeaderWeight", "otThreadGetLocalLeaderWeight",
     cli_test_otThreadGetLocalLeaderWeight},
    {"cli_test_otThreadGetVersion", "otThreadGetVersion",
     cli_test_otThreadGetVersion},
    {"cli_test_otLinkGetPollPeriod", "otLinkGetPollPeriod",
     cli_test_otLinkGetPollPeriod},
    {"cli_test_otLinkSetCslPeriod", "otLinkGetPollPeriod",
     cli_test_otLinkSetCslPeriod},
    {"cli_test_otLinkSetPollPeriod", "otLinkSetPollPeriod",
     cli_test_otLinkSetPollPeriod},
    {"cli_test_otLinkGetPanId", "otLinkGetPanId", cli_test_otLinkGetPanId},
    {"cli_test_otNetDataGetStableVersion", "otNetDataGetStableVersion",
     cli_test_otNetDataGetStableVersion},
    {"cli_test_otSrpClientSetLeaseInterval", "otSrpClientSetLeaseInterval",
     cli_test_otSrpClientSetLeaseInterval},
    {"cli_test_otSrpClientSetKeyLeaseInterval",
     "otSrpClientSetKeyLeaseInterval", cli_test_otSrpClientSetKeyLeaseInterval},
    {"cli_test_otSrpClientRemoveHostAndServices",
     "otSrpClientRemoveHostAndServices",
     cli_test_otSrpClientRemoveHostAndServices},
    {"cli_test_otSrpClientEnableAutoHostAddress",
     "otSrpClientEnableAutoHostAddress",
     cli_test_otSrpClientEnableAutoHostAddress},
    {"cli_test_otAppCliInit", "otAppCliInit", cli_test_otAppCliInit},
    {"cli_test_otThreadSetLinkMode", "otThreadSetLinkMode",
     cli_test_otThreadSetLinkMode},
    {"cli_test_otThreadGetLinkMode", "otThreadGetLinkMode",
     cli_test_otThreadGetLinkMode},
    {"cli_test_otThreadGetParentAverageRssi", "otThreadGetParentAverageRssi",
     cli_test_otThreadGetParentAverageRssi},
    {"cli_test_otThreadGetParentLastRssi", "otThreadGetParentLastRssi",
     cli_test_otThreadGetParentLastRssi},
    {"cli_test_otThreadGetNetworkKey", "otThreadGetNetworkKey",
     cli_test_otThreadGetNetworkKey},
    {"cli_test_otThreadErrorToString", "otThreadErrorToString",
     cli_test_otThreadErrorToString},
    {"cli_test_otBorderAgentGetId", "otBorderAgentGetId",
     cli_test_otBorderAgentGetId},
    {"cli_test_otThreadGetNetworkName", "otThreadGetNetworkName",
     cli_test_otThreadGetNetworkName},
    {"cli_test_otLinkGetExtendedAddress", "otLinkGetExtendedAddress",
     cli_test_otLinkGetExtendedAddress},
    {"cli_test_otThreadGetExtendedPanId", "otThreadGetExtendedPanId",
     cli_test_otThreadGetExtendedPanId},
    {"cli_test_otThreadGetMeshLocalPrefix", "otThreadGetMeshLocalPrefix",
     cli_test_otThreadGetMeshLocalPrefix},
    {"cli_test_otThreadGetLeaderRloc", "otThreadGetLeaderRloc",
     cli_test_otThreadGetLeaderRloc},
    {"cli_test_otNetDataGet", "otNetDataGet", cli_test_otNetDataGet},
    {"cli_test_otIp6SubscribeMulticastAddress",
     "otIp6SubscribeMulticastAddress", cli_test_otIp6SubscribeMulticastAddress},
    {"cli_test_otIp6UnsubscribeMulticastAddress",
     "otIp6UnsubscribeMulticastAddress",
     cli_test_otIp6UnsubscribeMulticastAddress},
    {"cli_test_otThreadGetNextNeighborInfo", "otThreadGetNextNeighborInfo",
     cli_test_otThreadGetNextNeighborInfo},
    {"cli_test_otNetDataGetNextRoute", "otNetDataGetNextRoute",
     cli_test_otNetDataGetNextRoute},
    {"cli_test_otLinkGetCounters", "otLinkGetCounters",
     cli_test_otLinkGetCounters},
    {"cli_test_otThreadGetIp6Counters", "otThreadGetIp6Counters",
     cli_test_otThreadGetIp6Counters},
    {"cli_test_otSetStateChangedCallback", "otSetStateChangedCallback",
     cli_test_otSetStateChangedCallback},
    {"cli_test_otIp6AddressFromString", "otIp6AddressFromString",
     cli_test_otIp6AddressFromString},
    {"cli_test_otIp6AddressToString", "otIp6AddressToString",
     cli_test_otIp6AddressToString},
    {"cli_test_otNetDataGetVersion", "otNetDataGetVersion",
     cli_test_otNetDataGetVersion},
    {"cli_test_otSysProcessDrivers", "otSysProcessDrivers",
     cli_test_otSysProcessDrivers},
    {"cli_test_otTaskletsProcess", "otTaskletsProcess",
     cli_test_otTaskletsProcess},
    {"cli_test_otThreadGetChildInfoById", "otThreadGetChildInfoById",
     cli_test_otThreadGetChildInfoById},
    {"cli_test_otIp6GetMulticastAddresses", "otIp6GetMulticastAddresses",
     cli_test_otIp6GetMulticastAddresses},
    {"cli_test_otThreadDiscover", "otThreadDiscover",
     cli_test_otThreadDiscover},
    {"cli_test_otSrpClientSetHostName", "otSrpClientSetHostName",
     cli_test_otSrpClientSetHostName},
    {"cli_test_otSrpClientAddService", "otSrpClientAddService",
     cli_test_otSrpClientAddService},
    {"cli_test_otSrpClientRemoveService", "otSrpClientRemoveService",
     cli_test_otSrpClientRemoveService},
    {"cli_test_otSrpClientClearService", "otSrpClientClearService",
     cli_test_otSrpClientClearService},
    {"cli_test_otSrpClientEnableAutoStartMode",
     "otSrpClientEnableAutoStartMode", cli_test_otSrpClientEnableAutoStartMode},
    {"cli_test_otSrpClientSetCallback", "otSrpClientSetCallback",
     cli_test_otSrpClientSetCallback},
    //{"cli_test_otDnsBrowseResponseGetServiceName", //to be tested within the API's only
    //"otDnsBrowseResponseGetServiceName",
    //cli_test_otDnsBrowseResponseGetServiceName},
    {"cli_test_otDnsClientBrowse", "otDnsClientBrowse",
     cli_test_otDnsClientBrowse},

    {"cli_test_otDnsClientGetDefaultConfig", "otDnsClientGetDefaultConfig",
     cli_test_otDnsClientGetDefaultConfig},

    {"cli_test_otDnsClientSetDefaultConfig", "otDnsClientSetDefaultConfig",
     cli_test_otDnsClientSetDefaultConfig},

    {"cli_test_otDnsInitTxtEntryIterator", "otDnsInitTxtEntryIterator",
     cli_test_otDnsInitTxtEntryIterator},

    {"cli_test_otDnsGetNextTxtEntry", "otDnsGetNextTxtEntry",
     cli_test_otDnsGetNextTxtEntry},

    {"cli_test_otDnsClientResolveService", "otDnsClientResolveService",
     cli_test_otDnsClientResolveService},

    // {"cli_test_otDnsServiceResponseGetServiceName",//to be tested within the API's only
    //  "otDnsServiceResponseGetServiceName",
    //  cli_test_otDnsServiceResponseGetServiceName},

    // {"cli_test_otDnsServiceResponseGetServiceInfo",
    //  "otDnsServiceResponseGetServiceInfo",
    //  cli_test_otDnsServiceResponseGetServiceInfo},

    {"cli_test_otIp6IsAddressUnspecified", "otIp6IsAddressUnspecified",
     cli_test_otIp6IsAddressUnspecified},

    {"cli_test_otDnsClientResolveAddress", "otDnsClientResolveAddress",
     cli_test_otDnsClientResolveAddress},

    {"cli_test_otIcmp6SetEchoMode", "otIcmp6SetEchoMode",
     cli_test_otIcmp6SetEchoMode},

    {"cli_test_otIp6SetReceiveFilterEnabled", "otIp6SetReceiveFilterEnabled",
     cli_test_otIp6SetReceiveFilterEnabled},

    {"cli_test_otIp6SetSlaacEnabled", "otIp6SetSlaacEnabled",
     cli_test_otIp6SetSlaacEnabled},

    {"cli_test_otIp6SetReceiveCallback", "otIp6SetReceiveCallback",
     cli_test_otIp6SetReceiveCallback},

    {"cli_test_otIp6NewMessage", "otIp6NewMessage", cli_test_otIp6NewMessage},

    {"cli_test_otIp6Send", "otIp6Send", cli_test_otIp6Send},
};

#define NCP_TOTAL_COMMANDS                                                     \
  sizeof(mpu_host_app_ot_cli_commands) / sizeof(struct mpu_host_cli_command_ncp)
#define SPACE_CHARACTER 32

/* -------------------------------------------------------------------------- */
/*                           Function prototypes                              */
/* -------------------------------------------------------------------------- */

static void ot_ncp_mainloop(void);
/* -------------------------------------------------------------------------- */
/*                              Private Functions                             */
/* -------------------------------------------------------------------------- */

/*Main loop function*/
static void ot_ncp_mainloop(void) {
  uint8_t user_cmd[256];
  uint8_t user_cmd_api[256];
  uint8_t input_cmd_length = 0;
  uint8_t tempcharc;
  int otcommandlen;
  static char *argv[32];
  int argc = 0;
  int ret = 0;
  int commandindex;

  /*print all aviable API's*/
  for (int i = 0; i < NCP_TOTAL_COMMANDS; i++) {
    printf("%s\r\n", mpu_host_app_ot_cli_commands[i].name);
  }
  printf("> ");

  while (1) {
    /*Receive command from user*/
    /*User has not sent command yet.*/
    scanf("%c", &tempcharc);

    if (tempcharc == '\n') {
      /*User pressed enter*/
      if (input_cmd_length != 0) {
        *(user_cmd + input_cmd_length) = '\0';
        input_cmd_length++;

        argv[0] = user_cmd; // Actual command/API
        /*create argc and argv from the user input*/
        for (int i = 0; i < input_cmd_length; i++) {
          if (user_cmd[i] == SPACE_CHARACTER) {
            argv[argc + 1] = &user_cmd[i + 1];
            user_cmd[i] = '\0';
            argc++;
          }
        }

        for (commandindex = 0; commandindex < NCP_TOTAL_COMMANDS;
             commandindex++) {
          if (!strcmp(mpu_host_app_ot_cli_commands[commandindex].name,
                      argv[0])) {
            /*If command is registered and matches,
             *call the respective API/command function*/
            ret =
                mpu_host_app_ot_cli_commands[commandindex].function(argc, argv);
            break;
          }
        }

        if (ret == -1) {
          printf("Bad response\r\n");
          input_cmd_length = 0;
          printf("> ");
          continue;
        }

        if (commandindex == (NCP_TOTAL_COMMANDS)) {
          if (strcmp(argv[0], "help") == 0) {
            /*print all aviable API's*/
            for (int i = 0; i < NCP_TOTAL_COMMANDS; i++) {
              printf("%s\r\n", mpu_host_app_ot_cli_commands[i].name);
            }
          } else {
            printf("Command not found\r\n");
          }

          input_cmd_length = 0;
          printf("> ");
          continue;
        }

        /*Command is processed at this point*/
        argc = 0;
        input_cmd_length = 0;
        printf("> ");
      } else {
        /*No command entered*/
        printf("> ");
      }
    } else {
      /*Continue reading characters from the user*/
      *(user_cmd + input_cmd_length) = tempcharc;
      input_cmd_length++;
    }

    usleep(10); /*Let sleep and other process to run*/
  }

  return;
}

#ifdef CONFIG_NCP_OT_API_TEST
void main(int argc, char *argv[]) {
  ot_api_init(getenv("NCP_PORT"));
  /*Call main task*/
  ot_ncp_mainloop();

  return;
}
#endif
