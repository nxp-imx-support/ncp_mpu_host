/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OT_CMDS_H__
#define __OT_CMDS_H__

/* -------------------------------------------------------------------------- */
/*                                  Includes                                  */
/* -------------------------------------------------------------------------- */

#include <stdint.h>

/* -------------------------------------------------------------------------- */
/*                              Variables                                     */
/* -------------------------------------------------------------------------- */

static uint8_t *otcommands[] = {"ba",
                                "bbr",
                                "br",
                                "bufferinfo",
                                "ccathreshold",
                                "ccm",
                                "channel",
                                "child",
                                "childip",
                                "childmax",
                                "childrouterlinks",
                                "childsupervision",
                                "childtimeout",
                                "coap",
                                "coaps",
                                "coex",
                                "commissioner",
                                "contextreusedelay",
                                "counters",
                                "csl",
                                "dataset",
                                "debug",
                                "delaytimermin",
                                "detach",
                                "deviceprops",
                                "diag",
                                "discover",
                                "dns",
                                "domainname",
                                "dua",
                                "eidcache",
                                "ephkey",
                                "eui64",
                                "extaddr",
                                "extpanid",
                                "factoryreset",
                                "fake",
                                "fem",
                                "help",
                                "history",
                                "ifconfig",
                                "instanceid",
                                "ipaddr",
                                "ipmaddr",
                                "joiner",
                                "joinerport",
                                "keysequence",
                                "leaderdata",
                                "leaderweight",
                                "linkmetrics",
                                "linkmetricsmgr",
                                "locate",
                                "log",
                                "lp",
                                "lwip",
                                "mac",
                                "macfilter",
                                "mdns",
                                "meshdiag",
                                "mliid",
                                "mlr",
                                "mode",
                                "multiradio",
                                "nat64",
#if CONFIG_NCP_USE_ENCRYPT
                                "ncp-sys-encrypt",
#endif
#ifdef CONFIG_NCP_USB
                                "ncp-usb-pm2",
#endif
                                "ncp-wake-cfg",
                                "neighbor",
                                "netdata",
                                "netstat",
                                "networkdiagnostic",
                                "networkidtimeout",
                                "networkkey",
                                "networkname",
                                "networktime",
                                "nexthop",
                                "panid",
                                "parent",
                                "parentpriority",
                                "partitionid",
                                "ping",
                                "platform",
                                "pollperiod",
                                "preferrouterid",
                                "prefix",
                                "promiscuous",
                                "pskc",
                                "pskcref",
                                "radio",
                                "radio_nxp",
                                "radiofilter",
                                "rcp",
                                "region",
                                "releaserouterid",
                                "reset",
                                "rloc16",
                                "route",
                                "router",
                                "routerdowngradethreshold",
                                "routereligible",
                                "routeridrange",
                                "routerselectionjitter",
                                "routerupgradethreshold",
                                "scan",
                                "service",
                                "singleton",
                                "sntp",
                                "srp",
                                "state",
                                "tcat",
                                "tcp",
                                "thread",
                                "timeinqueue",
                                "trel",
                                "tvcheck",
                                "txpower",
                                "udp",
                                "unsecureport",
                                "uptime",
                                "vendor",
                                "version",
                                "wifi"};

#endif /* __OT_CMDS_H__ */
