/** @file ncp_ot_api.c
 *
 *  @brief This file provides OT APIs implementation
 *
 *  Copyright 2025 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "ncp_ot_api.h"
#include <arpa/inet.h>
#include <stddef.h>

#include <ncp_adapter.h>
#include <ncp_debug.h>
#include <ncp_tlv_adapter.h>

// OT RX queue
static pthread_t ot_ncp_tlv_rx_thread;
#define NCP_OT_RX_QUEUE_NAME "/ncp_ot_rx_queue"
#define NCP_OT_CB_RX_QUEUE_NAME "/ncp_ot_cb_rx_queue"
static mqd_t ot_ncp_tlv_rx_msgq_handle;
static pthread_mutex_t ot_ncp_tlv_rx_queue_mutex;
static int ot_ncp_tlv_rx_queue_len = 0;
static mqd_t ot_ncp_cb_rx_msgq_handle;
static pthread_mutex_t ot_ncp_cb_rx_queue_mutex;
static pthread_t ot_ncp_cb_rx_thread;
// OT RX queue

/** command semaphore*/
sem_t cmd_sem_ot;

static char ot_ncp_tx_buf[2048 * 2] = {0};
/*call back function specific for udpreceive*/
void (*callback_udpreceive)(void *aContext, otMessage *aMessage,
                            const otMessageInfo *aMessageInfo);
void (*ncp_otStateChangedCallback)(otChangedFlags aFlags, void *aContext);
void (*ncp_otHandleActiveScanResult)(otActiveScanResult *aResult,
                                     void *aContext);
void (*ncp_otSrpClientAutoStartCallback)(const otSockAddr *aServerSockAddr,
                                         void *aContext);
void (*ncp_otSrpClientSetCallback)(otError aError,
                                   const otSrpClientHostInfo *aHostInfo,
                                   const otSrpClientService *aServices,
                                   const otSrpClientService *aRemovedServices,
                                   void *aContext);

void (*ncp_OnDnsBrowseResultcallback)(otError aError,
                                      const otDnsBrowseResponse *aResponse,
                                      void *aContext);

void (*ncp_otDnsServiceCallback)(otError aError,
                                 const otDnsServiceResponse *aResponse,
                                 void *aContext);

void (*ncp_otDnsAddressCallback)(otError aError,
                                 const otDnsAddressResponse *aResponse,
                                 void *aContext);

void (*ncp_otIp6ReceiveCallbackdef)(otMessage *aMessage, void *aContext);

static int registered_ptr_eventids = 0;
otUdpSocket g_ot_mSocket;
otInstance *g_p_ot_aInstance = (otInstance *)"OTinstance\0";
otOperationalDataset ncpdataset;
otOperationalDatasetTlvs ncpDatasetTlvs;

static struct ptr_to_eventid_mapping
    ptr_eventid_array[NCP_CALLBACK_TO_EVENTID_ARRAY_SZ] = {0};

static struct address_mapping_32_to_64
    addr_mapping_array[MAX_32_TO_64_ARRAY_LEN] = {0};
static int total_32_to_64_values = 0;
bool rx_wait_flag;

// BR -browse response API variables
static uint8_t *BR_serviceinstance_array[MaX_BR_INSTANCE_RECORDS] = {
    NULL}; // confirm max
static uint8_t *BR_serviceinfo_array[MaX_BR_INSTANCE_RECORDS] = {
    NULL}; // confirm max
static uint8_t oterror_getservicename = 0;
static char BR_name[OT_DNS_MAX_NAME_SIZE]; // 255

// otDnsClientResolveService related API's variables
static uint8_t *p_otDnsServiceResponseGetServiceName = NULL;
static uint8_t *p_otDnsServiceResponseGetServiceInfo = NULL;
static uint8_t *p_otDnsAddressResponseGetAddress = NULL;

/*Static functions declaration*/
static void handleUdpReceive(void *aContext, otMessage *aMessage,
                             const otMessageInfo *aMessageInfo); // cli_test
static void processStateChange(otChangedFlags aFlags,
                               void *aContext); // cli_test
static void HandleActiveScanResult(otActiveScanResult *aResult,
                                   void *aContext); // cli_test
static void ncp_OnSrpClientStateChange(const otSockAddr *aServerSockAddr,
                                       void *aContext); // cli_test
static void ncp_SrpClientCallback(otError aError,
                                  const otSrpClientHostInfo *aHostInfo,
                                  const otSrpClientService *aServices,
                                  const otSrpClientService *aRemovedServices,
                                  void *aContext); // cli_test
static void ncp_OnDnsBrowseResult(otError aError,
                                  const otDnsBrowseResponse *aResponse,
                                  void *aContext);
static void ncp_otDnsService_cb(otError aError,
                                const otDnsServiceResponse *aResponse,
                                void *aContext);
static void ncp_otDnsAddress_cb(otError aError,
                                const otDnsAddressResponse *aResponse,
                                void *aContext);
static void ncp_otIp6SetReceiveCallback(otMessage *aMessage, void *aContext);

static bool register_ptr_eventid(void *ptr_val, int eventid);
static void *get_ptr_from_eventid(int eventid);
static void remove_ptr_eventid(int eventid);

// ot cb handling
static void handle_ot_cb(void *arg);
static void recv_ot_cb_data(uint8_t *pld, uint32_t size);
#ifdef DEBUG_NCP_OT
void displaychar(char *char_addr, int NoOfChar);
#endif

#define NCP_TLV_CMD_TYPE 0X01
#define NCP_TLV_CMD_CLASS 0X02
#define NCP_TLV_CMD_SUBCLASS 0X02
#define NCP_TLV_CMD_RESULT 0X00
#define NCP_TLV_CMD_MSGTYPE 0X00

#define NCP_TLV_HDR_LEN 12
#define SPACE_CHARACTER 32
#define OT_OPCODE_SIZE 1

#define NCP_CMD_15D4 0x20000000
#define GET_MSG_TYPE(cmd) ((cmd)&0x000f0000)
#define GET_CMD_CLASS(cmd) (((cmd)&0xf0000000) >> 28)
#define GET_CMD_ID(cmd) ((cmd)&0x0000ffff)
#define GET_MSG_TYPE(cmd) ((cmd)&0x000f0000)
#define NCP_MSG_TYPE_CMD 0x00010000
#define NCP_MSG_TYPE_EVENT 0x00020000
#define NCP_MSG_TYPE_RESP 0x00030000
#define NCP_API_GET_RSP_ERROR(resp_index) (*(resp_index + 1))
#define NCP_API_GET_RSP_PAYLOAD(resp_index) (*((uint8_t *)resp_index + 8))
#define NCP_CMD_RESP_HDR_SZ 8     // 8 bytes (error 4 bytes + ot error 4 bytes)
#define NCP_CMD_RESP_OTERROR_SZ 1 // 1 byte for oterror in ncp response payload

typedef struct {
  uint32_t response_sz;
  uint8_t *recv_buf;
} ncp_response_t;

typedef struct command_header {
  /*bit0 ~ bit15 cmd id,  bit16 ~ bit19 message type, bit20 ~ bit27 cmd
   * subclass, bit28 ~ bit31 cmd class*/
  uint32_t cmd;
  uint16_t size;
  uint16_t seqnum;
  uint16_t result;
  uint16_t rsvd;
} NCP_TLV_COMMAND;

static ncp_response_t recv_item;

uint32_t *response_index;

void ot_api_init(char *dev_name) {
  int status = 0; // 0 -> success
  struct mq_attr qattr;
  pthread_attr_t tattr;

#ifndef CONFIG_NCP_MATTER_OT
  /*NCP adapter init*/
  int ret;

  ret = ncp_adapter_init(dev_name);

  if (ret != 0) {
    printf("ERROR: ncp_adapter_init \n");
  }
#endif

  if (sem_init(&cmd_sem_ot, 1, 0) == -1) // access to multiple process
  {
    printf("Failed to init semaphore!\r\n");
    goto err_sem;
  }

  // OT RX  queue
  status = pthread_mutex_init(&ot_ncp_tlv_rx_queue_mutex, NULL);
  if (status != 0) {
    goto err_mutex;
  }

  qattr.mq_flags = 0;
  qattr.mq_maxmsg = NCP_TLV_QUEUE_LENGTH;
  qattr.mq_msgsize = NCP_TLV_QUEUE_MSG_SIZE;
  qattr.mq_curmsgs = 0;
  ot_ncp_tlv_rx_msgq_handle =
      mq_open(NCP_OT_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);

  if ((int)ot_ncp_tlv_rx_msgq_handle == -1) {
    goto err_msgq;
  }
  // queue rx ends

  /* initialized thread with default attributes */
  status = pthread_attr_init(&tattr);
  if (status != 0) {
    goto err_arrt_init;
  }

  /*Install tlv handler for ot callback*/
  ncp_tlv_install_handler(NCP_TLV_CMD_CLASS, (void *)ot_ncp_callback);

  // task for handling response from device side
  status = pthread_create(&ot_ncp_tlv_rx_thread, &tattr,
                          (void *)handle_response, NULL);
  if (status != 0) {
    goto err_arrt_init;
  }

  // ot_cb_ handling
  status = pthread_mutex_init(&ot_ncp_cb_rx_queue_mutex, NULL);
  if (status != 0) {
    goto err_arrt_init;
  }

  ot_ncp_cb_rx_msgq_handle =
      mq_open(NCP_OT_CB_RX_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &qattr);

  if ((int)ot_ncp_cb_rx_msgq_handle == -1) {
    goto err_msgq_ot_cb;
  }

  status =
      pthread_create(&ot_ncp_cb_rx_thread, &tattr, (void *)handle_ot_cb, NULL);
  if (status != 0) {
    goto err_cb_rx_thread;
  }
  return;

err_cb_rx_thread:
  mq_close(ot_ncp_cb_rx_msgq_handle);
err_msgq_ot_cb:
  pthread_mutex_destroy(&ot_ncp_cb_rx_queue_mutex);
err_arrt_init:
  mq_close(ot_ncp_tlv_rx_msgq_handle);
err_msgq:
  pthread_mutex_destroy(&ot_ncp_tlv_rx_queue_mutex);
err_mutex:
  sem_destroy(&cmd_sem_ot);
err_sem:
#ifndef CONFIG_NCP_MATTER_OT
  ncp_adapter_deinit();
#endif
}

/*Callback function for ot*/
void ot_ncp_callback(void *tlv, size_t tlv_sz, int status) {
  ncp_tlv_qelem_t *qelem = NULL;
  uint8_t *qelem_pld = NULL;

  pthread_mutex_lock(&ot_ncp_tlv_rx_queue_mutex);
  if (tlv_sz > NCP_TLV_QUEUE_MSGPLD_SIZE) {
    goto Fail;
  }

  if (ot_ncp_tlv_rx_queue_len == NCP_TLV_QUEUE_LENGTH) {
    goto Fail;
  }

  qelem = (ncp_tlv_qelem_t *)malloc(sizeof(ncp_tlv_qelem_t) + tlv_sz);
  if (!qelem) {
    goto Fail;
  }

  qelem->tlv_sz = tlv_sz;
  qelem->priv = NULL;
  qelem_pld = (uint8_t *)qelem + sizeof(ncp_tlv_qelem_t);
  memcpy(qelem_pld, tlv, tlv_sz);
  qelem->tlv_buf = qelem_pld;

  if (mq_send(ot_ncp_tlv_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE,
              0) != 0) {
    free(qelem);
    goto Fail;
  }
  ot_ncp_tlv_rx_queue_len++;

Fail:
  pthread_mutex_unlock(&ot_ncp_tlv_rx_queue_mutex);
  return;
}

/*This function will handle response from the device side */
void handle_response(void *arg) {
  ssize_t tlv_sz = 0;
  ncp_tlv_qelem_t *qelem = NULL;

  while (1) {
    qelem = NULL;
    tlv_sz = mq_receive(ot_ncp_tlv_rx_msgq_handle, (char *)&qelem,
                        NCP_TLV_QUEUE_MSG_SIZE, NULL);
    if (tlv_sz == -1) {
      continue;
    }

    if (qelem == NULL) { // make sure qelem is not null
      continue;
    }

    pthread_mutex_lock(&ot_ncp_tlv_rx_queue_mutex);
    ot_ncp_tlv_rx_queue_len--;
    pthread_mutex_unlock(&ot_ncp_tlv_rx_queue_mutex);

    NCP_TLV_COMMAND *received_hdr = (NCP_TLV_COMMAND *)qelem->tlv_buf;
    uint32_t cmdeventid_id = GET_CMD_ID(received_hdr->cmd);
    uint32_t cmd_class = GET_CMD_CLASS(received_hdr->cmd);
    uint32_t cmd_msgtype = GET_MSG_TYPE(received_hdr->cmd);

    if (cmd_msgtype == NCP_MSG_TYPE_EVENT) // if response is of event type
    {
      recv_ot_cb_data(qelem->tlv_buf, qelem->tlv_sz);

    } else // normal response of the command sent earlier
    {
      recv_item.response_sz = qelem->tlv_sz;
      recv_item.recv_buf = (uint8_t *)malloc(qelem->tlv_sz + 1);

      if (recv_item.recv_buf == NULL) {
        return;
      }
      memcpy(recv_item.recv_buf, qelem->tlv_buf, qelem->tlv_sz);

      sem_post(&cmd_sem_ot);
      free(recv_item.recv_buf);
    }
    free(qelem);
  }
}

void handle_ot_cb(void *arg) {
  ssize_t tlv_sz = 0;
  ncp_ot_cb_qelem_t *qelem = NULL;

  while (1) {
    qelem = NULL;
    tlv_sz = mq_receive(ot_ncp_cb_rx_msgq_handle, (char *)&qelem,
                        NCP_TLV_QUEUE_MSG_SIZE, NULL);
    if (tlv_sz == -1) {
      continue;
    }

    if (qelem == NULL) { // make sure qelem is not NULL
      continue;
    }

    NCP_TLV_COMMAND *received_hdr = (NCP_TLV_COMMAND *)qelem->cb_pld_buf;
    uint32_t cmdeventid_id = GET_CMD_ID(received_hdr->cmd);
    uint32_t cmd_class = GET_CMD_CLASS(received_hdr->cmd);
    uint32_t cmd_msgtype = GET_MSG_TYPE(received_hdr->cmd);

    process_event(cmdeventid_id, (char *)&qelem->cb_pld_buf[NCP_TLV_HDR_LEN],
                  qelem->pld_sz);

    free(qelem);
  }
}

static void recv_ot_cb_data(uint8_t *pld, uint32_t size) {

  ncp_ot_cb_qelem_t *qelem = NULL;
  uint8_t *qelem_pld = NULL;

  pthread_mutex_lock(&ot_ncp_cb_rx_queue_mutex);

  qelem = (ncp_ot_cb_qelem_t *)malloc(sizeof(ncp_ot_cb_qelem_t) + size);
  if (!qelem) {
    goto Fail;
  }

  qelem->pld_sz = size;
  qelem_pld = (uint8_t *)qelem + sizeof(ncp_ot_cb_qelem_t);
  memcpy(qelem_pld, pld, size);
  qelem->cb_pld_buf = qelem_pld;

  if (mq_send(ot_ncp_cb_rx_msgq_handle, (char *)&qelem, NCP_TLV_QUEUE_MSG_SIZE,
              0) != 0) {
    free(qelem);
    goto Fail;
  }

Fail:
  pthread_mutex_unlock(&ot_ncp_cb_rx_queue_mutex);
  return;
}
/*This function init ot instance on ncp device side, currently return ot
 * instance is based on host side and it has nothing to do on the device side.*/
int cli_test_otInstanceInitSingle(int argc, char *argv[]) {
  otInstance *otinstance;
  otinstance = otInstanceInitSingle();

  printf("otInstanceInitSingle value is %p and device side is %x \r\n",
         otinstance, get_32_mapped_addr(otinstance));
  return 0;
}

otInstance *otInstanceInitSingle(void) {
  // we assume device has only one fixed ot isntance and already running, so we
  // just fix here on host side
  return g_p_ot_aInstance; // otinstance;
}

/*This function calls otSysInit*/
int cli_test_otSysInit(int argc, char *argv[]) {
  int error;
  error = otSysInit();

  printf("otSysInit status is %d \r\n", error);
  return 0;
}

int otSysInit(void) {
  int error;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSysInit;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  error = NCP_API_GET_RSP_ERROR(response_index);

  return error;
}

/*This function initializes otSysInit and gets otinstance*/
int cli_test_DoInit(int argc, char *argv[]) {
  otSysInit();
  usleep(5);
  otInstanceInitSingle();
  usleep(5);
  otIp6SetEnabled(g_p_ot_aInstance, 1);
  usleep(5);
  otThreadSetEnabled(g_p_ot_aInstance, 1);
  usleep(5);
  cli_test_otDatasetGetActive(0, 0);
  usleep(5);
  while ((0 || 1) == otThreadGetDeviceRole(g_p_ot_aInstance)) {
    printf("wait for the device to be attached... \r\n");
    usleep(2000000);
  }

  return 0;
}

/*This function will replica of thread start/stop*/
int cli_test_otThreadSetEnabled(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 1) {
    printf("Missing argument! use->cmd <1/0> \r\n");
    return -1;
  }

  oterror = otThreadSetEnabled(g_p_ot_aInstance, atoi(argv[1]));
  printf("otThreadSetEnabled OTERROR value is %d\r\n", oterror);
  return 0;
}

otError otThreadSetEnabled(otInstance *aInstance, bool val) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_SetThreadEnabled;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // value from the user
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = val;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

/*This function will replica of ifconfig up/down*/
int cli_test_otIp6SetEnabled(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 1) {
    printf("Missing argument! use->cmd <1/0> \r\n");
    return -1;
  }

  oterror = otIp6SetEnabled(g_p_ot_aInstance, atoi(argv[1]));
  printf("otIp6SetEnabled OTERROR value is %d\r\n", oterror);
  return 0;
}

otError otIp6SetEnabled(otInstance *aInstance, bool val) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6SetEnabled;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // value from the user
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = val;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));
  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

/*otIp6IsEnabled*/
int cli_test_otIp6IsEnabled(int argc, char *argv[]) {
  bool return_val;
  return_val = otIp6IsEnabled(g_p_ot_aInstance);
  printf("otIp6IsEnabled status is %d\r\n", return_val);
  return 0;
}

bool otIp6IsEnabled(otInstance *aInstance) {
  bool return_val;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6IsEnabled;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  return_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  return return_val;
}

/*Get all the thread Unicast IP address*/
int cli_test_otIp6GetUnicastAddresses(int argc, char *argv[]) {
  const otNetifAddress *unicastAddrs;
  unicastAddrs = otIp6GetUnicastAddresses(g_p_ot_aInstance);

  for (const otNetifAddress *addr = unicastAddrs; addr; addr = addr->mNext) {
    char ipv6_binary[17] = {0};
    char ipv6_tex[40] = {0};
    memcpy((char *)ipv6_binary, (char *)&(addr->mAddress), 16);
    inet_ntop(AF_INET6, ipv6_binary, ipv6_tex, 40);
    printf("%s\r\n", ipv6_tex);
  }

  return 0;
}

const otNetifAddress *otIp6GetUnicastAddresses(otInstance *aInstance) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_GET_IPADDR;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  //
  static char *p_otNetifAddress;
  uint8_t no_of_pointers =
      *((uint8_t *)(recv_item.recv_buf + (recv_item.response_sz - 1)));

  // if memory was previously allocated, we will free that, and will allocate
  // new one based on the required new size, Size can be different based on the
  // device ot state
  if (p_otNetifAddress == NULL) {
    //(no_of_pointers * 4) is required to compensate for 32 and 64 bit
    // architecture
    p_otNetifAddress =
        (char *)malloc(recv_item.response_sz + (no_of_pointers * 4) -
                       (NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                        1)); //- for opcode and response, 1 byte remove is for
                             // no_of_pointers payload
  } else {
    free(p_otNetifAddress);
    p_otNetifAddress =
        (char *)malloc(recv_item.response_sz + (no_of_pointers * 4) -
                       (NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                        1)); //- for opcode and response, 1 byte remove is for
                             // no_of_pointers payload
  }

  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index + NCP_CMD_RESP_HDR_SZ;
  otNetifAddress *unicastAddrs = (otNetifAddress *)p_otNetifAddress;
  uint32_t next_memeber = 0;
  otNetifAddress *next_unicastAddrs;

  do {
    char *p_mAddress = (char *)unicastAddrs;
    for (int i = 0; i < sizeof(otIp6Address); i++) {
      *p_mAddress++ = *p_payload_param++;
      payloadsaved++;
    }

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    char *p_mPrefixLength = (char *)&unicastAddrs->mPrefixLength;
    for (int i = 0; i < sizeof(uint8_t); i++) {
      *p_mPrefixLength++ = *p_payload_param++;
      payloadsaved++;
    }

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    char *p_mAddressOrigin = (char *)&unicastAddrs->mAddressOrigin;
    for (int i = 0; i < sizeof(uint8_t); i++) {
      *p_mAddressOrigin++ = *p_payload_param++;
      payloadsaved++;
    }

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mPreferred = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mValid = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mScopeOverrideValid = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mScopeOverride = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mRloc = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mMeshLocal = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    unicastAddrs->mSrpRegistered = *p_payload_param++;
    payloadsaved++;

    p_payload_param =
        (char *)response_index + NCP_CMD_RESP_HDR_SZ + payloadsaved;
    char *p_mNext = (char *)&next_memeber;
    for (int i = 0; i < sizeof(uint32_t); i++) {
      *p_mNext++ = *p_payload_param++;
      payloadsaved++;
    }

    next_unicastAddrs =
        (otNetifAddress *)&unicastAddrs->mNext +
        sizeof(unicastAddrs->mNext); // will point to next  otNetifAddress

    if (next_memeber != 0) {
      unicastAddrs->mNext = next_unicastAddrs;
    } else {
      unicastAddrs->mNext = NULL;
    }

    unicastAddrs = next_unicastAddrs;

  } while (next_memeber != 0);

  return (otNetifAddress *)p_otNetifAddress;
}

/*Get NCP device current role
    OT_DEVICE_ROLE_DISABLED = 0, ///< The Thread stack is disabled.
    OT_DEVICE_ROLE_DETACHED = 1, ///< Not currently participating in a Thread
   network/partition. OT_DEVICE_ROLE_CHILD    = 2, ///< The Thread Child role.
    OT_DEVICE_ROLE_ROUTER   = 3, ///< The Thread Router role.
    OT_DEVICE_ROLE_LEADER   = 4, ///< The Thread Leader role.
*/
int cli_test_otThreadGetDeviceRole(int argc, char *argv[]) {
  otDeviceRole dev_role;
  dev_role = otThreadGetDeviceRole(g_p_ot_aInstance);
  printf("device role is %d \r\n", dev_role);
  return 0;
}

otDeviceRole otThreadGetDeviceRole(otInstance *aInstance) {
  otDeviceRole dev_role = 0;
  /*Not to send ot instance, assuming single ot instance used*/
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_GET_ROLE;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  dev_role = NCP_API_GET_RSP_PAYLOAD(response_index);

  return dev_role;
}

int cli_test_IsThreadEnabled(int argc, char *argv[]) {
  bool isthreadenabled;
  isthreadenabled = IsThreadEnabled();
  printf("IsThreadEnabled value is %d \r\n", isthreadenabled);

  return 0;
}

bool IsThreadEnabled() {
  bool isthreadenabled;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_IsThreadEnabled;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  isthreadenabled = NCP_API_GET_RSP_PAYLOAD(response_index);

  return isthreadenabled;
}

int cli_test_otUdpOpen(int argc, char *argv[]) {
  void *aContext = {"context"};
  otError oterror = 0;
  oterror =
      otUdpOpen(g_p_ot_aInstance, &g_ot_mSocket, handleUdpReceive, aContext);
  printf("otUdpOpen return OTERROR status is %d with context %p\r\n", oterror,
         aContext);

  return 0;
}

int cli_test_otUdpClose(int argc, char *argv[]) {
  otError oterror = 0;
  oterror = otUdpClose(g_p_ot_aInstance, &g_ot_mSocket);
  printf("otUdpClose return OTERROR status is %d \r\n", oterror);
}

otError otUdpClose(otInstance *aInstance, otUdpSocket *aSocket) {
  otError oterror = 0;
  // unused aInstance, otUdpSocket *aSocket. no need to send this to device
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otUdpClose;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // aSocket
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint32_t device_aSocket = get_32_mapped_addr(aSocket);
  char *p_aSocket = (char *)&(device_aSocket);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_aSocket++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);
  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    remove_ptr_eventid(NCP_EVENT_ID_UDP_RECEIVE);
    remove_32_mapped_addr(aSocket);
  }

  return oterror;
}

static void handleUdpReceive(void *aContext, otMessage *aMessage,
                             const otMessageInfo *aMessageInfo) {
  char buf[1500] = {0};
  int length;
  char ipstring[40];
  inet_ntop(AF_INET6, &(aMessageInfo->mPeerAddr), ipstring, 40);
  length = otMessageRead(aMessage, 0, buf, sizeof(buf) - 1);
  buf[length] = '\0';
  printf("App context %p bytes received %d msg: %s from %s with port %d \r\n",
         aContext, length, buf, ipstring, aMessageInfo->mPeerPort);
}

/*This function will send otInstance, otUdpSocket, aCallback function and app
 * context */
otError otUdpOpen(otInstance *aInstance, otUdpSocket *aSocket,
                  otUdpReceive aCallback, void *aContext) {
  otError oterror = 0;
  uint32_t device_socket;
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otUdpOpen;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_aSocket = (char *)&aSocket;
  for (int i = 0; i < sizeof(uint64_t); i++) {
    *tlv_var_payload++ = *p_aSocket++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otUdpSocket.mSockName
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mSockName = (char *)&(aSocket->mSockName);
  for (int i = 0; i < sizeof(otSockAddr); i++) {
    *tlv_var_payload++ = *p_mSockName++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otUdpSocket.mPeerName
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mPeerName = (char *)&(aSocket->mPeerName);
  for (int i = 0; i < sizeof(otSockAddr); i++) {
    *tlv_var_payload++ = *p_mPeerName++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otUdpSocket.mHandler of udp socket
  uint32_t mHandler;
  mHandler =
      (uint32_t)aSocket
          ->mHandler; // need to check here, because pointer on linux is 64 bit
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mHandler = (char *)&(mHandler);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_mHandler++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otUdpSocket.*mContext
  uint32_t mContext;
  mContext =
      (uint32_t)aSocket
          ->mContext; // need to check here, because pointer on linux is 64 bit
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mContext = (char *)&(mContext);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_mContext++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otUdpSocket.*mHandle
  uint32_t mHandle;
  mHandle =
      (uint32_t)aSocket
          ->mHandle; // need to check here, because pointer on linux is 64 bit
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mHandle = (char *)&(mHandle);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_mHandle++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otUdpSocket.*mNext
  uint32_t mNext;
  mNext = (uint32_t)aSocket
              ->mNext; // need to check here, because pointer on linux is 64 bit
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mNext = (char *)&(mNext);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_mNext++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  /*
  // callback of type otUdpReceive
  tlv_var_payload    = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint64_t mCallback = (uint64_t)aCallback;

  char *p_mCallback = (char *)&(mCallback);
  for (int i = 0; i < sizeof(uint64_t); i++)
  {
      *tlv_var_payload++ = *p_mCallback++; // save char data char by char
  }
  total_tx_len += ((char *)tlv_var_payload - (char
  *)(&ot_ncp_tx_buf[total_tx_len]));
  */

  // context
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint64_t maContext = (uint64_t)aContext;
  char *p_maContext = (char *)&(maContext);
  for (int i = 0; i < sizeof(uint64_t); i++) {
    *tlv_var_payload++ = *p_maContext++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];
    char *p_device_socket = (char *)&device_socket;
    for (int i = 0; i < sizeof(uint32_t); i++) {
      *p_device_socket++ = *p_payload_param++;
      payloadsaved++;
    }
    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_UDP_RECEIVE);
    map_32_to_64_addr(device_socket,
                      aSocket); // will be used to refer this socket further
  }

  return oterror;
}

/*This function requires IP address, port number and interface to be bounded
 * with socket*/
int cli_test_otUdpBind(int argc, char *argv[]) {
  if (argc < 3) {
    printf("IP address, port number or interface is not specified! use->cmd "
           "<IP><Port><Interface> \r\n");
    return -1;
  }
  otError oterror = 0;
  otSockAddr server_sockaddr;
  otNetifIdentifier netif =
      atoi(argv[3]); // need to check if thread or backbone interface i.e
                     // OT_NETIF_THREAD
  inet_pton(AF_INET6, argv[1], &(server_sockaddr.mAddress));
  server_sockaddr.mPort = (uint16_t)atoi(argv[2]);

  oterror = otUdpBind(g_p_ot_aInstance, &g_ot_mSocket, &server_sockaddr, netif);
  printf("otUdpBind return OTERROR status is %d \r\n", oterror);

  return 0;
}

/*This function will save the address of cb function gainst provided eventid*/
static bool register_ptr_eventid(void *ptr_val, int eventid) {
  // check if eventid is not already registered
  bool eventid_registered = 0;
  int rot_eventid;
  for (int rot_eventid = 0; rot_eventid < registered_ptr_eventids;
       rot_eventid++) {
    if (ptr_eventid_array[rot_eventid].eventid == eventid) {
#ifdef DEBUG_NCP_OT
      printf(
          "register_ptr_eventid(): Already there. Event id %d cb func %p \r\n",
          eventid, ptr_val);
#endif
      eventid_registered = 1;
      break;
    }
  }

  if (eventid_registered == 0) {
    ptr_eventid_array[registered_ptr_eventids].eventid = eventid;
    ptr_eventid_array[registered_ptr_eventids].ptr_val = ptr_val;
    registered_ptr_eventids++;
#ifdef DEBUG_NCP_OT
    printf("register_ptr_eventid(): registered value. Event id %d cb func %p "
           "total reg %d\r\n",
           eventid, ptr_val, registered_ptr_eventids);
#endif
  }

  return eventid_registered;
}

static void remove_ptr_eventid(int eventid) {
  void *temp_ptr = NULL;
  int temp_eventid = 0;
  for (int rot_eventid = 0; rot_eventid < registered_ptr_eventids;
       rot_eventid++) {
    if (ptr_eventid_array[rot_eventid].eventid == eventid) {
      // need to remove here decrement registered_ptr_eventids and replace last
      // one at this position unless this is the the only value or its at the
      // last position

      if (registered_ptr_eventids == 1 ||
          (registered_ptr_eventids - rot_eventid) ==
              1) // if there is only one value or value found is the last index
                 // value
      {
#ifdef DEBUG_NCP_OT
        printf("remove_ptr_eventid(): Event id %d remove only cb func %p \r\n",
               eventid, ptr_eventid_array[rot_eventid].ptr_val);
#endif
        ptr_eventid_array[rot_eventid].eventid = 0;
        ptr_eventid_array[rot_eventid].ptr_val = NULL;
      } else {
#ifdef DEBUG_NCP_OT
        printf("remove_ptr_eventid(): Event id %d remove only cb func %p and "
               "move last one moved with id %d\r\n",
               eventid, ptr_eventid_array[rot_eventid].ptr_val,
               ptr_eventid_array[registered_ptr_eventids - 1].eventid);
#endif
        ptr_eventid_array[rot_eventid].eventid = 0;
        ptr_eventid_array[rot_eventid].ptr_val = NULL;

        temp_eventid = ptr_eventid_array[registered_ptr_eventids - 1].eventid;
        temp_ptr = ptr_eventid_array[registered_ptr_eventids - 1].ptr_val;

        ptr_eventid_array[registered_ptr_eventids - 1].eventid = 0;
        ptr_eventid_array[registered_ptr_eventids - 1].ptr_val = NULL;

        ptr_eventid_array[rot_eventid].eventid = temp_eventid;
        ptr_eventid_array[rot_eventid].ptr_val = temp_ptr;
      }
      registered_ptr_eventids--;

      break;
    }
  }

  return;
}

void process_udpreceive(char *response_index, int len, int eventid) {
  void *aContext;
  uint64_t received_aContext;
  otMessage *aMessage;
  otMessageInfo aMessageInfo;
  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;
  uint16_t getmessagelen = 0;
  uint16_t readmessagelen = 0;

  char *p_aContext = (char *)&received_aContext;
  for (int i = 0; i < sizeof(uint64_t); i++) {
    *p_aContext++ = *p_payload_param++;
    payloadsaved++;
  }
  aContext = (void *)received_aContext;

  // Get length of the received message
  p_payload_param = (char *)response_index + payloadsaved;
  char *p_messagelen = (char *)&getmessagelen;
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *p_messagelen++ = *p_payload_param++;
    payloadsaved++;
  }

  // Get length of the received message
  p_payload_param = (char *)response_index + payloadsaved;
  p_messagelen = (char *)&readmessagelen;
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *p_messagelen++ = *p_payload_param++;
    payloadsaved++;
  }

  // Get message based on the actual read length
  p_payload_param = (char *)response_index + payloadsaved;
  /*otMessage is saved in this manner
--> getmessgaelength
--> readmessgaelength
--> actualmessage
*/
  aMessage =
      malloc(readmessagelen + sizeof(getmessagelen) + sizeof(readmessagelen));
  memcpy((uint8_t *)aMessage, (uint8_t *)&getmessagelen, sizeof(getmessagelen));
  memcpy((uint8_t *)aMessage + sizeof(getmessagelen),
         (uint8_t *)&readmessagelen, sizeof(readmessagelen));
  char *p_aMessage =
      (char *)aMessage + sizeof(getmessagelen) + sizeof(readmessagelen);
  for (int i = 0; i < readmessagelen; i++) {
    *p_aMessage++ = *p_payload_param++;
    payloadsaved++;
  }

  // structure otMessageInfo
  // otMessageInfo.mSockAddr
  p_payload_param = (char *)response_index + payloadsaved;
  char *p_mSockAddr = (char *)&aMessageInfo.mSockAddr;
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    *p_mSockAddr++ = *p_payload_param++;
    payloadsaved++;
  }

  // otMessageInfomPeerAddr
  p_payload_param = (char *)response_index + payloadsaved;
  char *p_mPeerAddr = (char *)&(aMessageInfo.mPeerAddr);
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    *p_mPeerAddr++ = *p_payload_param++;
    payloadsaved++;
  }

  // otMessageInfo.mSockPort
  p_payload_param = (char *)response_index + payloadsaved;
  char *p_mSockPort = (char *)&(aMessageInfo.mSockPort);
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *p_mSockPort++ = *p_payload_param++;
    payloadsaved++;
  }

  // otMessageInfo.mPeerPort
  p_payload_param = (char *)response_index + payloadsaved;
  char *p_mPeerPort = (char *)&(aMessageInfo.mPeerPort);
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *p_mPeerPort++ = *p_payload_param++;
    payloadsaved++;
  }

  // otMessageInfo.mHopLimit
  p_payload_param = (char *)response_index + payloadsaved;
  aMessageInfo.mHopLimit = *p_payload_param++;
  payloadsaved++;

  // otMessageInfo.mEcn
  p_payload_param = (char *)response_index + payloadsaved;
  aMessageInfo.mEcn = *p_payload_param++;
  payloadsaved++;

  // otMessageInfo.mIsHostInterface
  p_payload_param = (char *)response_index + payloadsaved;
  aMessageInfo.mIsHostInterface = *p_payload_param++;
  payloadsaved++;
  // otMessageInfo.mAllowZeroHopLimit
  p_payload_param = (char *)response_index + payloadsaved;
  aMessageInfo.mAllowZeroHopLimit = *p_payload_param++;
  payloadsaved++;

  // otMessageInfo.mMulticastLoop
  p_payload_param = (char *)response_index + payloadsaved;
  aMessageInfo.mMulticastLoop = *p_payload_param++;
  payloadsaved++;

  /*get the callback function based on the eventid and call teh respective cb
   * function*/
  callback_udpreceive = get_ptr_from_eventid(eventid);

  if (callback_udpreceive != NULL) {
    callback_udpreceive(aContext, aMessage, &aMessageInfo);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }

  if (aMessage != NULL) {
    free(aMessage);
  }
}

/*This function returens address of the cb function on host side provided
 * eventid*/
static void *get_ptr_from_eventid(int eventid) {
  void *ret_ptr = NULL;
  for (int rot_eventid = 0; rot_eventid < registered_ptr_eventids;
       rot_eventid++) {
    if (ptr_eventid_array[rot_eventid].eventid == eventid) {
      ret_ptr = ptr_eventid_array[rot_eventid].ptr_val;
      break;
    }
  }
#ifdef DEBUG_NCP_OT
  printf("get_ptr_from_eventid(): Event id %d cb func %p\r\n", eventid,
         ret_ptr);
#endif
  return ret_ptr;
}

otError otUdpBind(otInstance *aInstance, otUdpSocket *aSocket,
                  const otSockAddr *aSockName, otNetifIdentifier aNetif) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otUdpBind;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // aSocket
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint32_t device_aSocket = get_32_mapped_addr(aSocket);
  char *p_aSocket = (char *)&(device_aSocket);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_aSocket++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otSockAddr.aSockName
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mAddress = (char *)&(aSockName->mAddress);
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    *tlv_var_payload++ = *p_mAddress++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otSockAddr.mport
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mPort = (char *)&(aSockName->mPort);
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *tlv_var_payload++ = *p_mPort++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // aNetif
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = aNetif;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otUdpIsOpen(int argc, char *argv[]) {
  bool return_val;

  return_val = otUdpIsOpen(g_p_ot_aInstance, &g_ot_mSocket);
  printf("otUdpIsOpen return value is %d \r\n", return_val);

  return 0;
}

bool otUdpIsOpen(otInstance *aInstance, const otUdpSocket *aSocket) {
  bool ret_value;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otUdpIsOpen;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // aSocket
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint32_t device_aSocket = get_32_mapped_addr(aSocket);
  char *p_aSocket = (char *)&(device_aSocket);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_aSocket++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_value = NCP_API_GET_RSP_PAYLOAD(response_index);

  return (bool)ret_value;
}

int cli_test_otUdpSend(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Too few arguments provided! use-> cmd <IP><Port><Message-ptr>\r\n");
    return -1;
  }

  otError oterror = 0;
  otMessageInfo aMessageInfo;
  memset(&aMessageInfo, 0, sizeof(otMessageInfo));
  uint64_t *
      message; // the pointer of already created message using NCP_otMessageFree
  message = (uint64_t *)strtol(argv[3], NULL,
                               16); // assumes user enters in number base 16
  inet_pton(AF_INET6, argv[1],
            &(aMessageInfo.mPeerAddr)); // assuming only use of IPV6 address
  aMessageInfo.mPeerPort = (uint16_t)atoi(argv[2]);

  oterror = otUdpSend(g_p_ot_aInstance, &g_ot_mSocket, (otMessage *)message,
                      &aMessageInfo);
  printf("otUdpSend return OTERROR status is %d \r\n", oterror);
}

otError otUdpSend(otInstance *aInstance, otUdpSocket *aSocket,
                  otMessage *aMessage, const otMessageInfo *aMessageInfo) {
  otError oterror = 0;
  uint16_t messagelen = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otUdpSend;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // aSocket
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint32_t device_aSocket = get_32_mapped_addr(aSocket);
  char *p_aSocket = (char *)&(device_aSocket);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_aSocket++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // message pointer
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint32_t device_message = get_32_mapped_addr(aMessage);
  char *p_device_message = (char *)&(device_message);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_message++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo
  // otMessageInfo.mSockAddr
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mSockAddr = (char *)&(aMessageInfo->mSockAddr);
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    *tlv_var_payload++ = *p_mSockAddr++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mPeerAddr
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mPeerAddr = (char *)&(aMessageInfo->mPeerAddr);
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    *tlv_var_payload++ = *p_mPeerAddr++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mSockPort
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mSockPort = (char *)&(aMessageInfo->mSockPort);
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *tlv_var_payload++ = *p_mSockPort++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mPeerPort
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mPeerPort = (char *)&(aMessageInfo->mPeerPort);
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *tlv_var_payload++ = *p_mPeerPort++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mHopLimit
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = aMessageInfo->mHopLimit;

  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mEcn
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = aMessageInfo->mEcn;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mIsHostInterface
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = aMessageInfo->mIsHostInterface;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mAllowZeroHopLimit
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = aMessageInfo->mAllowZeroHopLimit;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otMessageInfo.mMulticastLoop
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = aMessageInfo->mMulticastLoop;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE) {
    remove_32_mapped_addr(
        aMessage); // if not executed here, host need to call otMessageFree
  }

  return oterror;
}

int cli_test_otUdpNewMessage(int argc, char *argv[]) {
  otMessage *message;
  bool mineOT_MESSAGE_PRIORITY_NORMAL = 1;
  bool minemLinkSecurityEnabled = 1;
  otMessageSettings messageSettings = {minemLinkSecurityEnabled,
                                       mineOT_MESSAGE_PRIORITY_NORMAL};
  message = otUdpNewMessage(g_p_ot_aInstance, &messageSettings);
  printf("otUdpNewMessage pointer address %p \r\n", message);
}

otMessage *otUdpNewMessage(otInstance *aInstance,
                           const otMessageSettings *aSettings) {
  int payloadsaved = 0;
  char *p_payload_param;
  void *device_message;
  uint32_t received_message;
  void *host_message;
  uint8_t isNULL_aSettings = (aSettings == NULL) ? true : false;

  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otUdpNewMessage;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // save otMessageSettings

  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_var_payload++ = isNULL_aSettings;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  if (!isNULL_aSettings) {
    tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
    *tlv_var_payload++ = aSettings->mLinkSecurityEnabled;
    total_tx_len +=
        ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

    tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
    *tlv_var_payload++ = aSettings->mPriority;
    total_tx_len +=
        ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));
  }

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  // oterror           = NCP_API_GET_RSP_PAYLOAD(response_index);
  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];
  // oterror           = NCP_API_GET_RSP_PAYLOAD(response_index);
  char *p_device = (char *)&received_message;
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *p_device++ = *p_payload_param++;
    payloadsaved++;
  }

  if (received_message == 0) {
    host_message = NULL;
  } else {
    host_message = (uint8_t *)malloc(1);
    map_32_to_64_addr(received_message, host_message);
  }

  return host_message;
}

int cli_test_otMessageFree(int argc, char *argv[]) {
  uint64_t *message;
  message = (uint64_t *)strtol(argv[1], NULL,
                               16); // assumes user enters in number base 16
  otMessageFree((otMessage *)message);
  printf("otMessageFree done  %p\r\n", message);
  free(message);
}

void otMessageFree(otMessage *aMessage) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otMessageFree;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint64_t device_message = get_32_mapped_addr(aMessage);
  char *p_device_message = (char *)&(device_message);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_message++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  remove_32_mapped_addr(aMessage);

  return;
}

int cli_test_otMessageAppend(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Too few arguments provided! use-> cmd <Message-ptr>\r\n");
    return -1;
  }
  otError oterror = 0;
  uint64_t *
      message; // the pointer of already created message using NCP_otMessageFree
  message = (uint64_t *)strtol(argv[1], NULL,
                               16); // assumes user enters in number base 16
  const char udpmessage[] = {"HELLO from IMX NCP HOST. This message is sent "
                             "from NCP. NXP NCP Project"};
  oterror =
      otMessageAppend((otMessage *)message, udpmessage, sizeof(udpmessage));
  printf("otMessageAppend return OTERROR status is %d for address %p\r\n",
         oterror, message);
}

otError otMessageAppend(otMessage *aMessage, const void *aBuf,
                        uint16_t aLength) {
  otError oterror = 0;
  int total_tx_len = 0;
  uint16_t buff_len = aLength;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otMessageAppend;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  uint32_t device_message = get_32_mapped_addr(aMessage);
  char *p_device_message = (char *)&(device_message);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_message++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_buff_len = (char *)&buff_len;
  for (int i = 0; i < sizeof(uint16_t); i++) {
    *tlv_var_payload++ = *p_buff_len++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_aBuf = (char *)aBuf;
  for (int i = 0; i < buff_len; i++) {
    *tlv_var_payload++ = *p_aBuf++; // save char data char by char
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_datasetinit(int argc, char *argv[]) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otdatasetinit;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);
}

int cli_test_dataset_val_set(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Too few arguments provided! use-> cmd <property><value>\r\n");
    return -1;
  }

  uint16_t channel;
  uint16_t panid;
  uint8_t networkkey[OT_NETWORK_KEY_SIZE];
  otNetworkName networkname;
  int8_t otdataset_index = -1;
  int rot_otdataset;

  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otdataset_val_set;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  for (rot_otdataset = 0; rot_otdataset < OT_DATASET_MEMBERS_COUNT;
       rot_otdataset++) {
    if (strcmp(otdataset_array[rot_otdataset].member, argv[1]) == 0) {
      otdataset_index = otdataset_array[rot_otdataset].index;

      break;
    }
  }

  if (otdataset_index == -1) {
    return -1;
  }

  // used to identify dataset members
  *tlv_var_payload++ = otdataset_index;
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  if (strcmp(argv[1], "channel") == 0) {
    channel = atoi(argv[2]);

    char *p_channel = (char *)&channel;
    for (int i = 0; i < sizeof(uint16_t); i++) {
      *tlv_var_payload++ = *p_channel++; // save char data char by char
    }
    total_tx_len +=
        ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));
  }

  if (strcmp(argv[1], "panid") == 0) {
    panid = (uint16_t)strtol(argv[2], NULL,
                             16); // assumes user enters in number base 16
    char *p_panid = (char *)&panid;
    for (int i = 0; i < sizeof(uint16_t); i++) {
      *tlv_var_payload++ = *p_panid++; // save char data char by char
    }
    total_tx_len +=
        ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));
  }

  if (strcmp(argv[1], "networkkey") == 0) {
    if (strlen(argv[2]) < 32) {
      return -1; // networkkey should be of 16 bytes
    }
    ParseAsHexString(argv[2], networkkey);
    char *p_networkkey = (char *)&networkkey;
    for (int i = 0; i < sizeof(networkkey); i++) {
      *tlv_var_payload++ = *p_networkkey++; // save char data char by char
    }
    total_tx_len +=
        ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));
  }

  if (strcmp(argv[1], "networkname") == 0) {
    if (strlen(argv[2]) >
        (sizeof(networkname.m8) - 1)) // 16 bytes are allowed in NW name
    {
      return -1;
    }

    memcpy(&networkname.m8, argv[2], sizeof(networkname.m8));
    char *p_networkname = (char *)&networkname;
    for (int i = 0; i < sizeof(networkname.m8); i++) {
      *tlv_var_payload++ = *p_networkname++; // save char data char by char
    }
    total_tx_len +=
        ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));
  }

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);
}

void ParseAsHexString(char *arraytochange, char *arraytoreturn) {
  char *concatenate2bytes = malloc(2);
  char *p_concatenate2bytes = concatenate2bytes;
  int arraytoreturn_rot = 0;

  int i = 0;
  while (i < strlen(arraytochange)) {
    *p_concatenate2bytes++ = arraytochange[i];
    if (i % 2 != 0) {
      uint16_t num = (uint16_t)strtol(concatenate2bytes, NULL, 16);
      arraytoreturn[arraytoreturn_rot] = num;
      arraytoreturn_rot++;
      p_concatenate2bytes = concatenate2bytes;
    }
    i = i + 1;
  }

  free(concatenate2bytes);
}

void ot_ncp_send_command(uint8_t *userinputcmd, uint16_t userinputcmd_len) {
  uint8_t *cmd_buf = NULL;
  uint32_t total_len = 0;
  uint8_t otcommandlen;

  total_len = userinputcmd_len + NCP_TLV_HDR_LEN;

  cmd_buf = (uint8_t *)malloc(total_len);

  if (cmd_buf == NULL) {
    ncp_adap_e("failed to allocate memory for command");
    return;
  }

  NCP_TLV_COMMAND *cmd_hdr = (NCP_TLV_COMMAND *)cmd_buf;

  cmd_hdr->cmd = (NCP_TLV_CMD_CLASS << 28) | (NCP_TLV_CMD_SUBCLASS << 20) |
                 (NCP_TLV_CMD_MSGTYPE << 16) | NCP_TLV_CMD_TYPE;
  cmd_hdr->size = total_len;
  // cmd_hdr->seqnum   = 0x00;
  cmd_hdr->result = NCP_TLV_CMD_RESULT;
  // cmd_hdr->rsvd     = 0;

  if (userinputcmd_len > 0) {
    memcpy((cmd_buf + NCP_TLV_HDR_LEN), userinputcmd, userinputcmd_len);
  }

  ncp_tlv_send(cmd_buf, total_len);
  free(cmd_buf);

  sem_wait(&cmd_sem_ot); // wait for the cmd response.

  return;
}

/*This function takes eventid, received buff, received len
 *and calls the respective processing function*/
static void process_event(int eventid, char *response, int len) {
  if (eventid == NCP_EVENT_ID_UDP_RECEIVE) // for udpreceive
  {
    process_udpreceive(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_STATE_CHANGE) {
    process_otstatechange(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_THREAD_DISCOVER) {
    process_otthreaddiscover(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_SRP_CLIENT_STATE_CHANGE) {
    process_otsrpclientstatechange(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_SRP_CLIENT_SET_CALLBACK) {
    process_otsrpclientsetcallback(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_DNS_CLIENT_BROWSE) {
    process_otDnsClientBrowse(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_DNS_CLIENT_RESOLVE_SERVICE) {
    process_otDnsClientResolveService(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_DNS_CLIENT_RESOLVE_ADDRESS) {
    process_otDnsClientResolveAddress(response, len, eventid);
  }
  if (eventid == NCP_EVENT_ID_OT_SET_RECEIVE_CB) {
    process_otIp6SetReceiveCallback(response, len, eventid);
  }
}

void map_32_to_64_addr(uint32_t addr32bit, void *addr64bit) // confirmed
{
  bool addr_registered = 0;
  int rot_addr;

  for (int rot_addr = 0; rot_addr < total_32_to_64_values; rot_addr++) {
    if (addr_mapping_array[rot_addr].addr64 == (uint64_t)addr64bit &&
        addr_mapping_array[rot_addr].addr32 == addr32bit) {
      addr_registered = 1;
#ifdef DEBUG_NCP_OT
      printf("map_32_to_64_addr():values already there 64 bit addr %p and 32 "
             "bit addr %x  \r\n",
             addr64bit, addr32bit);
#endif

      break;
    }
  }

  if (addr_registered == 0) {
    addr_mapping_array[total_32_to_64_values].addr64 = (uint64_t)addr64bit;
    addr_mapping_array[total_32_to_64_values].addr32 = addr32bit;
    total_32_to_64_values++;
#ifdef DEBUG_NCP_OT
    printf("map_32_to_64_addr(): 64 bit addr %p and 32 bit addr %x  total "
           "values in array %d \r\n",
           addr64bit, addr32bit, total_32_to_64_values);
#endif
  }
}

void remove_32_mapped_addr(void *addr64bit) // checked
{
  uint64_t temp_save_64_mapped_addr = 0;
  uint32_t temp_save_32_mapped_addr = 0;
  for (int rot_addr_arr = 0; rot_addr_arr < total_32_to_64_values;
       rot_addr_arr++) {
    if (addr_mapping_array[rot_addr_arr].addr64 == (uint64_t)addr64bit) {
      // need to remove here decrement total_32_to_64_values and replace last
      // one at this position unless this is the the only value or its at the
      // last position

      if (total_32_to_64_values == 1 ||
          (total_32_to_64_values - rot_addr_arr) ==
              1) // if there is only one value or value found is the last index
                 // value
      {
        addr_mapping_array[rot_addr_arr].addr64 = 0;
        addr_mapping_array[rot_addr_arr].addr32 = 0;
#ifdef DEBUG_NCP_OT
        printf(
            "remove_32_mapped_addr(): 64 bit addr %p only value removed \r\n",
            addr64bit);
#endif
      } else {
        addr_mapping_array[rot_addr_arr].addr64 = 0;
        addr_mapping_array[rot_addr_arr].addr32 = 0;

        temp_save_64_mapped_addr =
            addr_mapping_array[total_32_to_64_values - 1].addr64;
        temp_save_32_mapped_addr =
            addr_mapping_array[total_32_to_64_values - 1].addr32;

        addr_mapping_array[total_32_to_64_values - 1].addr64 = 0;
        addr_mapping_array[total_32_to_64_values - 1].addr32 = 0;

        addr_mapping_array[rot_addr_arr].addr64 = temp_save_64_mapped_addr;
        addr_mapping_array[rot_addr_arr].addr32 = temp_save_32_mapped_addr;
#ifdef DEBUG_NCP_OT
        printf("remove_32_mapped_addr(): 64 bit addr %p value removed and last "
               "one moved %p \r\n",
               addr64bit, temp_save_64_mapped_addr);
#endif
      }
      total_32_to_64_values--;

      break;
    }
  }

  return;
}

uint64_t
get_64_mapped_addr(uint32_t addr32bit) // need to confirm its use and impl
{
  uint64_t ret_64_mapped_addr = 0;
  for (int rot_addr_arr = 0; rot_addr_arr < total_32_to_64_values;
       rot_addr_arr++) {
    if (addr_mapping_array[rot_addr_arr].addr32 == addr32bit) {
      ret_64_mapped_addr = addr_mapping_array[rot_addr_arr].addr64;
      break;
    }
  }
#ifdef DEBUG_NCP_OT
  printf(
      "get_64_mapped_addr(): 64 bit addr %p returned for 32 bit value %x \r\n",
      ret_64_mapped_addr, addr32bit);
#endif
  return ret_64_mapped_addr;
}

uint32_t get_32_mapped_addr(void *addr64bit) // verified
{
  uint32_t ret_32_mapped_addr = 0;
  for (int rot_addr_arr = 0; rot_addr_arr < total_32_to_64_values;
       rot_addr_arr++) {
    if (addr_mapping_array[rot_addr_arr].addr64 == (uint64_t)addr64bit) {
      ret_32_mapped_addr = addr_mapping_array[rot_addr_arr].addr32;
      break;
    }
  }
#ifdef DEBUG_NCP_OT
  printf("get_32_mapped_addr(): for 64 bit addr %p return 32 bit value %x \r\n",
         addr64bit, ret_32_mapped_addr);
#endif

  return ret_32_mapped_addr;
}

/*This API currently will not interact with device side. Assumes aMessage to be
 * local pointer */
uint16_t otMessageRead(const otMessage *aMessage, uint16_t aOffset, void *aBuf,
                       uint16_t aLength) {
  /*otMessage is saved in this manner
  --> getmessgaelength
  --> readmessgaelength
  --> actualmessage
  */
  uint16_t bytes_read = 0;

  if (aMessage != NULL && aBuf != NULL) {
    memcpy((uint8_t *)&bytes_read, (uint8_t *)aMessage + sizeof(uint16_t),
           sizeof(uint16_t)); // adding offset of getmessgaelength to point at
                              // readmessgaelength
    memcpy((uint8_t *)aBuf, (uint8_t *)aMessage + sizeof(uint32_t),
           bytes_read); // adding offset of getmessgaelength and
                        // readmessgaelength to point to actual message
  }

  return bytes_read;
}

/*This API currently will not interact with device side. Assumes aMessage to be
 * local pointer */
uint16_t otMessageGetLength(const otMessage *aMessage) {
  uint16_t ret_len = 0;
  memcpy((uint8_t *)&ret_len, (uint8_t *)aMessage, sizeof(uint16_t));

  return ret_len;
}

/*This function will set otOperationalDatasetTlvs.*/
int cli_test_otDatasetSetActiveTlvs(int argc, char *argv[]) {
  otError oterror = 0;
  otOperationalDatasetTlvs ncp_test_DatasetTlvs;
  // this string will set following parameters:
  // channel -> 15
  // networkkey -> 20414220414220414220414220412041
  // panid -> 0x123f
  // networkname -> OpenThread-0ecd
  char stringoftlv[106] = {
      0x0E, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x35, 0x06,
      0x00, 0x04, 0x00, 0x1F, 0xFF, 0xE0, 0x02, 0x08, 0x56, 0x1E, 0xD3, 0xE5,
      0xC8, 0x6C, 0xD4, 0xA4, 0x07, 0x08, 0xFD, 0x5F, 0x3B, 0x11, 0x3E, 0x47,
      0xF8, 0x11, 0x04, 0x10, 0x2C, 0x89, 0x3B, 0xE7, 0x1B, 0xFD, 0x78, 0x78,
      0x4E, 0xF8, 0x25, 0xA5, 0xED, 0xFF, 0x40, 0x9D, 0x0C, 0x04, 0x02, 0xA0,
      0xF7, 0xF8, 0x05, 0x10, 0x20, 0x41, 0x42, 0x20, 0x41, 0x42, 0x20, 0x41,
      0x42, 0x20, 0x41, 0x42, 0x20, 0x41, 0x20, 0x41, 0x01, 0x02, 0x12, 0x3F,
      0x00, 0x03, 0x00, 0x00, 0x0F, 0x03, 0x0F, 0x4F, 0x70, 0x65, 0x6E, 0x54,
      0x68, 0x72, 0x65, 0x61, 0x64, 0x2D, 0x30, 0x65, 0x63, 0x64};
  ncp_test_DatasetTlvs.mLength = 106;
  memcpy((char *)&ncp_test_DatasetTlvs.mTlvs, (char *)stringoftlv,
         ncp_test_DatasetTlvs.mLength);
  oterror = otDatasetSetActiveTlvs(g_p_ot_aInstance, &ncp_test_DatasetTlvs);
  printf("otDatasetSetActiveTlvs return OTERROR status is %d \r\n", oterror);
}

otError otDatasetSetActiveTlvs(otInstance *aInstance,
                               const otOperationalDatasetTlvs *aDataset) {
  otError oterror = 0;
  uint8_t datasetlen = aDataset->mLength;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDatasetSetActiveTlvs;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otOperationalDatasetTlvs --> *aDataset
  // mLength
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mLength = (char *)&(aDataset->mLength);
  for (int i = 0; i < sizeof(uint8_t); i++) {
    *tlv_var_payload++ = *p_mLength++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // mTlvs
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mTlvs = (char *)&(aDataset->mTlvs);
  for (int i = 0; i < datasetlen; i++) {
    *tlv_var_payload++ = *p_mTlvs++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

/*This function Indicates whether a valid network is present in the Active
 * Operational Dataset or not.*/
int cli_test_otDatasetIsCommissioned(int argc, char *argv[]) {
  bool ret_val;
  ret_val = otDatasetIsCommissioned(g_p_ot_aInstance);
  printf("otDatasetIsCommissioned return value is %d \r\n", ret_val);
}

bool otDatasetIsCommissioned(otInstance *aInstance) {
  bool ret_val;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDatasetIsCommissioned;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  return (bool)ret_val;
}

/*Gets the Active Operational Dataset in TLV format*/
int cli_test_otDatasetGetActiveTlvs(int argc, char *argv[]) {
  otError oterror = 0;
  otOperationalDatasetTlvs test_ncpDatasetTlvs;
  oterror = otDatasetGetActiveTlvs(g_p_ot_aInstance, &test_ncpDatasetTlvs);
#ifdef DEBUG_NCP_OT
  printf("TLVs:");
  for (int i = 0; i < test_ncpDatasetTlvs.mLength; i++) {
    printf("%x", test_ncpDatasetTlvs.mTlvs[i]);
  }
  printf("\r\nTLV len:%d\r\n", test_ncpDatasetTlvs.mLength);
#endif
  printf("otDatasetSetActiveTlvs return OTERROR value is %d \r\n", oterror);
}

otError otDatasetGetActiveTlvs(otInstance *aInstance,
                               otOperationalDatasetTlvs *aDataset) {
  otError oterror = 0;
  int total_tx_len = 0;
  uint8_t datasetlen;
  char *p_payload_param;
  int payloadsaved = 0;
  memset((char *)aDataset, 0, OT_OPERATIONAL_DATASET_MAX_LENGTH);

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDatasetGetActiveTlvs;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];
    char *p_datasetlen = (char *)&datasetlen;
    for (int i = 0; i < sizeof(uint8_t); i++) {
      *p_datasetlen++ = *p_payload_param++;
      payloadsaved++;
    }
    aDataset->mLength = datasetlen;

    char *p_mTlvs = (char *)&(aDataset->mTlvs);
    for (int i = 0; i < datasetlen; i++) {
      *p_mTlvs++ = *p_payload_param++;
      payloadsaved++;
    }
  }

  return oterror;
}

/*Gets the Active Operational Dataset */
int cli_test_otDatasetGetActive(int argc, char *argv[]) {
  otError oterror = 0;
  otOperationalDataset test_ncpdataset;
  oterror = otDatasetGetActive(g_p_ot_aInstance, &test_ncpdataset);

#ifdef DEBUG_NCP_OT
  printf("PanID: %x Networkname: %s Channel: %d  \r\n", test_ncpdataset.mPanId,
         test_ncpdataset.mNetworkName.m8, test_ncpdataset.mChannel);
  printf("Networkkey:");
  for (int i = 0; i < 16; i++) {
    printf("%x", test_ncpdataset.mNetworkKey.m8[i]);
  }
  printf("\r\n");

#endif

  printf("otDatasetGetActive return OTERROR value is %d \r\n", oterror);
}

otError otDatasetGetActive(otInstance *aInstance,
                           otOperationalDataset *aDataset) {
  otError oterror = 0;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDatasetGetActive;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)&(aDataset->mActiveTimestamp.mSeconds),
               (p_payload_param + payloadsaved), sizeof(uint64_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mActiveTimestamp.mTicks),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mActiveTimestamp.mAuthoritative),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mPendingTimestamp.mSeconds),
               (p_payload_param + payloadsaved), sizeof(uint64_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mPendingTimestamp.mTicks),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mPendingTimestamp.mAuthoritative),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mNetworkKey.m8),
               (p_payload_param + payloadsaved), OT_NETWORK_KEY_SIZE,
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mNetworkName.m8),
               (p_payload_param + payloadsaved), (OT_NETWORK_NAME_MAX_SIZE + 1),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mExtendedPanId.m8),
               (p_payload_param + payloadsaved), (OT_EXT_PAN_ID_SIZE),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mMeshLocalPrefix.m8),
               (p_payload_param + payloadsaved), (OT_IP6_PREFIX_SIZE),
               &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mDelay), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mPanId), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mChannel), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mPskc.m8), (p_payload_param + payloadsaved),
               (OT_PSKC_MAX_SIZE), &payloadsaved);

    ncp_memcpy((char *)&(aDataset->mSecurityPolicy.mRotationTime),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);

    aDataset->mSecurityPolicy.mObtainNetworkKeyEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mNativeCommissioningEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mRoutersEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mExternalCommissioningEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mCommercialCommissioningEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mAutonomousEnrollmentEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mNetworkKeyProvisioningEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mTobleLinkEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mNonCcmRoutersEnabled =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mSecurityPolicy.mVersionThresholdForRouting =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    ncp_memcpy((char *)&(aDataset->mChannelMask),
               (p_payload_param + payloadsaved), sizeof(uint32_t),
               &payloadsaved);

    aDataset->mComponents.mIsActiveTimestampPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsPendingTimestampPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsNetworkKeyPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsNetworkNamePresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsExtendedPanIdPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsMeshLocalPrefixPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsDelayPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsPanIdPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsChannelPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsPskcPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsSecurityPolicyPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;

    aDataset->mComponents.mIsChannelMaskPresent =
        *(char *)(p_payload_param + payloadsaved);
    payloadsaved++;
  }

  return oterror;
}

/*Gets the Pending Operational Dataset in TLV format*/
int cli_test_otDatasetGetPendingTlvs(int argc, char *argv[]) {
  otError oterror = 0;
  otOperationalDatasetTlvs test_ncpDatasetTlvs;
  oterror = otDatasetGetPendingTlvs(g_p_ot_aInstance, &test_ncpDatasetTlvs);
#ifdef DEBUG_NCP_OT
  printf("TLVs:");
  for (int i = 0; i < test_ncpDatasetTlvs.mLength; i++) {
    printf("%x", test_ncpDatasetTlvs.mTlvs[i]);
  }
  printf("\r\nTLV len:%d\r\n", test_ncpDatasetTlvs.mLength);
#endif
  printf("otDatasetGetPendingTlvs return OTERROR value is %d \r\n", oterror);
}

otError otDatasetGetPendingTlvs(otInstance *aInstance,
                                otOperationalDatasetTlvs *aDataset) {
  otError oterror = 0;
  int total_tx_len = 0;
  uint8_t datasetlen;
  char *p_payload_param;
  int payloadsaved = 0;
  memset((char *)aDataset, 0, OT_OPERATIONAL_DATASET_MAX_LENGTH);

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDatasetGetPendingTlvs;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];
    char *p_datasetlen = (char *)&datasetlen;
    for (int i = 0; i < sizeof(uint8_t); i++) {
      *p_datasetlen++ = *p_payload_param++;
      payloadsaved++;
    }
    aDataset->mLength = datasetlen;

    char *p_mTlvs = (char *)&(aDataset->mTlvs);
    for (int i = 0; i < datasetlen; i++) {
      *p_mTlvs++ = *p_payload_param++;
      payloadsaved++;
    }
  }

  return oterror;
}

/*This function will set otOperationalDatasetTlvs.*/
int cli_test_otDatasetSetPendingTlvs(int argc, char *argv[]) {
  otError oterror = 0;
  otOperationalDatasetTlvs ncp_test_DatasetTlvs;
  // this string will set following parameters:
  // channel -> 12
  // networkkey -> 20414220414220414220414220412041
  // panid -> 0x121f
  // networkname -> OpenThread-0ecd
  // Pending Timestamp: 1696177379
  // Active Timestamp: 1696177379
  // delay 60sec after 60sec pending tlv will become active
  char stringoftlv[122] = {
      0x35, 0x06, 0x00, 0x04, 0x00, 0x1F, 0xFF, 0xE0, 0x02, 0x08, 0xE6, 0xDD,
      0x05, 0x06, 0x12, 0x40, 0x9E, 0x33, 0x07, 0x08, 0xFD, 0x08, 0xF4, 0xF3,
      0x0C, 0x95, 0xD3, 0xAD, 0x04, 0x10, 0x2D, 0x2D, 0x76, 0xBB, 0x1A, 0x34,
      0x65, 0x69, 0x58, 0xD7, 0x48, 0xE9, 0xB8, 0xEA, 0xB3, 0x8B, 0x0C, 0x04,
      0x02, 0xA0, 0xF7, 0xF8, 0x03, 0x0F, 0x4F, 0x70, 0x65, 0x6E, 0x54, 0x68,
      0x72, 0x65, 0x61, 0x64, 0x2D, 0x30, 0x65, 0x63, 0x64, 0x05, 0x10, 0x20,
      0x41, 0x42, 0x20, 0x41, 0x42, 0x20, 0x41, 0x42, 0x20, 0x41, 0x42, 0x20,
      0x41, 0x20, 0x41, 0x01, 0x02, 0x12, 0x3F, 0x0E, 0x08, 0x00, 0x00, 0x65,
      0x19, 0x9C, 0xE3, 0x00, 0x00, 0x33, 0x08, 0x00, 0x00, 0x65, 0x19, 0x9C,
      0xE3, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0C, 0x34, 0x04, 0x00, 0x00,
      0xEA, 0x60};
  ncp_test_DatasetTlvs.mLength = 122;
  memcpy((char *)&ncp_test_DatasetTlvs.mTlvs, (char *)stringoftlv,
         ncp_test_DatasetTlvs.mLength);
  oterror = otDatasetSetPendingTlvs(g_p_ot_aInstance, &ncp_test_DatasetTlvs);
  printf("otDatasetSetPendingTlvs return OTERROR status is %d \r\n", oterror);
}

otError otDatasetSetPendingTlvs(otInstance *aInstance,
                                const otOperationalDatasetTlvs *aDataset) {
  otError oterror = 0;
  uint8_t datasetlen = aDataset->mLength;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDatasetSetPendingTlvs;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otOperationalDatasetTlvs --> *aDataset
  // mLength
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mLength = (char *)&(aDataset->mLength);
  for (int i = 0; i < sizeof(uint8_t); i++) {
    *tlv_var_payload++ = *p_mLength++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // mTlvs
  tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  char *p_mTlvs = (char *)&(aDataset->mTlvs);
  for (int i = 0; i < datasetlen; i++) {
    *tlv_var_payload++ = *p_mTlvs++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

/*
 * Erases all the OpenThread persistent info (network settings) stored on
 * non-volatile memory. Erase is successful only if the device is in `disabled`
 * state/role.
 */
int cli_test_otInstanceErasePersistentInfo(int argc, char *argv[]) {
  otError oterror = 0;
  oterror = otInstanceErasePersistentInfo(g_p_ot_aInstance);
  printf("otInstanceErasePersistentInfo otError return value is %d \r\n",
         oterror);
}

otError otInstanceErasePersistentInfo(otInstance *aInstance) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otInstanceErasePersistentInfo;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otThreadIsRouterEligible(int argc, char *argv[]) {
  bool ret_val;
  ret_val = otThreadIsRouterEligible(g_p_ot_aInstance);
  printf("otThreadIsRouterEligible return value is %d \r\n", ret_val);
}

bool otThreadIsRouterEligible(otInstance *aInstance) {
  bool ret_val;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadIsRouterEligible;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  return (bool)ret_val;
}

int cli_test_otLinkGetCslPeriod(int argc, char *argv[]) {
  uint32_t ret_val;
  ret_val = otLinkGetCslPeriod(g_p_ot_aInstance);
  printf("otLinkGetCslPeriod csl perod is %d \r\n", ret_val);
}

uint32_t otLinkGetCslPeriod(otInstance *aInstance) {
  uint32_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkGetCslPeriod;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otThreadSetRouterEligible(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 1) {
    printf("Missing argument! use->cmd <1/0> \r\n");
    return -1;
  }

  oterror = otThreadSetRouterEligible(g_p_ot_aInstance, atoi(argv[1]));
  printf("otThreadSetRouterEligible OTERROR value is %d\r\n", oterror);
  return 0;
}

otError otThreadSetRouterEligible(otInstance *aInstance, bool val) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadSetRouterEligible;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // user value
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), val, &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otThreadGetRloc16(int argc, char *argv[]) {
  uint16_t ret_val;
  ret_val = otThreadGetRloc16(g_p_ot_aInstance);
  printf("otThreadGetRloc16 Rloc16 is 0x%x \r\n", ret_val);
}

uint16_t otThreadGetRloc16(otInstance *aInstance) {
  uint16_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetRloc16;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otThreadGetLeaderRouterId(int argc, char *argv[]) {
  uint8_t ret_val;
  ret_val = otThreadGetLeaderRouterId(g_p_ot_aInstance);
  printf("otThreadGetLeaderRouterId LeaderRouterId is 0x%x \r\n", ret_val);
}

uint8_t otThreadGetLeaderRouterId(otInstance *aInstance) {
  uint8_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetLeaderRouterId;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otThreadGetPartitionId(int argc, char *argv[]) {
  uint32_t ret_val;
  ret_val = otThreadGetPartitionId(g_p_ot_aInstance);
  printf("otThreadGetPartitionId PartitionId is 0x%x \r\n", ret_val);
}

uint32_t otThreadGetPartitionId(otInstance *aInstance) {
  uint32_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetPartitionId;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otPlatRadioGetRssi(int argc, char *argv[]) {
  int8_t ret_val;
  ret_val = otPlatRadioGetRssi(g_p_ot_aInstance);
  printf("otPlatRadioGetRssi Rssi is %d \r\n", ret_val);
}

int8_t otPlatRadioGetRssi(otInstance *aInstance) {
  int8_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otPlatRadioGetRssi;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(int8_t), &payloadsaved);
  }

  return ret_val;
}

void ncp_memcpy(char *dest, char *src, int bytes_to_copy, int *totalsize) {
  memcpy((char *)dest, (char *)src,
         bytes_to_copy); // casting to char just be sure func if the receiving
                         // pointer is of diff type
  *totalsize += bytes_to_copy;

  return;
}

int cli_test_otThreadGetLeaderWeight(int argc, char *argv[]) {
  uint8_t ret_val;
  ret_val = otThreadGetLeaderWeight(g_p_ot_aInstance);
  printf("otThreadGetLeaderWeight LeaderWeight is %d \r\n", ret_val);
}

uint8_t otThreadGetLeaderWeight(otInstance *aInstance) {
  uint8_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetLeaderWeight;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otThreadGetLocalLeaderWeight(int argc, char *argv[]) {
  uint8_t ret_val;
  ret_val = otThreadGetLocalLeaderWeight(g_p_ot_aInstance);
  printf("otThreadGetLocalLeaderWeight LocalLeaderWeight is %d \r\n", ret_val);
}

uint8_t otThreadGetLocalLeaderWeight(otInstance *aInstance) {
  uint8_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetLocalLeaderWeight;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otThreadGetVersion(int argc, char *argv[]) {
  uint16_t ret_val;
  ret_val = otThreadGetVersion();
  printf("otThreadGetVersion ThreadVersion is %d \r\n", ret_val);
}

uint16_t otThreadGetVersion(void) {
  uint16_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetVersion;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
             sizeof(uint16_t), &payloadsaved);

  return ret_val;
}

int cli_test_otLinkGetPollPeriod(int argc, char *argv[]) {
  uint32_t ret_val;
  ret_val = otLinkGetPollPeriod(g_p_ot_aInstance);
  printf("otLinkGetPollPeriod PollPeriod is %d \r\n", ret_val);
}

uint32_t otLinkGetPollPeriod(otInstance *aInstance) {
  uint32_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkGetPollPeriod;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);
  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  char *p_device_Instance = (char *)&(device_Instance);
  for (int i = 0; i < sizeof(uint32_t); i++) {
    *tlv_var_payload++ = *p_device_Instance++;
  }
  total_tx_len +=
      ((char *)tlv_var_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otLinkSetCslPeriod(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 1) {
    printf("Missing argument! use->cmd <CslPeriod> \r\n");
    return -1;
  }

  oterror = otLinkSetCslPeriod(g_p_ot_aInstance, atoi(argv[1]));
  printf("otLinkSetCslPeriod OTERROR value is %d\r\n", oterror);
  return 0;
}

otError otLinkSetCslPeriod(otInstance *aInstance, uint32_t aPeriod) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkSetCslPeriod;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // aPeriod
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aPeriod),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otLinkSetPollPeriod(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 1) {
    printf("Missing argument! use->cmd <PollPeriod> \r\n");
    return -1;
  }

  oterror = otLinkSetPollPeriod(g_p_ot_aInstance, atoi(argv[1]));
  printf("otLinkSetPollPeriod OTERROR value is %d\r\n", oterror);
  return 0;
}

otError otLinkSetPollPeriod(otInstance *aInstance, uint32_t aPollPeriod) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkSetPollPeriod;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // aPeriod
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aPollPeriod),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otLinkGetPanId(int argc, char *argv[]) {
  otPanId ret_val;
  ret_val = otLinkGetPanId(g_p_ot_aInstance);
  printf("otLinkGetPanId PanId is 0x%x \r\n", ret_val);
}

otPanId otLinkGetPanId(otInstance *aInstance) {
  otPanId ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkGetPanId;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otNetDataGetStableVersion(int argc, char *argv[]) {
  uint8_t ret_val;
  ret_val = otNetDataGetStableVersion(g_p_ot_aInstance);
  printf("otNetDataGetStableVersion StableVersion is 0x%x \r\n", ret_val);
}

uint8_t otNetDataGetStableVersion(otInstance *aInstance) {
  uint8_t ret_val;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otNetDataGetStableVersion;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otSrpClientSetLeaseInterval(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <LeaseInterval> \r\n");
    return -1;
  }

  otSrpClientSetLeaseInterval(g_p_ot_aInstance, atoi(argv[1]));
  printf("otSrpClientSetLeaseInterval executed\r\n");
  return 0;
}

void otSrpClientSetLeaseInterval(otInstance *aInstance, uint32_t aInterval) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientSetLeaseInterval;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // aInterval
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aInterval),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  return;
}

int cli_test_otSrpClientSetKeyLeaseInterval(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <LeaseInterval> \r\n");
    return -1;
  }

  otSrpClientSetKeyLeaseInterval(g_p_ot_aInstance, atoi(argv[1]));
  printf("otSrpClientSetKeyLeaseInterval executed\r\n");
  return 0;
}

void otSrpClientSetKeyLeaseInterval(otInstance *aInstance, uint32_t aInterval) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientSetKeyLeaseInterval;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // aInterval
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aInterval),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  return;
}

int cli_test_otSrpClientRemoveHostAndServices(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 2) {
    printf("Missing argument! use->cmd <aRemoveKeyLease><aSendUnregToServer> "
           "\r\n");
    return -1;
  }

  oterror = otSrpClientRemoveHostAndServices(g_p_ot_aInstance, atoi(argv[1]),
                                             atoi(argv[2]));
  printf("otSrpClientRemoveHostAndServices OTERROR value is %d\r\n", oterror);
  return 0;
}

/*Need to confirm removal of mapping info upon suuccessful execution of this
 * function, or during srp callback. To be confirmed*/
otError otSrpClientRemoveHostAndServices(otInstance *aInstance,
                                         bool aRemoveKeyLease,
                                         bool aSendUnregToServer) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientRemoveHostAndServices;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // aRemoveKeyLease
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aRemoveKeyLease,
                   &total_tx_len);

  // aSendUnregToServer
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aSendUnregToServer,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otSrpClientEnableAutoHostAddress(int argc, char *argv[]) {
  otError oterror = 0;
  oterror = otSrpClientEnableAutoHostAddress(g_p_ot_aInstance);
  printf("otSrpClientEnableAutoHostAddress otError return value is %d \r\n",
         oterror);
}

otError otSrpClientEnableAutoHostAddress(otInstance *aInstance) {
  otError oterror = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientEnableAutoHostAddress;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otAppCliInit(int argc, char *argv[]) {
  otAppCliInit(g_p_ot_aInstance);
  printf("otAppCliInit executed\r\n");
  return 0;
}

void otAppCliInit(otInstance *aInstance) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otAppCliInit;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  return;
}

int cli_test_otThreadSetLinkMode(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Missing argument! use->cmd "
           "<mRxOnWhenIdle><mDeviceType><mNetworkData> \r\n");
    return -1;
  }

  otError oterror = 0;
  otLinkModeConfig linkMode;
  memset(&linkMode, 0, sizeof(otLinkModeConfig));
  linkMode.mRxOnWhenIdle = atoi(argv[1]);
  linkMode.mDeviceType = atoi(argv[2]);
  linkMode.mNetworkData = atoi(argv[3]);

  oterror = otThreadSetLinkMode(g_p_ot_aInstance, linkMode);
  printf("otThreadSetLinkMode return OTERROR status is %d \r\n", oterror);
}

otError otThreadSetLinkMode(otInstance *aInstance, otLinkModeConfig aConfig) {
  otError oterror = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadSetLinkMode;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // mRxOnWhenIdle
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   aConfig.mRxOnWhenIdle, &total_tx_len);

  // mDeviceType
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aConfig.mDeviceType,
                   &total_tx_len);

  // mNetworkData
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aConfig.mNetworkData,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otThreadGetLinkMode(int argc, char *argv[]) {
  otError oterror = 0;
  otLinkModeConfig linkMode;
  memset(&linkMode, 0, sizeof(otLinkModeConfig));

  linkMode = otThreadGetLinkMode(g_p_ot_aInstance);
  printf("otThreadGetLinkMode status is mRxOnWhenIdle %d mDeviceType %d "
         "mNetworkData %d\r\n",
         linkMode.mRxOnWhenIdle, linkMode.mDeviceType, linkMode.mNetworkData);
}

otLinkModeConfig otThreadGetLinkMode(otInstance *aInstance) {
  otLinkModeConfig linkMode;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetLinkMode;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    // linkMode.mRxOnWhenIdle
    linkMode.mRxOnWhenIdle = *(char *)(p_payload_param + payloadsaved++);

    // linkMode.mDeviceType
    linkMode.mDeviceType = *(char *)(p_payload_param + payloadsaved++);

    // linkMode.mNetworkData
    linkMode.mNetworkData = *(char *)(p_payload_param + payloadsaved++);
  }

  return linkMode;
}

int cli_test_otThreadGetParentAverageRssi(int argc, char *argv[]) {
  otError oterror = 0;
  int8_t averageRssi;
  oterror = otThreadGetParentAverageRssi(g_p_ot_aInstance, &averageRssi);
  printf("otThreadGetParentAverageRssi return OTERROR status is %d and RSSI is "
         "%d\r\n",
         oterror, averageRssi);
}

otError otThreadGetParentAverageRssi(otInstance *aInstance,
                                     int8_t *aParentRssi) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetParentAverageRssi;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aParentRssi), (p_payload_param + payloadsaved),
               sizeof(int8_t), &payloadsaved);
  }

  return oterror;
}

int cli_test_otThreadGetParentLastRssi(int argc, char *argv[]) {
  otError oterror = 0;
  int8_t lastRssi;
  oterror = otThreadGetParentLastRssi(g_p_ot_aInstance, &lastRssi);
  printf("otThreadGetParentLastRssi return OTERROR status is %d and last RSSI "
         "is %d\r\n",
         oterror, lastRssi);
}

otError otThreadGetParentLastRssi(otInstance *aInstance, int8_t *aLastRssi) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetParentLastRssi;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aLastRssi), (p_payload_param + payloadsaved),
               sizeof(int8_t), &payloadsaved);
  }

  return oterror;
}

int cli_test_otThreadGetNetworkKey(int argc, char *argv[]) {
  otNetworkKey networkKey;
  otThreadGetNetworkKey(g_p_ot_aInstance, &networkKey);
#ifdef DEBUG_NCP_OT
  printf("Networkkey:");
  for (int i = 0; i < OT_NETWORK_KEY_SIZE; i++) {
    printf("%x", networkKey.m8[i]);
  }
  printf("\r\n");
#endif
}

void otThreadGetNetworkKey(otInstance *aInstance, otNetworkKey *aNetworkKey) {
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetNetworkKey;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)(aNetworkKey->m8), (p_payload_param + payloadsaved),
               OT_NETWORK_KEY_SIZE, &payloadsaved);
  }

  return;
}

int cli_test_otThreadErrorToString(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <otError> \r\n");
    return -1;
  }

  printf("otThreadErrorToString result: %s \r\n",
         otThreadErrorToString(atoi(argv[1])));
}

const char *otThreadErrorToString(otError aError) {
  uint8_t stringlen = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadErrorToString;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otError
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aError,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  ncp_memcpy((char *)&(stringlen), (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  static char *p_to_error_string;

  // if memory was previously allocated, we will free that, and will allocate
  // new one based on the required new size, Size can be different based on the
  // error type
  if (p_to_error_string == NULL) {
    p_to_error_string = (char *)malloc(stringlen);
  } else {
    free(p_to_error_string);
    p_to_error_string = (char *)malloc(stringlen);
  }

  ncp_memcpy((char *)p_to_error_string, (p_payload_param + payloadsaved),
             stringlen, &payloadsaved);

  return p_to_error_string;
}

int cli_test_otBorderAgentGetId(int argc, char *argv[]) {
  otError oterror = 0;
  otBorderAgentId br_agentId;
  oterror = otBorderAgentGetId(g_p_ot_aInstance, &br_agentId);
  printf("otBorderAgentGetId return OTERROR status is %d \r\n", oterror);
#ifdef DEBUG_NCP_OT
  printf("OT_BORDER_AGENT_ID:");
  for (int i = 0; i < OT_BORDER_AGENT_ID_LENGTH; i++) {
    printf("%x", br_agentId.mId[i]);
  }
  printf("\r\n");
#endif
}

otError otBorderAgentGetId(otInstance *aInstance, otBorderAgentId *aId) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otBorderAgentGetId;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aId->mId), (p_payload_param + payloadsaved),
               OT_BORDER_AGENT_ID_LENGTH, &payloadsaved);
  }

  return oterror;
}

int cli_test_otThreadGetNetworkName(int argc, char *argv[]) {
  printf("otThreadGetNetworkName Networkname: %s \r\n",
         otThreadGetNetworkName(g_p_ot_aInstance));
}

const char *otThreadGetNetworkName(otInstance *aInstance) {
  uint8_t stringlen = 0;
  int ret_val = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetNetworkName;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_ERROR(response_index);

  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  ncp_memcpy((char *)&(stringlen), (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  static char *p_to_string;

  // if memory was previously allocated, we will free that, and will allocate
  // new one based on the required new size, Size can be different based on the
  // error type
  if (p_to_string == NULL) {
    p_to_string = (char *)malloc(stringlen);
  } else {
    free(p_to_string);
    p_to_string = (char *)malloc(stringlen);
  }

  ncp_memcpy((char *)p_to_string, (p_payload_param + payloadsaved), stringlen,
             &payloadsaved);

  if (stringlen == 0 && ret_val == -1) {
    return NULL;
  } else {
    return p_to_string;
  }
}

int cli_test_otLinkGetExtendedAddress(int argc, char *argv[]) {
  const otExtAddress *extAddress;
  extAddress = otLinkGetExtendedAddress(g_p_ot_aInstance);
  printf("otLinkGetExtendedAddress Executed  \r\n");
#ifdef DEBUG_NCP_OT
  if (extAddress != NULL) {
    printf("ExtendedAddress:");
    for (int i = 0; i < OT_EXT_ADDRESS_SIZE; i++) {
      printf("%x", extAddress->m8[i]);
    }
    printf("\r\n");
  }
#endif
}

const otExtAddress *otLinkGetExtendedAddress(otInstance *aInstance) {
  int ret_val = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkGetExtendedAddress;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_ERROR(response_index);
  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  static otExtAddress *p_to_string;

  if (p_to_string == NULL) {
    p_to_string = (otExtAddress *)malloc(OT_EXT_ADDRESS_SIZE);
  }

  if (ret_val != -1) {
    ncp_memcpy((char *)p_to_string, (p_payload_param + payloadsaved),
               OT_EXT_ADDRESS_SIZE, &payloadsaved);
  }

  return ((ret_val != -1) ? p_to_string : NULL);
}

int cli_test_otThreadGetExtendedPanId(int argc, char *argv[]) {
  const otExtendedPanId *extPanId;
  extPanId = otThreadGetExtendedPanId(g_p_ot_aInstance);
  printf("otThreadGetExtendedPanId Executed  \r\n");
#ifdef DEBUG_NCP_OT
  if (extPanId != NULL) {
    printf("ExtendedAddress:");
    for (int i = 0; i < OT_EXT_PAN_ID_SIZE; i++) {
      printf("%x", extPanId->m8[i]);
    }
    printf("\r\n");
  }
#endif
}

const otExtendedPanId *otThreadGetExtendedPanId(otInstance *aInstance) {
  int ret_val = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetExtendedPanId;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_ERROR(response_index);
  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  static otExtendedPanId *p_to_string;

  if (p_to_string == NULL) {
    p_to_string = (otExtendedPanId *)malloc(OT_EXT_PAN_ID_SIZE);
  }

  if (ret_val != -1) {
    ncp_memcpy((char *)p_to_string, (p_payload_param + payloadsaved),
               OT_EXT_PAN_ID_SIZE, &payloadsaved);
  }

  return ((ret_val != -1) ? p_to_string : NULL);
}

int cli_test_otThreadGetMeshLocalPrefix(int argc, char *argv[]) {
  const otMeshLocalPrefix *prefix;
  prefix = otThreadGetMeshLocalPrefix(g_p_ot_aInstance);
  printf("otThreadGetMeshLocalPrefix Executed  \r\n");
#ifdef DEBUG_NCP_OT
  if (prefix != NULL) {
    printf("ExtendedAddress:");
    for (int i = 0; i < OT_IP6_PREFIX_SIZE; i++) {
      printf("%x", prefix->m8[i]);
    }
    printf("\r\n");
  }
#endif
}

const otMeshLocalPrefix *otThreadGetMeshLocalPrefix(otInstance *aInstance) {
  int ret_val = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetMeshLocalPrefix;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_ERROR(response_index);
  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  static otMeshLocalPrefix *p_to_string;

  if (p_to_string == NULL) {
    p_to_string = (otMeshLocalPrefix *)malloc(OT_IP6_PREFIX_SIZE);
  }

  if (ret_val != -1) {
    ncp_memcpy((char *)p_to_string, (p_payload_param + payloadsaved),
               OT_IP6_PREFIX_SIZE, &payloadsaved);
  }

  return ((ret_val != -1) ? p_to_string : NULL);
}

int cli_test_otThreadGetLeaderRloc(int argc, char *argv[]) {
  otError oterror = 0;
  otIp6Address address;
  oterror = otThreadGetLeaderRloc(g_p_ot_aInstance, &address);
  printf("otThreadGetLeaderRloc return OTERROR status is %d\r\n", oterror);
#ifdef DEBUG_NCP_OT
  printf("mFields:");
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    printf("%x", *((char *)&(address.mFields) + i));
  }
  printf("\r\n");
#endif
}

otError otThreadGetLeaderRloc(otInstance *aInstance,
                              otIp6Address *aLeaderRloc) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetLeaderRloc;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aLeaderRloc), (p_payload_param + payloadsaved),
               sizeof(otIp6Address), &payloadsaved);
  }

  return oterror;
}

int cli_test_otNetDataGet(int argc, char *argv[]) {
  otError oterror = 0;
  if (argc < 1) {
    printf("Missing argument! use->cmd <aStable>\r\n");
    return -1;
  }

  uint8_t data[255];
  uint8_t len = sizeof(data);
  oterror = otNetDataGet(g_p_ot_aInstance, atoi(argv[1]), data, &len);
  printf("otNetDataGet OTERROR value is %d and datalen received %d \r\n",
         oterror, len);
#ifdef DEBUG_NCP_OT
  printf("datareceived:");
  for (int i = 0; i < len; i++) {
    printf("%x", data[i]);
  }
  printf("\r\n");
#endif
  return 0;
}

otError otNetDataGet(otInstance *aInstance, bool aStable, uint8_t *aData,
                     uint8_t *aDataLength) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otNetDataGet;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // aStable
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aStable,
                   &total_tx_len);

  // aDataLength
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), *aDataLength,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aDataLength), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
    ncp_memcpy((char *)(aData), (p_payload_param + payloadsaved), *aDataLength,
               &payloadsaved);
  }

  return oterror;
}

int cli_test_otIp6SubscribeMulticastAddress(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <IPADDR>\r\n");
    return -1;
  }
  otError oterror = 0;
  otIp6Address address;
  inet_pton(AF_INET6, argv[1],
            &(address)); // IPV6 address - Text to Binary
  oterror = otIp6SubscribeMulticastAddress(g_p_ot_aInstance, &address);
  printf("otIp6SubscribeMulticastAddress return OTERROR status is %d\r\n",
         oterror);
}

otError otIp6SubscribeMulticastAddress(otInstance *aInstance,
                                       const otIp6Address *aAddress) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6SubscribeMulticastAddress;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aAddress,
             sizeof(otIp6Address), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otIp6UnsubscribeMulticastAddress(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <IPADDR>\r\n");
    return -1;
  }
  otError oterror = 0;
  otIp6Address address;
  inet_pton(AF_INET6, argv[1],
            &(address)); // IPV6 address - Text to Binary
  oterror = otIp6UnsubscribeMulticastAddress(g_p_ot_aInstance, &address);
  printf("otIp6UnsubscribeMulticastAddress return OTERROR status is %d\r\n",
         oterror);
}

otError otIp6UnsubscribeMulticastAddress(otInstance *aInstance,
                                         const otIp6Address *aAddress) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6UnsubscribeMulticastAddress;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aAddress,
             sizeof(otIp6Address), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otThreadGetNextNeighborInfo(int argc, char *argv[]) {
  otError oterror = 0;
  otNeighborInfo neighborInfo;
  otNeighborInfoIterator iterator = OT_NEIGHBOR_INFO_ITERATOR_INIT;

#ifdef DEBUG_NCP_OT
  while (otThreadGetNextNeighborInfo(g_p_ot_aInstance, &iterator,
                                     &neighborInfo) == OT_ERROR_NONE) {
    printf("ExtendedAddress:");
    for (int i = 0; i < OT_EXT_ADDRESS_SIZE; i++) {
      printf("%x", neighborInfo.mExtAddress.m8[i]);
    }
    printf("\r\n");

    printf("mRloc16: %x\r\n", neighborInfo.mRloc16);
    printf("mVersion: %d\r\n", neighborInfo.mVersion);
    printf("mLinkQualityIn: %d\r\n", neighborInfo.mLinkQualityIn);
    printf("mAverageRssi: %d\r\n", neighborInfo.mAverageRssi);
    printf("mRxOnWhenIdle: %d\r\n", neighborInfo.mRxOnWhenIdle);
    printf("mFullThreadDevice: %d\r\n", neighborInfo.mFullThreadDevice);
    printf("mFullNetworkData: %d\r\n", neighborInfo.mFullNetworkData);
    printf("mIsChild: %d\r\n", neighborInfo.mIsChild);

    printf("............................................................\r\n");

    usleep(5);
  }
#else
  oterror =
      otThreadGetNextNeighborInfo(g_p_ot_aInstance, &iterator, &neighborInfo);
  printf("otThreadGetNextNeighborInfo return OTERROR status is %d\r\n",
         oterror);
#endif
}

otError otThreadGetNextNeighborInfo(otInstance *aInstance,
                                    otNeighborInfoIterator *aIterator,
                                    otNeighborInfo *aInfo) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetNextNeighborInfo;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aIterator,
             sizeof(otNeighborInfoIterator), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aIterator), (p_payload_param + payloadsaved),
               sizeof(otNeighborInfoIterator), &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mExtAddress.m8),
               (p_payload_param + payloadsaved), OT_EXT_ADDRESS_SIZE,
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mAge), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mConnectionTime),
               (p_payload_param + payloadsaved), sizeof(uint32_t),
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mRloc16), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mLinkFrameCounter),
               (p_payload_param + payloadsaved), sizeof(uint32_t),
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mMleFrameCounter),
               (p_payload_param + payloadsaved), sizeof(uint32_t),
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mLinkQualityIn),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mAverageRssi), (p_payload_param + payloadsaved),
               sizeof(int8_t), &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mLastRssi), (p_payload_param + payloadsaved),
               sizeof(int8_t), &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mLinkMargin), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mFrameErrorRate),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mMessageErrorRate),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)&(aInfo->mVersion), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
    aInfo->mRxOnWhenIdle = *(char *)(p_payload_param + payloadsaved++);
    aInfo->mFullThreadDevice = *(char *)(p_payload_param + payloadsaved++);
    aInfo->mFullNetworkData = *(char *)(p_payload_param + payloadsaved++);
    aInfo->mIsChild = *(char *)(p_payload_param + payloadsaved++);
  }

  return oterror;
}

int cli_test_otNetDataGetNextRoute(int argc, char *argv[]) {
  otError oterror = 0;
  otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
  otExternalRouteConfig routeConfig;

  oterror = otNetDataGetNextRoute(g_p_ot_aInstance, &iterator, &routeConfig);
  printf("otNetDataGetNextRoute return OTERROR status is %d\r\n", oterror);
#ifdef DEBUG_NCP_OT
  printf("mFields:");
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    printf("%x", *((char *)&(routeConfig.mPrefix.mPrefix.mFields) + i));
  }
  printf("\r\n");
  printf("mLength: %d\r\n", routeConfig.mPrefix.mLength);
  printf("mRloc16: 0x%x\r\n", routeConfig.mRloc16);
  printf("mPreference: %d\r\n", routeConfig.mPreference);
  printf("mNat64: %d\r\n", routeConfig.mNat64);
  printf("mStable: %d\r\n", routeConfig.mStable);
  printf("mNextHopIsThisDevice: %d\r\n", routeConfig.mNextHopIsThisDevice);
  printf("mAdvPio: %d\r\n", routeConfig.mAdvPio);
#endif
}

otError otNetDataGetNextRoute(otInstance *aInstance,
                              otNetworkDataIterator *aIterator,
                              otExternalRouteConfig *aConfig) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otNetDataGetNextRoute;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aIterator,
             sizeof(otNetworkDataIterator), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(aIterator), (p_payload_param + payloadsaved),
               sizeof(otNetworkDataIterator), &payloadsaved);
    ncp_memcpy((char *)&(aConfig->mPrefix.mPrefix.mFields),
               (p_payload_param + payloadsaved), sizeof(otIp6Address),
               &payloadsaved);
    ncp_memcpy((char *)&(aConfig->mPrefix.mLength),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);

    ncp_memcpy((char *)&(aConfig->mRloc16), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);

    aConfig->mPreference = *(char *)(p_payload_param + payloadsaved++);
    aConfig->mNat64 = *(char *)(p_payload_param + payloadsaved++);
    aConfig->mStable = *(char *)(p_payload_param + payloadsaved++);
    aConfig->mNextHopIsThisDevice = *(char *)(p_payload_param + payloadsaved++);
    aConfig->mAdvPio = *(char *)(p_payload_param + payloadsaved++);
  }

  return oterror;
}

int cli_test_otLinkGetCounters(int argc, char *argv[]) {
  const otMacCounters *macCounters;
  macCounters = otLinkGetCounters(g_p_ot_aInstance);
  printf("otLinkGetCounters executed\r\n");
#ifdef DEBUG_NCP_OT
  printf("mTxTotal %d \r\n", macCounters->mTxTotal);
  printf("mTxUnicast %d \r\n", macCounters->mTxUnicast);
  printf("mTxBroadcast %d \r\n", macCounters->mTxBroadcast);
  printf("mTxAckRequested %d \r\n", macCounters->mTxAckRequested);
  printf(" mTxNoAckRequested %d \r\n", macCounters->mTxNoAckRequested);
  printf("mTxData %d \r\n", macCounters->mTxData);
  printf("mTxDataPoll %d \r\n", macCounters->mTxDataPoll);
  printf("mTxBeacon %d \r\n", macCounters->mTxBeacon);
  printf("mTxBeaconRequest %d \r\n", macCounters->mTxBeaconRequest);
  printf("mTxDirectMaxRetryExpiry %d \r\n",
         macCounters->mTxDirectMaxRetryExpiry);
  printf("mTxIndirectMaxRetryExpiry %d \r\n",
         macCounters->mTxIndirectMaxRetryExpiry);
  printf("mTxErrCca %d \r\n", macCounters->mTxErrCca);
  printf("mTxErrAbort %d \r\n", macCounters->mTxErrAbort);
  printf("mTxErrBusyChannel %d \r\n", macCounters->mTxErrBusyChannel);
  printf("mRxTotal %d \r\n", macCounters->mRxTotal);
  printf("mRxUnicast %d \r\n", macCounters->mRxUnicast);
  printf("mRxBroadcast %d \r\n", macCounters->mRxBroadcast);
  printf("mRxData %d \r\n", macCounters->mRxData);
  printf("mRxDataPoll %d \r\n", macCounters->mRxDataPoll);
  printf("mRxBeacon %d \r\n", macCounters->mRxBeacon);
  printf("mRxBeaconRequest %d \r\n", macCounters->mRxBeaconRequest);
  printf("mRxOther %d \r\n", macCounters->mRxOther);
  printf("mRxAddressFiltered %d \r\n", macCounters->mRxAddressFiltered);
  printf("mRxDestAddrFiltered %d \r\n", macCounters->mRxDestAddrFiltered);
  printf("mRxDuplicated %d \r\n", macCounters->mRxDuplicated);
  printf("mRxErrNoFrame %d \r\n", macCounters->mRxErrNoFrame);
  printf("mRxErrUnknownNeighbor %d \r\n", macCounters->mRxErrUnknownNeighbor);
  printf("mRxErrInvalidSrcAddr %d \r\n", macCounters->mRxErrInvalidSrcAddr);
  printf("mRxErrSec %d \r\n", macCounters->mRxErrSec);
  printf("mRxErrFcs %d \r\n", macCounters->mRxErrFcs);
  printf("mRxErrOther %d \r\n", macCounters->mRxErrOther);

#endif
}

const otMacCounters *otLinkGetCounters(otInstance *aInstance) {
  int ret_val = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkGetCounters;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_ERROR(response_index);
  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  static otMacCounters *macCounters;

  if (macCounters == NULL) {
    macCounters = (otMacCounters *)malloc(sizeof(otMacCounters));
  }

  if (ret_val != -1) {
    /*Checked sizeof(otMacCounters) gives same size on host and device. Assuming
     * same member's alligment on two devices*/
    ncp_memcpy((char *)macCounters, (p_payload_param + payloadsaved),
               sizeof(otMacCounters), &payloadsaved);
  }

  return ((ret_val != -1) ? macCounters : NULL);
}

int cli_test_otThreadGetIp6Counters(int argc, char *argv[]) {
  const otIpCounters *ipCounters;
  ipCounters = otThreadGetIp6Counters(g_p_ot_aInstance);
  printf("otThreadGetIp6Counters executed\r\n");
#ifdef DEBUG_NCP_OT
  printf("mTxSuccess %d \r\n", ipCounters->mTxSuccess);
  printf("mRxSuccess %d \r\n", ipCounters->mRxSuccess);
  printf("mTxFailure %d \r\n", ipCounters->mTxFailure);
  printf("mRxFailure %d \r\n", ipCounters->mRxFailure);
#endif
}

const otIpCounters *otThreadGetIp6Counters(otInstance *aInstance) {
  int ret_val = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetIp6Counters;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_ERROR(response_index);
  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  static otIpCounters *ipCounters;

  if (ipCounters == NULL) {
    ipCounters = (otIpCounters *)malloc(sizeof(otIpCounters));
  }

  if (ret_val != -1) {
    /* Assuming same member's alligment on two devices*/
    ncp_memcpy((char *)ipCounters, (p_payload_param + payloadsaved),
               sizeof(otIpCounters), &payloadsaved);
  }

  return ((ret_val != -1) ? ipCounters : NULL);
}

int cli_test_otSetStateChangedCallback(int argc, char *argv[]) {
  void *aContext = {"otstatecontext"};
  otError oterror = 0;
  oterror =
      otSetStateChangedCallback(g_p_ot_aInstance, processStateChange, aContext);
  printf("otSetStateChangedCallback OTERROR status is %d with context %p\r\n",
         oterror, aContext);

  return 0;
}

otError otSetStateChangedCallback(otInstance *aInstance,
                                  otStateChangedCallback aCallback,
                                  void *aContext) {
  otError oterror = 0;
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSetStateChangedCallback;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // app context
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aContext),
             sizeof(uint64_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_STATE_CHANGE);
  }

  return oterror;
}

void process_otstatechange(char *response_index, int len, int eventid) {
  void *aContext;
  otChangedFlags aFlags;
  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;

  ncp_memcpy((char *)&aContext, (p_payload_param + payloadsaved),
             sizeof(uint64_t), &payloadsaved);
  ncp_memcpy((char *)&aFlags, (p_payload_param + payloadsaved),
             sizeof(otChangedFlags), &payloadsaved);

  /*get the callback function based on the eventid and call the respective cb
   * function*/
  ncp_otStateChangedCallback = get_ptr_from_eventid(eventid);

  if (ncp_otStateChangedCallback != NULL) {
    ncp_otStateChangedCallback(aFlags, aContext);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }
}

static void processStateChange(otChangedFlags aFlags, void *aContext) {
  printf("Callback:OT State Changed: aFlags 0x%x and app context %p\r\n",
         aFlags, aContext);
}

int cli_test_otIp6AddressFromString(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <IPADDR>\r\n");
    return -1;
  }
  otError oterror;
  char IPstring[OT_IP6_ADDRESS_STRING_SIZE];
  otIp6Address address;
  memcpy((char *)IPstring, (char *)argv[1], (strlen(argv[1]) + 1));
  oterror = otIp6AddressFromString(IPstring, &address);
  printf("otIp6AddressFromString return OTERROR status is %d\r\n", oterror);
#ifdef DEBUG_NCP_OT
  printf("mFields:");
  for (int i = 0; i < sizeof(otIp6Address); i++) {
    printf("%x", *((char *)&(address.mFields) + i));
  }
  printf("\r\n");
#endif
}

otError otIp6AddressFromString(const char *aString, otIp6Address *aAddress) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6AddressFromString;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  // sizeof aString
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   (strlen(aString) + 1), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aString,
             (strlen(aString) + 1), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                     NCP_CMD_RESP_OTERROR_SZ];

  ncp_memcpy((char *)(aAddress), (p_payload_param + payloadsaved),
             sizeof(otIp6Address), &payloadsaved);

  return oterror;
}

int cli_test_otIp6AddressToString(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <IPADDR>\r\n");
    return -1;
  }

  char IPstring[OT_IP6_ADDRESS_STRING_SIZE];
  otIp6Address address;
  inet_pton(AF_INET6, argv[1], &(address.mFields));

  otIp6AddressToString(&address, IPstring, sizeof(IPstring));
  printf("otIp6AddressToString executed\r\n");
#ifdef DEBUG_NCP_OT
  printf("IPADDRESS: %s\r\n", IPstring);
#endif
}

void otIp6AddressToString(const otIp6Address *aAddress, char *aBuffer,
                          uint16_t aSize) {
  uint16_t return_string_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6AddressToString;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aSize),
             sizeof(uint16_t), &total_tx_len);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aAddress,
             sizeof(otIp6Address), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  p_payload_param =
      (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

  ncp_memcpy((char *)&(return_string_len), (p_payload_param + payloadsaved),
             sizeof(uint16_t), &payloadsaved);
  ncp_memcpy((char *)(aBuffer), (p_payload_param + payloadsaved),
             return_string_len, &payloadsaved);

  return;
}
int cli_test_otNetDataGetVersion(int argc, char *argv[]) {
  uint8_t ret_val;
  ret_val = otNetDataGetVersion(g_p_ot_aInstance);
  printf("otNetDataGetVersion StableVersion is 0x%x \r\n", ret_val);
}

uint8_t otNetDataGetVersion(otInstance *aInstance) {
  uint8_t ret_val = 0;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otNetDataGetVersion;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
  }

  return ret_val;
}

int cli_test_otSysProcessDrivers(int argc, char *argv[]) {
  otSysProcessDrivers(g_p_ot_aInstance);
  printf("otSysProcessDrivers executed \r\n");
}

void otSysProcessDrivers(otInstance *aInstance) {
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSysProcessDrivers;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) == -1) {
#ifdef DEBUG_NCP_OT
    printf("Error: OT instance is not initialized  \r\n");
#endif
  }

  return;
}

int cli_test_otTaskletsProcess(int argc, char *argv[]) {
  otTaskletsProcess(g_p_ot_aInstance);
  printf("otTaskletsProcess executed \r\n");
}

void otTaskletsProcess(otInstance *aInstance) {
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otTaskletsProcess;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) == -1) {
#ifdef DEBUG_NCP_OT
    printf("Error: OT instance is not initialized  \r\n");
#endif
  }

  return;
}

int cli_test_otThreadGetChildInfoById(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <childID>\r\n");
    return -1;
  }

  otError oterror = 0;
  otChildInfo aChildInfo;
  oterror =
      otThreadGetChildInfoById(g_p_ot_aInstance, atoi(argv[1]), &aChildInfo);
  printf("otThreadGetChildInfoById OTERROR value is %d  \r\n", oterror);
#ifdef DEBUG_NCP_OT
  printf("ExtendedAddress:");
  for (int i = 0; i < OT_EXT_ADDRESS_SIZE; i++) {
    printf("%x", aChildInfo.mExtAddress.m8[i]);
  }
  printf("\r\n");
  printf("mTimeout: %d\r\n", aChildInfo.mTimeout);
  printf("mAge: %d\r\n", aChildInfo.mAge);
  printf("mConnectionTime: %ld\r\n", aChildInfo.mConnectionTime);
  printf("mRloc16: %x\r\n", aChildInfo.mRloc16);
  printf("mChildId: %x\r\n", aChildInfo.mChildId);
  printf("mNetworkDataVersion: %d\r\n", aChildInfo.mNetworkDataVersion);
  printf("mLinkQualityIn: %d\r\n", aChildInfo.mLinkQualityIn);
  printf("mAverageRssi: %d\r\n", aChildInfo.mAverageRssi);
  printf("mLastRssi: %d\r\n", aChildInfo.mLastRssi);
  printf("mFrameErrorRate: %d\r\n", aChildInfo.mFrameErrorRate);
  printf("mMessageErrorRate: %d\r\n", aChildInfo.mMessageErrorRate);
  printf("mQueuedMessageCnt: %d\r\n", aChildInfo.mQueuedMessageCnt);
  printf("mSupervisionInterval: %d\r\n", aChildInfo.mSupervisionInterval);
  printf("mVersion: %d\r\n", aChildInfo.mVersion);
  printf("mRxOnWhenIdle: %d\r\n", aChildInfo.mRxOnWhenIdle);
  printf("mFullThreadDevice: %d\r\n", aChildInfo.mFullThreadDevice);
  printf("mFullNetworkData: %d\r\n", aChildInfo.mFullNetworkData);
  printf("mIsStateRestoring: %d\r\n", aChildInfo.mIsStateRestoring);
  printf("mIsCslSynced: %d\r\n", aChildInfo.mIsCslSynced);
#endif
  return 0;
}

otError otThreadGetChildInfoById(otInstance *aInstance, uint16_t aChildId,
                                 otChildInfo *aChildInfo) {
  otError oterror = 0;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadGetChildInfoById;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aChildId),
             sizeof(uint16_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)(&aChildInfo->mExtAddress.m8),
               (p_payload_param + payloadsaved), OT_EXT_ADDRESS_SIZE,
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mTimeout),
               (p_payload_param + payloadsaved), sizeof(uint32_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mAge), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mConnectionTime),
               (p_payload_param + payloadsaved), sizeof(uint64_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mRloc16), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mChildId),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mNetworkDataVersion),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mLinkQualityIn),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mAverageRssi),
               (p_payload_param + payloadsaved), sizeof(int8_t), &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mLastRssi),
               (p_payload_param + payloadsaved), sizeof(int8_t), &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mFrameErrorRate),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mMessageErrorRate),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mQueuedMessageCnt),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mSupervisionInterval),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)(&aChildInfo->mVersion),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);
    aChildInfo->mRxOnWhenIdle = *(char *)(p_payload_param + payloadsaved++);
    aChildInfo->mFullThreadDevice = *(char *)(p_payload_param + payloadsaved++);
    aChildInfo->mFullNetworkData = *(char *)(p_payload_param + payloadsaved++);
    aChildInfo->mIsStateRestoring = *(char *)(p_payload_param + payloadsaved++);
    aChildInfo->mIsCslSynced = *(char *)(p_payload_param + payloadsaved++);
  }

  return oterror;
}

/*Get all the thread Unicast IP address*/
int cli_test_otIp6GetMulticastAddresses(int argc, char *argv[]) {
  const otNetifMulticastAddress *multicastAddrs;
  multicastAddrs = otIp6GetMulticastAddresses(g_p_ot_aInstance);

  for (const otNetifMulticastAddress *addr = multicastAddrs; addr;
       addr = addr->mNext) {
    char ipv6_binary[17] = {0};
    char ipv6_tex[40] = {0};
    memcpy((char *)ipv6_binary, (char *)&(addr->mAddress), 16);
    inet_ntop(AF_INET6, ipv6_binary, ipv6_tex, 40);
    printf("%s\r\n", ipv6_tex);
  }

  return 0;
}

const otNetifMulticastAddress *
otIp6GetMulticastAddresses(otInstance *aInstance) {
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6GetMulticastAddresses;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  //
  static char *p_otNetifMulticastAddress;
  uint8_t no_of_pointers =
      *((uint8_t *)(recv_item.recv_buf + (recv_item.response_sz - 1)));

  // if memory was previously allocated, we will free that, and will allocate
  // new one based on the required new size, Size can be different based on the
  // device ot state
  if (p_otNetifMulticastAddress == NULL) {
    //(no_of_pointers * 4) is required to compensate for 32 and 64 bit
    // architecture
    p_otNetifMulticastAddress =
        (char *)malloc(recv_item.response_sz + (no_of_pointers * 4) -
                       (NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                        1)); //- for opcode and response, 1 byte remove is for
                             // no_of_pointers payload
  } else {
    free(p_otNetifMulticastAddress);
    p_otNetifMulticastAddress =
        (char *)malloc(recv_item.response_sz + (no_of_pointers * 4) -
                       (NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                        1)); //- for opcode and response, 1 byte remove is for
                             // no_of_pointers payload
  }

  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index + NCP_CMD_RESP_HDR_SZ;
  otNetifMulticastAddress *multicastAddrs =
      (otNetifMulticastAddress *)p_otNetifMulticastAddress;
  uint32_t next_memeber = 0;
  otNetifMulticastAddress *next_multicastAddrs;

  do {
    ncp_memcpy((char *)(multicastAddrs), (p_payload_param + payloadsaved),
               sizeof(otIp6Address), &payloadsaved);
    ncp_memcpy((char *)&next_memeber, (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);

    next_multicastAddrs =
        (otNetifMulticastAddress *)&multicastAddrs->mNext +
        sizeof(multicastAddrs
                   ->mNext); // will point to next otNetifMulticastAddress

    if (next_memeber != 0) {
      multicastAddrs->mNext = next_multicastAddrs;
    } else {
      multicastAddrs->mNext = NULL;
    }

    multicastAddrs = next_multicastAddrs;

  } while (next_memeber != 0);

  return (otNetifMulticastAddress *)p_otNetifMulticastAddress;
}

void process_otthreaddiscover(char *response_index, int len, int eventid) {
  uint8_t is_scan_finished;
  void *aContext;
  otActiveScanResult aResult;
  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;

  ncp_memcpy((char *)&aContext, (p_payload_param + payloadsaved),
             sizeof(uint64_t), &payloadsaved);
  ncp_memcpy((char *)&is_scan_finished, (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  if (!is_scan_finished) {
    ncp_memcpy((char *)&aResult.mExtAddress.m8,
               (p_payload_param + payloadsaved), OT_EXT_ADDRESS_SIZE,
               &payloadsaved);
    ncp_memcpy((char *)&aResult.mNetworkName.m8,
               (p_payload_param + payloadsaved), (OT_NETWORK_NAME_MAX_SIZE + 1),
               &payloadsaved);
    ncp_memcpy((char *)&aResult.mExtendedPanId.m8,
               (p_payload_param + payloadsaved), OT_EXT_PAN_ID_SIZE,
               &payloadsaved);
    ncp_memcpy((char *)&aResult.mSteeringData.mLength,
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);
    ncp_memcpy((char *)&aResult.mSteeringData.m8,
               (p_payload_param + payloadsaved), OT_STEERING_DATA_MAX_LENGTH,
               &payloadsaved);
    ncp_memcpy((char *)&aResult.mPanId, (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
    ncp_memcpy((char *)&aResult.mJoinerUdpPort,
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)&aResult.mChannel, (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
    ncp_memcpy((char *)&aResult.mRssi, (p_payload_param + payloadsaved),
               sizeof(int8_t), &payloadsaved);
    ncp_memcpy((char *)&aResult.mLqi, (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
    aResult.mVersion = *(char *)(p_payload_param + payloadsaved++);
    aResult.mIsNative = *(char *)(p_payload_param + payloadsaved++);
    aResult.mDiscover = *(char *)(p_payload_param + payloadsaved++);
    aResult.mIsJoinable = *(char *)(p_payload_param + payloadsaved++);
  }

  /*get the callback function based on the eventid and call the respective cb
   * function*/
  ncp_otHandleActiveScanResult = get_ptr_from_eventid(eventid);

  if (ncp_otHandleActiveScanResult != NULL) {
    ncp_otHandleActiveScanResult(((is_scan_finished) ? NULL : &aResult),
                                 aContext);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }
}

static void HandleActiveScanResult(otActiveScanResult *aResult,
                                   void *aContext) {
  printf("Callback:HandleActiveScanResult:  app context %p\r\n", aContext);
#ifdef DEBUG_NCP_OT
  if (aResult == NULL) {
    printf("Thread Discover finished.\r\n");
  } else {
    printf("ExtendedAddress:");
    for (int i = 0; i < OT_EXT_ADDRESS_SIZE; i++) {
      printf("%x", aResult->mExtAddress.m8[i]);
    }
    printf("\r\n");
    printf("NetworkName: %s\r\n", aResult->mNetworkName.m8);
    printf("ExtendedPanId:");
    for (int i = 0; i < OT_EXT_PAN_ID_SIZE; i++) {
      printf("%x", aResult->mExtendedPanId.m8[i]);
    }
    printf("\r\n");
    printf("mSteeringData.mLength: %d\r\n", aResult->mSteeringData.mLength);
    printf("mPanId: 0x%x\r\n", aResult->mPanId);
    printf("mJoinerUdpPort: %d\r\n", aResult->mJoinerUdpPort);
    printf("mChannel: %d\r\n", aResult->mChannel);
    printf("mRssi: %d\r\n", aResult->mRssi);
    printf("mLqi: %d\r\n", aResult->mLqi);
    printf("mVersion: %d\r\n", aResult->mVersion);
    printf("mIsNative: %d\r\n", aResult->mIsNative);
    printf("mDiscover: %d\r\n", aResult->mDiscover);
    printf("mIsJoinable: %d\r\n", aResult->mIsJoinable);
    printf("--------------------------------------------------\r\n");
  }

#endif
}

int cli_test_otThreadDiscover(int argc, char *argv[]) {
  void *aContext = {"otThreadDiscover"};
  otError oterror = 0;
  uint32_t ScanChannels = 0;
  uint16_t PanId = OT_PANID_BROADCAST;
  bool aJoiner = 0;
  bool aEnableEui64Filtering = 0;
  if (argc >= 1) {
    ScanChannels = 1 << atoi(argv[1]);
    printf("scanning  %d \r\n", atoi(argv[1]));
  }

  oterror =
      otThreadDiscover(g_p_ot_aInstance, ScanChannels, PanId, aJoiner,
                       aEnableEui64Filtering, HandleActiveScanResult, aContext);
  printf("otThreadDiscover OTERROR status is %d with context %p\r\n", oterror,
         aContext);

  return 0;
}

otError otThreadDiscover(otInstance *aInstance, uint32_t aScanChannels,
                         uint16_t aPanId, bool aJoiner,
                         bool aEnableEui64Filtering,
                         otHandleActiveScanResult aCallback,
                         void *aCallbackContext) {
  otError oterror = 0;
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otThreadDiscover;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aScanChannels),
             sizeof(uint32_t), &total_tx_len);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aPanId),
             sizeof(uint16_t), &total_tx_len);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aJoiner),
             sizeof(uint8_t), &total_tx_len);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(aEnableEui64Filtering), sizeof(uint8_t), &total_tx_len);

  // app context
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(aCallbackContext), sizeof(uint64_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_THREAD_DISCOVER);
  }

  return oterror;
}

int cli_test_otSrpClientSetHostName(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <hostname>\r\n");
    return -1;
  }
  otError oterror = 0;
  char *hostName = argv[1];

  oterror = otSrpClientSetHostName(g_p_ot_aInstance, hostName);
  printf("otSrpClientSetHostName return OTERROR status is %d\r\n", oterror);
}

otError otSrpClientSetHostName(otInstance *aInstance, const char *aName) {
  otError oterror = 0;
  uint8_t hostname_len = strlen(aName) + 1; // plus 1 for null character
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientSetHostName;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), hostname_len,
                   &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aName,
             hostname_len,
             &total_tx_len); // copy data including null character

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

/*Need to test comrehensively*/
int cli_test_otSrpClientAddService(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Missing argument! use->cmd <name><InstanceName>\r\n");
    return -1;
  }

  otError oterror = 0;
  otSrpClientService *aService;
  aService = (otSrpClientService *)malloc(sizeof(otSrpClientService));
  char *name = argv[1];
  char *InstanceName = argv[2];
  char array1_SubTypeLabels[] = {"sub1"};
  char array2_SubTypeLabels[] = {"sub2"};
  const char *array_SubTypeLabels[3] = {array1_SubTypeLabels,
                                        array2_SubTypeLabels, NULL};
  aService->mName = name;
  aService->mInstanceName = InstanceName;
  aService->mSubTypeLabels = array_SubTypeLabels;
  static const otDnsTxtEntry txtEntries[] = {
      {"tv", "1.3.0", 5}, // Version of Thread Specification
  };
  aService->mTxtEntries = txtEntries;
  aService->mPort = 12345;
  aService->mNumTxtEntries = 1;
  aService->mKeyLease = 1234;
  aService->mLease = 1000;
  aService->mPriority = 2;

  oterror = otSrpClientAddService(g_p_ot_aInstance, aService);
  printf("otSrpClientAddService return OTERROR status is %d\r\n", oterror);

  if (aService != NULL) {
    // free(aService);//need to comment out if need to test for more than 1
    // services to get diffrent address
  }
}

otError otSrpClientAddService(otInstance *aInstance,
                              otSrpClientService *aService) {
  otError oterror = 0;
  uint32_t device_aservice;
  uint8_t len_mName = strlen(aService->mName) + 1;
  uint8_t len_mInstanceName = strlen(aService->mInstanceName) + 1;
  uint8_t len_mSubTypeLabels = 0;
  char array_mSubTypeLabels[255]; // assuming sybtypes does not exceed 255 bytes
                                  // size
  char array_TxtEntries[255]; // assuming TxtEntries does not exceed 255 bytes
                              // size
  uint8_t len_mTxtEntries = 0;
  uint8_t equal_ascii = 0x3D;

  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientAddService;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&len_mInstanceName,
             sizeof(len_mInstanceName), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)(aService->mInstanceName), len_mInstanceName,
             &total_tx_len); // copy data including null character

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&len_mName,
             sizeof(len_mName), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)(aService->mName),
             len_mName,
             &total_tx_len); // copy data including null character

  // if mSubTypeLabels is null, we will just inform the NCP device that
  // mSubTypeLabels is NULL by sending zero value else send actual len and data.
  // Array of sub-type labels (must end with `NULL` or can be `NULL`)
  if (aService->mSubTypeLabels == NULL) {
    len_mSubTypeLabels = 0;
  } else // get all the sub-types
  {
    int i = 0;
    while (aService->mSubTypeLabels[i] != NULL) {
      memcpy((char *)&array_mSubTypeLabels[len_mSubTypeLabels],
             (char *)aService->mSubTypeLabels[i],
             strlen(aService->mSubTypeLabels[i]) + 1);
      len_mSubTypeLabels =
          len_mSubTypeLabels + (strlen(aService->mSubTypeLabels[i]) + 1);
      i++;
    }
  }

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&len_mSubTypeLabels, sizeof(len_mSubTypeLabels),
             &total_tx_len);

  if (len_mSubTypeLabels != 0) // copy all sybtypeslabels
  {
    ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
               (char *)array_mSubTypeLabels, len_mSubTypeLabels, &total_tx_len);
  }

  // mTxtEntries starts here
  if (aService->mNumTxtEntries != 0) // only copy if there are entries
  {
    // structure should be format like this len+key+value -->len is total of
    // key+value
    for (int i = 0; i < aService->mNumTxtEntries; i++) {
      if (aService->mTxtEntries[i].mKey != NULL) {
        uint8_t key_value_len = 0;
        key_value_len = strlen(aService->mTxtEntries[i].mKey) +
                        aService->mTxtEntries[i].mValueLength +
                        sizeof(equal_ascii);
        memcpy((char *)&array_TxtEntries[len_mTxtEntries],
               (char *)&key_value_len, sizeof(key_value_len));
        len_mTxtEntries = len_mTxtEntries + sizeof(key_value_len);
        memcpy((char *)&array_TxtEntries[len_mTxtEntries],
               (char *)aService->mTxtEntries[i].mKey,
               strlen(aService->mTxtEntries[i].mKey));
        len_mTxtEntries =
            len_mTxtEntries + (strlen(aService->mTxtEntries[i].mKey));
        memcpy((char *)&array_TxtEntries[len_mTxtEntries], (char *)&equal_ascii,
               sizeof(equal_ascii));
        len_mTxtEntries = len_mTxtEntries + sizeof(equal_ascii);
        memcpy((char *)&array_TxtEntries[len_mTxtEntries],
               (char *)aService->mTxtEntries[i].mValue,
               aService->mTxtEntries[i].mValueLength);
        len_mTxtEntries =
            len_mTxtEntries + aService->mTxtEntries[i].mValueLength;
      }
    }

    // len_mTxtEntries will be the total no of bytes for all mTxtEntries in
    // array array_TxtEntries
    ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&len_mTxtEntries,
               sizeof(len_mTxtEntries), &total_tx_len);

    ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)array_TxtEntries,
               len_mTxtEntries, &total_tx_len);
  } // mTxtEntries ends here

  /*Whatever is the value of this variable, OT uses 1 to indicate if there are
   * entries and zero if no entry*/
  if (aService->mNumTxtEntries != 0) {
    aService->mNumTxtEntries = 1;
  }

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&aService->mNumTxtEntries, sizeof(uint8_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&aService->mPort,
             sizeof(uint16_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&aService->mPriority, sizeof(uint16_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&aService->mWeight,
             sizeof(uint16_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&aService->mLease,
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&aService->mKeyLease, sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    ncp_memcpy((char *)&(device_aservice), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
    // need to check when to clear this. can be removed if call to
    // 'NCP_otSrpClientClearService' is made
    map_32_to_64_addr(device_aservice, aService);
  }

  return oterror;
}

int cli_test_otSrpClientRemoveService(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <addres-of-service>\r\n");
    return -1;
  }
  otError oterror = 0;
  otSrpClientService *aService =
      (otSrpClientService *)strtol(argv[1], NULL, 16);
  oterror = otSrpClientRemoveService(g_p_ot_aInstance, aService);
  printf("otSrpClientRemoveService return OTERROR status is %d\r\n", oterror);
}

otError otSrpClientRemoveService(otInstance *aInstance,
                                 otSrpClientService *aService) {
  otError oterror = 0;
  uint32_t device_aservice;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientRemoveService;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  device_aservice = get_32_mapped_addr(aService);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&device_aservice,
             sizeof(uint32_t),
             &total_tx_len); // send device side pointer value

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  return oterror;
}

int cli_test_otSrpClientClearService(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <addres-of-service>\r\n");
    return -1;
  }
  otError oterror = 0;
  otSrpClientService *aService =
      (otSrpClientService *)strtol(argv[1], NULL, 16);
  oterror = otSrpClientClearService(g_p_ot_aInstance, aService);
  printf("otSrpClientClearService return OTERROR status is %d\r\n", oterror);
}

otError otSrpClientClearService(otInstance *aInstance,
                                otSrpClientService *aService) {
  otError oterror = 0;
  uint32_t device_aservice;
  char *p_payload_param;
  int payloadsaved = 0;
  int total_tx_len = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientClearService;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  device_aservice = get_32_mapped_addr(aService);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&device_aservice,
             sizeof(uint32_t),
             &total_tx_len); // send device side pointer value

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    remove_32_mapped_addr(aService);
  }

  return oterror;
}

static void ncp_OnSrpClientStateChange(const otSockAddr *aServerSockAddr,
                                       void *aContext) {
  char ipv6_binary[17] = {0};
  char ipv6_tex[40] = {0};
  memcpy((char *)ipv6_binary, (char *)&(aServerSockAddr->mAddress), 16);
  inet_ntop(AF_INET6, ipv6_binary, ipv6_tex, 40);
  printf("CALLBACK: ncp_OnSrpClientStateChange Port:%d and IPaddress: %s \r\n",
         aServerSockAddr->mPort, ipv6_tex);
}

int cli_test_otSrpClientEnableAutoStartMode(int argc, char *argv[]) {
  otSrpClientEnableAutoStartMode(g_p_ot_aInstance, ncp_OnSrpClientStateChange,
                                 NULL);
  printf("otSrpClientEnableAutoStartMode executed \r\n");

  return 0;
}

void otSrpClientEnableAutoStartMode(otInstance *aInstance,
                                    otSrpClientAutoStartCallback aCallback,
                                    void *aContext) {
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientEnableAutoStartMode;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // Matter is currently using NULL for context

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_SRP_CLIENT_STATE_CHANGE);
  }

  return;
}

void process_otsrpclientstatechange(char *response_index, int len,
                                    int eventid) {
  otSockAddr otsockaddr;
  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;

  ncp_memcpy((char *)&otsockaddr.mAddress, (p_payload_param + payloadsaved),
             sizeof(otIp6Address), &payloadsaved);
  ncp_memcpy((char *)&otsockaddr.mPort, (p_payload_param + payloadsaved),
             sizeof(uint16_t), &payloadsaved);

  /*get the callback function based on the eventid and call the respective cb
   * function*/
  ncp_otSrpClientAutoStartCallback = get_ptr_from_eventid(eventid);

  if (ncp_otSrpClientAutoStartCallback != NULL) {
    ncp_otSrpClientAutoStartCallback(&otsockaddr, NULL);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }
}

static void ncp_SrpClientCallback(otError aError,
                                  const otSrpClientHostInfo *aHostInfo,
                                  const otSrpClientService *aServices,
                                  const otSrpClientService *aRemovedServices,
                                  void *aContext) {

#ifdef DEBUG_NCP_OT
  printf("CALLBACK:otSrpClientSetCallback: OTerror %d \r\n", aError);
  printf("CALLBACK:otSrpClientSetCallback: Host name %s \r\n",
         aHostInfo->mName);

  if (aHostInfo->mNumAddresses != 0) {
    const otIp6Address *p_mAddresses = aHostInfo->mAddresses;
    for (int i = 0; i < (aHostInfo->mNumAddresses); i++) {
      char ipv6_binary[17] = {0};
      char ipv6_tex[40] = {0};
      memcpy((char *)ipv6_binary, (char *)(p_mAddresses), 16);
      inet_ntop(AF_INET6, ipv6_binary, ipv6_tex, 40);
      printf("CALLBACK:otSrpClientSetCallback: IPaddress %s \r\n", ipv6_tex);
      p_mAddresses++;
    }
  }

  printf("CALLBACK:otSrpClientSetCallback: mAutoAddress %d \r\n",
         aHostInfo->mAutoAddress);
  printf("CALLBACK:otSrpClientSetCallback: mState %d \r\n", aHostInfo->mState);

  if (aServices != NULL) {
    const otSrpClientService *service;
    for (service = aServices; service != NULL; service = service->mNext) {
      printf("CALLBACK:otSrpClientSetCallback: Current services-> service %p "
             "service next %p\r\n",
             service, service->mNext);
    }
  }

  if (aRemovedServices != NULL) {
    const otSrpClientService *service;
    for (service = aRemovedServices; service != NULL;
         service = service->mNext) {
      printf("CALLBACK:otSrpClientSetCallback:Removed services-> "
             "aRemovedServices %p aRemovedServices next %p\r\n",
             aRemovedServices, aRemovedServices->mNext);
    }
  }

#endif
}

/*Pending: need to clear mapping based on the received call back..but if call
 * back is not activated?????*/
void process_otsrpclientsetcallback(char *response_index, int len,
                                    int eventid) {
  otError aError = 0;
  otSrpClientHostInfo aHostInfo;
  otSrpClientService *aServices = NULL;
  otSrpClientService *aRemovedServices = NULL;
  uint8_t len_mName;
  uint8_t IP_mNumAddresses;
  uint8_t *p_mName = NULL;
  otIp6Address *p_mAddresses = NULL;
  uint8_t len_Services = 0;
  uint8_t cnt_Services = 0;
  uint32_t tmp_host_service = 0;
  otSrpClientService *tmp_device_service = NULL;
  otSrpClientService *tmp_prv_device_service = NULL;
  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;

  ncp_memcpy((char *)&aError, (p_payload_param + payloadsaved), sizeof(uint8_t),
             &payloadsaved);

  // start of aHostInfo
  ncp_memcpy((char *)&len_mName, (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);
  if (len_mName != 0) {
    p_mName = (uint8_t *)malloc(len_mName);
    ncp_memcpy((char *)p_mName, (p_payload_param + payloadsaved), len_mName,
               &payloadsaved);
    aHostInfo.mName = p_mName;
  }

  // IPv6 addresses handling. This section is not tested because auto mode is
  // on, i.e., srp client host address auto Array of host IPv6 addresses (NULL
  // if not set or auto address is enabled)
  ncp_memcpy((char *)&IP_mNumAddresses, (p_payload_param + payloadsaved),
             sizeof(IP_mNumAddresses), &payloadsaved);
  aHostInfo.mNumAddresses = IP_mNumAddresses;
  if (IP_mNumAddresses != 0) {
    p_mAddresses =
        (otIp6Address *)malloc(sizeof(otIp6Address) * IP_mNumAddresses);
    ncp_memcpy((char *)p_mAddresses, (p_payload_param + payloadsaved),
               (sizeof(otIp6Address) * IP_mNumAddresses), &payloadsaved);
    aHostInfo.mAddresses = p_mAddresses;
  }

  aHostInfo.mAutoAddress = *(char *)(p_payload_param + payloadsaved++);
  aHostInfo.mState = *(char *)(p_payload_param + payloadsaved++);
  // End of aHostInfo

  // start of aServices
  /* Get len_Services and cnt_Services from the device side.zero value in
   *len_Services mean no entry for aRemovedServices, else no. of
   *aRemovedServices will be determined by cnt_Services
   */
  ncp_memcpy((char *)&len_Services, (p_payload_param + payloadsaved),
             sizeof(len_Services), &payloadsaved);

  if (len_Services !=
      0) // Do processing only if aServices is not NULL on device side
  {
    ncp_memcpy((char *)&cnt_Services, (p_payload_param + payloadsaved),
               sizeof(cnt_Services), &payloadsaved);

    // for loop to fill aServices
    uint8_t i;
    for (i = 0; i < cnt_Services; i++) {
      ncp_memcpy((char *)&tmp_host_service, (p_payload_param + payloadsaved),
                 sizeof(tmp_host_service), &payloadsaved);
      tmp_device_service =
          (otSrpClientService *)get_64_mapped_addr(tmp_host_service);
      tmp_device_service->mNext = NULL;
      if (tmp_prv_device_service ==
          NULL) // first vaue shoud point to actual aservice frst entry
      {
        aServices = tmp_device_service;
      } else {
        tmp_prv_device_service->mNext = tmp_device_service;
      }

      tmp_prv_device_service = tmp_device_service;

    } // end of for loop for aServices
  }
  // end of aServices

  // aRemovedServices starts here
  //  Get len_Services and cnt_Services from the device side.zero value in
  //  len_Services mean no entry for aRemovedServices,
  // else no. of aRemovedServices will be determined by cnt_Services
  ncp_memcpy((char *)&len_Services, (p_payload_param + payloadsaved),
             sizeof(len_Services), &payloadsaved);

  if (len_Services !=
      0) // Do processing only if aServices is not NULL on device side
  {
    ncp_memcpy((char *)&cnt_Services, (p_payload_param + payloadsaved),
               sizeof(cnt_Services), &payloadsaved);

    // for loop to fill aServices
    uint8_t i;
    tmp_device_service = NULL;
    tmp_prv_device_service = NULL;
    for (i = 0; i < cnt_Services; i++) {
      ncp_memcpy((char *)&tmp_host_service, (p_payload_param + payloadsaved),
                 sizeof(tmp_host_service), &payloadsaved);
      tmp_device_service =
          (otSrpClientService *)get_64_mapped_addr(tmp_host_service);
      remove_32_mapped_addr(tmp_device_service); // delete entry from the
                                                 // mapping
      tmp_device_service->mNext = NULL;
      if (tmp_prv_device_service ==
          NULL) // first vaue shoud point to actual aRemovedServices first entry
      {
        aRemovedServices = tmp_device_service;
      } else {
        tmp_prv_device_service->mNext = tmp_device_service;
      }

      tmp_prv_device_service = tmp_device_service;

    } // end of for loop for aServices
  }
  // aRemovedServices ends here

  /*get the callback function based on the eventid and call the respective cb
   * function*/
  ncp_otSrpClientSetCallback = get_ptr_from_eventid(eventid);

  if (ncp_otSrpClientSetCallback != NULL) {
    // for the moment no Context is used during registartion and here, also used
    // NULL in matter code
    ncp_otSrpClientSetCallback(aError, &aHostInfo, aServices, aRemovedServices,
                               NULL);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }

  if (p_mName != NULL) {
    free(p_mName);
  }
  if (p_mAddresses != NULL) {
    free(p_mAddresses);
  }
}

int cli_test_otSrpClientSetCallback(int argc, char *argv[]) {
  otSrpClientSetCallback(g_p_ot_aInstance, ncp_SrpClientCallback, NULL);
  printf("otSrpClientSetCallback executed \r\n");

  return 0;
}

void otSrpClientSetCallback(otInstance *aInstance,
                            otSrpClientCallback aCallback, void *aContext) {
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otSrpClientSetCallback;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // Matter is currently using NULL for context

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_SRP_CLIENT_SET_CALLBACK);
  }

  return;
}

int cli_test_otDnsBrowseResponseGetServiceName(
    const otDnsBrowseResponse *aResponse) {
  otError oterror = 0;
  char name[OT_DNS_MAX_NAME_SIZE];

  oterror = otDnsBrowseResponseGetServiceName(aResponse, name, sizeof(name));
  printf("otDnsBrowseResponseGetServiceName return OTERROR status is %d\r\n",
         oterror);
#ifdef DEBUG_NCP_OT
  if (aResponse != NULL) {
    printf("received buffer -> \r\n");
    for (int i = 0; i < sizeof(name); i++) {
      printf("[%d]: %x\n", i, name[i]);
    }
    printf("\r\n service name: %s\r\n", name);
  } else {
    printf("aResponse IS NULL\r\n");
  }
#endif

  return 0;
}

/*Must only be used within otDnsClientBrowse's callback*/
otError otDnsBrowseResponseGetServiceName(const otDnsBrowseResponse *aResponse,
                                          char *aNameBuffer,
                                          uint16_t aNameBufferSize) {
  /* retirve ino from BR_name and oterror_getservicename. We will not use here
  aResponse and aNameBufferSize and need improvement on this */

  assert(
      OT_DNS_MAX_NAME_SIZE ==
      aNameBufferSize); // otherwise need to entertain size variable accordingly
  memcpy(aNameBuffer, BR_name, aNameBufferSize);

  return oterror_getservicename;
}

int cli_test_otDnsClientBrowse(int argc, char *argv[]) {
  otError oterror = 0;
  const char *aServiceName = "_service._udp.example.com";
  void *aContext = {"otDnsClientBrowse"};
  oterror = otDnsClientBrowse(g_p_ot_aInstance, aServiceName,
                              ncp_OnDnsBrowseResult, aContext, NULL);
  printf("otDnsClientBrowse return OTERROR status is %d\r\n", oterror);

  return 0;
}

otError otDnsClientBrowse(otInstance *aInstance, const char *aServiceName,
                          otDnsBrowseCallback aCallback, void *aContext,
                          const otDnsQueryConfig *aConfig) {
  otError oterror = 0;
  uint8_t len_aServiceName = strlen(aServiceName) + 1;
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsClientBrowse;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&len_aServiceName,
             sizeof(len_aServiceName), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aServiceName,
             len_aServiceName, &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aContext),
             sizeof(uint64_t), &total_tx_len);

  // currrently matter is using NULL for aConfig, so have a check if it is not
  // NULL and need to implement if matter uses any config
  assert(aConfig == NULL);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_DNS_CLIENT_BROWSE);
  }

  return oterror;
}

void ncp_OnDnsBrowseResult(otError aError, const otDnsBrowseResponse *aResponse,
                           void *aContext) {
  printf("In callback:ncp_OnDnsBrowseResult return OTERROR status is %d with "
         "context %p and aResponse value %p\r\n",
         aError, aContext, aResponse);

  /*need to call other api's here  otDnsBrowseResponseGetServiceName,
  otDnsBrowseResponseGetServiceInstance, otDnsBrowseResponseGetServiceInfo*/

  cli_test_otDnsBrowseResponseGetServiceName(aResponse);

  cli_test_otDnsBrowseResponseGetServiceInstance(aResponse);

  return;
}

void process_otDnsClientBrowse(char *response_index, int len, int eventid) {
  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;
  otError oterror = 0;
  void *hostaContext;
  uint64_t received_aContext;
  uint32_t device_aResponse = 0;
  static uint64_t *aResponse = NULL;
  /*after use, either de-alloc or use static one ?*/
  aResponse = malloc(1); /*This should be generated with a fake value and
    should make a corresponse with value received from device and should be
    mapped and this value host_aContext willbe used by host */

  ncp_memcpy((char *)&oterror, (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  ncp_memcpy((char *)&device_aResponse, (p_payload_param + payloadsaved),
             sizeof(uint32_t), &payloadsaved);

  map_32_to_64_addr(device_aResponse, aResponse);

  ncp_memcpy((char *)&received_aContext, (p_payload_param + payloadsaved),
             sizeof(uint64_t), &payloadsaved);
  hostaContext = (void *)received_aContext;

  /*handling of api's wich need to be handled within callback*/

  char label[OT_DNS_MAX_LABEL_SIZE]; // 64
  uint16_t dynamic_datasize = 0;
  static uint8_t *apis_data = NULL;

  ncp_memcpy((char *)&oterror_getservicename, (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  ncp_memcpy((char *)BR_name, (p_payload_param + payloadsaved), sizeof(BR_name),
             &payloadsaved);

  ncp_memcpy((char *)&dynamic_datasize, (p_payload_param + payloadsaved),
             sizeof(dynamic_datasize), &payloadsaved);
  /*Allocate dynamic memory required*/
  apis_data = (uint8_t *)malloc(dynamic_datasize);

  // for the moment assuming one instance record to be available
  int totalpayload = payloadsaved + dynamic_datasize;
  int rot_apisdata = 0;
  int instance_records = 0;
  uint8_t temp_oterror_getserviceinstance = 0;
  uint8_t oterror_getserviceinfo = 0;

  while (payloadsaved < totalpayload) {
    // save index
    ncp_memcpy((char *)(apis_data + rot_apisdata),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    BR_serviceinstance_array[instance_records] =
        (char *)(apis_data + rot_apisdata);
    rot_apisdata += sizeof(uint16_t);

    // oterror_getserviceinstance
    ncp_memcpy((char *)&(temp_oterror_getserviceinstance),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);

    *(char *)(apis_data + rot_apisdata) = temp_oterror_getserviceinstance;
    rot_apisdata += sizeof(uint8_t);

    // label
    ncp_memcpy((char *)(apis_data + rot_apisdata),
               (p_payload_param + payloadsaved), OT_DNS_MAX_LABEL_SIZE,
               &payloadsaved);
    BR_serviceinfo_array[instance_records] = (char *)(apis_data + rot_apisdata);
    rot_apisdata += OT_DNS_MAX_LABEL_SIZE;

    if (temp_oterror_getserviceinstance ==
        OT_ERROR_NONE) { // save oterror_getserviceinfo and serviceinfo

      // oterror_getserviceinfo
      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint8_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint8_t);

      /*  uint32_t     mTtl;                ///< Service record TTL (in
      seconds). uint16_t     mPort;               ///< Service port number.

      uint16_t     mPriority;           ///< Service priority.
      uint16_t     mWeight;             ///< Service weight.
      char        *mHostNameBuffer;     ///< Buffer to output the service host
      name (can be NULL if not needed). uint16_t     mHostNameBufferSize; ///<
      Size of `mHostNameBuffer`. otIp6Address mHostAddress;
      ///< The host IPv6 address. Set to all zero if not available. uint32_t
      mHostAddressTtl;     ///< The host address TTL. uint8_t     *mTxtData;
      ///< Buffer to output TXT data (can be NULL if not needed). uint16_t
      mTxtDataSize;        ///< On input, size of `mTxtData` buffer. On output
      number bytes written. bool         mTxtDataTruncated;   ///< Indicates if
      TXT data could not fit in `mTxtDataSize` and was truncated. uint32_t
      mTxtDataTtl;
      */
      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint32_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint32_t);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint16_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint16_t);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint16_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint16_t);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint16_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint16_t);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(BR_name),
                 &payloadsaved);
      rot_apisdata += sizeof(BR_name);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(otIp6Address),
                 &payloadsaved);
      rot_apisdata += sizeof(otIp6Address);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint32_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint32_t);

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), MAX_TXTBUFFER_LEN,
                 &payloadsaved);
      rot_apisdata += MAX_TXTBUFFER_LEN; // txtBuffer kMaxTxtDataSize

      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint8_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint8_t);

      // mTxtDataTtl
      ncp_memcpy((char *)(apis_data + rot_apisdata),
                 (p_payload_param + payloadsaved), sizeof(uint32_t),
                 &payloadsaved);
      rot_apisdata += sizeof(uint32_t);

      /* will be gandled whgen fetched through api --> mHostNameBuffer,
       * mHostNameBufferSize, *mTxtData, mTxtDataSize */
    }
    instance_records++;
  }

  /*get the callback function based on the eventid and call the respective cb
   * function*/
  ncp_OnDnsBrowseResultcallback = get_ptr_from_eventid(eventid);

  if (ncp_OnDnsBrowseResultcallback != NULL) {
    ncp_OnDnsBrowseResultcallback(oterror, (otDnsBrowseResponse *)aResponse,
                                  hostaContext);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }

  if (aResponse != NULL) {
    free(aResponse);
  }

  if (apis_data != NULL) {
    free(apis_data);
  }

  for (int i = 0; i < MaX_BR_INSTANCE_RECORDS; i++) {
    BR_serviceinfo_array[i] = NULL;
    BR_serviceinstance_array[i] = NULL;
  }

  // need to clear here all allocation related to this specific callback based
  // on aresponse ???
}

int cli_test_otDnsBrowseResponseGetServiceInstance(
    const otDnsBrowseResponse *aResponse) {

  uint16_t index = 0;
  char label[OT_DNS_MAX_LABEL_SIZE];    // 64
  char name[OT_DNS_MAX_NAME_SIZE];      // 255
  uint8_t txtBuffer[MAX_TXTBUFFER_LEN]; // 512 kMaxTxtDataSize
  otDnsServiceInfo serviceInfo;
  serviceInfo.mHostNameBuffer = name;
  serviceInfo.mHostNameBufferSize = sizeof(name);
  serviceInfo.mTxtData = txtBuffer;
  serviceInfo.mTxtDataSize = sizeof(txtBuffer);
  while ((otDnsBrowseResponseGetServiceInstance(
             aResponse, index, label, sizeof(label))) == OT_ERROR_NONE) {
#ifdef DEBUG_NCP_OT

    printf(
        "otDnsBrowseResponseGetServiceInstance received buffer for index %d  "
        "-> "
        "\r\n",
        index);
    for (int i = 0; i < sizeof(label); i++) {
      printf("[%d]: %x\n", i, label[i]);
    }
    printf("\r\n label: %s\r\n", label);

#endif
    cli_test_otDnsBrowseResponseGetServiceInfo(aResponse, label, &serviceInfo);
    index++;
  }
}

otError
otDnsBrowseResponseGetServiceInstance(const otDnsBrowseResponse *aResponse,
                                      uint16_t aIndex, char *aLabelBuffer,
                                      uint8_t aLabelBufferSize) {
  // aResponse not used here, search for index and sent back label buffer
  uint8_t oterror_getserviceinstance = 0;

  assert(aIndex <
         MaX_BR_INSTANCE_RECORDS); // need to check implementation further to
                                   // have more instance records to entertain
  uint16_t index_from_array = 0;
  for (int i = 0; i < MaX_BR_INSTANCE_RECORDS; i++) {
    if (BR_serviceinstance_array[i] == NULL) {
      break;
    }
    memcpy(&index_from_array, BR_serviceinstance_array[i], 2);
    if (index_from_array == aIndex) // if specific index value exists ?
    {
      // copy label data to aLabelBuffer
      assert(aLabelBufferSize <= OT_DNS_MAX_LABEL_SIZE);
      memcpy(&oterror_getserviceinstance,
             (BR_serviceinstance_array[i]) + sizeof(index_from_array),
             sizeof(oterror_getserviceinstance));
      memcpy(aLabelBuffer, BR_serviceinfo_array[i], aLabelBufferSize);
    }
  }

  return oterror_getserviceinstance;
}

int cli_test_otDnsBrowseResponseGetServiceInfo(
    const otDnsBrowseResponse *aResponse, const char *aInstanceLabel,
    otDnsServiceInfo *aServiceInfo) {
  otDnsBrowseResponseGetServiceInfo(aResponse, aInstanceLabel, aServiceInfo);
}

// pending verification, to be tested upon with matter or dns commands
otError otDnsBrowseResponseGetServiceInfo(const otDnsBrowseResponse *aResponse,
                                          const char *aInstanceLabel,
                                          otDnsServiceInfo *aServiceInfo) {
  /*aResponse will be unused here, aInstanceLabel should be compared with
   * BR_serviceinfo_array entries and return service info */
  uint8_t *serviceinfo_apisdata = NULL;
  uint8_t oterror_getserviceinfo = 0;
  int dataretrieved = 0;
  for (int i = 0; i < MaX_BR_INSTANCE_RECORDS; i++) {
    printf("strcmp(aInstanceLabel,BR_serviceinfo_array[i]) \r\n");
    if (BR_serviceinfo_array[i] == NULL) {
      break;
    }
    if (strcmp(aInstanceLabel, BR_serviceinfo_array[i]) == 0) { // label matches
      serviceinfo_apisdata = BR_serviceinfo_array[i] + OT_DNS_MAX_LABEL_SIZE;
      printf("insie if) \r\n");
      // BR_serviceinfo_array entries points to label, and next entries are
      // oterror_getserviceinfo and followed by aServiceInfo
      ncp_memcpy((uint8_t *)&(oterror_getserviceinfo),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint8_t),
                 &dataretrieved);

      /*  uint32_t     mTtl;                ///< Service record TTL (in
         seconds). uint16_t     mPort;               ///< Service port number.

          uint16_t     mPriority;           ///< Service priority.
          uint16_t     mWeight;             ///< Service weight.
          char        *mHostNameBuffer;     ///< Buffer to output the service
         host name (can be NULL if not needed). uint16_t mHostNameBufferSize;
         ///< Size of `mHostNameBuffer`. otIp6Address mHostAddress;
         ///< The host IPv6 address. Set to all zero if not available. uint32_t
         mHostAddressTtl;     ///< The host address TTL. uint8_t     *mTxtData;
         ///< Buffer to output TXT data (can be NULL if not needed). uint16_t
         mTxtDataSize;        ///< On input, size of `mTxtData` buffer. On
         output number bytes written. bool         mTxtDataTruncated;   ///<
         Indicates if TXT data could not fit in `mTxtDataSize` and was
         truncated. uint32_t     mTxtDataTtl;
          */
      ncp_memcpy((uint8_t *)&(aServiceInfo->mTtl),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint32_t),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mPort),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mPriority),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mWeight),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)(aServiceInfo->mHostNameBuffer),
                 (serviceinfo_apisdata + dataretrieved), OT_DNS_MAX_NAME_SIZE,
                 &dataretrieved);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mHostNameBufferSize),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mHostAddress),
                 (serviceinfo_apisdata + dataretrieved), sizeof(otIp6Address),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mHostAddressTtl),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint32_t),
                 &dataretrieved);
      ncp_memcpy((uint8_t *)(aServiceInfo->mTxtData),
                 (serviceinfo_apisdata + dataretrieved), MAX_TXTBUFFER_LEN,
                 &dataretrieved); // 512 kMaxTxtDataSize
      ncp_memcpy((uint8_t *)&(aServiceInfo->mTxtDataSize),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
                 &dataretrieved);
      aServiceInfo->mTxtDataTruncated =
          *(uint8_t *)(serviceinfo_apisdata + dataretrieved++);
      ncp_memcpy((uint8_t *)&(aServiceInfo->mTxtDataTtl),
                 (serviceinfo_apisdata + dataretrieved), sizeof(uint32_t),
                 &dataretrieved);
    }
  }

  return oterror_getserviceinfo;
}

int cli_test_otDnsClientGetDefaultConfig(int argc, char *argv[]) {
  const otDnsQueryConfig *defaultConfig = NULL;
  defaultConfig = otDnsClientGetDefaultConfig(g_p_ot_aInstance);
  printf("otDnsClientGetDefaultConfig executed with defaultConfig val %p\r\n",
         defaultConfig);
#ifdef DEBUG_NCP_OT
  char ipv6_binary[17] = {0};
  char ipv6_tex[40] = {0};
  memcpy((char *)ipv6_binary,
         (char *)&(defaultConfig->mServerSockAddr.mAddress), 16);
  inet_ntop(AF_INET6, ipv6_binary, ipv6_tex, 40);
  printf("mServerSockAddr:  %s\r\n", ipv6_tex);
  printf("otDnsClientGetDefaultConfig:port # %d \r\n",
         defaultConfig->mServerSockAddr.mPort);
  printf("otDnsClientGetDefaultConfig:mTransportProto -> %d \r\n",
         defaultConfig->mTransportProto);

#endif

  return 0;
}

const otDnsQueryConfig *otDnsClientGetDefaultConfig(otInstance *aInstance) {
  static otDnsQueryConfig defaultConfig;
  uint32_t host_defaultConfig = 0;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsClientGetDefaultConfig;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  //

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(defaultConfig.mServerSockAddr.mAddress),
               (p_payload_param + payloadsaved), sizeof(otIp6Address),
               &payloadsaved);
    ncp_memcpy((char *)&(defaultConfig.mServerSockAddr.mPort),
               (p_payload_param + payloadsaved), sizeof(uint16_t),
               &payloadsaved);
    ncp_memcpy((char *)&(defaultConfig.mResponseTimeout),
               (p_payload_param + payloadsaved), sizeof(uint32_t),
               &payloadsaved);
    ncp_memcpy((char *)&(defaultConfig.mMaxTxAttempts),
               (p_payload_param + payloadsaved), sizeof(uint8_t),
               &payloadsaved);

    defaultConfig.mRecursionFlag =
        *(uint8_t *)(p_payload_param + payloadsaved++);
    defaultConfig.mNat64Mode = *(uint8_t *)(p_payload_param + payloadsaved++);
    defaultConfig.mServiceMode = *(uint8_t *)(p_payload_param + payloadsaved++);
    defaultConfig.mTransportProto =
        *(uint8_t *)(p_payload_param + payloadsaved++);
  }

  return &defaultConfig;
}

int cli_test_otDnsClientSetDefaultConfig(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <addres-of-defaultconfig>\r\n");
    return -1;
  }
  otDnsQueryConfig *defaultConfig =
      (otDnsQueryConfig *)strtol(argv[1], NULL, 16);
  // change few variables
  defaultConfig->mServerSockAddr.mPort = 55;
  defaultConfig->mTransportProto = OT_DNS_TRANSPORT_TCP;
  otDnsClientSetDefaultConfig(g_p_ot_aInstance, defaultConfig);
  printf("otDnsClientSetDefaultConfig is executed \r\n");
}

void otDnsClientSetDefaultConfig(otInstance *aInstance,
                                 const otDnsQueryConfig *aConfig) {
  uint32_t host_defaultConfig = 0;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsClientSetDefaultConfig;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  // need to copy contetnts of aConfig because it might have been changed by
  // host. Need to send updated values
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(aConfig->mServerSockAddr.mAddress), sizeof(otIp6Address),
             &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(aConfig->mServerSockAddr.mPort), sizeof(uint16_t),
             &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(aConfig->mResponseTimeout), sizeof(uint32_t),
             &total_tx_len);

  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   aConfig->mMaxTxAttempts, &total_tx_len);

  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   aConfig->mRecursionFlag, &total_tx_len);
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aConfig->mNat64Mode,
                   &total_tx_len);
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   aConfig->mServiceMode, &total_tx_len);
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   aConfig->mTransportProto, &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  //
  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    // if processing needed
  }

  return;
}

int cli_test_otDnsInitTxtEntryIterator(int argc, char *argv[]) {

  // aTxtData, aTxtDataLength(2 bytes) comes from otDnsServiceInfo &aServiceInfo
  uint8_t txtBuffer[MAX_TXTBUFFER_LEN];
  memset(txtBuffer, 0, MAX_TXTBUFFER_LEN);
  uint16_t txtdatalength = sizeof(txtBuffer);
  otDnsTxtEntryIterator iterator;

  otDnsInitTxtEntryIterator(&iterator, txtBuffer, txtdatalength);
  printf("otDnsInitTxtEntryIterator is executed with aIterator %p \r\n",
         &iterator);
}

void otDnsInitTxtEntryIterator(otDnsTxtEntryIterator *aIterator,
                               const uint8_t *aTxtData,
                               uint16_t aTxtDataLength) {
  uint32_t aIterator_device = 0;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsInitTxtEntryIterator;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aTxtDataLength),
             sizeof(aTxtDataLength), &total_tx_len);

  // copy contents of aTxtData based on aTxtDataLength
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)(aTxtData),
             aTxtDataLength, &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    // need to do mapping here for aIterator with aIterator_device
    ncp_memcpy((char *)&(aIterator_device), (p_payload_param + payloadsaved),
               sizeof(uint32_t), &payloadsaved);
    map_32_to_64_addr(aIterator_device, aIterator);
  }
}

int cli_test_otDnsGetNextTxtEntry(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <addres-of-aIterator>\r\n");
    return -1;
  }
  otDnsTxtEntry entry;
  otError oterror = 0;
  otDnsTxtEntryIterator *iterator =
      (otDnsTxtEntryIterator *)strtol(argv[1], NULL, 16);
  oterror = otDnsGetNextTxtEntry(iterator, &entry);
  printf("otDnsGetNextTxtEntry is executed  with ot error %d \r\n", oterror);
}

// not tested on real dns environment
otError otDnsGetNextTxtEntry(otDnsTxtEntryIterator *aIterator,
                             otDnsTxtEntry *aEntry) {
  otError oterror = 0;
  uint16_t string_len = 0;
  static uint8_t *p_mKey = NULL;
  static uint8_t *p_mValue = NULL;
  uint32_t device_aIterator = 0;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsGetNextTxtEntry;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  device_aIterator = get_32_mapped_addr(aIterator);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(device_aIterator), sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror != OT_ERROR_NOT_FOUND &&
      NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];
    // save aEntry members,i.e.,  mkey, mValue, mValueLength
    ncp_memcpy((char *)&(string_len), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
    if (string_len == 0) {
      aEntry->mKey = NULL;
    } else { // string_len will include null character
      if (p_mKey == NULL) {
        p_mKey = (uint8_t *)malloc(string_len);
      } else {
        free(p_mKey);
        p_mKey = (uint8_t *)malloc(string_len);
      }
      aEntry->mKey = p_mKey;
      ncp_memcpy((char *)(aEntry->mKey), (p_payload_param + payloadsaved),
                 string_len, &payloadsaved);
    }

    // check for mValueLength and mValue
    ncp_memcpy((char *)&(string_len), (p_payload_param + payloadsaved),
               sizeof(uint16_t), &payloadsaved);
    aEntry->mValueLength = string_len;
    /*NOt taken nto account - If `mValue` is not NULL but `mValueLength` is
    zero, then it is treated as empty value and encoded as "key=". So, having
    mValueLength=0 will have dangling pointer for aEntry->mValue */
    if (string_len != 0) {
      if (p_mValue == NULL) {
        p_mValue = (uint8_t *)malloc(string_len);
      } else {
        free(p_mValue);
        p_mValue = (uint8_t *)malloc(string_len);
      }
      aEntry->mValue = p_mValue;
      ncp_memcpy((char *)(aEntry->mValue), (p_payload_param + payloadsaved),
                 string_len, &payloadsaved);
    }
  }

  // remove mapping upon specific ot error i,e, OT_ERROR_NOT_FOUND
  if (oterror == OT_ERROR_NOT_FOUND) {
    remove_32_mapped_addr(aIterator);
    if (p_mValue != NULL) {
      free(p_mValue);
    }

    if (p_mKey != NULL) {
      free(p_mKey);
    }
  }

  return oterror;
}

void process_otDnsClientResolveService(char *response_index, int len,
                                       int eventid) {

  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;
  otError oterror = 0;
  void *hostaContext;
  uint64_t received_aContext;
  uint32_t device_aResponse = 0;
  static uint64_t *aResponse = NULL;
  uint16_t len_apis_data = 0;
  int rot_apisdata = 0;
  uint8_t *apis_data = NULL;
  /*after use, either de-alloc or use static one ?*/
  aResponse = malloc(1); /*This should be generated with a fake value and
    should make a corresponse with value received from device and should be
    mapped and this value host_aContext willbe used by host */

  ncp_memcpy((char *)&oterror, (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  ncp_memcpy((char *)&device_aResponse, (p_payload_param + payloadsaved),
             sizeof(uint32_t), &payloadsaved);

  map_32_to_64_addr(device_aResponse, aResponse);

  ncp_memcpy((char *)&received_aContext, (p_payload_param + payloadsaved),
             sizeof(uint64_t), &payloadsaved);
  hostaContext = (void *)received_aContext;

  // handling of API's
  ncp_memcpy((char *)&len_apis_data, (p_payload_param + payloadsaved),
             sizeof(uint16_t), &payloadsaved);

  /*This allocation will have structure like this -> device_aResponse, oterror,
  label, name, oterror,serviceinfo
  */
  apis_data = (uint8_t *)malloc(len_apis_data + sizeof(device_aResponse));

  p_otDnsServiceResponseGetServiceName = apis_data;

  // save device_aResponse to later compare with aResponse
  memcpy((char *)(apis_data + rot_apisdata), (&device_aResponse),
         sizeof(device_aResponse));
  rot_apisdata += sizeof(device_aResponse);

  ncp_memcpy((char *)(apis_data + rot_apisdata),
             (p_payload_param + payloadsaved), sizeof(uint8_t), &payloadsaved);
  rot_apisdata += sizeof(uint8_t);

  ncp_memcpy((char *)(apis_data + rot_apisdata),
             (p_payload_param + payloadsaved), OT_DNS_MAX_LABEL_SIZE,
             &payloadsaved);
  rot_apisdata += OT_DNS_MAX_LABEL_SIZE;

  ncp_memcpy((char *)(apis_data + rot_apisdata),
             (p_payload_param + payloadsaved), OT_DNS_MAX_NAME_SIZE,
             &payloadsaved);
  rot_apisdata += OT_DNS_MAX_NAME_SIZE;

  p_otDnsServiceResponseGetServiceInfo = (char *)(apis_data + rot_apisdata);

  // copy all at once
  ncp_memcpy(
      (char *)(apis_data + rot_apisdata), (p_payload_param + payloadsaved),
      (len_apis_data - rot_apisdata + sizeof(device_aResponse)), &payloadsaved);

  ncp_otDnsServiceCallback = get_ptr_from_eventid(eventid);

  if (ncp_otDnsServiceCallback != NULL) {
    ncp_otDnsServiceCallback(oterror, (otDnsServiceResponse *)aResponse,
                             hostaContext);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }

  remove_32_mapped_addr(
      aResponse); // this mapping was only required for this specific call back

  if (aResponse != NULL) {
    free(aResponse);
  }

  if (apis_data != NULL) {
    free(apis_data);
  }

  p_otDnsServiceResponseGetServiceName = NULL;
  p_otDnsServiceResponseGetServiceInfo = NULL;
}

void ncp_otDnsService_cb(otError aError, const otDnsServiceResponse *aResponse,
                         void *aContext) {
  printf("In callback:ncp_otDnsService_cb return OTERROR status is %d with "
         "context %p and aResponse value %p\r\n",
         aError, aContext, aResponse);

  cli_test_otDnsServiceResponseGetServiceName(aResponse);

  cli_test_otDnsServiceResponseGetServiceInfo(aResponse);
}

int cli_test_otDnsClientResolveService(int argc, char *argv[]) {

  if (argc < 3) {
    printf("Missing argument! use->cmd "
           "<name><InstanceLabel><service_Name><dnsConfig>\r\n");
    return -1;
  }

  otError oterror = 0;
  char *label = argv[1];
  char *service_name = argv[2];
  void *aContext = {"OtDnsClientResolveService"};
  otDnsQueryConfig *defaultConfig =
      (otDnsQueryConfig *)strtol(argv[3], NULL, 16);

  oterror =
      otDnsClientResolveService(g_p_ot_aInstance, label, service_name,
                                ncp_otDnsService_cb, aContext, defaultConfig);
  printf("otDnsClientResolveService return OTERROR status is %d with requested "
         "context %p \r\n",
         oterror, aContext);
}

otError otDnsClientResolveService(otInstance *aInstance,
                                  const char *aInstanceLabel,
                                  const char *aServiceName,
                                  otDnsServiceCallback aCallback,
                                  void *aContext,
                                  const otDnsQueryConfig *aConfig) {
  otError oterror = 0;
  uint32_t host_defaultConfig = 0;
  uint8_t len_aInstanceLabel = strlen(aInstanceLabel) + 1;
  uint8_t len_aServiceName = strlen(aServiceName) + 1;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsClientResolveService;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&len_aInstanceLabel, sizeof(len_aInstanceLabel),
             &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aInstanceLabel,
             len_aInstanceLabel, &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&len_aServiceName,
             sizeof(len_aServiceName), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aServiceName,
             len_aServiceName, &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aContext),
             sizeof(uint64_t), &total_tx_len);

  host_defaultConfig = get_32_mapped_addr((void *)aConfig);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(host_defaultConfig), sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_DNS_CLIENT_RESOLVE_SERVICE);
  }

  return oterror;
}

// to be called inside the callback only
int cli_test_otDnsServiceResponseGetServiceName(
    const otDnsServiceResponse *aResponse) {

  char name[OT_DNS_MAX_NAME_SIZE];
  char label[OT_DNS_MAX_LABEL_SIZE]; // 64
  otError oterror = 0;

  oterror = otDnsServiceResponseGetServiceName(aResponse, label, sizeof(label),
                                               name, sizeof(name));
  printf("otDnsServiceResponseGetServiceName return OTERROR status is %d label "
         "%s and  name %s \r\n",
         oterror, label, name);
}

// to be called inside the callback only
otError otDnsServiceResponseGetServiceName(
    const otDnsServiceResponse *aResponse, char *aLabelBuffer,
    uint8_t aLabelBufferSize, char *aNameBuffer, uint16_t aNameBufferSize) {
  otError oterror = 0;
  int rot_apisdata = 0;
  assert(p_otDnsServiceResponseGetServiceName != NULL);
  uint8_t *apis_data = p_otDnsServiceResponseGetServiceName;

  uint32_t device_aResponse = 0;

  // because current impelementation is based on predeifned size for name and
  // label, so have a check
  assert(aLabelBufferSize <= OT_DNS_MAX_LABEL_SIZE);
  assert(aNameBufferSize <= OT_DNS_MAX_NAME_SIZE);

  ncp_memcpy((char *)&device_aResponse, (char *)(apis_data + rot_apisdata),
             sizeof(device_aResponse), &rot_apisdata);

  // check here if device response matches with the requested one
  assert(device_aResponse == get_32_mapped_addr((void *)aResponse));

  ncp_memcpy((char *)&oterror, (char *)(apis_data + rot_apisdata),
             sizeof(uint8_t), &rot_apisdata);

  ncp_memcpy((char *)aLabelBuffer, (char *)(apis_data + rot_apisdata),
             OT_DNS_MAX_LABEL_SIZE, &rot_apisdata);

  ncp_memcpy((char *)aNameBuffer, (char *)(apis_data + rot_apisdata),
             OT_DNS_MAX_NAME_SIZE, &rot_apisdata);

  return oterror;
}

// to be called inside the callback only
int cli_test_otDnsServiceResponseGetServiceInfo(
    const otDnsServiceResponse *aResponse) {
  otError oterror = 0;
  char label[OT_DNS_MAX_LABEL_SIZE];    // 64
  char name[OT_DNS_MAX_NAME_SIZE];      // 255
  uint8_t txtBuffer[MAX_TXTBUFFER_LEN]; // 512 kMaxTxtDataSize
  otDnsServiceInfo serviceInfo;
  serviceInfo.mHostNameBuffer = name;
  serviceInfo.mHostNameBufferSize = sizeof(name);
  serviceInfo.mTxtData = txtBuffer;
  serviceInfo.mTxtDataSize = sizeof(txtBuffer);

  oterror = otDnsServiceResponseGetServiceInfo(aResponse, &serviceInfo);
  printf("otDnsServiceResponseGetServiceInfo return OTERROR status is %d \r\n",
         oterror);
#ifdef DEBUG_NCP_OT
  printf("otDnsServiceResponseGetServiceInfo: mPort %d  \r\n",
         serviceInfo.mPort);
  printf("otDnsServiceResponseGetServiceInfo: mTxtDataSize %d  \r\n",
         serviceInfo.mTxtDataSize);

  printf("otDnsServiceResponseGetServiceInfo: mHostNameBuffer %s  \r\n",
         serviceInfo.mHostNameBuffer);
  printf("otDnsServiceResponseGetServiceInfo: mTxtDataTtl %d  \r\n",
         serviceInfo.mTxtDataTtl);

  printf("otDnsServiceResponseGetServiceInfo: mPriority %d  \r\n",
         serviceInfo.mPriority);

  printf("otDnsServiceResponseGetServiceInfo: mTxtDataTtl %d  \r\n",
         serviceInfo.mTxtDataTtl);

#endif
}

// to be called inside the callback only
otError
otDnsServiceResponseGetServiceInfo(const otDnsServiceResponse *aResponse,
                                   otDnsServiceInfo *aServiceInfo) {

  otError oterror = 0;
  int dataretrieved = 0;
  uint32_t device_aResponse = 0;
  assert(p_otDnsServiceResponseGetServiceName != NULL);
  uint8_t *p_device_aResponse = p_otDnsServiceResponseGetServiceName;
  uint8_t *serviceinfo_apisdata = p_otDnsServiceResponseGetServiceInfo;

  assert(aServiceInfo->mTxtDataSize <= MAX_TXTBUFFER_LEN);
  assert(aServiceInfo->mHostNameBufferSize <= OT_DNS_MAX_NAME_SIZE);

  memcpy((char *)&device_aResponse, (char *)(p_device_aResponse),
         sizeof(device_aResponse));

  // check here if device response matches with the requested one
  assert(device_aResponse == get_32_mapped_addr((void *)aResponse));

  //  serviceinfo
  ncp_memcpy((uint8_t *)&(oterror), (serviceinfo_apisdata + dataretrieved),
             sizeof(uint8_t), &dataretrieved);

  ncp_memcpy((uint8_t *)&(aServiceInfo->mTtl),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint32_t),
             &dataretrieved);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mPort),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
             &dataretrieved);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mPriority),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
             &dataretrieved);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mWeight),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
             &dataretrieved);
  ncp_memcpy((uint8_t *)(aServiceInfo->mHostNameBuffer),
             (serviceinfo_apisdata + dataretrieved), OT_DNS_MAX_NAME_SIZE,
             &dataretrieved);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mHostNameBufferSize),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
             &dataretrieved);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mHostAddress),
             (serviceinfo_apisdata + dataretrieved), sizeof(otIp6Address),
             &dataretrieved);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mHostAddressTtl),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint32_t),
             &dataretrieved);
  ncp_memcpy((uint8_t *)(aServiceInfo->mTxtData),
             (serviceinfo_apisdata + dataretrieved), MAX_TXTBUFFER_LEN,
             &dataretrieved); // 512 kMaxTxtDataSize
  ncp_memcpy((uint8_t *)&(aServiceInfo->mTxtDataSize),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint16_t),
             &dataretrieved);
  aServiceInfo->mTxtDataTruncated =
      *(uint8_t *)(serviceinfo_apisdata + dataretrieved++);
  ncp_memcpy((uint8_t *)&(aServiceInfo->mTxtDataTtl),
             (serviceinfo_apisdata + dataretrieved), sizeof(uint32_t),
             &dataretrieved);

  return oterror;
}

void ncp_val_mem_copy(char *dest, char src, int *totalsize) {
  *(char *)dest = (char)src;
  *totalsize += 1;

  return;
}

int cli_test_otIp6IsAddressUnspecified(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <IPADDR>\r\n");
    return -1;
  }
  bool response;
  otIp6Address address;
  inet_pton(AF_INET6, argv[1],
            &(address)); // IPV6 address - Text to Binary
  response = otIp6IsAddressUnspecified(&address);
  printf("otIp6IsAddressUnspecified response is %d\r\n", response);
}

bool otIp6IsAddressUnspecified(const otIp6Address *aAddress) {
  uint8_t response = 0;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6IsAddressUnspecified;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aAddress,
             sizeof(otIp6Address), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  response = NCP_API_GET_RSP_PAYLOAD(response_index);

  return (bool)response;
}
void process_otDnsClientResolveAddress(char *response_index, int len,
                                       int eventid) {

  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;
  otError oterror = 0;
  void *hostaContext;
  uint64_t received_aContext;
  uint32_t device_aResponse = 0;
  static uint64_t *aResponse = NULL;
  uint16_t len_apis_data = 0;
  int rot_apisdata = 0;
  uint8_t *apis_data = NULL;
  /*after use, either de-alloc or use static one ?*/
  aResponse = malloc(1); /*This should be generated with a fake value and
  should make a corresponse with value received from device and should be
  mapped and this value host_aContext willbe used by host */

  ncp_memcpy((char *)&oterror, (p_payload_param + payloadsaved),
             sizeof(uint8_t), &payloadsaved);

  ncp_memcpy((char *)&device_aResponse, (p_payload_param + payloadsaved),
             sizeof(uint32_t), &payloadsaved);

  map_32_to_64_addr(device_aResponse, aResponse);

  ncp_memcpy((char *)&received_aContext, (p_payload_param + payloadsaved),
             sizeof(uint64_t), &payloadsaved);
  hostaContext = (void *)received_aContext;

  // handling of API's
  ncp_memcpy((char *)&len_apis_data, (p_payload_param + payloadsaved),
             sizeof(uint16_t), &payloadsaved);

  /*This allocation will have structure like this -> device_aResponse, oterror,
   * aAddress,aTtl
   */
  apis_data = (uint8_t *)malloc(len_apis_data + sizeof(device_aResponse));

  p_otDnsAddressResponseGetAddress = apis_data;

  // save device_aResponse to later compare with aResponse
  memcpy((char *)(apis_data + rot_apisdata), (&device_aResponse),
         sizeof(device_aResponse));
  rot_apisdata += sizeof(device_aResponse);

  ncp_memcpy((char *)(apis_data + rot_apisdata),
             (p_payload_param + payloadsaved), sizeof(uint8_t), &payloadsaved);
  rot_apisdata += sizeof(uint8_t);

  ncp_memcpy((char *)(apis_data + rot_apisdata),
             (p_payload_param + payloadsaved), sizeof(otIp6Address),
             &payloadsaved);
  rot_apisdata += sizeof(otIp6Address);

  ncp_memcpy((char *)(apis_data + rot_apisdata),
             (p_payload_param + payloadsaved), sizeof(uint32_t), &payloadsaved);
  rot_apisdata += sizeof(uint32_t);

  ncp_otDnsAddressCallback = get_ptr_from_eventid(eventid);

  if (ncp_otDnsAddressCallback != NULL) {
    ncp_otDnsAddressCallback(oterror, (otDnsAddressResponse *)aResponse,
                             hostaContext);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }

  remove_32_mapped_addr(
      aResponse); // this mapping was only required for this specific call back

  if (aResponse != NULL) {
    free(aResponse);
  }
  if (apis_data != NULL) {
    free(apis_data);
  }

  p_otDnsAddressResponseGetAddress = NULL;
}

/*callback function for NCP_otDnsClientResolveAddress*/
void ncp_otDnsAddress_cb(otError aError, const otDnsAddressResponse *aResponse,
                         void *aContext) {
  printf("In callback:ncp_otDnsAddress_cb return OTERROR status is %d with "
         "context %p and aResponse value %p\r\n",
         aError, aContext, aResponse);
  cli_test_otDnsAddressResponseGetAddress(aResponse);
}

int cli_test_otDnsClientResolveAddress(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Missing argument! use->cmd <hostname><config>\r\n");
    return -1;
  }

  otError oterror = 0;
  char *name = argv[1];
  otDnsQueryConfig *defaultConfig =
      (otDnsQueryConfig *)strtol(argv[2], NULL, 16);
  void *aContext = {"otDnsClientResolveAddress"};

  oterror = otDnsClientResolveAddress(
      g_p_ot_aInstance, name, ncp_otDnsAddress_cb, aContext, defaultConfig);
  printf("otDnsClientResolveAddress return OTERROR status is %d with requested "
         "context %p \r\n",
         oterror, aContext);
}

otError otDnsClientResolveAddress(otInstance *aInstance, const char *aHostName,
                                  otDnsAddressCallback aCallback,
                                  void *aContext,
                                  const otDnsQueryConfig *aConfig) {
  otError oterror = 0;
  uint32_t host_defaultConfig = 0;
  uint8_t len_aHostName = strlen(aHostName) + 1;
  assert(len_aHostName <= OT_DNS_MAX_NAME_SIZE);

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otDnsClientResolveAddress;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&len_aHostName,
             sizeof(len_aHostName), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)aHostName,
             len_aHostName, &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(aContext),
             sizeof(uint64_t), &total_tx_len);

  host_defaultConfig = get_32_mapped_addr((void *)aConfig);
  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(host_defaultConfig), sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (oterror == OT_ERROR_NONE && NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ +
                                       NCP_CMD_RESP_OTERROR_SZ];

    /*This callback value of 64 bit is saved and mapped to eventid
     * This value of cbfunc will also be stored at device side and
     * a mapping of 32 to 64 bit will be available on device side*/
    register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_DNS_CLIENT_RESOLVE_ADDRESS);
  }

  return oterror;
}

int cli_test_otDnsAddressResponseGetAddress(
    const otDnsAddressResponse *aResponse) {
  otError oterror = 0;
  otIp6Address aAddress;
  uint32_t aTtl;

  oterror = otDnsAddressResponseGetAddress(aResponse, 0, &aAddress, &aTtl);
  printf("otDnsAddressResponseGetAddress return OTERROR status is %d with TTL "
         "value %d \r\n",
         oterror, aTtl);
}

otError otDnsAddressResponseGetAddress(const otDnsAddressResponse *aResponse,
                                       uint16_t aIndex, otIp6Address *aAddress,
                                       uint32_t *aTtl) {
  otError oterror = 0;
  int dataretrieved = 0;
  uint32_t device_aResponse = 0;
  assert(p_otDnsAddressResponseGetAddress != NULL);
  assert(aIndex == 0); // Matter is currently using zero
  // uint8_t *p_device_aResponse = p_otDnsAddressResponseGetAddress;
  uint8_t *apisdata = p_otDnsAddressResponseGetAddress;

  ncp_memcpy((uint8_t *)&(device_aResponse), (apisdata + dataretrieved),
             sizeof(device_aResponse), &dataretrieved);
  // check here if device response matches with the requested one
  assert(device_aResponse == get_32_mapped_addr((void *)aResponse));

  // ot error
  ncp_memcpy((uint8_t *)&(oterror), (apisdata + dataretrieved), sizeof(uint8_t),
             &dataretrieved);

  // otIp6Address
  ncp_memcpy((uint8_t *)aAddress, (apisdata + dataretrieved),
             sizeof(otIp6Address), &dataretrieved);

  // TTL
  ncp_memcpy((uint8_t *)aTtl, (apisdata + dataretrieved), sizeof(uint32_t),
             &dataretrieved);

  return oterror;
}

int cli_test_otIcmp6SetEchoMode(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <EchoMode>\r\n");
    return -1;
  }
  int echomode = 0;
  echomode = (int)strtol(argv[1], NULL, 10);
  otIcmp6SetEchoMode(g_p_ot_aInstance, (otIcmp6EchoMode)echomode);
  printf("otIcmp6SetEchoMode is executed with user echo mode %d  \r\n",
         echomode);
}

void otIcmp6SetEchoMode(otInstance *aInstance, otIcmp6EchoMode aMode) {
  uint8_t amode_val = (uint8_t)aMode;
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIcmp6SetEchoMode;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&aMode,
             sizeof(uint8_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  return;
}

int cli_test_otIp6SetReceiveFilterEnabled(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <aEnabled>\r\n");
    return -1;
  }
  bool aEnabled = 0;
  aEnabled = (bool)strtol(argv[1], NULL, 10);
  otIp6SetReceiveFilterEnabled(g_p_ot_aInstance, aEnabled);
  printf("otIp6SetReceiveFilterEnabled is executed with aEnabled %d  \r\n",
         aEnabled);
}

void otIp6SetReceiveFilterEnabled(otInstance *aInstance, bool aEnabled) {
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6SetReceiveFilterEnabled;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aEnabled,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  return;
}

int cli_test_otIp6SetSlaacEnabled(int argc, char *argv[]) {
  if (argc < 1) {
    printf("Missing argument! use->cmd <aEnabled>\r\n");
    return -1;
  }
  bool aEnabled = 0;
  aEnabled = (bool)strtol(argv[1], NULL, 10);
  otIp6SetSlaacEnabled(g_p_ot_aInstance, aEnabled);
  printf("otIp6SetSlaacEnabled is executed with aEnabled %d  \r\n", aEnabled);
}

void otIp6SetSlaacEnabled(otInstance *aInstance, bool aEnabled) {
  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6SetSlaacEnabled;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aEnabled,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  return;
}

int cli_test_otIp6SetReceiveCallback(int argc, char *argv[]) {

  void *aContext = {"otIp6SetReceiveCallback"};

  otIp6SetReceiveCallback(g_p_ot_aInstance, ncp_otIp6SetReceiveCallback,
                          aContext);
  printf("otIp6SetReceiveCallback executed with requested "
         "context %p \r\n",
         aContext);
}

static void ncp_otIp6SetReceiveCallback(otMessage *aMessage, void *aContext) {
  char buf[1500] = {0};
  int readlength;
  int getlength;
  getlength = otMessageGetLength(aMessage);
  readlength = otMessageRead(aMessage, 0, buf, sizeof(buf) - 1);
  buf[readlength] = '\0';
  printf("In callback:ncp_otIp6SetReceiveCallback context %p msg readlength %d "
         "getlength %d msg : %s \r\n",
         aContext, readlength, getlength, buf);
}

void process_otIp6SetReceiveCallback(char *response_index, int len,
                                     int eventid) {
  uint16_t getlength = 0;
  uint16_t readlength = 0;
  static otMessage *aMessage = NULL;

  int payloadsaved = 0;
  char *p_payload_param = (char *)response_index;
  otError oterror = 0;
  void *hostaContext;
  uint64_t received_aContext;

  ncp_memcpy((char *)&getlength, (p_payload_param + payloadsaved),
             sizeof(getlength), &payloadsaved);

  ncp_memcpy((char *)&readlength, (p_payload_param + payloadsaved),
             sizeof(readlength), &payloadsaved);

  aMessage = malloc(readlength + sizeof(getlength) + sizeof(readlength));
  memcpy((uint8_t *)aMessage, (uint8_t *)&getlength, sizeof(getlength));
  memcpy((uint8_t *)aMessage + sizeof(getlength), (uint8_t *)&readlength,
         sizeof(readlength));
  ncp_memcpy((char *)aMessage + sizeof(getlength) + sizeof(readlength),
             (p_payload_param + payloadsaved), readlength, &payloadsaved);

  ncp_memcpy((char *)&received_aContext, (p_payload_param + payloadsaved),
             sizeof(uint64_t), &payloadsaved);
  hostaContext = (void *)received_aContext;

  ncp_otIp6ReceiveCallbackdef = get_ptr_from_eventid(eventid);

  if (ncp_otIp6ReceiveCallbackdef != NULL) {
    ncp_otIp6ReceiveCallbackdef(aMessage, hostaContext);
  } else {
    printf("No callback function registered against this eventid %d\r\n",
           eventid);
  }

  if (aMessage != NULL) {
    free(aMessage);
  }
}

void otIp6SetReceiveCallback(otInstance *aInstance,
                             otIp6ReceiveCallback aCallback,
                             void *aCallbackContext) {

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6SetReceiveCallback;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]),
             (char *)&(aCallbackContext), sizeof(uint64_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  /*This callback value of 64 bit is saved and mapped to eventid
   * This value of cbfunc will also be stored at device side and
   * a mapping of 32 to 64 bit will be available on device side*/
  register_ptr_eventid(aCallback, NCP_EVENT_ID_OT_SET_RECEIVE_CB);
}

int cli_test_otIp6NewMessage(int argc, char *argv[]) {
  otMessage *message;
  bool mineOT_MESSAGE_PRIORITY_NORMAL = 1;
  bool minemLinkSecurityEnabled = 1;
  otMessageSettings messageSettings = {minemLinkSecurityEnabled,
                                       mineOT_MESSAGE_PRIORITY_NORMAL};
  message = otIp6NewMessage(g_p_ot_aInstance, &messageSettings);
  printf("otIp6NewMessage pointer address %p \r\n", message);
}

otMessage *otIp6NewMessage(otInstance *aInstance,
                           const otMessageSettings *aSettings) {

  uint32_t device_message;
  void *host_message = NULL;
  uint32_t ret_val;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6NewMessage;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]),
                   aSettings->mLinkSecurityEnabled, &total_tx_len);
  ncp_val_mem_copy((char *)(&ot_ncp_tx_buf[total_tx_len]), aSettings->mPriority,
                   &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(device_message), (p_payload_param + payloadsaved),
               sizeof(device_message), &payloadsaved);

    if (device_message != 0) {
      host_message = (uint8_t *)malloc(1);
      printf("host %p and dev %x\r\n", host_message, device_message);
      map_32_to_64_addr(device_message,
                        host_message); // either otip6send or otMessageFree API
                                       // shoudl remove this mapping
    }
  }

  return (otMessage *)host_message;
}

int cli_test_otIp6Send(int argc, char *argv[]) {
  otError oterror = 0;
  uint64_t *
      message; // the pointer of already created message using NCP_otMessageFree
  message = (uint64_t *)strtol(argv[1], NULL,
                               16); // assumes user enters in number base 16

  oterror = otIp6Send(g_p_ot_aInstance, (otMessage *)message);
  printf("otIp6Send return OTERROR status is %d \r\n", oterror);
}

otError otIp6Send(otInstance *aInstance, otMessage *aMessage) {
  uint32_t device_message = get_32_mapped_addr(aMessage);
  otError oterror = 0;

  int payloadsaved = 0;
  char *p_payload_param;
  int total_tx_len = 0;
  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otIp6Send;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ncp_memcpy((char *)(&ot_ncp_tx_buf[total_tx_len]), (char *)&(device_message),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  oterror = NCP_API_GET_RSP_PAYLOAD(response_index);

  remove_32_mapped_addr(aMessage); // need to remove here, irrespective of
  // messgae was sent successfully or not

  return oterror;
}

int cli_test_otLinkGetChannel(int argc, char *argv[]) {
  uint8_t ret_val;
  ret_val = otLinkGetChannel(g_p_ot_aInstance);
  printf("otLinkGetChannel is %d \r\n", ret_val);
}

uint8_t otLinkGetChannel(otInstance *aInstance) {
  uint8_t ret_val = 0;
  int total_tx_len = 0;
  char *p_payload_param;
  int payloadsaved = 0;

  int *tlv_payload = (int *)(&ot_ncp_tx_buf[total_tx_len]);
  *tlv_payload++ = (int)NCP_CMD_OPCODE_otLinkGetChannel;
  total_tx_len +=
      ((char *)tlv_payload - (char *)(&ot_ncp_tx_buf[total_tx_len]));

  char *tlv_var_payload = (char *)(&ot_ncp_tx_buf[total_tx_len]);

  // otinstnace
  uint32_t device_Instance = get_32_mapped_addr(aInstance);
  ncp_memcpy((char *)(tlv_var_payload), (char *)&(device_Instance),
             sizeof(uint32_t), &total_tx_len);

  ot_ncp_send_command(ot_ncp_tx_buf, total_tx_len);

  response_index = (uint32_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN];
  ret_val = NCP_API_GET_RSP_PAYLOAD(response_index);

  if (NCP_API_GET_RSP_ERROR(response_index) != -1) {
    p_payload_param =
        (uint8_t *)&recv_item.recv_buf[NCP_TLV_HDR_LEN + NCP_CMD_RESP_HDR_SZ];

    ncp_memcpy((char *)&(ret_val), (p_payload_param + payloadsaved),
               sizeof(uint8_t), &payloadsaved);
  }

  return ret_val;
}

/*DEbug functions*/
#ifdef DEBUG_NCP_OT
void displaychar(char *char_addr, int NoOfChar) {
  for (int i = 0; i < NoOfChar; i++) {
    printf("no.[%d] --char val %c -- char-dec-val %d\r\n", i,
           (*(char_addr + i)), *(char_addr + i));
  }
}
#endif
