/*
 * transport.c
 *
 * CPSC4510: Project 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <stdbool.h>

// Constant
const static unsigned int MAX_SEQUENCE_NUM = 255;
const static unsigned int WINDOW_SIZE = 3072;

#define STCP_HEADER_LEN 5
#define STCP_MAX_PKT_SIZE sizeof(STCPHeader) + STCP_MSS; // STCP_MSS from .h

enum
{
  CSTATE_ESTABLISHED, // establish connection
  // connect labels
  SYN_SENT,
  SYN_RECV,
  ACK_SENT,
  ACK_RECV,
  SYN_ACK_SENT,
  SYN_ACK_RECV,
  // tear down labels
  FIN_SENT,
  CSTATE_CLOSED, // close connection
};               /* you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
  bool_t done; /* TRUE once connection is closed */

  int connection_state; /* state of the connection (established, etc.) */
  tcp_seq initial_sequence_num;

  unsigned int send_seq_num;
  unsigned int recv_seq_num; // next sequence number to recieve
  unsigned int window_size;  // window size

  /* any other connection-wide global variables go here */
} context_t;

/******************************************
    Initial setup
******************************************/
static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

/*****************************************
    Connection Setup
******************************************/

// Create and Send packets function
STCPHeader *create_SYN_packet(unsigned int seq_num, unsigned int ack);
bool send_SYN(mysocket_t sd, context_t *ctx);
STCPHeader *create_SYN_ACK_packet(unsigned int seq_num, unsigned int ack);
bool send_SYN_ACK(mysocket_t sd, context_t *ctx);
STCPHeader *create_ACK_packet(unsigned int seq_num, unsigned int ack);
bool send_ACK(mysocket_t sd, context_t *ctx);

// Wait for arriving packet functions
void wait_for_SYN_ACK(mysocket_t sd, context_t *ctx);
void wait_for_ACK(mysocket_t sd, context_t *ctx);
void wait_for_SYN(mysocket_t sd, context_t *ctx);

void connection_setup(mysocket_t sd, context_t *ctx, bool is_active);

/*****************************************
    Connection Teardown
******************************************/
STCPHeader *create_FIN_packet(unsigned int seq_num, unsigned int ack);
bool send_FIN(mysocket_t sd, context_t *ctx);

/*****************************************
    Creat & Send & Parse Data Packet
******************************************/
STCPHeader *create_DATA_packet(unsigned int seq_num, unsigned int ack,
                               char *payload, size_t payload_lenght);
bool send_DATA_network(mysocket_t sd, context_t *ctx,
                       char *payload, size_t payload_length);
void send_DATA_app(mysocket_t sd, context_t *ctx,
                   char *payload, size_t payload_length);
void parse_DATA(context_t *ctx, char *payload, bool &isFin, bool &isDup);

/*****************************************
    Network and APP event
******************************************/
void app_data_event(mysocket_t sd, context_t *ctx);
void network_data_event(mysocket_t sd, context_t *ctx);
void app_close_event(mysocket_t sd, context_t *ctx);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
  context_t *ctx;

  ctx = (context_t *)calloc(1, sizeof(context_t));
  assert(ctx);

  generate_initial_seq_num(ctx);

  /* XXX: you should send a SYN packet here if is_active, or wait for one
   * to arrive if !is_active.  after the handshake completes, unblock the
   * application with stcp_unblock_application(sd).  you may also use
   * this to communicate an error condition back to the application, e.g.
   * if connection fails; to do so, just set errno appropriately (e.g. to
   * ECONNREFUSED, etc.) before calling the function.
   */
  if (is_active)
  { // client control path
    if (!send_SYN(sd, ctx))
      return;

    wait_for_SYN_ACK(sd, ctx);

    if (!send_ACK(sd, ctx))
      return;
  }
  else
  { // reciver control path
    wait_for_SYN(sd, ctx);

    if (!send_SYN_ACK(sd, ctx))
      return;

    wait_for_ACK(sd, ctx);
  }

  ctx->connection_state = CSTATE_ESTABLISHED;
  stcp_unblock_application(sd);

  control_loop(sd, ctx);

  /* do any cleanup here */
  free(ctx);
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
  assert(ctx);

#ifdef FIXED_INITNUM
  /* please don't change this! */
  ctx->initial_sequence_num = 1;
#else
  /* you have to fill this up */
  ctx->initial_sequence_num = rand() + MAX_SEQUENCE_NUM + 1;
#endif
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
  assert(ctx);
  assert(!ctx->done);

  while (!ctx->done)
  {
    if (ctx->connection_state == CSTATE_CLOSED)
    {
      ctx->done = true;
      continue;
    }

    unsigned int event;

    /* see stcp_api.h or stcp_api.c for details of this function */
    /* XXX: you will need to change some of these arguments! */
    event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    /* check whether it was the network, app, or a close request */
    if (event == APP_DATA)
      /* the application has requested that data be sent */
      /* see stcp_app_recv() */
      app_data_event(sd, ctx);

    if (event == NETWORK_DATA)
      network_data_event(sd, ctx);

    if (event == APP_CLOSE_REQUESTED)
      app_close_event(sd, ctx);

    /* etc. */
  }
}

/***********************************************
 *          Connection Setup
 ************************************************/
STCPHeader *create_SYN_packet(unsigned int seq_num, unsigned int ack)
{
  STCPHeader *SYN_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
  SYN_packet->th_seq = htonl(seq_num);
  SYN_packet->th_ack = htonl(ack);
  SYN_packet->th_off = htons(STCP_HEADER_LEN); // header size offset for packed data
  SYN_packet->th_flags = TH_SYN;               // set packet type to SYN
  SYN_packet->th_win = htons(WINDOW_SIZE);     // default value
  return SYN_packet;
}

STCPHeader *create_SYN_ACK_packet(unsigned int seq_num, unsigned int ack)
{
  STCPHeader *SYN_ACK_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
  SYN_ACK_packet->th_seq = htonl(seq_num);
  SYN_ACK_packet->th_ack = htonl(ack);
  SYN_ACK_packet->th_off = htons(STCP_HEADER_LEN); // header size offset for packed data
  SYN_ACK_packet->th_flags = (TH_SYN | TH_ACK);    // set packet type to SYN
  SYN_ACK_packet->th_win = htons(WINDOW_SIZE);     // default value
  return SYN_ACK_packet;
}

STCPHeader *create_ACK_packet(unsigned int seq_num, unsigned int ack)
{
  STCPHeader *ACK_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
  ACK_packet->th_seq = htonl(seq_num);
  ACK_packet->th_ack = htonl(ack);
  ACK_packet->th_off = htons(STCP_HEADER_LEN); // header size offset for packed data
  ACK_packet->th_flags = TH_ACK;               // set packet type to SYN
  ACK_packet->th_win = htons(WINDOW_SIZE);     // default value
  return ACK_packet;
}

bool send_SYN(mysocket_t sd, context_t *ctx)
{
  STCPHeader *packet = create_SYN_packet(ctx->initial_sequence_num, 0);
  ctx->initial_sequence_num++;

  ssize_t bytes;
  if ((bytes = stcp_network_send(sd, packet, sizeof(STCPHeader), NULL)) > 0)
  {
    ctx->connection_state = SYN_SENT;
    free(packet);
    return true;
  }
  else
  {
    free(packet);
    free(ctx);
    errno = ECONNREFUSED;
    return false;
  }
}

bool send_SYN_ACK(mysocket_t sd, context_t *ctx)
{
  STCPHeader *packet = create_SYN_ACK_packet(ctx->initial_sequence_num, ctx->recv_seq_num + 1);
  ctx->initial_sequence_num++;

  ssize_t bytes;
  if ((bytes = stcp_network_send(sd, packet, sizeof(STCPHeader), NULL)) > 0)
  {
    ctx->connection_state = SYN_ACK_SENT;
    free(packet);
    return true;
  }
  else
  {
    free(packet);
    free(ctx);
    stcp_unblock_application(sd);
    errno = ECONNREFUSED;
    return false;
  }
}

bool send_ACK(mysocket_t sd, context_t *ctx)
{
  STCPHeader *packet = create_ACK_packet(ctx->initial_sequence_num, ctx->recv_seq_num + 1);

  ssize_t bytes;
  if ((bytes = stcp_network_send(sd, packet, sizeof(STCPHeader), NULL)) > 0)
  {
    ctx->connection_state = ACK_SENT;
    free(packet);
    return true;
  }
  else
  {
    free(packet);
    free(ctx);
    errno = ECONNREFUSED;
    return false;
  }
}

void wait_for_SYN_ACK(mysocket_t sd, context_t *ctx)
{
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t bytes;
  if ((bytes = stcp_network_recv(sd, buffer, STCP_MSS)) < sizeof(STCPHeader))
  {
    free(ctx);
    errno = ECONNREFUSED;
    return;
  }

  STCPHeader *packet = (STCPHeader *)buffer;
  if ((packet->th_flags = (TH_SYN | TH_ACK)))
  {
    ctx->recv_seq_num = ntohl(packet->th_seq);
    ctx->window_size = ntohs(packet->th_win) > 0 ? ntohs(packet->th_win) : 1;
    ctx->connection_state = SYN_ACK_RECV;
  }
}

void wait_for_ACK(mysocket_t sd, context_t *ctx)
{
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t bytes;
  if ((bytes = stcp_network_recv(sd, buffer, STCP_MSS)) < sizeof(STCPHeader))
  {
    free(ctx);
    errno = ECONNREFUSED;
    return;
  }

  STCPHeader *packet = (STCPHeader *)buffer;
  if (packet->th_flags == TH_ACK)
  {
    ctx->recv_seq_num = ntohl(packet->th_seq);
    ctx->window_size = ntohs(packet->th_win) > 0 ? ntohs(packet->th_win) : 1;
    // // ctx->connection_state = ACK_RECV;
    // if (ctx->connection_state == FIN_SENDER_SENT)
    // 	ctx->connection_state == FIN_RECV_SENT;
    if (ctx->connection_state == FIN_SENDER_SENT)
      ctx->connection_state = CSTATE_CLOSED;
  }
}
void wait_for_SYN(mysocket_t sd, context_t *ctx)
{
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t bytes;
  if ((bytes = stcp_network_recv(sd, buffer, STCP_MSS)) < sizeof(STCPHeader))
  {
    free(ctx);
    errno = ECONNREFUSED;
    return;
  }

  STCPHeader *packet = (STCPHeader *)buffer;
  if (packet->th_flags == TH_SYN)
  {
    ctx->recv_seq_num = ntohl(packet->th_seq);
    ctx->window_size = ntohs(packet->th_win) > 0 ? ntohs(packet->th_win) : 1;
    ctx->connection_state = SYN_RECV;
  }
}

void connection_setup(mysocket_t sd, context_t *ctx, bool is_active)
{
  if (is_active)
  { // client control path
    ctx->initial_sequence_num = 1;
    if (!send_SYN(sd, ctx))
      return;

    wait_for_SYN_ACK(sd, ctx);

    if (!send_ACK(sd, ctx))
      return;
  }
  else
  { // reciver control path
    ctx->initial_sequence_num = 101;
    wait_for_SYN(sd, ctx);

    if (!send_SYN_ACK(sd, ctx))
      return;

    wait_for_ACK(sd, ctx);
  }
}

/*****************************************
    Connection Teardown
******************************************/
STCPHeader *create_FIN_packet(unsigned int seq_num, unsigned int ack)
{
  STCPHeader *FIN_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
  FIN_packet->th_seq = htonl(seq_num);
  FIN_packet->th_ack = htonl(ack);
  FIN_packet->th_flags = TH_FIN;
  FIN_packet->th_win = htons(WINDOW_SIZE);
  FIN_packet->th_off = htons(STCP_HEADER_LEN);
  return FIN_packet;
}
bool send_FIN(mysocket_t sd, context_t *ctx)
{
  STCPHeader *packet = create_FIN_packet(ctx->initial_sequence_num, ctx->recv_seq_num + 1);
  ctx->initial_sequence_num++;

  ssize_t bytes;
  if ((bytes = stcp_network_send(sd, packet, sizeof(STCPHeader), NULL)) > 0)
  {
    ctx->connection_state = FIN_SENT;
    wait_for_ACK(sd, ctx);
    free(packet);
    return true;
  }
  else
  {
    free(packet);
    free(ctx);
    errno = ECONNREFUSED;
    return false;
  }
}

/***********************************************
 *          Data
 ************************************************/
STCPHeader *create_DATA_packet(unsigned int seq_num, unsigned int ack,
                               char *payload, size_t payload_length)
{
  unsigned int packet_size = sizeof(STCPHeader) + payload_length;

  STCPHeader *packet = (STCPHeader *)malloc(packet_size);
  packet->th_seq = htonl(seq_num);
  packet->th_ack = htonl(ack);
  packet->th_off = htons(STCP_HEADER_LEN);
  packet->th_win = htons(WINDOW_SIZE);
  packet->th_flags = NETWORK_DATA;

  memcpy((char *)packet + sizeof(STCPHeader), payload, payload_length);
  return packet;
}
bool send_DATA_network(mysocket_t sd, context_t *ctx,
                       char *payload, size_t payload_length)
{
  STCPHeader *packet = create_DATA_packet(ctx->initial_sequence_num,
                                          ctx->recv_seq_num + 1, payload, payload_length);
  ctx->initial_sequence_num += payload_length;

  ssize_t bytes;
  if ((bytes = stcp_network_send(sd, packet, sizeof(STCPHeader) + payload_length, NULL)) > 0)
  {
    free(packet);
    return true;
  }
  else
  {
    free(packet);
    free(ctx);
    errno = ECONNREFUSED;
    return false;
  }
}
void send_DATA_app(mysocket_t sd, context_t *ctx,
                   char *payload, size_t payload_length)
{
  stcp_app_send(sd, payload + sizeof(STCPHeader), payload_length - sizeof(STCPHeader));
}

void parse_DATA(context_t *ctx, char *payload, bool &isFin, bool &isDup)
{
  STCPHeader *data = (STCPHeader *)payload;
  ctx->recv_seq_num = ntohl(data->th_seq);
  ctx->window_size = ntohs(data->th_win);
  isFin = data->th_flags == TH_FIN;
}

/*****************************************
    Network and APP event
******************************************/
void app_data_event(mysocket_t sd, context_t *ctx)
{
  unsigned int length = (STCP_MSS < ctx->recv_seq_num) ? STCP_MSS : ctx->recv_seq_num;
  size_t max_payload_length = length - sizeof(STCPHeader);

  char payload[max_payload_length];
  ssize_t bytes;
  if ((bytes = stcp_app_recv(sd, payload, max_payload_length)) == 0)
  {
    free(ctx);
    errno = ECONNREFUSED;
    return;
  }

  send_DATA_network(sd, ctx, payload, bytes);
  wait_for_ACK(sd, ctx);
}

void network_data_event(mysocket_t sd, context_t *ctx)
{
  bool isFin = false;
  bool isDup = false;
  char payload[STCP_MSS];

  ssize_t bytes;
  if ((bytes = stcp_network_recv(sd, payload, STCP_MSS)) < (long unsigned int)sizeof(STCPHeader))
  {
    free(ctx);
    errno = ECONNREFUSED;
    return;
  }

  parse_DATA(ctx, payload, isFin, isDup);
  if (isDup)
  {
    send_ACK(sd, ctx);
    return;
  }

  if (isFin)
  {
    send_ACK(sd, ctx);
    stcp_fin_received(sd);
    ctx->connection_state = CSTATE_CLOSED;
  }
}

void app_close_event(mysocket_t sd, context_t *ctx)
{
  if (ctx->connection_state == CSTATE_ESTABLISHED)
    send_FIN(sd, ctx);
  printf("connection_state: %d\n", ctx->connection_state);
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format, ...)
{
  va_list argptr;
  char buffer[1024];

  assert(format);
  va_start(argptr, format);
  vsnprintf(buffer, sizeof(buffer), format, argptr);
  va_end(argptr);
  fputs(buffer, stdout);
  fflush(stdout);
}