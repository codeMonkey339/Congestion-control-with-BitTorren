/*
 * reliable_udp.h
 * Initial Authoer: justin <justinyang339@yahoo.com>
 *
 * implements reliable communication protocol ontop of udp
 *
 * provide features similar to TCP, but implemented ontop of udp
 */


#ifndef _RELIABLE_UDP_H
#define _RELIABLE_UDP_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "utility.h"
#include "packet.h"

#define DEFAULT_WINDOW_SIZE 8

typedef struct udp_sender_session{
  short last_packet_acked;
  short last_acceptable_frame;
  short peer_id;
  char ip[IP_STR_LEN];
  short sock;
  char chunk_hash[CHUNK_HASH_SIZE];
  char *data;
  /* the size of stored data */
  int buf_size;
  uint8_t data_complete;
  /* indicate whether the packet has been received */
  short recved_flags[DEFAULT_WINDOW_SIZE];
}udp_recv_session;

/*
  simulate a tcp-like connection session to implement reliable
  delivery and traffic control

  should there be a window to record the packet # that has been received?
 */
typedef struct udp_session{
  short last_packet_sent;
  short last_packet_acked;
  short last_packet_available;
  short send_window;
  short recv_window;
  short peer_id;
  /* # of duplicate acknowledgements */
  short dup_ack;
  /* file pointer in case the buffer needs to be regenerated */
  FILE *f;
  /* ip address of the recipient */
  char ip[IP_STR_LEN];
  /* port of the recipient udp socket */
  short sock;
  char *chunk_hash;
  short chunk_index;
  char *data;
  uint32_t index[DEFAULT_WINDOW_SIZE];
  /* timers for sent packets */
  vector timers;
  //char *buf; /* buffer to hold necessary sent chunks */
}udp_session;

void send_udp_packet(char *ip, int port, char *msg);
void send_udp_packet_with_sock(char *ip, int port_no, char *msg, int sock, int size);
void send_udp_packet_r(udp_session *session, FILE *f1, char *from_ip, int port, int mysock);
void build_header(packet_h *header, int magicNo, int versionNo, int packType, int headerLen, int packLen, int seqNo, int ackNo);
void send_packet(char *ip, int port, packet_h *header, char *query, int mysock, int body_size);
void build_packet(packet_h *header, char *query, char *msg);
#endif /* _RELIABLE_UDP_H */
