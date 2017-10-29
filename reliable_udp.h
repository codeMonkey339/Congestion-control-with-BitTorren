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

#define DEFAULT_WINDOW_SIZE 8

typedef struct udp_sender_session{
  short last_packet_acked;
  short peer_id;
  char ip[IP_STR_LEN];
  short sock;
  char *chunk_hash;
  char *data;
}udp_sender_session;

/*
  simulate a tcp-like connection session to implement reliable
  delivery and traffic control
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
  char *data;
  //char *buf; /* buffer to hold necessary sent chunks */
}udp_session;

void send_udp_packet(char *ip, int port, char *msg);
void send_udp_packet_with_sock(char *ip, int port_no, char *msg, int sock, int size);
void send_udp_packet_r(char *ip, int port, char *msg, int sock, int size);
#endif /* _RELIABLE_UDP_H */
