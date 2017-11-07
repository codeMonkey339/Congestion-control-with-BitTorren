#include "reliable_udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "utility.h"
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>

/*
 * char *msg: the message to send to destination address
 *
 * send a message through udp procotol
 */
void send_udp_packet(char *ip, int port_no, char *msg){
    char port[PORT_LEN];
    struct addrinfo hints, *res = NULL;
    int sock;
    memset(&hints, 0, sizeof(hints));
    memset(port, 0, PORT_LEN);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    sprintf(port, "%d", port_no);
    int err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0){
      fprintf(stderr, "Failed to resolve remote socket address (err = %d)", err);
      exit(-1);
    }
    if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1){
      fprintf(stderr, "Failed to create the UDP socket");
      exit(-1);
    }
    if (sendto(sock, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen) == -1){
      fprintf(stderr, "Failed to send UDP data (err = %s) \n", strerror(errno));
      exit(-1);
    }
    return;
}


void send_udp_packet_with_sock(char *ip, int port_no, char *msg, int sock, int size){
    char port[PORT_LEN];
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    memset(port, 0, PORT_LEN);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    sprintf(port, "%d", port_no);
    int err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0){
      fprintf(stderr, "Failed to resolve remote socket address (err = %d)", err);
      exit(-1);
    }
    if (sendto(sock, msg, size, 0, res->ai_addr, res->ai_addrlen) == -1){
      fprintf(stderr, "Failed to send UDP data (err = %s) \n", strerror(errno));
      exit(-1);
    }
    return;
}

/*
  send packets of data reliably through udp protocol and a session
  this function will be invoked in 2 places:
  1. when a new GET request comes
  2. when a timeout occurs
  in both of these 2 cases, need to send all the packets from last acked.
 */
void send_udp_packet_r(udp_session *session, char *from_ip, int port,
                       int mysock, int timeout){
  if ((session->last_packet_sent - session->last_packet_acked) < DEFAULT_WINDOW_SIZE){
    char filebuf[UDP_MAX_PACK_SIZE];
    int packSize = 0;
    packet_h cur_header;
    // sending binary data?
    memset(filebuf, 0, UDP_MAX_PACK_SIZE);
    memset(&cur_header, 0, sizeof(packet_h));

    if (!timeout){/* non-timeout */
      fseek(session->f, session->chunk_index * CHUNK_LEN + (UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN) * session->last_packet_sent, SEEK_SET);
      while((session->last_packet_sent - session->last_packet_acked) < DEFAULT_WINDOW_SIZE){
        if ((packSize = fread(filebuf, 1, UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN, session->f)) > 0){
          build_header(&cur_header, 15441, 1, 3, PACK_HEADER_BASE_LEN, packSize,
                       session->last_packet_sent + 1, session->last_packet_acked);
          send_packet(from_ip, port, &cur_header, filebuf, mysock, packSize);
          session->last_packet_sent++;
          add_timer(&session->timers, from_ip, port, &cur_header, filebuf);
        }else{
          fprintf(stderr, "Failed to read packet from File descriptor %p\n", session->f);
          exit(1);
        }
      }
    }else{/* timeout */
      fseek(session->f, session->chunk_index * CHUNK_LEN + (UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN) * session->last_packet_acked, SEEK_SET);
      for (int i = session->last_packet_acked; i < session->last_packet_sent; i++){
        if ((packSize = fread(filebuf, 1, UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN, session->f)) > 0){
          build_header(&cur_header, 15441, 1, 3, PACK_HEADER_BASE_LEN, packSize,
                       i + 1, session->last_packet_acked);
          send_packet(from_ip, port, &cur_header, filebuf, mysock, packSize);
          if (i == 0){
            /* only add timer for the repeated packet */
            add_timer(&session->timers, from_ip, port, &cur_header, filebuf);
          }
        }else{
          fprintf(stderr, "Failed to read packet from File descriptor %p\n", session->f);
          exit(1);
        }
      }
    }
  }else{
    //todo: there have been enough pending packets, what todo?
  }
  return;
}


/*
  build the packet header for an udp packet
 */
void build_header(packet_h *header, int magicNo, int versionNo, int packType, int headerLen, int packLen, int seqNo, int ackNo){
  header->magicNo = magicNo;
  header->versionNo = versionNo;
  header->packType = packType;
  header->headerLen = headerLen;
  header->packLen = packLen;
  header->seqNo = seqNo;
  header->ackNo = ackNo;
  return;
}

/*
 * packet_h *header: the packet header
 * char *query: the packet body
 *
 * given the packet header & packet body, send the packet to recipient
 */
void send_packet(char *ip, int port, packet_h *header, char *query, int mysock, int body_size){
  char *msg;
  if (query != NULL){
    msg = (char*)malloc(header->headerLen + body_size);
  }else{
    msg = (char*)malloc(header->headerLen);
  }

  build_packet(header, query, msg);
  send_udp_packet_with_sock(ip, port, msg, mysock, header->headerLen + body_size);
  free(msg);
  return;
}


void build_packet(packet_h *header, char *query, char *msg){
  /* there is no endian problem for a single byte */
  uint16_t magicNo = htons(header->magicNo);
  uint16_t headerLen = htons(header->headerLen);
  uint16_t packLen = htons(header->packLen);
  uint32_t seqNo = htonl(header->seqNo);
  uint32_t ackNo = htonl(header->ackNo);
  memcpy(msg, &magicNo, 2);
  memcpy(msg + 2, &header->versionNo , 1);
  memcpy(msg + 3, &header->packType, 1);
  memcpy(msg + 4, &headerLen, 2);
  memcpy(msg + 6, &packLen, 2);
  memcpy(msg + 8, &seqNo, 4);
  memcpy(msg + 12, &ackNo, 4);
  //todo: possibly there are extended headers
  if (query != NULL){
    memcpy(msg + header->headerLen, query, strlen(query));
  }
  return;
}

/*
  check the flag array, move forward the window if possible
 */
int move_window(udp_recv_session *session, char *buf, size_t recv_size){
  size_t index;
  size_t arr_size = sizeof(session->recved_flags) /sizeof(session->recved_flags[0]);

  memcpy(session->data + session->buf_size, buf, recv_size - PACK_HEADER_BASE_LEN);
  session->buf_size += recv_size - PACK_HEADER_BASE_LEN;
  session->recved_flags[0] = 1;
  for (index = 0; index < arr_size; index++){
    if (session->recved_flags[index] == 0){
      break;
    }
  }
  if (index > 0){
    session->last_packet_acked += index;
    session->last_acceptable_frame += index;
    for (size_t i = 0; i < (arr_size - index) ; i++ ){
      session->recved_flags[i] = session->recved_flags[i + index];
    }
    for (size_t i = (arr_size - index); i < arr_size; i++){
      session->recved_flags[i] = 0;
    }
  }

  return index;
}


/*
  check whether all data packets are received
 */
int check_data_complete(vector *recv_sessions){
    int all_data_received = 1;
    /* mutiple chunks will be requested from different peers, check
       whether have received complete chunks from all of them
    */
    for (int i = 0; i < recv_sessions->len; i++){
      udp_recv_session *cur_session = (udp_recv_session*)vec_get(recv_sessions, i);
      if (!cur_session->data_complete){
        all_data_received = 0;
        break;
      }
    }
    return all_data_received;
}
