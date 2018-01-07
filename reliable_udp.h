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
#include "constants.h"
#include "job.h"
#include "packet_handler.h"

#define DEFAULT_WINDOW_SIZE 8

typedef struct udp_sender_session {
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
} udp_recv_session;

/*
  simulate a tcp-like connection session to implement reliable
  delivery and traffic control

  should there be a window to record the packet # that has been received?
 */
typedef struct udp_session {
    short last_packet_sent;
    short last_packet_acked;
    short peer_id;
    /* # of duplicate acknowledgements */
    short dup_ack;
    /* file pointer in case the buffer needs to be regenerated */
    FILE *f;
    /* ip address of the recipient */
    char ip[IP_STR_LEN];
    /* port of the recipient udp socket */
    short port;
    short chunk_index;
    char chunk_hash[CHUNK_HASH_SIZE];
    uint32_t sent_bytes;
    uint32_t index[DEFAULT_WINDOW_SIZE];
    /* array for recording the time of sent packets */
    time_t packets_sent_time[SS_THRESHOLD];
    /* sent_packet_timers for sent packets */
    vector sent_packet_timers;
    /* the window size of sending side */
    uint8_t send_window_size;
    /* the slow start threshold for the current connection */
    uint8_t ss_threshold;
    /* the state for the current reliable connection */
    enum CONN_STATE conn_state;
    /* the time for last window size increment */
    time_t last_wind_size_incr_time;
    /* the round trip time for the current connection */
    double rtt;
    //char *buf; /* buffer to hold necessary sent chunks */
} udp_session;


void send_udp_packet(char *ip, int port, char *msg);

void
send_udp_packet_with_sock(char *ip, int port_no, char *msg, int sock, int size);

void send_udp_packet_r(udp_session *session, char *from_ip, int port,
                       int mysock, int timeout);

void build_header(packet_h *header, int magicNo, int versionNo, int packType,
                  int headerLen, int packLen, int seqNo, int ackNo);

void send_packet(char *ip, int port, packet_m *packet, int mysock);

void build_packet(packet_h *header, char *query, char *msg, size_t query_len);

int cumulative_ack(udp_recv_session *session, handler_input *input,
                   int header_seqNo);

int check_data_complete(vector *recv_sessions, vector *queued_requests,
                        vector *data);

void build_udp_recv_session(udp_recv_session *recv_session, int peer_id, char
*chunk_hash, vector *peers);

udp_session *find_session(char *from_ip, short from_sock, vector *sessions);

udp_session *create_new_session();

void init_send_session(udp_session *send_session,
                       send_data_sessions *send_data_session,
                       ip_port_t *ip_port, size_t chunk_idx,
                       handler_input *input);

void send_udp_packet_reliable(udp_session *send_session, ip_port_t *ip_port,
                              int mysock);

udp_recv_session *find_recv_session(vector *recv_sessions, char *ip, int
port);

int udp_recv_session_exists(vector *recv_sessions, size_t peer_id);

void process_queued_up_requests(vector *queued_requests, udp_recv_session
*recv_session, job_t *job);

void free_udp_recv_session(vector *recv_sessions, udp_recv_session *
recv_session);

void ack_recv_data_packet(udp_recv_session *recv_session, job_t *job,
                          handler_input *input);

void move_send_window_forward(udp_session *send_session,
                              send_data_sessions *send_data_session,
                              handler_input *input);

void handle_duplicate_ack_packet(udp_session *send_session, handler_input *
input, send_data_sessions *send_data_session);
void copy_recv_packet_2_buf(udp_recv_session *recv_session, handler_input
*input);

void copy_chunk_2_job_buf(udp_recv_session *recv_session, job_t *job, int
chunk_to_download_id);
void remove_acked_packet_timers(udp_session *send_session, size_t ackNo);

#endif /* _RELIABLE_UDP_H */
