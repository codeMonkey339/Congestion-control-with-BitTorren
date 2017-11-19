/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 * Implemented by Justin: justinyang339@yahoo.com
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "utility.h"
#include <ctype.h>
#include "reliable_udp.h"
#include <netdb.h>
#include <errno.h>
#include "packet.h"
#include <math.h>
#include "packet.h"




#define DEFAULT_CHUNK_SIZE 10

//#define CHUNK_HASH_SIZE 20 /* keep hash in string format */

#define CHUNK_NUM_PER_PACK ((UDP_MAX_PACK_SIZE - strlen("whohas") - sizeof(int)) / CHUNK_HASH_SIZE)


void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
  bt_config_t config;

  bt_init(&config, argc, argv);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
  config.identity = 1; // your group number here
  strcpy(config.chunk_file, "chunkfile");
  strcpy(config.has_chunk_file, "haschunks");
#endif

  bt_parse_command_line(&config);

#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&config);
  }
#endif

  peer_run(&config);
  return 0;
}

/*
  last_packet_sent: should be initialized to 0
  last_packte_acked: should be intialized to 0
  last_packet_available: should be initialized to 0

  actual data packet number will start from 1
 */
void init_session(udp_session *session, short send_window, short recv_window, int peer_id, short dup_ack, FILE *f, char *from_ip, short port){
  session->last_packet_sent = 0;
  session->last_packet_acked = 0;
  session->last_packet_available = 0;
  session->send_window = send_window;
  session->recv_window = recv_window;
  session->peer_id = peer_id;
  session->dup_ack = dup_ack;
  session->f = f;
  strcpy(session->ip, from_ip);
  session->sock = port;
  session->sent_bytes = 0;
  for (uint32_t i = 0; i < sizeof(session->index)/sizeof(uint32_t); i++){
    session->index[i] = 0;
  }
  init_vector(&session->timers, sizeof(timer));
  return;
}

/*
  vector *sender_sessions: the vector to store all the current sessions
  char *ip: the ip address of the incoming message

  identify the sender session that store the current reliabel communication
 */
udp_recv_session *find_recv_session(vector *recv_sessions, char *ip, int sock){
  for (int i = 0; i < recv_sessions->len; i++){
    udp_recv_session *recv_session = (udp_recv_session*)vec_get(recv_sessions, i);
    if (!strcmp(recv_session->ip, ip) && recv_session->sock == sock){
      return recv_session;
    }
  }
  return NULL;
}


/*
 * peers_t *peers: a pointer to all peers
 * int idx: the index of the queries peer
 *
 * given a peer index, this function will return the information about that peer
 */
peer_info_t *get_peer_info(peers_t *peers, int idx){
  peer_info_t *p;
  for (int i = 0; i < peers->peer.len ;i++){
    p = (peer_info_t*)vec_get(&peers->peer, i);
    if (p->id == idx){
      break;
    }
  }
  return p;
}

/*
  find the peer information based on given ip & sock
 */
peer_info_t *find_peer_from_list(peers_t *peers, char *ip, int sock){
  peer_info_t *p;
  for (int i = 0; i < peers->peer.len; i++){
    p = (peer_info_t*)vec_get(&peers->peer, i);
    if (!strcmp(ip, p->ip) && sock == p->port){
      return p;
    }
  }
  return NULL;
}


/*
 * bt_config_t *config: the config struct
 * char *chunk_msg: the chunk hash
 * int peer_idx: index of the peer
 * vector *chunk_data: the vector that will hold chunk data
 */
int request_chunk(bt_config_t *config, char *chunk_msg, int peer_idx, int force){
  packet_h header;
  char *query = (char*)malloc(strlen("GET") + CHUNK_HASH_SIZE + 2), *packet;
  int timer_exists = 0;
  memset(query, 0, strlen("GET") + CHUNK_HASH_SIZE + 2);
  strcat(query, "GET ");
  strcat(query, chunk_msg);
  build_header(&header, 15441, 1, 2, PACK_HEADER_BASE_LEN, PACK_HEADER_BASE_LEN + strlen(query), 0, 0);
  packet = (char*)malloc(PACK_HEADER_BASE_LEN + strlen(query));
  peer_info_t *peer = get_peer_info(config->peer, peer_idx);
  send_packet(peer->ip, peer->port, &header, query, config->mysock, strlen(query));

  for (int i = 0;i < config->get_timers.len; i++){
    timer *t = (timer*)vec_get(&config->get_timers, i);
    if (!strcmp(t->ip, peer->ip) && t->sock == peer->port){
      timer_exists = 1;
      break;
    }
  }
  if (force){ // force request for the chunk
    timer_exists = 0;
  }
  if (timer_exists){ // queue up the message
    request_t r;
    strcpy(r.ip, peer->ip);
    r.port = peer->port;
    strcpy(r.chunk, query);
    vec_add(&config->request_queue, &r);
  }else{
    //todo: need to handle timeout situation
    add_timer(&config->get_timers, peer->ip, peer->port, NULL, query);
  }
  free(query);
  free(packet);
  return timer_exists;
}

/*
 * FILE *f: file pointer to file which will be read from
 * vector *v: a vector pointer which will hold read chunk hashes
 */
void read_chunk(FILE *f, vector *v){
  char *token, *line = NULL;
  size_t line_len;

  while(getline(&line, &line_len, f) != -1){
    token = strtok(line, " ");
    if (isdigit(token[0])){
      token = strtok(NULL, " ");
      if (token[strlen(token) -1] == '\n'){
        token[strlen(token) -1] = '\0';
      }
      vec_add(v, token);
    }else{
      /* skip the current line */
      fprintf(stdout, "Comment line in chunk file\n");
    }
    free(line); // memory is dynamically allocated in getline
    line = NULL;
    line_len = 0;
  }
  return;
}

/*
  todo:
  release all the memories occupies by timers
 */
void release_all_timers(bt_config_t *config){
  vector *whohas = &config->whohas_timers;
  for (int i = 0; i < whohas->len; i++){
    timer *t = vec_get(whohas, i);
    free(t->msg);
    free(vec_get(whohas, i));
  }
  return;
}


void release_all_dynamic_memory(bt_config_t *config){
  /* free all the ihave messages */
  for (int i = 0; i < config->ihave_msgs.len; i++){
    ihave_t *ihave = vec_get(&config->ihave_msgs, i);
    free(ihave->msg);
    for (int j = 0; j < ihave->chunk_num; j++){
      free(ihave->chunks[j]);
    }
    free(ihave->chunks);
    free(ihave);
  }

  return;
}


/*
 * the REPLY message is in the format: "IHAVE 2 000...015
 * 0000...00441"
 *
 * todo: the reply_builder could be made more general
 */
char *build_ihave_reply(char *reply, int num){
  int buf_len = strlen(reply) + sizeof(num) + strlen("ihave") + 3;
  char *res = (char*)malloc(buf_len);
  memset(res, 0, buf_len);
  strcat(res, "IHAVE ");
  sprintf(res + strlen(res), "%d ", num);
  strcat(res, reply);
  return res;
}

/*
 * handle whohas message from peers
 * check whether the chunks exist in itw own has_chunk_file, if so
 * then replies the IHAVE message, otherwise there is no reply
 *
 * Assume the maximum packet size for UDP is 1500 bytes. The peer must
 * split the list into multiple WHOHAS queries if the list is too
 * large for a single packet. It is assumed that all IHAVE messages
 * will have sizes less than 1500 byte
 *
 * the REPLY message is in the format: "IHAVE 2 000...015 0000...00441"
 */
void process_whohas(int sock, char *buf, struct sockaddr_in from, socklen_t fromlen, int BUFLEN, bt_config_t *config, packet_h *header){
  //todo: need to send message correctly
  FILE *f;
  char *token, *reply = (char*)malloc(BUFLEN), ip[IP_STR_LEN];
  vector v;
  int chunks_num, reply_len = 0, hash_len = 0, buf_size = BUFLEN, has_num = 0, port;
  if ((f = fopen(config->has_chunk_file, "r")) == NULL){
    fprintf(stderr, "Error opening the has_chunk_file %s\n", config->has_chunk_file);
    exit(1);
  }
  init_vector(&v, CHUNK_HASH_SIZE);
  read_chunk(f, &v);
  token = strtok(buf, " ");
  token = strtok(NULL, " ");
  chunks_num = atoi(token);
  memset(reply, 0, BUFLEN);

  /* don't have to use the packet length here, chunks_num is enough */
  while(chunks_num-- > 0){
    token = strtok(NULL, " "); /* get a new chunk hash, token is null terminated? */
    for (int i = 0; i < v.len; i++){
      char *msg = vec_get(&v, i);
      if (strstr(msg, token) != NULL){
        /* strtok will replace ' ' with '\0' */
        hash_len = strlen(token);
        if ((reply_len + hash_len) >= buf_size){
          reply = (char*)realloc(reply, 2 * buf_size);
        }
        strcat(reply, vec_get(&v, i));
        strcat(reply, " ");
        has_num++;
        break;
      }
    }
  }
  char *reply_msg = build_ihave_reply(reply, has_num);
  memset(ip, 0, IP_STR_LEN);
  inet_ntop(AF_INET, &(from.sin_addr), ip, IP_STR_LEN);
  port = ntohs(from.sin_port);
  packet_h reply_header;
  build_header(&reply_header, 15441, 1, 1, PACK_HEADER_BASE_LEN, PACK_HEADER_BASE_LEN + strlen(reply_msg), 0, 0);
  send_packet(ip, port, &reply_header, reply_msg, config->mysock, strlen(reply_msg));
  free(reply);
  free(reply_msg);
  return;
}


/*
  this function is a comparator to sort chunk_dis struct
 */
int chunks_dis_cmp(chunk_dis *dis1, chunk_dis *dis2){
  if (dis1->idx.len > dis2->idx.len){
    return 1;
  }else if (dis1->idx.len < dis2->idx.len){
    return -1;
  }else{
    return 0;
  }
}


/*
  initialize the various fields of the sender session
 */
void build_udp_recv_session(udp_recv_session *session, int peer_id, char *chunk_hash, bt_config_t *config){
  peer_info_t *peer = get_peer_info(config->peer, peer_id);
  session->last_packet_acked = 0;
  session->last_acceptable_frame = session->last_packet_acked + DEFAULT_WINDOW_SIZE;
  session->peer_id = peer_id;
  strcpy(session->ip, peer->ip);
  session->sock = peer->port;
  strcpy(session->chunk_hash, chunk_hash);
  session->data = (char*)malloc(CHUNK_LEN);
  session->data_complete = 0;
  for (int i = 0; i < sizeof(session->recved_flags) * 1.0 / sizeof(session->recved_flags[0]); i++){
    session->recved_flags[i] = 0;
  }
  return;
}

/*
 * Have collected replies from all peers. Need to send GET messages to
 * corresponding peers based on scarcity
 *
 * The DATA packets need to employ reliable tranfer, so everything will completed here
 *
 * Notes:
 * once a command line request is processed, all dynamically allocated
 * resources should be released
 *
 * Bittorrent user a "rarest-chunk-first" heuristic where it tries to
 * fetch the rarest chunk first. The peer can download/upload 4
 * different chunks at the same time
 */
void send_get_queries(bt_config_t *config, vector *ihave_msgs){
  vector chunks;
  init_vector(&chunks, sizeof(chunk_dis));

  /* loop through peers to collect distribution of chunks */
  for (int i = 0; i < config->desired_chunks.len; i++){
    char *chunk = vec_get(&config->desired_chunks, i);
    chunk_dis chunk_info;
    init_vector(&chunk_info.idx, sizeof(short));
    strcpy(chunk_info.msg, chunk);
    for (int j = 0; j < ihave_msgs->len; j++){
      ihave_t *ihave = (ihave_t*)vec_get(ihave_msgs, j);
      for (int k = 0; k < ihave->chunk_num; k++){
        char *chunk_have = ihave->chunks[k];
        if (!strcmp(chunk, chunk_have) || strstr(chunk, chunk_have) != NULL){
          vec_add(&chunk_info.idx, &ihave->idx);
          break;
        }
      }
    }
    vec_add(&chunks, &chunk_info);
  }
  //todo: need to complete the sorting function
  vec_sort(&chunks, chunks_dis_cmp);
  time_t t;
  srand((unsigned)time(&t));
  for (int i = 0; i < chunks.len ;i++){
    chunk_dis *chunk_info = (chunk_dis*)vec_get(&chunks, i);
    char *chunk_msg = chunk_info->msg;
     /*
      naive implementation here, randomly pick a peer from the list
    */
    int idx = rand() % chunk_info->idx.len;
    int peer_idx = *(short*)vec_get(&chunk_info->idx, idx);
    udp_recv_session *session = (udp_recv_session*)malloc(sizeof(udp_recv_session));
    build_udp_recv_session(session, peer_idx, chunk_msg, config);
    if(!request_chunk(config, chunk_msg, peer_idx, 0))
      vec_add(&config->recv_sessions, session);
  }

  /* cleanup dynamic memory */
  for (int i = 0; i < chunks.len; i++){
    vec_free(&((chunk_dis*)vec_get(&chunks, i))->idx);
  }
  vec_free(&chunks);
  //release_all_timers(config);
  //release_all_dynamic_memory(config);
  return;
}


/*
  make the functio more generic?
 */
void remove_timer(vector *cur_timer, char *ip, int sock){
  timer *t;
  for (int i = 0; i < cur_timer->len; i++){
    t = (timer*)vec_get(cur_timer, i);
    if (!strcmp(t->ip, ip) && t->sock == sock){
      t->start = -1; /* only need to reset the start time */
      break;
    }
  }
  return;
}


/*
 *  char *buf: the incoming message has been read and stored in this
 *
 *  process IHAVE message from a peer.
 *
 *  BitTorrent uses a "rarest-chunk-first" heuristic where it tries to
 *  fetch the rarest chunk first.
 *
 *
 *  format of the IHAVE message: "IHAVE 2 0000...015 0000..00441"
 *
 *  Edge case:
 *  what if for a certain chunk, none of the peers owning it replies.
 *
 */
void process_ihave(int sock, char *buf, struct sockaddr_in from,
                   socklen_t fromlen, int BUFLEN, bt_config_t *config, vector *ihave_msgs, packet_h *header){
  //todo: what if receive the reply after time out? check whether has received from the peer
  char *token, *ip, peer_idx, *next_space, *buf_backup;
  int ihave_nums;

  ip = inet_ntoa(from.sin_addr);
  /* get the peer_id of the incoming packet */
  for (int i = 0; i < config->peer->peer.len; i++){
    peer_info_t *peer = (peer_info_t*)vec_get(&config->peer->peer, i);
    if (!strcmp(ip, peer->ip)){
      peer_idx = peer->id;
      break;
    }
  }

  /* parse the IHAVE reply message */
  buf_backup = (char*)malloc(strlen(buf) + 1);
  strcpy(buf_backup, buf);
  token = strtok(buf, " ");
  token = strtok(NULL, " ");
  ihave_nums = atoi(token);
  ihave_t *ihave = (ihave_t*)malloc(sizeof(ihave_t));
  ihave->chunk_num = ihave_nums;
  ihave->msg = (char*)malloc(strlen(buf_backup) + 1);
  strcpy(ihave->msg, buf_backup);
  ihave->chunks = (char**)malloc(sizeof(char*) * ihave_nums);
  ihave->idx = peer_idx;
  for (int i = 0; i < ihave_nums; i++){
    token = strtok(NULL, " ");
    ihave->chunks[i] = (char*)malloc(strlen(token) + 1);
    strcpy(ihave->chunks[i], token);
  }
  vec_add(ihave_msgs, ihave);
  remove_timer(&config->whohas_timers, ip, sock);
  /* have received the replies from all peers */
  if (ihave_msgs->len == config->desired_chunks.len){
    send_get_queries(config, ihave_msgs);
  }
  free(buf_backup);
  return;
}

/*
  lookg for a session based on from_ip and from_sock,
 */
udp_session *find_session(char *from_ip, short from_sock, vector *sessions){
  udp_session *session = NULL;
  for (int i = 0; i < sessions->len; i++){
    udp_session *cur_session = (udp_session*)vec_get(sessions, i);
    if (!strcmp(cur_session->ip, from_ip) && from_sock == cur_session->sock){
      session = cur_session;
      break;
    }
  }
  return session;
}

int find_chunk_idx(char *chunk, char *chunk_file, char *masterfile){
  FILE *f;
  char *line, line_backup[BT_FILENAME_LEN], *t;
  size_t line_len = 0;
  int idx, chunk_idx;
  if ((f = fopen(chunk_file, "r")) == NULL){
    fprintf(stderr, "Failed to open chunk file %s\n", chunk_file);
    exit(1);
  }
  while(getline(&line, &line_len, f) != -1){
    memset(line_backup, 0, BT_FILENAME_LEN);
    strcpy(line_backup, line);
    t = strtok(line_backup, " ");
    if (!isdigit(*t)){ /* the first line */
      t = strtok(NULL, " ");
      memset(masterfile, 0, BT_FILENAME_LEN);
      strcpy(masterfile, t);
      t = strtok(NULL, " "); /* there is a remaining hash line */
      if (t != NULL){
        idx = *(int*)t;
        t = strtok(NULL, " ");
        if (!strcmp(t, chunk) || strstr(t, chunk) != NULL){
          chunk_idx = idx;
          free(line);
          break;
        }
      }
    }else{ /* chunk hash line */
      idx = atoi(t);
      t = strtok(NULL, " ");
      if (!strcmp(t, chunk) || strstr(t, chunk) != NULL){
        chunk_idx = idx;
        free(line);
        break;
      }
    }
    free(line);
    line = NULL;
    line_len = 0;
  }
  return chunk_idx;
}


/*
  need to send DATA packet through reliable communication

  Chunk File: i.e c.masterchunks
  File: <path to the file which neeeds sharing>
  Chunks:
  id chunk-hash

  How to handle acknolwegement packet?
  main a session for each peer, extract sending data packet into a new function.

  the sequence number always starts with 1 for a new "GET" connection
  should not combine DATA packet and ACK packet. A DATA packet should
  not contain ACK, and vice versa

  GET packets don't have to be transmitted through reliabe
  transmission

  Each peer can only have 1 simultaneous download from any other peer
  in the network, meaning that IP address and UDP port will uniquely
  determine which download a DATA packet belongs to --> save the
  trouble demultiplexing packets!

  todo:
  1. what to do if no slot within the window?
*/
void process_peer_get(int sock, char *buf, struct sockaddr_in from,
                      socklen_t fromlen, int BUFLEN,
                      bt_config_t *config, packet_h *header){
  FILE *f1;
  char *buf_backup = (char*)malloc(strlen(buf) + 1), *token, masterfile[BT_FILENAME_LEN], *from_ip;
  int chunk_idx;
  udp_session *session = NULL;
  short port = ntohs(from.sin_port);
  memset(buf_backup, 0, strlen(buf) + 1);
  strcpy(buf_backup, buf);
  from_ip = inet_ntoa(from.sin_addr);
  short session_exist = 1;

  if ((session = find_session(from_ip, port, &config->sessions)) == NULL){
    session = (udp_session*)malloc(sizeof(udp_session));
    memset(session, 0, sizeof(udp_session));
    session_exist = 0;
  }else{
    /*
      todo:
      should accept only 1 simultaneous connection from a particular host
      send a DENIED packet
     */
    free(buf_backup);
    return;
  }

  token = strtok(buf_backup, " ");
  token = strtok(NULL, " "); /* token pointers to chunk hash */
  chunk_idx = find_chunk_idx(token, config->chunk_file, masterfile);
  if ((f1 = fopen(masterfile, "r")) == NULL){
    fprintf(stderr, "Cannot open master chunk file %s \n", masterfile);
    exit(1);
  }
  // debug purpose
  uint32_t offset = chunk_idx * CHUNK_LEN;
  char *buffer = (char*)malloc(CHUNK_LEN);
  fseek(f1, offset, SEEK_SET);
  fread(buffer, 1, CHUNK_LEN, f1);
  char *new_chunk_hash = get_chunk_hash(buffer, CHUNK_LEN);
  if (strcmp(new_chunk_hash, token)){
    fprintf(stderr, "unmatched hash, %s\n", new_chunk_hash);
  }
  if (session->f== NULL){ // init session struct
    init_session(session, 8, 8, config->identity, 0, f1, from_ip, port);
  }
  session->chunk_index = chunk_idx;
  send_udp_packet_r(session, from_ip, port, config->mysock, 0);
  if (!session_exist){
    vec_add(&config->sessions, session);
    free(session);
  }
  return;
}

/*
  Based on acknowledgements from peers, take next step actions
*/
void process_ack(int sock, char *buf, struct sockaddr_in from, socklen_t fromLen,
                 int BUFLEN, bt_config_t *config, packet_h *header){
  char *from_ip = inet_ntoa(from.sin_addr), file_buf[UDP_MAX_PACK_SIZE];
  short port = ntohs(from.sin_port);
  memset(file_buf, 0, UDP_MAX_PACK_SIZE);
  udp_session *session = find_session(from_ip, port, &config->sessions);
  if (header->ackNo == (uint32_t)(session->last_packet_acked + 1)){
    session->last_packet_acked++;
    session->dup_ack = 0;
    if (session->sent_bytes >= CHUNK_LEN){
      if (session->last_packet_acked == session->last_packet_sent){
        vec_delete(&config->sessions, session);
      }
    }else{
      fseek(session->f, session->chunk_index * CHUNK_LEN + header->ackNo * (UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN), SEEK_SET);
      send_udp_packet_r(session, from_ip, port, config->mysock, 0);
    }
  }else if (header->ackNo == (uint32_t)(session->last_packet_sent)){
    /* current repeat times is 5 */
    session->dup_ack++;
    if (session->dup_ack > 5){
      // todo: the peer is crashes, how to recover?
    }else{
      fseek(session->f, session->chunk_index * CHUNK_LEN + session->last_packet_acked * (UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN), SEEK_SET);
      send_udp_packet_r(session, from_ip, port, config->mysock, 1);
    }
  }
  return;
}

/*
 impl notes:
 3. if received all chunks, need to create a new file
 5. need to release dynamic memeory like config->udp_sender_session
 */
void process_data(int sock, char *buf, struct sockaddr_in from, socklen_t fromLen,
                  int BUFLEN, bt_config_t *config, packet_h *header, int recv_size){
  static int counter = 0;
  vector *recv_sessions = &config->recv_sessions;
  char *ip = inet_ntoa(from.sin_addr);
  int port = ntohs(from.sin_port);
  udp_recv_session *session;
  size_t forward_n = 0;
  if ((session = find_recv_session(recv_sessions, ip, port)) == NULL){
    fprintf(stderr, "Cannot find stored session for ip %s & port %d\n", ip, port);
    return;
  }
  packet_h curheader;
  if ((short)header->seqNo <= session->last_packet_acked || (short)header->seqNo >
      session->last_acceptable_frame){
    fprintf(stdout, "Received a stray packet out of the current window\n");
    return;
  }
  if ((session->last_packet_acked + 1) == (short)header->seqNo){
    //debug purpse
    char *packet_hash = get_chunk_hash(buf, recv_size - PACK_HEADER_BASE_LEN);
    fprintf(stdout, "packet hash is %s\n", packet_hash);
    free(packet_hash);
    forward_n = move_window(session, buf, recv_size, header->seqNo);
    build_header(&curheader, 15441, 1, 4, PACK_HEADER_BASE_LEN, 0, 0, session->last_packet_acked);
  }else{
    build_header(&curheader, 15441, 1, 4, PACK_HEADER_BASE_LEN, 0, 0, session->last_packet_acked);
    if ((uint32_t)session->last_packet_acked < header->seqNo){
      // assume: every packet is of the fixed size???
      memcpy(session->data + (UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN) *
             (header->seqNo - 1), buf, recv_size - PACK_HEADER_BASE_LEN );
      session->buf_size += recv_size - PACK_HEADER_BASE_LEN;
      session->recved_flags[header->seqNo - session->last_packet_acked - 1] = 1;
    }
  }
  /* send ACK packet */
  send_packet(ip, port, &curheader, NULL, config->mysock, 0);
  if (recv_size >= UDP_MAX_PACK_SIZE){
    // more packets to go
  }else{
    session->data_complete = 1;
    vector *data = &config->data;
    for (int i = 0; i < data->len; i++){
      data_t *d = (data_t*)vec_get(data, i);
      if (!strcmp(d->chunk_hash, session->chunk_hash)){
        char *chunk_hash = get_chunk_hash(session->data, CHUNK_LEN);
        if (!strcmp(chunk_hash, session->chunk_hash)){
          d->data = (char*)malloc(CHUNK_LEN);
          memcpy(d->data, session->data, CHUNK_LEN);
          fprintf(stdout,"The hash of received data matches with chunk hash\n");
        }else{
          //todo: need to build a recovery mechanism in corrupted data
          fprintf(stdout, "Corrupted chunk data receied due to unmatched hash\n");
        }
        free(chunk_hash);
        break;
      }
    }
    if (check_data_complete(recv_sessions, &config->request_queue, &config->data)){
      FILE *newfile;
      if ((newfile = fopen(config->output_file, "w")) == NULL){
        fprintf(stderr, "Failed to create the new file %s\n", config->output_file);
        exit(1);
      }
      for (int i = 0; i < config->data.len; i++){
        data_t *d = vec_get(&config->data, i);
        fwrite(d->data, 1, CHUNK_LEN, newfile);
      }
    }else{
      vector *queued_requests = &config->request_queue;
      char *token;
      // check for queued_up requests and process it
      for (int i = 0; i < queued_requests->len; i++){
        request_t *r = vec_get(queued_requests, i);
        if (!strcmp(r->ip, ip) && port == r->port){
          token = strtok(r->chunk, " ");
          token = strtok(NULL, " ");
          udp_recv_session *new_session = (udp_recv_session*)malloc(sizeof(udp_recv_session));
          peer_info_t *peer = find_peer_from_list(config->peer, ip, port);
          build_udp_recv_session(new_session, peer->id, token, config);
          if(!request_chunk(config, token, peer->id, 1))
            vec_add(&config->recv_sessions, new_session);
          vec_delete(queued_requests, r);
          free(new_session);
        }
      }
    }
    vec_delete(recv_sessions, session);
  }
  counter++;
  return;
}

/**
 * entry point to process inbound udp packets, different types of packets
 * will handled separately
 * @param sock the socket that the current packet is received from
 * @param config config file of the current peer
 */
void process_inbound_udp(int sock, bt_config_t *config) {
  /* can write #define everywhere since the preprocessor is not aware of the
   * program */
  #define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN], *buf_backup, *token, *buf_backup_ptr;
  int recv_size = 0;

  memset(buf, 0, BUFLEN);
  fromlen = sizeof(from);
  recv_size = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)
          &from, &fromlen);
  if ((buf_backup = (char*)malloc(BUFLEN)) == NULL){
    fprintf(stderr, "malloc failed in process_inbound_upd\n");
    return;
  }
  memcpy(buf_backup, buf, BUFLEN);
  buf_backup_ptr = buf_backup;
  packet_h* header = parse_packet(&buf_backup);
  if (header == NULL){
    fprintf(stderr, "Have received an invalid packet \n");
    return;
  }
  //todo: C support native enum, replace here
  if (header->packType == 0){
    process_whohas(sock, buf + header->headerLen, from, fromlen, BUFLEN,
                   config, header);
  }else if (header->packType == 1){
    process_ihave(sock, buf + header->headerLen, from, fromlen, BUFLEN,
                  config, &config->ihave_msgs, header);
  }else if (header->packType == 2){
    process_peer_get(sock, buf + header->headerLen, from, fromlen, BUFLEN,
                     config, header);
  }else if (header->packType == 3){
    process_data(sock, buf + header->headerLen, from, fromlen, BUFLEN, config,
                 header, recv_size);
  }else if (header->packType == 4){
    process_ack(sock, buf + header->headerLen, from, fromlen, BUFLEN, config,
                header);
  }else if (header->packType == 5){
    //todo: denied packet
  }else{
    //todo: corrupted message
  }
  //todo: need to release correctly
  free(buf_backup_ptr);
  free(header);
  return;
}



/*
 * char *chunkfile: a filename pointing to a file containing chunks to
 * be retrieved
 * char *has_chunk_file: a filename pointing to a file containing
 * chunks to owned by current peer
 *
 * return char *: filtered chunk hashes in the format "hash hash hash
 * ..."
 * note: better save filtered chunks in a vector in case multiple
 * messages need to be built out of it
 *
 * given a chunkfile and current peer's has_chunk_file, only keep
 * those chunks in chunkfile that are not in has_chunk_file
 *
 * todo: need to break down into smaller function, provide vector diff function
 */
vector *filter_chunkfile(char *chunkfile, char *has_chunk_file, int *chunks_num, bt_config_t *config){
  FILE *f1, *f2;
  vector v1, v2;
  vector *res = NULL;
  if ((res = (vector*)malloc(sizeof(vector))) == NULL){
    fprintf(stderr, "Failed to allocate memory for a new vector \n");
    return NULL;
  }
  memset(res, 0, sizeof(vector));
  init_vector(res, CHUNK_HASH_SIZE);
  //todo: change impl
  init_vector(&v1, CHUNK_HASH_SIZE);
  init_vector(&v2, CHUNK_HASH_SIZE);

  if ((f1 = fopen(chunkfile, "r")) == NULL){
    fprintf(stderr, "Error opening chunkfile %s \n", chunkfile);
    return NULL;
  }
  if ((f2 = fopen(has_chunk_file, "r")) == NULL){
    fprintf(stderr, "Error opening has_chunk_file %s\n", has_chunk_file);
    return NULL;
  }
  read_chunk(f1, &v1);
  read_chunk(f2, &v2);
  /* improve performance by replacing the list with a hashmap */
  for (int i = 0; i < v1.len; i++){
    int own = 0;
    char *str_i = vec_get(&v1, i);
    for (int j = 0; j < v2.len; j++){
      char *str_j = vec_get(&v2, j);
      if (!strcmp(str_i, str_j)){
        own = 1;
        break;
      }
    }
    data_t d; /* to record the order of chunks in somewhether */
    strcpy(d.chunk_hash, str_i);
    d.data = NULL;
    // this is mixture of logc, a few layers have been crossed
    if (!own){
      d.own = 0;
      vec_add(res, str_i);
      vec_add(&config->desired_chunks, str_i);
    }else{
      d.own = 1;
    }
    vec_add(&config->data, &d);
  }
  *chunks_num = res->len;
  vec_free(&v1);
  vec_free(&v2);
  /* for (int i = 0; i < res->len; i++){ */
  /*   fprintf(stdout, "%d %s", i, (char*)vec_get(res, i)); */
  /*   fprintf(stdout, "\n"); */
  /* } */
  return res;
}



/*
 * char *peer_list_file: a filename pointing to a file that contains
 * all peers
 * vector *ihave_msgs: a vector which will contain query messages
 *
 * when loading peers, need to exclude the peer itself
 */
peers_t *load_peers(bt_config_t *config){
  FILE *f;
  char *line = NULL, *token, line_backup[100];
  size_t line_len;
  char *peer_list_file = config->peer_list_file;
  short peer_id;
  peers_t *peers = (peers_t*)malloc(sizeof(peers_t));
  config->peer = peers;
  init_vector(&config->ihave_msgs, sizeof(ihave_t));
  init_vector(&peers->peer, sizeof(peer_info_t));
  init_vector(&config->sessions, sizeof(udp_session));
  init_vector(&config->desired_chunks, CHUNK_HASH_SIZE);
  init_vector(&config->recv_sessions, sizeof(udp_recv_session));
  init_vector(&config->data, sizeof(data_t));
  if ((f = fopen(peer_list_file, "r")) == NULL){
    fprintf(stderr, "Failed to open peer_list_file %s\n", peer_list_file);
    return NULL;
  }

  while(getline(&line, &line_len, f) != -1){
    memset(line_backup, 0, 100);
    strcpy(line_backup, line);
    token = strtok(line_backup, " ");
    peer_id = atoi(token); /* any *token has to be a char */
    /*
      format of the peer info
      1 127.0.0.1 1111
     */
    if (*token != '#' && peer_id != config->identity){
      peer_info_t *peer = (peer_info_t*)malloc(sizeof(peer_info_t));
      peer->id = peer_id;
      token = strtok(NULL, " ");
      strcpy(peer->ip, token);
      token = strtok(NULL, " ");
      peer->port = atoi(token);
      vec_add(&peers->peer, peer);
      /* insert the ihave element into vector */
      ihave_t *ihave = (ihave_t*)malloc(sizeof(ihave_t));
      vec_add(&config->ihave_msgs, ihave);
    }else{
      // comment line, do nothing here
    }
    free(line);
    line = NULL;
    line_len = 0;
  }
  config->peer = peers;
  return peers;
}

/*
 * query example: WHOHAS 2 000...015 0000..00441
 */
vector *build_query(vector *filtered_chunks, unsigned int chunks_num){
  vector *res = (vector*)malloc(sizeof(vector));
  init_vector(res, UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN);
  int cnt = 0;

  while(chunks_num > 0){
    int num = CHUNK_NUM_PER_PACK > chunks_num?chunks_num:CHUNK_NUM_PER_PACK;
    int buf_len = strlen("whohas") + sizeof(int) + num * CHUNK_HASH_SIZE + 2;
    char *query = (char*)malloc(buf_len);
    memset(query, 0, buf_len);
    strcat(query, "WHOHAS ");
    sprintf(query + strlen(query), "%d ", num);
    for (int i = 0; i < num; i++){
      char *hash = vec_get(filtered_chunks, cnt++);
      strcat(query, hash);
      if (i != (num - 1)){
        strcat(query, " ");
      }
    }
    vec_add(res, query);
    chunks_num -= num;
  }

  return res;
}

/*
 * peers_t peers: contains a list of peers info
 * char *query: the query info to flood to peers
 */
void flood_peers_query(peers_t *peers, vector *queries, bt_config_t *config){
  init_vector(&config->whohas_timers, sizeof(timer));
  init_vector(&config->get_timers, sizeof(timer));
  init_vector(&config->request_queue, sizeof(request_t));
  for (int j = 0; j < queries->len; j++){
    char *query = (char*)vec_get(queries, j);
    packet_h header;
    header.magicNo = 15441;
    header.versionNo = 1;
    header.packType = 0;
    header.headerLen = PACK_HEADER_BASE_LEN;
    header.packLen = PACK_HEADER_BASE_LEN + strlen(query);
    /* not used in non-data packets */
    header.seqNo = 0;
    header.ackNo = 0;
    for (int i = 0; i < peers->peer.len; i++){
      peer_info_t *peer = (peer_info_t*)vec_get(&peers->peer, i);
      send_packet(peer->ip, peer->port, &header, query, config->mysock, strlen(query));
      add_timer(&config->whohas_timers, peer->ip, peer->port, NULL, query);
    }
  }

  return;
}


/**
  need to parse user's command and send requests to server and
  peers
 * @param chunkfile file contains chunks to be downloaded
 * @param outputfile
 * @param config
 */
void process_get(char *chunkfile, char *outputfile, bt_config_t *config) {
  //todo: need to extract this into the job module
  FILE *f1, *f2;
  vector v1, v2;

  init_vector(&v1, CHUNK_HASH_SIZE);
  init_vector(&v2, CHUNK_HASH_SIZE);

  if ((f1 = fopen(chunkfile, "r")) == NULL){
    fprintf(stderr, "Error opening chunkfile %s \n", chunkfile);
    exit(-1);
  }
  if ((f2 = fopen(config->has_chunk_file, "r")) == NULL){
    fprintf(stderr, "Error opening has_chunk_file %s\n",
            config->has_chunk_file);
    exit(-1);
  }

  read_chunk(f1, &v1);
  read_chunk(f2, &v2);
  vector *diff_chunk_hash = vec_diff(&v1, &v2);
  vector *common_chunk_hash = vec_common(&v1, &v2);

  for (int i = 0;i < diff_chunk_hash->len; i++){
    vec_add(&config->desired_chunks, vec_get(diff_chunk_hash, i));
  }
  for (int i = 0; i < common_chunk_hash->len; i++){
    data_t d;
    strcpy(d.chunk_hash, vec_get(common_chunk_hash, i));
    d.data = NULL;
    vec_add(&config->data, &d);
  }

  vector *query = build_query(diff_chunk_hash, diff_chunk_hash->len);
  flood_peers_query(config->peer, query, config);

  vec_free(query);
  free(query);
  vec_free(diff_chunk_hash);
  free(diff_chunk_hash);
  vec_free(common_chunk_hash);
  free(common_chunk_hash);
  return;
}



/*
 * hanldes requests coming from both command & other peers
 *
 * for requests coming from command line in the format:
 * GET /tmp/B.chunks /tmp/newB.tar
 * this command will ask your peer to fetch all chunks listed in /tmp/B.chunks
 *
 * for requests coming from other peer:
 * @param line the commandline input from user console
 * @param cbdata
 * @param config the config of current peer
 */
void handle_user_input(char *line, void *cbdata, bt_config_t *config) {
  char chunkf[128], outf[128];

  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));

  /*
    format specifier: "%120s" will read no more than 120 chars !
   */
  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    if (strlen(outf) > 0) {
      process_get(chunkf, outf, config);
    }
  }
}


/*
 * checks all the timers stored in config. If there is any timeouts,
 * need to re-send the message.
 *
 * todo: need to remove the timer when the message has been received!
 */
void check_for_timeouts(bt_config_t *config){
  // need to check timeouts in other sessions

  /* check for whohas timeouts */
  for (int i = 0; i < config->whohas_timers.len; i++){
    clock_t cur = clock();
    timer *t = (timer*)vec_get(&config->whohas_timers, i);
    if (t->start > 0){ /* hasn't received message */
      if ((cur - t->start) * 1000 / CLOCKS_PER_SEC >= IHAVE_TIMEOUT_TIME){
        t->repeat_times++;
        t->start = clock();
        //todo: need to send the message again!
        fprintf(stdout, "Sending the query to the peer again \n");
      }
    }
  }
  return;
}

void release_all_peers(bt_config_t *config){
  for (int i = 0; i < config->peer->peer.len; i++){
    free(vec_get(&config->peer->peer, i));
  }
  free(config->peer);


  return;
}

/*
 * main entry point for the work horse of the bittorrent peer
 * handles both incoming & outcoming communication
 *
 * Notes:
 *
 * Regarding timer & callback
 * there is a compromise made here on timer. Since no library is
 * provided to provide the utility of time out & callback. A crude
 * approach is employed here: when a request is sent, the current
 * clock is recorded. In the main loop, all timers will be checked
 * constantly to ensure all timeout timers are processed
 */
void peer_run(bt_config_t *config) {
  int sock;
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;

  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
  /* open UDP port instead of TCP port */
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }

  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);
  //test_vec();
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }

  config->mysock = sock;
  /* load peer should be moved to a proper place */
  if (load_peers(config) == NULL){
    fprintf(stderr, "Error loading peers from peer file \n");
    exit(1);
  }
  spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

  while (1) {
    int nfds;
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);

    nfds = select(sock+1, &readfds, NULL, NULL, NULL);
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds)) {
	process_inbound_udp(sock, config);
      }

      if (FD_ISSET(STDIN_FILENO, &readfds)) {
	process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused", config);
      }
    }
    check_for_timeouts(config);
  }

  /* try to avoid double release */
  release_all_peers(config);
}
