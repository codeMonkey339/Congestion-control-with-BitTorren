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




#define DEFAULT_CHUNK_SIZE 10
/* Chunk hashes have a fixed length of 20 bytes */
#define CHUNK_HASH_SIZE 45 * sizeof(char)
//#define CHUNK_HASH_SIZE 20 /* keep hash in string format */


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
 * large for a single packet 
 *
 * the REPLY message is in the format: "IHAVE 2 000...015 0000...00441"
 */
void process_whohas(int sock, char *buf, struct sockaddr_in from, socklen_t fromlen, int BUFLEN, bt_config_t *config){
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
  
  while(chunks_num-- > 0){
    token = strtok(NULL, " "); /* get a new chunk hash, token is null terminated? */
    for (int i = 0; i < v.len; i++){
      char *msg = vec_get(&v, i);
      if (strstr(msg, token) != NULL){
        /* strtok will replace ' ' with '\0' */
        hash_len = strlen(token);
        if ((reply_len + hash_len) >= buf_size){
          buf = (char*)realloc(reply, 2 * buf_size);
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
  /* if contains no chunks, reply with an empty list of chunks */
  send_udp_packet_with_sock(ip, port, reply_msg, config->mysock);
  free(reply);
  free(reply_msg);
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
 */
void send_get_queries(bt_config_t *config, vector *ihave_msgs){
  /* todo:
     1. find the correct peer based on scarcity and send GET query
     2. remove all timers for whohas messages
     3. remove dynamically allocated memeories

  */
  release_all_timers(config);
  release_all_dynamic_memory(config);
  fprintf(stdout, "sending GET query to the right peer based on scarcity \n");
  return;
}


/*
  make the functio more generic?
 */
void remove_timer(vector *cur_timer, int idx){
  timer *t;
  for (int i = 0; i < cur_timer->len; i++){
    t = (timer*)vec_get(cur_timer, i);
    if (t->peer_id == idx){
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
                   socklen_t fromlen, int BUFLEN, bt_config_t *config, vector *ihave_msgs){
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
  for (int i = 0; i < ihave_nums; i++){
    token = strtok(NULL, " ");
    ihave->chunks[i] = (char*)malloc(strlen(token) + 1);
    strcpy(ihave->chunks[i], token);
  }
  vec_insert_at(ihave_msgs, ihave, peer_idx);
  remove_timer(&config->whohas_timers, peer_idx);
  /* have received the replies from all peers */
  if (ihave_msgs->len == config->peer->peer.len){
    send_get_queries(config, ihave_msgs);
  }
  free(buf_backup);
  return;
}

/*
  counterpart of the process_ihave function
  what kind of reliable protocol to develop?
 */
void process_peer_get(int sock, char *buf, struct sockaddr_in from,
                      socklen_t fromlen, int BUFLEN, bt_config_t *config){
  // 1. open the master hash_chunk_file
  // 2. how to retrieve the chunk based on chunk hash & id???

  
  fprintf(stdout, "Servicing peers' request for a certain chunk of  file \n");
  return;
}

/*
 * int sock: socket # that has incoming messages
 *
 * vector *ihave_msgs: should not be a separate argument, instead, it
 * should be placed within config in a proper way
 */
void process_inbound_udp(int sock, bt_config_t *config, vector *ihave_msgs) {
  /* what is the scope of this #define macro */
#define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN], buf_backup[BUFLEN], * token;

  memset(buf, 0, BUFLEN);
  fromlen = sizeof(from);
  /* read from available socket into buf, don't care about
     reliability here */
  spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);
  strcpy(buf_backup, buf);
  token = strtok(buf_backup, " ");
  if (!strcasecmp(token, "WHOHAS")){
    process_whohas(sock, buf, from, fromlen, BUFLEN, config);
    return;
  }
  if (!strcasecmp(token, "IHAVE")){
    process_ihave(sock, buf, from, fromlen, BUFLEN, config, ihave_msgs);
    return;
  }
  if (!strcasecmp(token, "GET")){
    process_peer_get(sock, buf, from, fromlen, BUFLEN, config);
    return;
  }
  // ack message?
  
  /* none of the above matches, corrupted message */
  fprintf(stderr, "Corrupted incoming message from %s: %d\n%s\n\n",
          inet_ntoa(from.sin_addr), ntohs(from.sin_port), buf);
  return;
}



/*
 * char *chunkfile: a filename pointing to a file containing chunks to
 * be retrieved
 * char *has_chunk_file: a filename pointing to a file containing
 * chunks to owned by current peer
 *
 * return char *: filtered chunk hashes in the format "hash hash hash ..."
 *
 * given a chunkfile and current peer's has_chunk_file, only keep
 * those chunks in chunkfile that are not in has_chunk_file
 */
char *filter_chunkfile(char *chunkfile, char *has_chunk_file, int *chunks_num){
  FILE *f1, *f2;
  char *filtered_chunks = (char*)malloc(DEFAULT_CHUNK_SIZE * CHUNK_HASH_SIZE);
  vector v1, v2;
  init_vector(&v1, CHUNK_HASH_SIZE);
  init_vector(&v2, CHUNK_HASH_SIZE);
  int filtered_num = 0, filtered_size = DEFAULT_CHUNK_SIZE;
  
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
    if (!own){
      /* strncat will overwrite the terminating null byte at the end
         of dest, and then appends a terminating null byte */
      strcat(filtered_chunks, str_i);
      strcat(filtered_chunks, " ");
      if (++filtered_num > filtered_size){
        filtered_chunks = realloc(filtered_chunks, filtered_size * CHUNK_HASH_SIZE * 2);
        filtered_size *= 2;
      }
    }
  }
  *chunks_num = filtered_num;
  return filtered_chunks;
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
char *build_query(char *chunkfile, int chunks_num){
  int buf_len = strlen(chunkfile) + sizeof(int) + strlen("WHOHAS") + 3;
  char *query = (char*)malloc(buf_len);
  memset(query, 0, buf_len);
  strcat(query, "WHOHAS ");
  sprintf(query + strlen(query), "%d ", chunks_num);
  strcat(query, chunkfile);
  return query;
}

/*
 * peers_t peers: contains a list of peers info
 * char *query: the query info to flood to peers
 */
void flood_peers_query(peers_t *peers, char *query, bt_config_t *config){
  init_vector(&config->whohas_timers, sizeof(timer));
  for (int i = 0; i < peers->peer.len; i++){
    peer_info_t *peer = (peer_info_t*)vec_get(&peers->peer, i);
    send_udp_packet_with_sock(peer->ip, peer->port, query, config->mysock);
    clock_t start = clock();
    timer *t = (timer*)malloc(sizeof(timer));
    t->start = start;
    t->repeat_times = 0;
    t->peer_id = ((peer_info_t*)vec_get(&peers->peer,i))->id;
    t->msg = (char*)malloc(strlen(query) + 1);
    strcpy(t->msg, query);
    vec_add(&config->whohas_timers, t);
  }

  return;
}
/*
  need to parse user's command and send requests to server and
  peers

  reliable transfer: only data packets will be transmitted reliably

  testing:
  1. create chunk files for testing purpose
  2. how to proceed with unit testing?
  * for small stuff, you can conditionally compile these tests in the
  same file in which you have defined them
  * write separate "test_foo.c" files that use the functions in the
  foo file. The advantage is that it also enforces better modularization

*/
void process_get(char *chunkfile, char *outputfile, bt_config_t *config, vector *ihave_msgs) {
  /*
    todos:
    2. build a reliable file transfer protocol ontop of UDP
  */
  int chunks_num;
  if ((chunkfile = filter_chunkfile(chunkfile, config->has_chunk_file, &chunks_num)) == NULL){
    fprintf(stderr, "Error filtering chunk files that are in own hash-chunk-file \n");
    exit(1);
  }
  char *query = build_query(chunkfile, chunks_num);
  flood_peers_query(config->peer, query, config);
  /* allocated in filter_chunkfile function */
  free(chunkfile);
  free(query);
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
 * 
 */
void handle_user_input(char *line, void *cbdata, bt_config_t *config, vector *ihave_msgs) {
  char chunkf[128], outf[128];

  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));

  /*
    format specifier: "%120s" will read no more than 120 chars !
   */
  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    if (strlen(outf) > 0) {
      process_get(chunkf, outf, config, ihave_msgs);
    }
  }
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
 * checks all the timers stored in config. If there is any timeouts,
 * need to re-send the message.
 *
 * todo: need to remove the timer when the message has been received!
 */
void check_for_timeouts(bt_config_t *config){
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
 *
 * todos:
 * 1. when receiving from command line, it is fine reading directly
 * from socket. However, when receiving from peers, all messages are
 * sent in a certain format. That woudl require special reading
 * function to read packet in certain format from socket
 */
void peer_run(bt_config_t *config) {
  int sock;
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
  /* this vector should be placed in config */
  vector ihave_msgs;

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

  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }

  config->mysock = sock;
  /* peers will remain unchanged, load them at the beginning */
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
	process_inbound_udp(sock, config, &ihave_msgs);
      }

      if (FD_ISSET(STDIN_FILENO, &readfds)) {
	process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused", config, &ihave_msgs);
      }
    }
    check_for_timeouts(config);
  }

  /* try to avoid double release */
  release_all_peers(config);
}
