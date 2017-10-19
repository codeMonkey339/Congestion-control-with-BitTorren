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


#define IP_STR_LEN 15
#define DEFAULT_CHUNK_SIZE 10
#define CHUNK_HASH_SIZE 45


typedef struct peer_info{
  int id;
  char ip[IP_STR_LEN];
  int port;
}peer_info_t;

typedef struct peers{
  vector peer;
  int num;
}peers_t;

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
 * handle whohas message from peers
 * check whether the chunks exist in itw own has_chunk_file, if so
 * then replies the IHAVE message, otherwise there is no reply
 */
void process_whohas(int sock, char *buf, struct sock_addr_in from, socklen_t fromlen, int BUFLEN, bt_config_t *config){
  // 1. open the has_chunks_file of self
  // 2. parse the query & get hash_num
  // 3. loop through chunks & check whether owns requested chunk
  FILE *f;
  char *line = NULL, *token;
  size_t line_len;
  if ((f = fopen(config->has_chunk_file, "r")) == NULL){
    fprintf(stderr, "Error opening the has_chunk_file %s\n", config->has_chunk_file);
    exit(1);
  }

  while(getline(&line, &line_len, f) != -1){
    token = strtok(line, " ");
    if (isdigit(*token)){
      token = strtok(NULL, " ");
    }else{
      // comment line, do nothing
    }
  }
  return;
}

/*
  process IHAVE message from a peer.
  need to develop a reliable transfer protocol ontop of UDP
 */
void process_ihave(int sock, char *buf, struct sock_addr_in from, socklen_t fromlen, int BUFLEN, bt_config_t *config){
  return;
}

/*
  counterpart of the process_ihave function
  what kind of reliable protocol to develop?
 */
void process_peer_get(int sock, char *buf, struct sock_addr_in from, socklen_t fromlen, int BUFLEN, bt_config_t *config){
  // 1. open the master hash_chunk_file
  // 2. how to retrieve the chunk based on chunk hash & id???
  return;
}

/*
 * int sock: socket # that has incoming messages
 */
void process_inbound_udp(int sock, bt_config_t *config) {
  /* what is the scope of this #define macro */
#define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN], buf_backup[BUFLEN], * token;

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
    process_ihave(sock, buf, from, fromlen, BUFLEN, config);
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
 * FILE *f: file pointer to file which will be read from
 * vector *v: a vector pointer which will hold read chunk hashes
 */
void read_chunk(FILE *f, vector *v){
  char *token, *line = NULL;
  size_t line_len;

  while(getline(&line, &line_len, f) != -1){
    token = strtok(line, " ");
    if (isdigit(token)){
      token = strtok(NULL, " ");
      vec_add(v, token);
    }else{
      /* skip the current line */
      fprintf(stderr, "Wrong format of chunk file");
    }
    free(line); // memory is dynamically allocated in getline
  }
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
  init_vector(&v1, DEFAULT_CHUNK_SIZE);
  init_vector(&v2, DEFAULT_CHUNK_SIZE);
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
      /* make sure neighboring elements separated by 1 element */
      strncat(filtered_chunks, str_i, strlen(str_i) + 1);
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
 *
 * 
 */
peers_t *load_peers(char *peer_list_file, peers_t *peers){
  FILE *f;
  char *line = NULL, *token;
  size_t line_len;
  if ((f = fopen(peer_list_file, "r")) == NULL){
    fprintf(stderr, "Failed to open peer_list_file %s\n", peer_list_file);
    return NULL;
  }

  while(getline(&line, &line_len, f) != -1){
    token = strtok(line, " ");
    if (*token != '#'){ // non-comment line
      peer_info_t *peer = (peer_info_t*)malloc(sizeof(peer_info_t));
      peer->id = atoi(token);
      token = strtok(NULL, " ");
      strcpy(peer->ip, token);
      token = strtok(NULL, " ");
      peer->port = atoi(token);
      vec_add(&peers->peer, peer);
    }else{
      // comment line, do nothing here
    }
  }
  return peers;
}

/*
 * query example: WHOHAS 2 000...015 0000..00441
 */
char *build_query(char *chunkfile, int chunks_num){
  char *query = (char*)malloc(strlen(chunkfile) + sizeof(int) + strlen("WHOHAS") + 2);
  strcat(query, "WHOHAS ");
  sprintf(query + strlen(query), "%d ", chunks_num);
  strcat(query, chunkfile);
  return query;
}

/*
 * peers_t peers: contains a list of peers info
 * char *query: the query info to flood to peers
 */
void flood_peers_query(peers_t *peers, char *query){
  // 1. loop through each peer in peers
  // 2. send query to each peer with reliability
  for (int i = 0; i < peers->peer.len; i++){
    //todo: design the interface to communicate with another peer with idx
  }
}
/*
  need to parse user's command and send requests to server and
  peers

  reliable transfer: only data packets will be transmitted reliably

*/
void process_get(char *chunkfile, char *outputfile, bt_config_t *config) {
  /*
    todos:
    * collect replies from peers? how to store them? a dynamic list?
    * pick the proper one and initiate data transfer

    2. build a reliable file transfer protocol ontop of UDP

    testing:
    1. create chunk files for testing purpose
    2. how to proceed with unit testing?
    * for small stuff, you can conditionally compile these tests in the
    same file in which you have defined them
    * write separate "test_foo.c" files that use the functions in the
    foo file. The advantage is that it also enforces better modularization
   */
  int chunks_num;
  peers_t peers;
  init_vector(&peers.peer, sizeof(peer_info_t));

  chunkfile = filter_chunkfile(chunkfile, config->has_chunk_file, &chunks_num);
  if(load_peers(config->peer_list_file, &peers) == NULL){
    fprintf(stderr, "Error loading the peer_list_info file %s\n", config->peer_list_file);
    exit(1);
  }
  char *query = build_query(chunkfile, chunks_num);
  flood_peers_query(&peers, query);
  /* allocated in filter_chunkfile function */
  free(chunkfile);
  /* free all peers info */
  for (int i = 0; i < peers.peer.len; i++){
    free(vec_get(&peers.peer, i));
  }
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
 * main entry point for the work horse of the bittorrent peer
 * handles both incoming & outcoming communication
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
  
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
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
  }
}
