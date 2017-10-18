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

#define IP_STR_LEN 15

typedef struct peer_info{
  int id;
  char ip[IP_STR_LEN];
  int port;
}peer_info_t;

typedef struct peers{
  peer_info_t *peer;
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

void process_whohas(int sock, char *buf, struct sock_addr_in from, socklen_t fromlen, int BUFLEN){
  return;
}

/*
  process IHAVE message from a peer.
  need to develop a reliable transfer protocol ontop of UDP
 */
void process_ihave(int sock, char *buf, struct sock_addr_in from, socklen_t fromlen, int BUFLEN){
  return;
}

/*
  counterpart of the process_ihave function
  what kind of reliable protocol to develop?
 */
void process_peer_get(int sock, char *buf, struct sock_addr_in from, socklen_t fromlen, int BUFLEN){
  return;
}

/*
 * int sock: socket # that has incoming messages
 */
void process_inbound_udp(int sock) {
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
    process_whohas(sock, buf, from, fromlen, BUFLEN);
  }
  if (!strcasecmp(token, "IHAVE")){
    process_ihave(sock, buf, from, fromlen, BUFLEN);
  }
  if (!strcasecmp(token, "GET")){
    process_peer_get(sock, buf, from, fromlen, BUFLEN);
  }
  // ack message?
  
  /* none of the above matches, corrupted message */
  fprintf(stderr, "Corrupted incoming message from %s: %d\n%s\n\n",
          inet_ntoa(from.sin_addr), ntohs(from.sin_port), buf);
}

/*
 * char *chunkfile: a filename pointing to a file containing chunks to
 * be retrieved
 * char *has_chunk_file: a filename pointing to a file containing
 * chunks to owned by current peer
 */
char *filter_chunkfile(char *chunkfile, char *has_chunk_file){

  return NULL;
}


/*
 * char *peer_list_file: a filename pointing to a file that contains
 * all peers
 */
peers_t load_peers(char *peer_list_file){
  return NULL;
}

char *build_query(char *chunkfile){
  return NULL;
}

/*
 * peers_t peers: contains a list of peers info
 * char *query: the query info to flood to peers
 */
void flood_peers_query(peers_t peers, char *query){
  
}
/*
  need to parse user's command and send requests to server and
  peers

  reliable transfer: only data packets will be transmitted reliably

*/
void process_get(char *chunkfile, char *outputfile, bt_config_t *config) {
  /*
    todos:
    1. flood the network to send whohas message first
    steps
    * get files path from commandline params
    * get ips of each peer and send them the whohas message
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


  chunkfile = filter_chunkfile(chunkfile, config->has_chunk_file);
  peers_t peers = load_peers(config->peer_list_file);
  char *query = build_query(chunkfile);
  flood_peers_query(peers, query);
  printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n", 
         chunkfile, outputfile);
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
	process_inbound_udp(sock);
      }

      if (FD_ISSET(STDIN_FILENO, &readfds)) {
	process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused", config);
      }
    }
  }
}
