/*
 * bt_parse.h
 *
 * Initial Author: Ed Bardsley <ebardsle+441@andrew.cmu.edu>
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2 command line and config file parsing
 * stubs.
 *
 */

#ifndef _BT_PARSE_H_
#define _BT_PARSE_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "utility.h"

#define BT_FILENAME_LEN 255
#define BT_MAX_PEERS 1024

typedef struct bt_peer_s {
  short  id;
  struct sockaddr_in addr;
  struct bt_peer_s *next;
} bt_peer_t;

struct bt_config_s {
  /* chunk_file points to the masterchunks file*/
  char  chunk_file[BT_FILENAME_LEN];
  /* current chunk within the current peer */
  char  has_chunk_file[BT_FILENAME_LEN];
  /* output file name */
  char  output_file[BT_FILENAME_LEN];
  /* a list of all running peers */
  char  peer_list_file[BT_FILENAME_LEN];
  /* max # of connections to peers */
  int   max_conn;
  /* id identifies the current peer
     this should be used by the peer to get its hostname and port from
     peer-list-file 
   */
  short identity;
  /* port of the current peer, read from nodes.map?*/
  unsigned short myport;

  int argc; 
  char **argv;
  /* peers stored in a self-implemented vector */
  peers_t *peer;
  /* starter code provided, employs a linked list implementation */
  bt_peer_t *peers;
};
typedef struct bt_config_s bt_config_t;


void bt_init(bt_config_t *c, int argc, char **argv);
void bt_parse_command_line(bt_config_t *c);
void bt_parse_peer_list(bt_config_t *c);
void bt_dump_config(bt_config_t *c);
bt_peer_t *bt_peer_info(const bt_config_t *c, int peer_id);

#endif /* _BT_PARSE_H_ */
