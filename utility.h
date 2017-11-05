#ifndef _UTILITY_
#define _UTILITY_

#include <time.h>
#include "packet.h"


#define DEFAULT_VEC_SIZE 10
#define IP_STR_LEN 15
#define IHAVE_TIMEOUT_TIME 180 /* timeout time is 180s */
#define PORT_LEN 12
/* maximum udp packet size excluding header */
#define UDP_MAX_PACK_SIZE 1500
/* Chunk hashes have a fixed length of 20 bytes */
#define CHUNK_HASH_SIZE 45 * sizeof(char)
#define CHUNK_LEN 524288 /* chunk size is 512kB*/


typedef struct vector{
  void *val;
  int ele_size;
  int len;
  int size;
}vector;


typedef struct peer_info{
  int id;
  char ip[IP_STR_LEN];
  int port;
}peer_info_t;

typedef struct peers{
  vector peer;
  int num;
}peers_t;


typedef struct timer{
  clock_t start;
  short repeat_times;
  short peer_id;
  /* ip of recipient */
  char ip[IP_STR_LEN];
  /* socket of recipient */
  short sock;
  /* each timer carries with itself the message to send */
  char *msg;
}timer;

typedef struct ihave{
  char *msg; /* the ihave message from the peer */
  int idx; /* the index of the peer */
  int chunk_num; /* the # of chunks stored on peer peer */
  char **chunks; /* a double pointer to chunks stored on peer peer */
}ihave_t;

typedef struct chunk_dis{
  /* the chunk hash */
  char msg[CHUNK_HASH_SIZE];
  /* the indexes of peers that own this chunk */
  vector idx;
}chunk_dis;

typedef struct chunk_buf{
  /* hash of the chunk */
  char *chunk_hash;
  /* peer ip*/
  char *ip;
  /* peer port */
  short port;
  /* chunk data */
  char *data;
}chunk_buf;

void init_vector(vector *vec, int ele_size);
void vec_add(vector *vec, void *ele);
void *vec_get(vector *vec, int idx);
void vec_insert_at(vector *vec, void *ele, int idx);
void vec_free(vector *vec);
/* chunk_dis is not general enough, how about void* ? */
void vec_sort(vector *vec, int (*cmp)(chunk_dis *, chunk_dis*));
int read_from_sock(int sock, char *buf, int BUFLEN);
void add_timer(vector *timers, char *ip, int sock, packet_h *header, char *filebuf);
#endif
