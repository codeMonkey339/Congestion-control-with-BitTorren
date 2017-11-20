#ifndef _UTILITY_
#define _UTILITY_

#include <time.h>
#include "packet.h"




typedef struct vector{
  int ele_size;
  int len;
  int size;
  void *val;
}vector;

typedef struct data{
  char chunk_hash[CHUNK_HASH_SIZE];
  char *data;
  short own;
}data_t;

typedef struct peer_info{
  int id;
  char ip[IP_STR_LEN];
  int port;
}peer_info_t;

typedef struct peers{
  vector peer;
  int num;
}peers_t;


typedef struct request{
  char ip[IP_STR_LEN];
  int port;
  char chunk[CHUNK_HASH_SIZE + 5];
} request_t;


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
int vec_delete(vector *vec, void *ele);
int read_from_sock(int sock, char *buf, int BUFLEN);
void add_timer(vector *timers, char *ip, int sock, packet_h *header, char *filebuf);
void test_vec();
char *get_chunk_hash(char *chunk, size_t size);
vector *vec_diff(vector *v1, vector *v2);
vector *vec_common(vector *v1, vector *v2);
#endif
