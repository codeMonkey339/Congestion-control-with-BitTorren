#ifndef _UTILITY_
#define _UTILITY_

#include <time.h>


#define DEFAULT_VEC_SIZE 10
#define IP_STR_LEN 15
#define IHAVE_TIMEOUT_TIME 180 /* timeout time is 180s */
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
}timer;

typedef struct ihave{
  char *msg; /* the ihave message from the peer */
  int idx; /* the index of the peer */
  int chunk_num; /* the # of chunks stored on peer peer */
  char **chunks; /* a double pointer to chunks stored on peer peer */
}ihave_t;


void init_vector(vector *vec, int ele_size);
void vec_add(vector *vec, void *ele);
void *vec_get(vector *vec, int idx);
void vec_insert_at(vector *vec, void *ele, int idx);
int read_from_sock(int sock, char *buf, int BUFLEN);
#endif
