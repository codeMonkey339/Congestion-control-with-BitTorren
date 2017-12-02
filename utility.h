#ifndef _UTILITY_
#define _UTILITY_

#include <time.h>
#include "packet.h"
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>




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
  char *body;
  packet_h *header;
}timer;


typedef struct ip_port_t{
    char ip[IP_STR_LEN];
    uint16_t port;
}ip_port_t;


void init_vector(vector *vec, int ele_size);
void vec_add(vector *vec, void *ele);
void *vec_get(vector *vec, int idx);
void vec_insert_at(vector *vec, void *ele, int idx);
void vec_free(vector *vec);
int vec_delete(vector *vec, void *ele);
void vec_copy2_str(vector *v, char *buf);
int read_from_sock(int sock, char *buf, int BUFLEN);
void add_timer(vector *timers, char *ip, int sock, packet_h *header, char *filebuf,
               size_t buf_len);
void test_vec();

vector *vec_diff(vector *v1, vector *v2);
vector *vec_common(vector *v1, vector *v2);
FILE *Fopen(char *filename, char *mode);
ip_port_t* parse_peer_ip_port(struct sockaddr_in *from);
void delete_timer_of_ackNo(vector *timers, char *ip, int port, size_t ackNo);
char *Malloc(int size);

#endif
