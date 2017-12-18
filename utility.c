#include "utility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "chunk.h"
#include "sha.h"



// implement a vector type here


void init_vector(vector *vec, int ele_size){
  vec->val = (void*)malloc(ele_size * DEFAULT_VEC_SIZE);
  vec->size = DEFAULT_VEC_SIZE;
  vec->len = 0;
  vec->ele_size = ele_size;
  return;
}

void vec_add(vector *vec, void *ele){
  if (vec->size == vec->len){
    /* char *tmp = (void*)malloc(vec->ele_size * vec->size * 2); */
    /* memcpy(tmp, vec->val, vec->ele_size * vec->size); */
    /* //the problem occurs in re-sizing */
    /* free(vec->val); */
    vec->val = (void *)realloc(vec->val, vec->ele_size * vec->size * 2); // double
    //vec->val = tmp;
    vec->size *= 2;
  }
  memcpy((char*)vec->val + vec->len * vec->ele_size, ele, vec->ele_size); // memory copy
  vec->len++;
  return;
}


void *vec_get(vector *vec, int idx){
  if (idx > vec->len){
    return NULL;
  }else{
    return (void*)(vec->val + idx * vec->ele_size);
  }
}


void vec_free(vector *vec){
  free(vec->val);
  return;
}

void vec_sort(vector *vec, int (*cmp)(chunk_dis *, chunk_dis*)){
  //todo: implement quick sort here? should it be in-place?
}

int vec_delete(vector *vec, void *ele){
  int i = 0;
  for (; i < vec->len; i++){
    void *cur_ele = vec_get(vec, i);
    if (!memcmp(ele, cur_ele, vec->ele_size)){
      break;
    }
  }
  if (i >= vec->len){
    return -1;
  }else{
    if (vec->len > 0){
      memmove(((char*)vec->val) + i * vec->ele_size, ((char*)vec->val) + (i + 1) * vec->ele_size, (vec->len - i - 1) * vec->ele_size);
      vec->len--;
    }else{
      memset(vec->val, 0, vec->ele_size);
    }
    return 0;
  }
}

/*
 * vector *vec: the vector pointer
 * void *ele: pointer to the vector element
 * int idx: the index at which should the vector element be inserted at
 *
 * this function will insert an element ele at index idx into vector vec
 * assumption: all the elements before idx have been initialized
 */
void vec_insert_at(vector *vec, void *ele, int idx){
  void *cur = vec_get(vec, idx);
  strncpy(cur, ele, vec->ele_size);
  return;
}


/*
 * checks whether element ele is contained within vec
 */
void *vec_contains(vector *vec, void *ele){

  return NULL;
}

/**
 * find elements in v1 but not v2
 * @param v1 the vector with more elements
 * @param v2 the vector with less elements
 * @return the elements which are in v1 not v2
 */
vector *vec_diff(vector *v1, vector *v2){
  vector *res = (vector*)malloc(sizeof(vector));
  init_vector(res, v1->ele_size);
  if (v1->len == 0){
    return res;
  }
  for (int i = 0; i < v1->len; i++){
    void *ele1 = vec_get(v1, i);
    short own = 0;
    for (int j = 0; j < v2->len; j++){
      void *ele2 = vec_get(v2, j);
      if (!memcmp(ele1, ele2, v1->ele_size)){
        own = 1;
        break;
      }
    }
    if (!own){
      vec_add(res, ele1);
    }
  }
  return res;
}
/**
 * find elements in both v1 & v2
 * @param v1
 * @param v2
 * @return
 */
vector *vec_common(vector *v1, vector *v2){
  vector *res = (vector*)malloc(sizeof(vector));
  init_vector(res, v1->ele_size);
  if (v1->len == 0 || v2->len == 0){
    return res;
  }
  for (int i = 0; i < v1->len; i++){
    void *ele1 = vec_get(v1, i);
    for (int j = 0; j < v2->len; j++){
      void *ele2 = vec_get(v2, j);
      if (!memcmp(ele1, ele2, strlen(ele1))){
        vec_add(res, ele1);
        break;
      }
    }
  }
  return res;
}

/**
 * copy elements of a vector a string buffer
 * @param v pointer to vector
 * @param buf
 */
void vec_copy2_str(vector *v, char *buf){
    for (size_t i = 0; i < v->len; i++){
        strcat(buf, vec_get(v, i));
        if (i != (v->len -1)){
            strcat(buf, " ");
        }
    }
    return;
}


int read_from_sock(int sock, char *buf, int BUFLEN){
  int len = 0;
  if ((len == read_from_sock(sock, buf, BUFLEN)) < 0){
    fprintf(stderr, "Error reading from socket sock %d with error code %d", sock, errno);
    exit(1);
  }
  return len;
}


/**
 * add a timer to the timer vector
 * @param timers
 * @param ip ip of the message recipient
 * @param sock port # of the message recipient
 * @param header header of the sent packget
 * @param filebuf body of the sent packet
 * @param buf_len the body length of the sent packet
 */
void add_timer(vector *timers, char *ip, int sock, packet_h *header, char *filebuf,
               size_t buf_len) {
    timer *cur_timer = (timer *) Malloc(sizeof(timer));
    cur_timer->start = clock();
    cur_timer->repeat_times = 0;
    strcpy(cur_timer->ip, ip);
    cur_timer->sock = sock;

    if (header != NULL) {
        cur_timer->header = Malloc(sizeof(packet_h));
        memcpy(cur_timer->header, header, sizeof(packet_h));
    }
    if (filebuf != NULL){
        cur_timer->body = Malloc(buf_len);
        memcpy(cur_timer->body, filebuf, buf_len);
    }

    vec_add(timers, cur_timer);
    free(cur_timer);

    return;
}

/**
 * delete a timer from the timer vector
 * @param timers
 * @param ip
 * @param port
 * @param ackNo
 */
void delete_timer_of_ackNo(vector *timers, char *ip, int port, size_t ackNo){
    for (size_t i = 0;i < timers->len; i++){
        timer *cur_timer = vec_get(timers, i);
        if (!strcmp(cur_timer->ip, ip) && cur_timer->sock == port &&
                cur_timer->header->ackNo == ackNo){

            if (cur_timer->header != NULL){
                free(cur_timer->header);
            }

            if (cur_timer->body == NULL){
                free(cur_timer->body);
            }
            vec_delete(timers, cur_timer);
            return;
        }
    }

    return;
}


void test_vec(){
  vector vec;
  init_vector(&vec, sizeof(int));
  for (int i = 0; i < 20; i++){
    vec_add(&vec, &i);
    int tmp = *(int*)vec_get(&vec, i);
    fprintf(stdout, "tmp is %d\n", tmp);
  }
  free(vec.val);
  return;
}



/**
 * wrapper for fopen
 * @param filename
 * @param mode
 * @return
 */
FILE *Fopen(char *filename, char *mode){
    FILE *f;
    if ((f = fopen(filename, mode)) == NULL){
        fprintf(stderr, "Failed to open file %s \n", filename);
        exit(-1);
    }
    return f;
}

ip_port_t* parse_peer_ip_port(struct sockaddr_in *from){
    ip_port_t *h = (ip_port_t*)malloc(sizeof(ip_port_t));
    memset(h, 0, sizeof(ip_port_t));
    inet_ntop(AF_INET, &(from->sin_addr), h->ip, IP_STR_LEN);
    h->port = htons(from->sin_port);
    return h;
}

/**
 * malloc wrapper
 * @param size
 * @return
 */
char *Malloc(int size){
    char *res;
    if ((res = malloc(size)) == NULL){
        fprintf(stderr, "Failed to allocate memory of size %d\n", size);
    }
    return res;
}

