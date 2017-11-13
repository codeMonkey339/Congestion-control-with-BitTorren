#include "utility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>



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

int read_from_sock(int sock, char *buf, int BUFLEN){
  int len = 0;
  if ((len == read_from_sock(sock, buf, BUFLEN)) < 0){
    fprintf(stderr, "Error reading from socket sock %d with error code %d", sock, errno);
    exit(1);
  }
  return len;
}


/*
  add a new timer into the vector of timers
*/
void add_timer(vector *timers, char *ip, int sock, packet_h *header, char *filebuf){
  timer *cur_timer = (timer*)malloc(sizeof(timer));
  cur_timer->start = clock();
  cur_timer->repeat_times = 0;
  strcpy(cur_timer->ip, ip);
  cur_timer->sock = sock;
  if (header == NULL){
    cur_timer->msg = (char*)malloc(strlen(filebuf) + 1);
    strcpy(cur_timer->msg, filebuf);
  }else{
    cur_timer->msg = (char*)malloc(sizeof(packet_h) + strlen(filebuf));
    memcpy(cur_timer->msg, header, sizeof(packet_h));
    memcpy(cur_timer->msg + sizeof(packet_h), filebuf, strlen(filebuf));
  }
  vec_add(timers, cur_timer);
  free(cur_timer);
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
