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
    vec->val = (void *)realloc(vec->val, vec->ele_size * vec->size * 2); // double
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


/*
 * vector *vec: the vector pointer
 * void *ele: pointer to the vector element
 * int idx: the index at which should the vector element be inserted at
 *
 * this function will insert an element ele at index idx into vector vec
 */
void vec_insert_at(vector *vec, void *ele, int idx){

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
