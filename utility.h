#ifndef _UTILITY_
#define _UTILITY_


#define DEFAULT_VEC_SIZE 10

typedef struct vector{
  void *val;
  int ele_size;
  int len;
  int size;
}vector;

void init_vector(vector *vec, int ele_size);
void vec_add(vector *vec, void *ele);
void *vec_get(vector *vec, int idx);
#endif
