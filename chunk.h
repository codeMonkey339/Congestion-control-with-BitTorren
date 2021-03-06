/*
 * bt_parse.h
 *
 * Initial Author: Debabrata Dash
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2 chunk processing
 *
 */

#ifndef _CHUNK_H_
#define _CHUNK_H_
#include <stdio.h>
#include <inttypes.h>
#include "utility.h"

#define BT_CHUNK_SIZE (512 * 1024)

#define ascii2hex(ascii,len,buf) hex2binary((ascii),(len),(buf))
#define hex2ascii(buf,len,ascii) binary2hex((buf),(len),(ascii))

typedef struct chunk_dis{
    /* the chunk hash */
    char msg[CHUNK_HASH_SIZE];
    /* the indexes of peers that own this chunk */
    vector idx;
    /* current index into the vector idx, used in crash recovery*/
    size_t cur_idx;
}chunk_dis;

#ifdef __cplusplus
extern "C" {
#endif
  /* Returns the number of chunks created, return -1 on error */
  int make_chunks(FILE *fp, uint8_t **chunk_hashes);  

  /* returns the sha hash of the string */
  void shahash(uint8_t *chr, int len, uint8_t *target);

  /* converts a hex string to ascii */
  void binary2hex(uint8_t *buf, int len, char *ascii);

  /* converts an ascii to hex */
  void hex2binary(char *hex, int len, uint8_t*buf);

  void read_chunk(char *filename, vector *v);
  size_t find_chunk_idx_from_hash(char *chunk_hash, char *hash_chunk_file);
  void seek_to_chunk_pos(FILE *f, size_t chunk_idx);
  void seek_to_packet_pos(FILE *f, size_t chunk_idx, size_t last_sent_packet);
  void verify_chunk_hash(FILE *f, char *requested_chunk_hash, size_t chunk_idx);
  char *get_chunk_hash(char *chunk, size_t size);
#ifdef __cplusplus
}
#endif

#endif /* _CHUNK_H_ */
