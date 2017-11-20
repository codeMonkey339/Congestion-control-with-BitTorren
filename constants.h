#ifndef __CONSTANTS__
#define __CONSTANTS__


#define DEFAULT_VEC_SIZE 10
#define IP_STR_LEN 15
#define IHAVE_TIMEOUT_TIME 180 /* timeout time is 180s */
#define PORT_LEN 12
/* maximum udp packet size excluding header */
#define UDP_MAX_PACK_SIZE 1500
/* Chunk hashes have a fixed length of 20 bytes */
#define CHUNK_HASH_SIZE 45 * sizeof(char)
#define CHUNK_LEN 524288 /* chunk size is 512kB*/


#endif