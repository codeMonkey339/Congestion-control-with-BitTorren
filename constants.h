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
/* packet header length */
#define PACK_HEADER_BASE_LEN 16

#define BT_FILENAME_LEN 255
#define BT_MAX_PEERS 1024
#define SEND_WINDOW_SIZE 8
#define RECV_WINDOW_SIZE 8
#define MAXIMUM_DUP_ACK 5


enum PACKET_TYPE{
    WHOHAS = 0,
    IHAVE = 1,
    GET = 2,
    DATA= 3,
    ACK = 4,
    DENIED = 5
};



#endif