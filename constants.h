#ifndef __CONSTANTS__
#define __CONSTANTS__


#define DEFAULT_VEC_SIZE 10
#define IP_STR_LEN 15
#define IHAVE_TIMEOUT_TIME 180 /* timeout time is 180s */
#define WHOHAS_TIMEOUT_TIME 20 /* timeout time is 20s */
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
#define MAXIMUM_DUP_ACK 3 /* # of dup acks before resending the packet */
#define SS_THRESHOLD 64 /* the slow start threshold of window size */
#define ESTIMATED_RTT_WEIGHT 0.8


enum PACKET_TYPE{
    WHOHAS = 0,
    IHAVE = 1,
    GET = 2,
    DATA= 3,
    ACK = 4,
    DENIED = 5
};

enum CONN_STATE{
    SLOW_START = 0,
    CONG_AVOID = 1,
    FAST_RETRANS = 2,
    FAST_RECOVERY = 3
};



#endif