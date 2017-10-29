#ifndef __PACKET__
#define __PACKET__

#include <stdint.h>
/*
  by changing the header length, the peers can provide custom
  optimization for all the packets
 */
typedef struct packet_h{
  /* magic number: 15441*/
  uint16_t magicNo;
  /* version number: 1 */
  uint8_t versionNo;
  /* packet type
     WHOHAS: 0
     IHAVE: 1
     GET: 2
     DATA: 3
     ACK: 4
     DENIED: 5
   */
  uint8_t packType;
  /* header length */
  uint16_t headerLen;
  /* total packet length */
  uint16_t packLen;
  /* sequence number for congestion control & reliable transmission */
  uint32_t seqNo;
  /* acknowledge number for congestion control & reliable transmission */
  uint32_t ackNo;
}packet_h;

typedef struct packet_b{
  packet_h header;
  char *body;
}packet_b;

#define PACK_HEADER_BASE_LEN 16
#endif
