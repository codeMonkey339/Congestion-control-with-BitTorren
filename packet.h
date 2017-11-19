#ifndef __PACKET__
#define __PACKET__

#include <stdint.h>

#define PACK_HEADER_BASE_LEN 16

/* the struct to represent packet header */
typedef struct packet_h{
  /* magic number: 15441*/
  uint16_t magicNo;
  /* version number: 1 */
  uint8_t versionNo;
  uint8_t packType;
  /* header length */
  uint16_t headerLen;
  /* total packet length */
  uint16_t packLen;
  uint32_t seqNo;
  /* acknowledge number for congestion control & reliable transmission */
  uint32_t ackNo;
}packet_h;

typedef struct packet_b{
  packet_h header;
  char *body;
}packet_b;

packet_h * parse_packet(char **buf);

#endif
