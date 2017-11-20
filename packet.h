#ifndef __PACKET__
#define __PACKET__

#include <stdint.h>
#include "constants.h"


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



typedef struct packet_message{
    packet_h header;
    char body[CHUNK_LEN];
    uint32_t body_len;
}packet_m;

packet_m * packet_message_builder(char *header, char* body, uint32_t body_len);
packet_h * parse_packet(char **buf);
void build_packet_header(packet_h *header, int magicNo, int versionNo, int packType,
                         int headerLen, int packLen, int seqNo, int ackNo);


#endif
