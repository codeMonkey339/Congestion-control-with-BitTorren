#include "packet.h"

/**
 * parses the header out from received buffer
 * @param buf pointer to the buffer that has just been read from socket
 * @return pointer to the parsed packet header
 */
packet_h * parse_packet(char **buf){
    char *start = *buf;
    packet_h *header = (packet_h*)malloc(sizeof(packet_h));
    header->magicNo = ntohs(*(uint16_t*)start);
    header->versionNo = *(uint8_t*)(start + 2);
    header->packType = *(uint8_t*)(start + 3);
    header->headerLen = ntohs(*(uint16_t*)(start + 4));
    header->packLen = ntohs(*(uint16_t*)(start + 6));
    header->seqNo = ntohl(*(uint32_t*)(start + 8));
    header->ackNo = ntohl(*(uint32_t*)(start + 12));
    if (header->magicNo != 15441 || header->versionNo != 1){
        return NULL;
    }
    if (header->packLen != header->headerLen){
        *buf = start + header->headerLen;
    }else{
        *buf = NULL;
    }
    return header;
}