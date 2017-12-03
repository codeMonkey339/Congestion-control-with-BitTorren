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

/**
 * build of packet header
 * @param header
 * @param magicNo
 * @param versionNo
 * @param packType
 * @param headerLen
 * @param packLen
 * @param seqNo
 * @param ackNo
 */
void build_packet_header(packet_h *header, int magicNo, int versionNo, int packType,
                         int headerLen, int packLen, int seqNo, int ackNo){
    header->magicNo = magicNo;
    header->versionNo = versionNo;
    header->packType = packType;
    header->headerLen = headerLen;
    header->packLen = packLen;
    header->seqNo = seqNo;
    header->ackNo = ackNo;
    return;
}


/**
 * builder for packet
 * @param header
 * @param body
 * @param body_len
 * @return
 */
packet_m * packet_message_builder(char *header, char* body, uint32_t body_len){
    packet_m *msg = (packet_m*)malloc(sizeof(packet_m));
    memset(msg, 0, sizeof(packet_m));
    memcpy(&msg->header, header, PACK_HEADER_BASE_LEN);

    /* in case that the body is empty */
    if (body != NULL){
        memcpy(&msg->body, body, body_len);
    }
    msg->body_len = body_len;
    return msg;
}