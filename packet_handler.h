#ifndef __PACKET_HANDLER__
#define __PACKET_HANDLER__

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "job.h"
#include "constants.h"

/* input struct tot packet handlers */
typedef struct handler_input{
    /* the socket through which input comes */
    uint16_t incoming_socket;
    /* buffer contains packet body */
    char *body_buf;
    /* the incoming packet ip */
    struct sockaddr_in *from_ip;
    /* the incoming packet length */
    socklen_t from_len;
    /* the total length of buffer (header + body)*/
    uint16_t buf_len;
    /* total length received from socket */
    uint32_t recv_size;
    packet_h *header;
}handler_input;

char *build_whohas_query(vector *chunks_to_download);
handler_input * build_handler_input(uint16_t incoming_socket, char *body_buf,
                                    struct socket_in *from_ip, socklen_t
                                    from_len, uint16_t buf_len, uint32_t
                                    recv_size, packet_h *header);

void parse_whohas_packet(char *buf, vector *v);
void process_whohas(handler_input *input, job_t *job);

#endif

