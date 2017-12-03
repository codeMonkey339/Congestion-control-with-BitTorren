#ifndef __PACKET_HANDLER__
#define __PACKET_HANDLER__

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "job.h"
#include "constants.h"
#include "packet.h"
#include "utility.h"

/* input struct tot packet handlers */
typedef struct handler_input{
    /* the socket through which input comes */
    int incoming_socket;
    /* buffer contains packet body */
    char *body_buf;
    /* the incoming packet ip */
    struct socket_in *from_ip;
    /* the incoming packet length */
    socklen_t from_len;
    /* the total length of buffer (header + body)*/
    int buf_len;
    /* total length received from socket */
    int recv_size;
    packet_h *header;
}handler_input;

typedef struct ihave{
    char *msg; /* the ihave message from the peer */
    int idx; /* the index of the peer */
    int chunk_num; /* the # of chunks stored on peer peer */
    char **chunks; /* a double pointer to chunks stored on peer peer */
}ihave_t;

char *build_whohas_query(vector *chunks_to_download);
handler_input *build_handler_input(int incoming_socket, char *body_buf,
                                   struct socket_in *from_ip, socklen_t
                                   from_len, int buf_len, int
                                   recv_size, packet_h *header);

void parse_whohas_packet(char *buf, vector *v);
void process_whohas_packet(handler_input *input, job_t *job);
char *build_ihave_reply(vector *common_hashes);
void process_ihave_packet(handler_input *input, job_t *job);
int check_all_ihave_msg_received(handler_input
                                 *input, job_t *job);
ihave_t *parse_ihave_packet(handler_input *input, vector *peers);
vector *collect_peer_own_chunk_relation(vector *chunks_to_download, vector
*ihave_msgs);
vector *shuffle_peer_ids(vector *chunk_peer_relations);
packet_b *build_get_request_body(char *chunk_hash);
int send_get_request(job_t *job, char *chunk_hash, size_t peer_id);
void send_get_requests(vector *chunk_peer_relations, job_t *job);
vector *get_peer_ids_for_chunks(handler_input *input, job_t *job);
int check_all_ihave_msg_received(handler_input *input, job_t *job);
void process_get_packet(handler_input *input, job_t *job);
void process_data_packet(handler_input *input, job_t *job);
void process_ack_packet(handler_input *input, job_t *job);
#endif

