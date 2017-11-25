#include "packet_handler.h"
#include "packet.h"
#include <stdio.h>
#include "utility.h"
#include <string.h>
#include <stdlib.h>
#include "chunk.h"
#include "reliable_udp.h"
#include "peer_utils.h"

/**
 * given a list of chunks to download, build the whohas query message
 * @param chunks_to_download
 * @return
 */
char *build_whohas_query(vector *chunks_to_download){
    uint32_t query_len = chunks_to_download->len * CHUNK_HASH_SIZE
                         + strlen("WHOHAS");
    char *query = (char*)malloc(query_len);
    memset(query, 0, query_len);
    strcat(query, "WHOHAS ");
    sprintf(query + strlen(query), "%d ", chunks_to_download->len);
    for (int i = 0; i < chunks_to_download->len; i++){
        chunk_to_download *chunk = vec_get(chunks_to_download, i);
        strcat(query, chunk->chunk_hash);
        if (i != (chunks_to_download->len - 1)){
            strcat(query, " ");
        }
    }
    return query;
}

/**
 * builder for handler_input
 * @param incoming_socket
 * @param body_buf
 * @param from_ip
 * @param from_len
 * @param buf_len
 * @param recv_size
 * @param header
 * @return
 */
handler_input *build_handler_input(uint16_t incoming_socket, char *body_buf,
                                   struct socket_in *from_ip, socklen_t
                                   from_len, uint16_t buf_len, uint32_t
                                   recv_size, packet_h *header){
    handler_input *res = (handler_input*)malloc(sizeof(handler_input));
    res->incoming_socket = incoming_socket;
    res->body_buf = body_buf;
    res->from_ip = from_ip;
    res->from_len = from_len;
    res->buf_len = buf_len;
    res->recv_size = recv_size;
    res->header = header;
    return res;
}

/**
 * parse a WHOHAS packet, return the chunk hashes in a vector
 * @param buf buffer that contains the WHOHAS message
 * @param v vector that will store the chunk hashes in message
 */
void parse_whohas_packet(char *buf, vector *v){
    char *token;
    int chunks_num;

    token = strtok(buf, " ");
    token = strtok(NULL, " ");
    chunks_num = atoi(token);
    while(chunks_num-- > 0){
        token = strtok(NULL, " ");
        vec_add(v, token);
    }
    return;
}

/**
 * given the IHAVE chunks, build the IHAVE reply message
 * @param common_hashes the chunk hashes current peer has
 * @return a string contains the reply IHAVE message
 */
char *build_ihave_reply(vector *common_hashes){
    char *res = (char*)malloc(strlen("WHOHAS ") + common_hashes->len *
                                                 CHUNK_HASH_SIZE);
    strcpy(res, "WHOHAS ");
    vec_copy2_str(res + strlen(res), common_hashes);
    return res;
}

/**
 * handles incoming WHOHAS message
 * @param input pointer to handler_input which contains necessary info
 * @param job pointer to current job
 */
void process_whohas(handler_input *input, job_t *job){
    packet_h reply_header;
    vector v, v2, *common_hashes;
    char *reply;

    init_vector(&v, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    read_chunk(job->has_chunk_file, &v);
    parse_whohas_packet(input->body_buf, &v2);
    common_hashes = vec_common(&v, &v2);
    reply = build_ihave_reply(common_hashes);
    build_packet_header(&reply_header, 15441, 1, 1, PACK_HEADER_BASE_LEN,
                        PACK_HEADER_BASE_LEN + strlen(reply), 0, 0);
    ip_port_t *ip_port = parse_peer_ip_port(input->from_ip);
    packet_m *packet = packet_message_builder(&reply_header, reply, strlen
            (reply));
    send_packet(ip_port->ip, ip_port->port, packet, input->incoming_socket);

    free(reply);
    free(packet);
    free(ip_port);
    return;
}

/**
 * parse the IHAVE message into msg, chunk-hashes, chunk-num sections, and
 * stored the chunks in a vector
 * @param buf
 * @param buf_len
 * @return
 */
ihave_t *parse_ihave_packet(handler_input *input, vector *peers){
    char *buf = input->body_buf;
    size_t buf_len = input->buf_len;
    char *buf_backup = Malloc(buf_len), *token;
    ihave_t *ihave_res = Malloc(sizeof(ihave_t));
    size_t ihave_msg_nums;
    ip_port_t *ip_port = parse_peer_ip_port(input->from_ip);
    size_t idx = get_peer_id(ip_port, peers);

    memcpy(buf_backup, buf, buf_len);
    token = strtok(buf_backup, " ");
    token = strtok(NULL, " ");
    ihave_msg_nums = atoi(token);
    ihave_res->chunk_num = ihave_msg_nums;
    ihave_res->msg = Malloc(buf_len);
    ihave_res->idx = idx;
    memcpy(ihave_res->msg, buf, buf_len);
    ihave_res->chunks = (char**)Malloc(sizeof(char*) * ihave_msg_nums);

    for (size_t i = 0;i < ihave_msg_nums; i++){
        token = strtok(NULL, " ");
        ihave_res->chunks[i] = Malloc(strlen(token) + 1);
        strcpy(ihave_res->chunks[i], token);
    }

    /* free has no knowledge of \0 terminated strings */
    free(buf_backup);
    return ihave_res;
}

/**
 * collect the distribution of chunks among peers
 * @param chunks_to_download
 * @param ihave_msgs
 * @return
 */
vector *collect_peer_own_chunk_relation(vector *chunks_to_download, vector
*ihave_msgs){
    vector *chunk_peer_relations = Malloc(sizeof(vector));
    init_vector(peer_chunk_relations, sizeof(chunk_dis));

    for (size_t i = 0; i < chunks_to_download->len; i++){
        char *chunk = vec_get(chunks_to_download, i);
        chunk_dis chunk_info;
        init_vector(&chunk_info.idx, sizeof(unsigned short));
        strcpy(chunk_info.msg, chunk);

        for (size_t j = 0; j < ihave_msgs->len; j++){
            ihave_t *ihave_msg = (ihave_t*)vec_get(ihave_msgs, j);
            for (size_t k = 0; k < ihave_msg->len; k++){
                char *k_chunk_owned = ihave_msg->chunks[k];
                if (!strcmp(chunk, k_chunk_owned) || strstr(chunk,
                                                            k_chunk_owned)){
                    vec_add(&chunk_info.idx, &ihave_msg->idx);
                    break;
                }
            }
        }

        vec_add(peer_chunk_relations, &chunk_info);
    }

    return chunk_peer_relations;
}

void send_get_queries(handler_input *input, job_t *job){
    vector *chunk_peer_relations = collect_peer_own_chunk_relation
            (job->chunks_to_download, job->ihave_msgs);
    //todo: send GET queries to all peers
}



/**
 * check whether the IHAVE messages have been received from all peers
 * @param input
 * @param job
 * @return
 */
int check_all_ihave_msg_received(handler_input
        *input, job_t *job){
    if (job->ihave_msgs->len == job->peers->len){
        return 1;
    }
    return 0;
}

/**
 * handles incoming IHAVE packet
 * @param input
 * @param job
 */
void process_ihave(handler_input *input, job_t *job){
    ihave_t *ihave_parsed_msg;

    ihave_parsed_msg = parse_ihave_packet(input, job->peers);
    vec_add(job->ihave_msgs, ihave_parsed_msg);
    if (check_all_ihave_msg_received(input, job)){
        send_get_queries(job);
    }

    return;
}