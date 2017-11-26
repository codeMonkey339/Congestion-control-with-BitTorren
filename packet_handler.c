#include "packet_handler.h"
#include "packet.h"
#include <stdio.h>
#include "utility.h"
#include <string.h>
#include <stdlib.h>
#include "chunk.h"
#include "reliable_udp.h"
#include "peer_utils.h"
#include <sys/socket.h>

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
    init_vector(chunk_peer_relations, sizeof(chunk_dis));

    for (size_t i = 0; i < chunks_to_download->len; i++){
        char *chunk = vec_get(chunks_to_download, i);
        chunk_dis chunk_info;
        init_vector(&chunk_info.idx, sizeof(unsigned short));
        strcpy(chunk_info.msg, chunk);

        for (size_t j = 0; j < ihave_msgs->len; j++){
            ihave_t *ihave_msg = (ihave_t*)vec_get(ihave_msgs, j);
            for (size_t k = 0; k < ihave_msg->chunk_num; k++){
                char *k_chunk_owned = ihave_msg->chunks[k];
                if (!strcmp(chunk, k_chunk_owned) || strstr(chunk,
                                                            k_chunk_owned)){
                    vec_add(&chunk_info.idx, &ihave_msg->idx);
                    break;
                }
            }
        }

        vec_add(chunk_peer_relations, &chunk_info);
    }

    return chunk_peer_relations;
}

/**
 * for each chunk, shuffle the ids of peer owning it
 * @param chunk_peer_relations
 * @return
 */
vector *shuffle_peer_ids(vector *chunk_peer_relations){
    time_t t;
    srand((unsigned)time(&t));
    for (size_t i = 0; i < chunk_peer_relations->len; i++){
        chunk_dis *peer_ids = vec_get(chunk_peer_relations, i);
        size_t *ids = (size_t*)Malloc(sizeof(size_t) * peer_ids->idx.len);
        size_t shift = rand() % peer_ids->idx.len;

        for (size_t j = 0; j < peer_ids->idx.len; j++){
            ids[j] = *(int*)vec_get(&peer_ids->idx, i);
        }

        for (size_t j = 0; j < peer_ids->idx.len; j++){
            size_t shifted_pos = (j + shift) % peer_ids->idx.len;
            *(int*)vec_get(&peer_ids->idx, j) = shifted_pos;
        }
    }

    return chunk_peer_relations;
}



/**
 * build the body for GET request
 * @param chunk_hash
 * @return
 */
packet_b *build_get_request_body(char *chunk_hash){
    packet_b *packet_body = Malloc(sizeof(packet_b));
    size_t body_len = strlen("GET") +CHUNK_HASH_SIZE + 2;
    char *body = (char*)Malloc(body_len);

    memset(packet_body, 0, body_len);
    strcat(body, "GET ");
    strcat(body, chunk_hash);
    packet_body->body = body;
    packet_body->body_len = strlen(body) + 1;

    return packet_body;
}

/**
 * send the GET packet to peer with id "peer_id"
 * @param job
 * @param chunk_hash
 * @param peer_id
 * @return
 */
int send_get_request(job_t *job, char *chunk_hash, size_t peer_id){
    packet_h packet_header;
    /* inconsistent behavior, better not use output arguments */
    packet_b *packet_body = build_get_request_body(chunk_hash);
    build_packet_header(&packet_header, 15441, 1, GET, PACK_HEADER_BASE_LEN,
                        PACK_HEADER_BASE_LEN + packet_body->body_len, 0, 0);
    peer_info_t *peer_info = get_peer_info_from_id(job->peers, peer_id);
    ip_port_t *ip_port = convert_peer_info_2_ip_port(peer_info);
    packet_m *packet = packet_message_builder(&packet_header,
                                              packet_body->body,
                                              packet_body->body_len);
    send_packet(ip_port->ip, ip_port->port, packet, job->mysock);
    return 1;
}


/**
 * loop through all the chunk messages, and send GET packets
 *
 * Considering GET packets are not supposed to send through reliable
 * communication, there is no need to set timers
 *
 * @param chunk_peer_relations
 * @param job
 */
void send_get_requests(vector *chunk_peer_relations, job_t *job){
    for (size_t i = 0; i < chunk_peer_relations->len; i++){
        chunk_dis *peer_ids_for_a_chunk = vec_get(chunk_peer_relations, i);
        char *chunk_hash = peer_ids_for_a_chunk->msg;
        size_t peer_id = *(int*)vec_get(&peer_ids_for_a_chunk->idx, 0);
        udp_recv_session *recv_session = (udp_recv_session*)Malloc(sizeof
                                                                  (udp_recv_session));
        build_udp_recv_session(recv_session, peer_id, chunk_hash,job->peers);
        /* assumes that there is packet loss here */
        send_get_request(job, chunk_hash, peer_id);
        vec_add(job->recv_sessions, recv_session);
    }
    return;
}


/** for each chunk, get the id of peers owning it
 * @param input
 * @param job
 */
vector *get_peer_ids_for_chunks(handler_input *input, job_t *job){
    vector *chunk_peer_relations = collect_peer_own_chunk_relation
            (job->chunks_to_download, job->ihave_msgs);
    shuffle_peer_ids(chunk_peer_relations);
    send_get_requests(chunk_peer_relations, job);
    return chunk_peer_relations;
}



/**
 * check whether the IHAVE messages have been received from all peers
 * @param input
 * @param job
 * @return
 */
int check_all_ihave_msg_received(handler_input *input, job_t *job){
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
    vector *sorted_peer_ids;

    ihave_parsed_msg = parse_ihave_packet(input, job->peers);
    vec_add(job->ihave_msgs, ihave_parsed_msg);
    if (check_all_ihave_msg_received(input, job)){
        sorted_peer_ids = get_peer_ids_for_chunks(input, job);
        send_get_requests(sorted_peer_ids, job);


        vec_free(sorted_peer_ids);
        free(sorted_peer_ids);
        free(ihave_parsed_msg);
    }

    return;
}

/**
 * parse from the GET packet, get the chunk_hash requested
 * @param buf
 * @param buf_len
 * @return
 */
char *parse_get_packet(char *buf, size_t buf_len){
    char *buf_backup = Malloc(buf_len);
    char *chunk_hash;

    memset(buf_backup, 0, buf_len);
    strcpy(buf_backup, buf);
    chunk_hash = strtok(buf_backup, " ");
    chunk_hash = strtok(NULL, " ");

    return chunk_hash;
}


/**
 * send a DEINIED packet to peer since there is already a connection from it
 * @param ip_port
 * @param job
 */
void send_denied_packet(ip_port_t *ip_port, job_t *job){
    //todo: need to send a DENIED packet

    return;
}


void process_peer_get(handler_input *input, job_t *job){
    udp_session *send_session = NULL;
    char *requested_chunk_hash;
    size_t chunk_idx;
    ip_port_t *ip_port = parse_peer_ip_port(input->from_ip);


    requested_chunk_hash = parse_get_packet(input->body_buf, input->buf_len);
    chunk_idx = find_chunk_idx_from_hash(requested_chunk_hash,
                                         job->has_chunk_file);
    if (find_session(ip_port->ip, ip_port->port, job->send_sessions) == NULL){
        send_session = create_new_session();
        init_send_session(send_session, job, ip_port, chunk_idx);
    }else{
        //todo: need to queue up the requests?
        send_denied_packet(ip_port, job);
        return;
    }

    verify_chunk_hash(send_session->f, requested_chunk_hash, chunk_idx);
    seek_to_chunk_pos(send_session->f, chunk_idx);
    send_udp_packet_reliable(send_session, ip_port, job);
    //todo: need to add sessions to vector
    free(requested_chunk_hash);
}
