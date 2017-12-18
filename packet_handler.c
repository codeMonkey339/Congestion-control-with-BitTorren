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
char *build_whohas_query(vector *chunks_to_download) {
    uint32_t query_len = chunks_to_download->len * CHUNK_HASH_SIZE
                         + strlen("WHOHAS");
    char *query = (char *) malloc(query_len);
    memset(query, 0, query_len);
    strcat(query, "WHOHAS ");
    sprintf(query + strlen(query), "%d ", chunks_to_download->len);
    for (int i = 0; i < chunks_to_download->len; i++) {
        chunk_to_download *chunk = vec_get(chunks_to_download, i);
        if (!chunk->own) {
            strcat(query, chunk->chunk_hash);
            if (i != (chunks_to_download->len - 1)) {
                strcat(query, " ");
            }
        }
    }
    return query;
}

/**
 * build the handler input struct
 * @param incoming_socket
 * @param body_buf
 * @param from_ip
 * @param from_len
 * @param buf_len
 * @param recv_size
 * @param header
 * @return
 */
handler_input *build_handler_input(int incoming_socket, char *body_buf,
                                   struct sockaddr_in *from_ip,
                                   socklen_t from_len, int buf_len,
                                   int recv_size, packet_h *header,
                                   vector *peers) {
    handler_input *res = (handler_input *) malloc(sizeof(handler_input));
    res->incoming_socket = incoming_socket;
    res->body_buf = body_buf;
    memcpy(&res->from_ip, from_ip, sizeof(struct sockaddr_in));
    res->from_len = from_len;
    res->buf_len = buf_len;
    res->recv_size = recv_size;
    res->header = header;
    res->ip_port = parse_peer_ip_port(from_ip);
    res->peer_id = get_peer_id(res->ip_port, peers);
    return res;
}

/**
 * parse a WHOHAS packet, return the chunk hashes in a vector
 * @param buf buffer that contains the WHOHAS message
 * @param v vector that will store the chunk hashes in message
 */
void parse_whohas_packet(char *buf, vector *v) {
    char *token;
    int chunks_num;

    token = strtok(buf, " ");
    token = strtok(NULL, " ");
    chunks_num = atoi(token);
    while (chunks_num-- > 0) {
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
char *build_ihave_reply(vector *common_hashes) {
    char *res = (char *) malloc(strlen("IHAVE ") + common_hashes->len *
                                                    CHUNK_HASH_SIZE);
    sprintf(res, "%s %d ", "IHAVE", common_hashes->len);
    vec_copy2_str(common_hashes, res + strlen(res));
    return res;
}

/**
 * handles incoming WHOHAS message
 * @param input pointer to handler_input which contains necessary info
 * @param job pointer to current job
 */
void process_whohas_packet(handler_input *input, char *has_chunk_file) {
    packet_h reply_header;
    vector v, v2, *common_hashes;
    char *reply;

    init_vector(&v, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    read_chunk(has_chunk_file, &v);
    parse_whohas_packet(input->body_buf, &v2);
    common_hashes = vec_common(&v, &v2);
    reply = build_ihave_reply(common_hashes);
    build_packet_header(&reply_header, 15441, 1, 1, PACK_HEADER_BASE_LEN,
                        PACK_HEADER_BASE_LEN + strlen(reply), 0, 0);
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);
    packet_m *packet = packet_message_builder(&reply_header, reply, strlen
            (reply));
    send_packet(ip_port->ip, ip_port->port, packet, input->incoming_socket);

    free(common_hashes);
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
ihave_t *parse_ihave_packet(handler_input *input, vector *peers) {
    char *buf = input->body_buf;
    size_t buf_len = input->buf_len;
    char *buf_backup = Malloc(buf_len), *token;
    ihave_t *ihave_res = Malloc(sizeof(ihave_t));
    size_t ihave_msg_nums;
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);
    size_t idx = get_peer_id(ip_port, peers);

    memcpy(buf_backup, buf, buf_len);
    token = strtok(buf_backup, " ");
    token = strtok(NULL, " ");
    ihave_msg_nums = atoi(token);
    ihave_res->chunk_num = ihave_msg_nums;
    ihave_res->msg = Malloc(buf_len);
    ihave_res->idx = idx;
    memcpy(ihave_res->msg, buf, buf_len);
    ihave_res->chunks = (char **) Malloc(sizeof(char *) * ihave_msg_nums);

    for (size_t i = 0; i < ihave_msg_nums; i++) {
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
*ihave_msgs) {
    vector *chunk_peer_relations = Malloc(sizeof(vector));
    init_vector(chunk_peer_relations, sizeof(chunk_dis));

    for (size_t i = 0; i < chunks_to_download->len; i++) {
        char *chunk = vec_get(chunks_to_download, i);
        chunk_dis chunk_info;
        init_vector(&chunk_info.idx, sizeof(unsigned short));
        strcpy(chunk_info.msg, chunk);

        for (size_t j = 0; j < ihave_msgs->len; j++) {
            ihave_t *ihave_msg = (ihave_t *) vec_get(ihave_msgs, j);
            for (size_t k = 0; k < ihave_msg->chunk_num; k++) {
                char *k_chunk_owned = ihave_msg->chunks[k];
                if (!strcmp(chunk, k_chunk_owned) || strstr(chunk,
                                                            k_chunk_owned)) {
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
vector *shuffle_peer_ids(vector *chunk_peer_relations) {
    time_t t;
    srand((unsigned) time(&t));
    for (size_t i = 0; i < chunk_peer_relations->len; i++) {
        chunk_dis *peer_ids = vec_get(chunk_peer_relations, i);
        size_t *ids = (size_t *) Malloc(sizeof(size_t) * peer_ids->idx.len);
        size_t shift = rand() % peer_ids->idx.len;

        for (size_t j = 0; j < peer_ids->idx.len; j++) {
            ids[j] = *(int *) vec_get(&peer_ids->idx, i);
        }

        for (size_t j = 0; j < peer_ids->idx.len; j++) {
            size_t shifted_pos = (j + shift) % peer_ids->idx.len;
            *(int *) vec_get(&peer_ids->idx, j) = shifted_pos;
        }
    }

    return chunk_peer_relations;
}


/**
 * build the body for GET request
 * @param chunk_hash
 * @return
 */
packet_b *build_get_request_body(char *chunk_hash) {
    packet_b *packet_body = Malloc(sizeof(packet_b));
    size_t body_len = strlen("GET") + CHUNK_HASH_SIZE + 2;
    char *body = (char *) Malloc(body_len);

    memset(packet_body, 0, sizeof(packet_b));
    memset(body, 0, body_len);
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
int send_get_request(job_t *job, char *chunk_hash, size_t peer_id) {
    packet_h packet_header;
    udp_recv_session *recv_session = (udp_recv_session *) Malloc(sizeof
                                                                         (udp_recv_session));
    build_udp_recv_session(recv_session, peer_id, chunk_hash, job->peers);
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
    vec_add(job->recv_sessions, recv_session);
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
void send_get_requests(vector *chunk_peer_relations, job_t *job) {
    for (size_t i = 0; i < chunk_peer_relations->len; i++) {
        chunk_dis *peer_ids_for_a_chunk = vec_get(chunk_peer_relations, i);
        char *chunk_hash = peer_ids_for_a_chunk->msg;
        size_t peer_id = *(int *) vec_get(&peer_ids_for_a_chunk->idx, 0);
        peer_ids_for_a_chunk->cur_idx = 0;

        if (!udp_recv_session_exists(job->recv_sessions, peer_id)) {
            send_get_request(job, chunk_hash, peer_id);
        } else {
            request_t *req = build_request(chunk_hash, peer_id, job->peers);
            vec_add(job->queued_requests, req);
            free(req);
        }
    }
    return;
}


/** for each chunk, get the id of peers owning it
 * @param input
 * @param job
 */
vector *get_peer_ids_for_chunks(handler_input *input, job_t *job) {
    vector *chunk_peer_relations = collect_peer_own_chunk_relation
            (job->chunks_to_download, job->ihave_msgs);
    shuffle_peer_ids(chunk_peer_relations);
    return chunk_peer_relations;
}


/**
 * check whether the IHAVE messages have been received from all peers
 * @param input
 * @param job
 * @return
 */
int check_all_ihave_msg_received(handler_input *input, job_t *job) {
    if (job->ihave_msgs->len == job->peers->len) {
        return 1;
    }
    return 0;
}

/**
 * handles incoming IHAVE packet
 *
 * for WHOHAS/IHAVE packet, assume the network is reliable. If received no
 * reply within timeout, then the peer is considered down.
 *
 * @param input
 * @param job
 */
void process_ihave_packet(handler_input *input, job_t *job) {
    ihave_t *ihave_parsed_msg;
    vector *sorted_peer_ids_for_chunks;

    ihave_parsed_msg = parse_ihave_packet(input, job->peers);
    vec_add(job->ihave_msgs, ihave_parsed_msg);
    remove_timer_by_ip(job->who_has_timers, input->ip_port);
    if (check_all_ihave_msg_received(input, job)) {
        sorted_peer_ids_for_chunks = get_peer_ids_for_chunks(input, job);
        job->sorted_peer_ids_for_chunks = sorted_peer_ids_for_chunks;
        send_get_requests(sorted_peer_ids_for_chunks, job);

        vec_free(sorted_peer_ids_for_chunks);
        free(sorted_peer_ids_for_chunks);
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
char *parse_get_packet(char *buf, size_t buf_len) {
  char *buf_backup = Malloc(buf_len), *chunk_hash_buf, *chunk_hash;

    memset(buf_backup, 0, buf_len);
    strcpy(buf_backup, buf);
    chunk_hash = strtok(buf_backup, " ");
    chunk_hash = strtok(NULL, " ");
    chunk_hash_buf = (char*)Malloc(strlen(chunk_hash));
    strcpy(chunk_hash_buf, chunk_hash);

    free(buf_backup);
    return chunk_hash_buf;
}


/**
 * send a DEINIED packet to peer since there is already a connection from it
 * @param ip_port
 * @param job
 */
void send_denied_packet(ip_port_t *ip_port, job_t *job) {
    /* todo: need to send a DENIED packet
     * current request peer will queue up requests, so there is no need to
     * send DENIED packets
     */

    return;
}


/**
 * handles GET packet
 * @param input
 * @param send_data_sessions
 */
void process_get_packet(handler_input *input,
                        send_data_sessions *send_data_sessions) {
    udp_session *send_session = NULL;
    char *requested_chunk_hash;
    size_t chunk_idx;
    ip_port_t *ip_port = input->ip_port;


    requested_chunk_hash = parse_get_packet(input->body_buf, input->buf_len);
    chunk_idx = find_chunk_idx_from_hash(requested_chunk_hash,
                                         send_data_sessions->master_chunk_file);
    if (find_session(ip_port->ip, ip_port->port,
                     &send_data_sessions->send_sessions) == NULL) {
        send_session = create_new_session();
        init_send_session(send_session, send_data_sessions, ip_port, chunk_idx,
                          input);
    } else {
        send_denied_packet(ip_port, send_data_sessions);
        return;
    }

    verify_chunk_hash(send_session->f, requested_chunk_hash, chunk_idx);
    send_udp_packet_reliable(send_session, ip_port, input->incoming_socket);

    vec_add(&send_data_sessions->send_sessions, send_session);
    free(send_session);
    free(requested_chunk_hash);
    return;
}

/**
 * process packet of type DATA
 * @param input
 * @param job
 */
void process_data_packet(handler_input *input, job_t *job) {
    udp_recv_session *recv_session;
    packet_h *recv_header = input->header;
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);

    if ((recv_session = find_recv_session(job->recv_sessions, ip_port->ip,
                                          ip_port->port)) == NULL) {
        fprintf(stderr, "Cannot find recv session from ip: %s and port: "
                "%d\n", ip_port->ip, ip_port->port);
        return;
    }

    if (recv_header->seqNo <= recv_session->last_packet_acked ||
        recv_header->seqNo > recv_session->last_acceptable_frame) {
        fprintf(stderr, "Received a stray packet out of current window \n");
        return;
    }

    ack_recv_data_packet(recv_session, job, input);

    if (input->recv_size < UDP_MAX_PACK_SIZE) {
        if (!verify_hash(recv_session->chunk_hash, recv_session->data)) {
            int chunk_to_download_id = get_chunk_to_download_id
                    (recv_session->chunk_hash, job->chunks_to_download);
            copy_chunk_2_job_buf(recv_session, job, chunk_to_download_id);
            /* by OO principle, the method should be within job */
            update_owned_chunks(job, recv_session->chunk_hash);
        } else {
            fprintf(stderr, "Received a corrupted chunk with chunk hash "
                    "%s\n", recv_session->chunk_hash);
            send_get_request(job, recv_session->chunk_hash,
                             recv_session->peer_id);
        }

        if (!check_all_chunks_received(job->chunks_to_download)) {
            write_data_outputfile(job, job->outputfile);
        } else {
            process_queued_up_requests(job->queued_requests, recv_session, job);
        }
        free_udp_recv_session(job->recv_sessions, recv_session);
    }

    return;
}

/**
 * write the hash of the newly downloaded chunk into peer's own has_chunk_file
 * @param job
 * @param chunk_hash
 */
void update_owned_chunks(job_t *job, char *chunk_hash){
    size_t chunk_id = find_chunk_idx_from_hash(chunk_hash,
                                               job->master_chunk_file);
    char updated_chunk_entry[CHUNK_HASH_SIZE + 3];
    FILE *f = Fopen(job->has_chunk_file, "a");

    /* the same chunk won't get copies twice in one job, so there is no need
     * to check redundancy here
     */
    memset(updated_chunk_entry, 0, CHUNK_HASH_SIZE + 3);
    fprintf(f, "%d %s\n", chunk_id, chunk_hash);
    fclose(f);
    return;
}

/**
 * process incoming ACK packet
 * @param input
 * @param send_data_session
 */
void process_ack_packet(handler_input *input,
                        send_data_sessions *send_data_session) {
    packet_h *header = input->header;
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);
    udp_session *send_session = find_session(ip_port->ip, ip_port->port,
                                             &send_data_session->send_sessions);

    if (send_session == NULL) {
        fprintf(stderr, "Received a stray ACK packet from ip: %s, port %d\n",
                ip_port->ip, ip_port->port);
        return;
    }

    /* cumulative acknowledgement could happen*/
    if (header->ackNo >= (send_session->last_packet_acked + 1)) {
        move_send_window_forward(send_session, send_data_session, input);
    } else if (header->ackNo == send_session->last_packet_sent) {
        handle_duplicate_ack_packet(send_session, input, send_data_session);
    } else {
        fprintf(stderr, "Received a stray ACK packet \n");
    }

    return;
}
