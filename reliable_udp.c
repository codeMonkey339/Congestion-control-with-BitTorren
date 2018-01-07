#include "reliable_udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "utility.h"
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include "peer_utils.h"
#include "job.h"
#include "chunk.h"
#include "packet_handler.h"
#include "spiffy.h"



void send_udp_packet_with_sock(char *ip, int port_no, char *msg, int sock,
                               int size) {
    char port[PORT_LEN];
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    memset(port, 0, PORT_LEN);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    sprintf(port, "%d", port_no);
    int err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "Failed to resolve remote socket address (err = %d)",
                err);
        exit(-1);
    }

    if (spiffy_sendto(sock, msg, size, 0, res->ai_addr, res->ai_addrlen) == -1){
        fprintf(stderr, "Failed to send UDP data (err = %s) \n",
                strerror(errno));
        exit(-1);
    }

    return;
}


/**
 * most top level function of sending packets in reliable_udp module
 * @param ip
 * @param port
 * @param packet_msg a pointer to packet_m
 * @param mysock the socket through which my packets are sent
 */
void send_packet(char *ip, int port, packet_m *packet_msg, int mysock) {
    char *msg;
    if (packet_msg->body_len != 0) {
        msg = (char *) malloc(
                packet_msg->header.headerLen + packet_msg->body_len);
    } else {
        msg = (char *) malloc(packet_msg->header.headerLen);
    }

    build_packet(&packet_msg->header, packet_msg->body, msg,
                 packet_msg->body_len);
    send_udp_packet_with_sock(ip, port, msg, mysock,
                              packet_msg->header.headerLen +
                              packet_msg->body_len);
    free(msg);
    return;
}

/**
 * given the header & body, build a pacekt with dynamic allocated memory
 * @param header
 * @param query
 * @param msg
 * @param query_len
 */
void build_packet(packet_h *header, char *query, char *msg, size_t query_len) {
    /* there is no endian problem for a single byte */
    uint16_t magicNo = htons(header->magicNo);
    uint16_t headerLen = htons(header->headerLen);
    uint16_t packLen = htons(header->packLen);
    uint32_t seqNo = htonl(header->seqNo);
    uint32_t ackNo = htonl(header->ackNo);
    memcpy(msg, &magicNo, 2);
    memcpy(msg + 2, &header->versionNo, 1);
    memcpy(msg + 3, &header->packType, 1);
    memcpy(msg + 4, &headerLen, 2);
    memcpy(msg + 6, &packLen, 2);
    memcpy(msg + 8, &seqNo, 4);
    memcpy(msg + 12, &ackNo, 4);
    //todo: possibly there are extended headers
    if (query != NULL) {
        memcpy(msg + header->headerLen, query, query_len);
    }
    return;
}



/**
 * builder for udp_recv_session
 * @param recv_session
 * @param peer_id
 * @param chunk_hash
 * @param peers
 */
void build_udp_recv_session(udp_recv_session *recv_session, int peer_id, char
*chunk_hash, vector *peers) {
    memset(recv_session, 0, sizeof(udp_recv_session));
    memset(recv_session->chunk_hash, 0, CHUNK_HASH_SIZE);

    peer_info_t *peer_info = get_peer_info_from_id(peers, peer_id);
    recv_session->last_packet_acked = 0;
    recv_session->last_acceptable_frame = recv_session->last_packet_acked +
                                          DEFAULT_WINDOW_SIZE;
    recv_session->peer_id = peer_id;
    recv_session->sock = peer_info->port;
    strcpy(recv_session->ip, peer_info->ip);
    strcpy(recv_session->chunk_hash, chunk_hash);
    recv_session->data = (char *) Malloc(CHUNK_LEN);
    recv_session->data_complete = 0;
    strcpy(recv_session->chunk_hash, chunk_hash);

    for (size_t i = 0; i < sizeof(recv_session->recved_flags) / sizeof
    (recv_session->recved_flags[0]); i++) {
        recv_session->recved_flags[i] = 0;
    }

    return;
}


/**
 * look for the session with input ip & socket, return NULL if no match
 * @param from_ip
 * @param from_sock
 * @param sessions
 * @return
 */
udp_session *find_session(char *from_ip, short from_sock, vector *sessions) {
    udp_session *session = NULL;
    for (int i = 0; i < sessions->len; i++) {
        udp_session *cur_session = (udp_session *) vec_get(sessions, i);
        if (!strcmp(cur_session->ip, from_ip) &&
            from_sock == cur_session->port) {
            session = cur_session;
            break;
        }
    }
    return session;
}


/**
 * create a new udp_session for a new connection
 * @return
 */
udp_session *create_new_session() {
    udp_session *new_session = (udp_session *) Malloc(sizeof(udp_session));
    memset(new_session, 0, sizeof(udp_session));
    return new_session;
}

/**
 * initialize the udp_sesession
 * @param send_session
 * @param send_data_session
 * @param ip_port
 */
void init_send_session(udp_session *send_session,
                       send_data_sessions *send_data_session,
                       ip_port_t *ip_port, size_t chunk_idx,
                       handler_input *input) {
    send_session->last_packet_sent = 0;
    send_session->last_packet_acked = 0;
    send_session->peer_id = input->peer_id;
    send_session->dup_ack = 0;
    send_session->f = Fopen(send_data_session->master_data_file, "r");
    strcpy(send_session->ip, ip_port->ip);
    send_session->port = ip_port->port;
    send_session->sent_bytes = 0;
    send_session->chunk_index = chunk_idx;
    send_session->send_window_size = 1;
    send_session->ss_threshold = SS_THRESHOLD;
    send_session->conn_state = SLOW_START;
    send_session->last_wind_size_incr_time = 0;
    send_session->rtt = 0;
    memset(send_session->packets_sent_time, 0, sizeof
    (send_session->packets_sent_time) / sizeof(time_t));

    for (uint32_t i = 0; i < sizeof(send_session->index) / sizeof(uint32_t);
         i++) {
        send_session->index[i] = 0;
    }
    init_vector(&send_session->sent_packet_timers, sizeof(timer));
    return;
}

/**
 * given the input udp_session, send packets within send_window reliably
 * @param send_session
 * @param ip_port
 * @param mysock
 */
void send_udp_packet_reliable(udp_session *send_session, ip_port_t *ip_port,
                              int mysock) {
    if ((send_session->last_packet_sent - send_session->last_packet_acked) <
        send_session->send_window_size) {
        char filebuf[UDP_MAX_PACK_SIZE];
        uint32_t read_packet_size, full_body_size, bytes_to_send, left_bytes;
        packet_h packet_header;
        packet_m *packet;

        memset(filebuf, 0, UDP_MAX_PACK_SIZE);
        memset(&packet_header, 0, sizeof(packet_h));
        seek_to_packet_pos(send_session->f, send_session->chunk_index,
                           send_session->last_packet_sent);

        while((send_session->last_packet_sent -
                send_session->last_packet_acked) < send_session->send_window_size){
            full_body_size = UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN;
            left_bytes = CHUNK_LEN - send_session->sent_bytes;
            bytes_to_send = left_bytes>full_body_size?full_body_size:left_bytes;
            read_packet_size = fread(filebuf, 1,bytes_to_send, send_session->f);
            build_packet_header(&packet_header, 15441, 1 ,3,
            PACK_HEADER_BASE_LEN, read_packet_size,
                    send_session->last_packet_sent + 1,
                    send_session->last_packet_acked);
            packet = packet_message_builder(&packet_header, filebuf,
                                            read_packet_size);
            send_packet(ip_port->ip, ip_port->port, packet, mysock);
            fprintf(stdout, "Sent a packet of size %ud \n", read_packet_size);
            //todo: these details could be hidden
            send_session->last_packet_sent++;
            send_session->sent_bytes += read_packet_size;
            add_timer(&send_session->sent_packet_timers, ip_port->ip, ip_port->port,
                      &packet_header, filebuf, read_packet_size);
            time_t cur_time = time(0);
            size_t sent_packet_array_idx = send_session->last_packet_sent -
                    send_session->last_packet_acked - 1;
            send_session->packets_sent_time[sent_packet_array_idx] = cur_time;
            free(packet);
        }
    } else {
        fprintf(stdout, "Packets in sending window are all pending "
                "acknowledgement \n");
    }
    return;
}

/**
 * check whether the recv session exists
 * @param recv_sessions
 * @param ip
 * @param port
 * @return
 */
udp_recv_session *find_recv_session(vector *recv_sessions, char *ip, int port) {
    for (int i = 0; i < recv_sessions->len; i++) {
        udp_recv_session *recv_session = (udp_recv_session *) vec_get(
                recv_sessions, i);
        if (!strcmp(recv_session->ip, ip) && recv_session->sock == port) {
            return recv_session;
        }
    }
    return NULL;
}


/**
 * cumulatively acknowledge the received packet, return # of packet acked
 * @param session
 * @param input
 * @param header_seqNo
 * @return
 */
int cumulative_ack(udp_recv_session *session, handler_input *input,
                   int header_seqNo) {
    size_t index;
    size_t arr_size =
            sizeof(session->recved_flags) / sizeof(session->recved_flags[0]);
    copy_recv_packet_2_buf(session, input);
    for (index = 0; index < arr_size; index++) {
        if (session->recved_flags[index] == 0) {
            break;
        }
    }
    if (index > 0) {
        session->last_packet_acked += index;
        session->last_acceptable_frame += index;
        for (size_t i = 0; i < (arr_size - index); i++) {
            session->recved_flags[i] = session->recved_flags[i + index];
        }
        for (size_t i = (arr_size - index); i < arr_size; i++) {
            session->recved_flags[i] = 0;
        }
    }

    return index;
}

/**
 * copy the received packet to the appropriate buf place
 * @param recv_session
 * @param input
 */
void copy_recv_packet_2_buf(udp_recv_session *recv_session, handler_input
*input){
    size_t seqNo = input->header->seqNo;
    size_t full_packet_len = UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN;
    if ((recv_session->last_packet_acked < seqNo) &&
            (recv_session->last_acceptable_frame >= seqNo)){
        memcpy(recv_session->data + full_packet_len * (seqNo - 1),
               input->body_buf,
               input->header->packLen);
        recv_session->buf_size += input->header->packLen;
        recv_session->recved_flags[seqNo - recv_session->last_packet_acked -1]
                = 1;
    }

    return;
}

/**
 * check whether there is recv_session with a peer of given id
 * @param recv_sessions
 * @param peer_id
 * @return
 */
int udp_recv_session_exists(vector *recv_sessions, size_t peer_id){
    for (size_t i = 0; i < recv_sessions->len; i++){
        udp_recv_session *recv_session = vec_get(recv_sessions, i);
        if (recv_session->peer_id == peer_id){
            return 1;
        }
    }

    return 0;
}


/**
 * for previously denied GET requests, process one of them connected to the
 * same peer as the current recv_session
 *
 * @param queued_requests
 * @param recv_session
 * @param job
 */
void process_queued_up_requests(vector *queued_requests, udp_recv_session
*recv_session, job_t *job){
    char *hash;

    for (size_t i = 0; i < queued_requests->len; i++){
        request_t *r = vec_get(queued_requests, i);
        if (!strcmp(r->ip, recv_session->ip) && r->port == recv_session->sock){
            hash = strtok(r->chunk, " ");
            hash = strtok(NULL, " ");
            send_get_request(job, hash, recv_session->peer_id);
            vec_delete(queued_requests, r);

            return;
        }
    }
    return;
}

/**
 * free the memory related to a completed udp_recv_session
 * @param recv_sessions
 * @param recv_session
 */
void free_udp_recv_session(vector *recv_sessions, udp_recv_session *
recv_session){
    free(recv_session->data);
    vec_delete(recv_sessions, recv_session);

    return;
}


/**
 * ackknowledge received packet, and move window forward
 * @param recv_session
 * @param job
 * @param input
 */
void ack_recv_data_packet(udp_recv_session *recv_session, job_t *job,
                          handler_input *input){
    size_t packet_num_acked, peer_id;
    packet_h reply_header, *recv_header = input->header;
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);
    packet_m *packet;

    if ((recv_session->last_packet_acked + 1) == recv_header->seqNo){
        packet_num_acked = cumulative_ack(recv_session, input,
                                          recv_header->seqNo);
        build_packet_header(&reply_header, 15441, 1, 4, PACK_HEADER_BASE_LEN,
                            0, 0, recv_session->last_packet_acked);
    }else{
        copy_recv_packet_2_buf(recv_session, input);
        build_packet_header(&reply_header, 15441, 1, 4, PACK_HEADER_BASE_LEN,
                            0, 0, recv_session->last_packet_acked);
    }

    packet = packet_message_builder(&reply_header, NULL, 0);
    send_packet(ip_port->ip, ip_port->port, packet, job->mysock);
    free(packet);

    return;
}

/**
 * move forward the sending window through sending more packets if any
 * @param send_session
 * @param send_data_session
 * @param input
 */
void move_send_window_forward(udp_session *send_session,
                              send_data_sessions *send_data_session,
                              handler_input *input){
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);

    remove_acked_packet_timers(send_session, input->header->ackNo);
    send_session->last_packet_acked = input->header->ackNo;
    send_session->dup_ack = 0;
    if (send_session->sent_bytes >= CHUNK_LEN){
        if (send_session->last_packet_acked == send_session->last_packet_sent){
            fprintf(stdout, "Sent and received ack for all %d packets\n",
                    send_session->last_packet_sent);
            vec_delete(&send_data_session->send_sessions, send_session);
        }
    }else{
        send_udp_packet_reliable(send_session, ip_port, input->incoming_socket);
        increase_send_window_size(send_session);
    }
    return;
}

/**
 * given the state of the current connection, increase the sending window
 * size accordingly
 *
 * @param send_session
 */
void increase_send_window_size(udp_session *send_session){
    if (send_session->conn_state == SLOW_START){
        if (++send_session->send_window_size == send_session->ss_threshold){
            send_session->conn_state = CONG_AVOID;
        }
    }else if (send_session->conn_state == CONG_AVOID){
        double updated_rtt = update_rtt(send_session);
        double time_diff = time(0) - send_session->last_wind_size_incr_time;
        if (send_session->last_wind_size_incr_time == 0
            || time_diff >= updated_rtt){
            send_session->send_window_size++;
            send_session->last_wind_size_incr_time = time(0);
        }
    }
    return;
}


double update_rtt(udp_session *send_session){
    time_t cur_time = time(0);
    time_t cur_rtt = cur_time - send_session->packets_sent_time[0];
    time_t history_rtt = send_session->rtt == 0? cur_rtt:send_session->rtt;
    send_session->rtt = cur_rtt * ESTIMATED_RTT_WEIGHT +
            history_rtt * (1 - ESTIMATED_RTT_WEIGHT);
    // shift the position of packets sent time
    for(int i = 0; i < (sizeof(send_session->packets_sent_time) /
                               sizeof(time_t) - 1); i++){
        send_session->packets_sent_time[i] =
                send_session->packets_sent_time[i + 1];
    }

    return send_session->rtt;
}

/**
 * remove the sent packet timers
 * @param send_session
 * @param ackNo
 */
void remove_acked_packet_timers(udp_session *send_session, size_t ackNo){
    vector *sent_packet_timers = &send_session->sent_packet_timers;

    for (size_t acked_idx = send_session->last_packet_acked + 1; acked_idx <=
            ackNo;
         acked_idx++){
        for (size_t packet_idx = 0; packet_idx < sent_packet_timers->len;
             packet_idx++){
            timer *t = vec_get(sent_packet_timers, packet_idx);
            if (t->header->seqNo == acked_idx){
                vec_delete(sent_packet_timers, t);
            }
        }
    }

    return;
}

/**
 * repeat a sent udp packet
 * @param send_session
 * @param input
 * @param mysock
 */
void repeat_udp_packet_reliable(udp_session *send_session, handler_input
*input, int mysock){
    char *filebuf[UDP_MAX_PACK_SIZE];
    uint32_t read_packet_size, full_body_size, bytes_to_send, left_bytes;
    packet_h packet_header;
    packet_m *packet;
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);

    memset(filebuf, 0, UDP_MAX_PACK_SIZE);
    memset(&packet_header, 0, sizeof(packet_h));
    seek_to_packet_pos(send_session->f, send_session->chunk_index,
                       send_session->last_packet_acked);

    //todo: here only the lost packet should be re-send. otherwise this will
    // speed the re-transmission of the lost packet: one more one times of
    // subsequent packets will be acked.
    for (size_t i = send_session->last_packet_acked + 1; i <=
        send_session->last_packet_sent; i++){
        full_body_size = UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN;
        if (send_session->sent_bytes == CHUNK_LEN && i ==
                                                             send_session->last_packet_sent){
            bytes_to_send = CHUNK_LEN % full_body_size;
        }else{
            bytes_to_send = full_body_size;
        }
        read_packet_size = fread(filebuf, 1, bytes_to_send, send_session->f);
        build_packet_header(&packet_header, 15441, 1, 3,
                            PACK_HEADER_BASE_LEN, read_packet_size,
                            i,
                            send_session->last_packet_acked);
        packet = packet_message_builder(&packet_header, filebuf,
                                        read_packet_size);
        send_packet(ip_port->ip, ip_port->port, packet, mysock);
        fprintf(stdout, "Sent a repeating packet of packet number %ud\n", i);
        free(packet);

        if (i == (send_session->last_packet_acked + 1)){
            add_timer(&send_session->sent_packet_timers, ip_port->ip, ip_port->port,
                      &packet_header, filebuf, read_packet_size);
        }
    }

    return;
}

/**
 * handle received duplicate ACK handle. Initiate crash recovery if necessary
 * @param send_session
 * @param input
 * @param send_data_session
 */
void handle_duplicate_ack_packet(udp_session *send_session, handler_input *
input, send_data_sessions *send_data_session){
    ip_port_t *ip_port = parse_peer_ip_port(&input->from_ip);
    send_session->dup_ack++;
    delete_timer_of_ackNo(&send_session->sent_packet_timers, ip_port->ip, ip_port->port,
                          send_session->last_packet_acked);

    if (send_session->dup_ack > MAXIMUM_DUP_ACK){
        decrease_ss_threshold_and_window_size(send_session);
        fprintf(stderr, "One packet has been lost at peer with ip %s, port: "
                        "%d\n",
                send_session->ip, send_session->port);
    }
    repeat_udp_packet_reliable(send_session, input, send_data_session->mysock);

    return;
}

/**
 * decrease the slow start threshold and sending window size
 *
 * @param send_session
 */
void decrease_ss_threshold_and_window_size(udp_session *send_session){
    uint8_t half_thres = send_session->ss_threshold / 2;
    send_session->ss_threshold = half_thres > 2?half_thres:2;
    send_session->send_window_size = 1;
    send_session->conn_state = SLOW_START;

    return;
}

/**
 * when a peer is crashed, this function will recover through request the
 * chunk from another peer. If the crashed peer is the only peer owning the
 * chunk, then the job will stop.
 * @param send_session
 * @param job
 */
void recover_from_crashed_peer(udp_session *send_session, job_t *job){
    vector *sorted_peer_ids_for_chunks = job->sorted_peer_ids_for_chunks;

    if (sorted_peer_ids_for_chunks->len == 1){
        fprintf(stderr, "The only peer owning chunk with hash %s is crashed. "
                "The job stops here \n", send_session->chunk_hash);
    }
    for (size_t i = 0; i < sorted_peer_ids_for_chunks->len; i++) {
        chunk_dis *peer_ids_for_a_chunk = vec_get(sorted_peer_ids_for_chunks, i);
        if (!strcmp(peer_ids_for_a_chunk->msg, send_session->chunk_hash)){
            char *chunk_hash = peer_ids_for_a_chunk->msg;
            size_t peer_id = *(int *) vec_get(&peer_ids_for_a_chunk->idx,
                                              peer_ids_for_a_chunk->cur_idx++);
            if (!udp_recv_session_exists(job->recv_sessions, peer_id)) {
                send_get_request(job, chunk_hash, peer_id);
            } else {
                if (i != (sorted_peer_ids_for_chunks->len - 1)){
                    continue;
                }else{
                    request_t *req = build_request(chunk_hash, peer_id, job->peers);
                    vec_add(job->queued_requests, req);
                    free(req);
                }
            }
        }
    }

    vec_delete(job->send_sessions, send_session);
    return;
}

/**
 * once received a complete chunk of data, copy to the buffer in job
 * @param recv_session
 * @param job
 */
void copy_chunk_2_job_buf(udp_recv_session *recv_session, job_t *job, int
chunk_to_download_id){
    vector *chunks_to_download = job->chunks_to_download;
    recv_session->data_complete = 1;
    chunk_to_download *chunk = vec_get(chunks_to_download,
                                       chunk_to_download_id);

    chunk->chunk = Malloc(CHUNK_LEN);
    memset(chunk->chunk, 0, CHUNK_LEN);
    memcpy(chunk->chunk, recv_session->data, CHUNK_LEN);
    fprintf(stdout, "Copied chunk from session buffer to job "
            "buffer");
    return;
}
