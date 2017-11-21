#include "packet_handler.h"
#include "packet.h"

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
 * builder for the handler_input struct
 * @param incoming_socket
 * @param body_buf
 * @param from_ip
 * @param from_len
 * @param buf_len
 * @param recv_size
 * @param header
 * @param job
 * @return
 */
handler_input * build_handler_input(uint16_t incoming_socket, char *body_buf,
                                    struct socket_in *from_ip, socket_t
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
    return;
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

}

void process_whohas(handler_input *input, job_t *job){
    FILE *f;
    packet_h reply_header;
    vector v, v2, *common_hashes;
    char *reply, ip[IP_STR_LEN];
    int reply_len = 0, hash_len = 0, buf_size = BUFLEN, has_num = 0, port;

    init_vector(&v, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    read_chunk(job->has_chunk_file, &v);
    parse_whohas_packet(input->body_buf, &v2);
    common_hashes = vec_common(&v, &v2);
    reply = build_ihave_reply(common_hashes);
    build_packet_header(&reply_header, 15441, 1, 1, PACK_HEADER_BASE_LEN,
                        PACK_HEADER_BASE_LEN + strlen(reply), 0, 0);
    //todo: need to find a proper way to place the ip/port handling


}