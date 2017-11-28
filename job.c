#include "job.h"
#include "packet.h"
#include "utility.h"
#include <stdio.h>
#include "chunk.h"
#include <stdlib.h>
#include <string.h>
#include "packet_handler.h"
#include "peer_utils.h"
#include <ctype.h>


/**
 * initialize the job struct with necessary information
 * @param chunkfile
 * @param outputfile
 * @param config
 */
job_t* job_init(char *chunkfile, char *outputfile, bt_config_t *config){
    FILE *f1, *f2;
    vector v1, v2;
    job_t *job = (job_t*)Malloc(sizeof(job_t));
    memset(job, 0, sizeof(job_t));

    job->chunks_to_download = (vector*)Malloc(sizeof(vector));
    job->ihave_msgs = (vector*)Malloc(sizeof(vector));
    job->recv_sessions = (vector*)Malloc(sizeof(udp_recv_session));
    job->send_sessions = (vector*)Malloc(sizeof(udp_session));
    job->queued_requests = (vector*)Malloc(sizeof(request_t));
    strcpy(job->has_chunk_file, config->has_chunk_file);
    get_masterfile(job->masterfile, job->has_chunk_file);
    job->mysock = config->mysock;
    job->peers = &config->peer->peer;
    job->identity = config->identity;
    init_vector(&v1, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    init_vector(job->chunks_to_download, sizeof(chunk_to_download));
    init_vector(job->ihave_msgs, sizeof(ihave_t));
    init_vector(job->recv_sessions, sizeof(udp_recv_session));
    init_vector(job->send_sessions, sizeof(udp_session));
    init_vector(job->queued_requests, sizeof(request_t));

    if ((f1 = fopen(chunkfile, "r")) == NULL){
        fprintf(stderr, "Error opening chunkfile %s \n", chunkfile);
        exit(-1);
    }
    if ((f2 = fopen(config->has_chunk_file, "r")) == NULL){
        fprintf(stderr, "Error opening has_chunk_file %s\n",
                config->has_chunk_file);
        exit(-1);
    }

    read_chunk(f1, &v1);
    read_chunk(f2, &v2);
    vector *diff_chunk_hash = vec_diff(&v1, &v2);
    vector *common_chunk_hash = vec_common(&v1, &v2);
    vector *chunks_to_download = job->chunks_to_download;

    for (size_t i = 0; i < v1.len; i++){
        chunk_to_download ch;
        memset(&ch, 0, sizeof(chunk_to_download));
        strcpy(ch.chunk_hash, vec_get(&v1, i));

        for (size_t j = 0; j < common_chunk_hash->len; j++){
            if(!strcmp(ch.chunk_hash, vec_get(common_chunk_hash, j))){
                ch.own = 1;
            }
        }
        vec_add(chunks_to_download, &ch);
    }

    strcpy(job->outputfile, outputfile);



    vec_free(diff_chunk_hash);
    free(diff_chunk_hash);
    vec_free(common_chunk_hash);
    free(common_chunk_hash);
    return job;
}

/**
 * de-initialize the job struct
 * @param job
 */
void job_deinit(job_t *job){
    /*todo: de-intialize the job struct
     * 1. de-initialize chunks_to_download
     * */
}


/**
 * find the masterfile name in hash_chunk_file and copy into masterfile
 * @param masterfile
 * @param hash_chunk_file
 */
void get_masterfile(char *masterfile, char *hash_chunk_file){
    FILE *f;
    char *line, line_backup[BT_FILENAME_LEN], *t;
    size_t line_len = 0;

    f = Fopen(hash_chunk_file, "r");
    while (getline(&line, &line_len, f) != -1) {
        memset(line_backup, 0, BT_FILENAME_LEN);
        strcpy(line_backup, line);
        t = strtok(line_backup, " ");
        if (!isdigit(*t)) { /* the first line */
            t = strtok(NULL, " ");
            memset(masterfile, 0, BT_FILENAME_LEN);
            strcpy(masterfile, t);
            break;
        }
        free(line);
        line = NULL;
        line_len = 0;
    }
    return;
}


/**
 * flood whohas messages to all peers
 * @param peers
 * @param query_msg
 * @param job
 */
void job_flood_whohas_msg(vector *peers, char *query_msg, job_t *job){
    packet_h header;
    build_packet_header(&header, 15441, 1, 0, PACK_HEADER_BASE_LEN,
                        PACK_HEADER_BASE_LEN + strlen(query_msg), 0, 0);
    for (int i = 0;i < peers->len; i++){
        peer_info_t *peer = (peer_info_t*)vec_get(peers, i);
        /* strlen can be used here to find the body length */
        packet_m *packet = packet_message_builder(&header, query_msg, strlen
                (query_msg));
        send_packet(peer->ip, peer->port, packet, job->mysock);
        free(packet);
    }
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




/**
 * find the index of the chunk hash in vector chunks_to_download
 * @param chunk_hash
 * @param chunks_to_download
 * @return
 */
int get_chunk_to_download_id(char *chunk_hash, vector *chunks_to_download){
    for (size_t i = 0; i < chunks_to_download->len; i++){
        chunk_to_download *chunk = (chunk_to_download*)vec_get
                (chunks_to_download, i);
        if(!strcmp(chunk->chunk_hash, chunk_hash)){
            return i;
        }
    }

    return -1;
}

/**
 * verify that calculated hash from data matches that of the given hash
 * @param chunk_hash
 * @param data
 * @return
 */
int verify_hash(char *chunk_hash, char *data){
    char *calculated_chunk_hash = get_chunk_hash(data, CHUNK_LEN);

    if (!strcmp(chunk_hash, calculated_chunk_hash)){
        free(calculated_chunk_hash);
        return 0;
    }else{
        free(calculated_chunk_hash);
        return 1;
    }
}

/**
 * check whether all chunks to be downloaded have been downloaded
 * @param chunks_to_download
 * @return
 */
int check_all_chunks_received(vector *chunks_to_download){
    int all_chunks_received = 0;
    for (size_t i = 0; i < chunks_to_download->len; i++){
        chunk_to_download *chunk = vec_get(chunks_to_download, i);
        if (chunk->own){
            continue;
        }else{
            if (chunk->chunk != NULL){
                continue;
            }else{
                all_chunks_received = 1;
                break;
            }
        }
    }

    return all_chunks_received;
}

/**
 * write all received chunks into the outputfile
 * @param job
 * @param outputfile
 */
void write_data_outputfile(job_t *job, char *outputfile){
    FILE *newfile = Fopen(outputfile, "w");

    for(size_t i = 0; i < job->chunks_to_download->len; i++){
        chunk_to_download *chunk = vec_get(job->chunks_to_download, i);
        fwrite(chunk->chunk, 1, CHUNK_LEN, newfile);
    }

    return;
}

/**
 * build a request struct given relevant info
 * @param chunk_hash
 * @param peer_id
 * @param peers
 * @return
 */
request_t *build_request(char *chunk_hash, size_t peer_id, vector *peers){
    packet_b *get_query = build_get_request_body(chunk_hash);
    request_t *req = Malloc(sizeof(request_t));
    peer_info_t *peer_info = get_peer_info_from_id(peers, peer_id);
    strcpy(req->ip, peer_info->ip);
    req->port = peer_info->port;
    strcpy(req->chunk, get_query);

    free(get_query);
    return  get_query;
}