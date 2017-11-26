#include "job.h"
#include "packet.h"
#include "utility.h"
#include <stdio.h>
#include "chunk.h"
#include <stdlib.h>
#include <string.h>
#include "packet_handler.h"
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
    job->chunks_to_copy_from_local = (vector*)Malloc(sizeof(vector));
    job->ihave_msgs = (vector*)Malloc(sizeof(vector));
    job->recv_sessions = (udp_recv_session*)Malloc(sizeof(udp_recv_session));
    job->send_sessions = (udp_session*)Malloc(sizeof(udp_session));
    strcpy(job->has_chunk_file, config->has_chunk_file);
    get_masterfile(job->masterfile, job->has_chunk_file);
    job->mysock = config->mysock;
    job->peers = &config->peer->peer;
    job->identity = config->identity;
    init_vector(&v1, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    init_vector(job->chunks_to_download, sizeof(chunk_to_download));
    init_vector(job->chunks_to_copy_from_local, sizeof(chunk_to_download));
    init_vector(job->ihave_msgs, sizeof(ihave_t));
    init_vector(job->recv_sessions, sizeof(udp_recv_session));
    init_vector(job->send_sessions, sizeof(udp_session));

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
    vector *chunks_to_copy_from_local = job->chunks_to_copy_from_local;

    for (int i = 0;i < diff_chunk_hash->len; i++){
        chunk_to_download ch;
        memset(&ch, 0, sizeof(chunk_to_download));
        strcpy(ch.chunk_hash, vec_get(diff_chunk_hash, i));
        ch.own = 0;
        vec_add(chunks_to_download, &ch);
    }
    for (int i = 0; i < common_chunk_hash->len; i++){
        chunk_to_download ch;
        memset(&ch, 0, sizeof(chunk_to_download));
        strcpy(ch.chunk_hash, vec_get(common_chunk_hash, i));
        ch.own = 1;
        vec_add(chunks_to_copy_from_local, &ch);
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
    //todo: de-intialize the job struct
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
