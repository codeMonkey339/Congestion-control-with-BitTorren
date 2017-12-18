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
#include "reliable_udp.h"


/**
 * initialize the job struct with necessary information
 * @param chunkfile
 * @param outputfile
 * @param config
 */
job_t* job_init(char *chunkfile, char *outputfile, bt_config_t *config){
    vector v1, v2;
    job_t *job = (job_t*)Malloc(sizeof(job_t));
    memset(job, 0, sizeof(job_t));

    job->chunks_to_download = (vector*)Malloc(sizeof(vector));
    job->ihave_msgs = (vector*)Malloc(sizeof(vector));
    job->recv_sessions = (vector*)Malloc(sizeof(udp_recv_session));
    job->send_sessions = (vector*)Malloc(sizeof(udp_session));
    job->queued_requests = (vector*)Malloc(sizeof(request_t));
    //todo: make a deep copy of the peers
    job->who_has_timers = (vector*)Malloc(sizeof(vector));
    strcpy(job->has_chunk_file, config->has_chunk_file);
    strcpy(job->master_chunk_file, config->chunk_file);
    strcpy(job->outputfile, outputfile);
    get_masterfile(job->master_data_file, job->master_chunk_file);
    job->mysock = config->mysock;
    job->identity = config->identity;
    job->peers = &config->peer->peer;
    init_vector(&v1, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    init_vector(job->chunks_to_download, sizeof(chunk_to_download));
    init_vector(job->ihave_msgs, sizeof(ihave_t));
    init_vector(job->recv_sessions, sizeof(udp_recv_session));
    init_vector(job->send_sessions, sizeof(udp_session));
    init_vector(job->queued_requests, sizeof(request_t));
    init_vector(job->who_has_timers, sizeof(timer));

    read_chunk(chunkfile, &v1);
    read_chunk(config->has_chunk_file, &v2);
    vector *diff_chunk_hash = vec_diff(&v1, &v2);
    vector *common_chunk_hash = vec_common(&v1, &v2);
    vector *chunks_to_download = job->chunks_to_download;
    populate_chunks_to_download(chunks_to_download, &v1, common_chunk_hash,
                                job);



    vec_free(diff_chunk_hash);
    free(diff_chunk_hash);
    vec_free(common_chunk_hash);
    free(common_chunk_hash);
    return job;
}

/**
 * fill chunks information into the chunks_to_download vector
 * @param chunks_to_download
 * @param v1
 * @param common_chunk_hash
 * @param job
 */
void populate_chunks_to_download(vector *chunks_to_download, vector *v1, vector
*common_chunk_hash, job_t *job){
    for (size_t i = 0; i < v1->len; i++){
        chunk_to_download ch;
        char *chunk_hash = vec_get(v1, 1);
        memset(&ch, 0, sizeof(chunk_to_download));

        strcpy(ch.chunk_hash, vec_get(v1, i));
        ch.chunk_id = find_chunk_idx_from_hash(ch.chunk_hash,
                                               job->master_chunk_file);
        for (size_t j = 0; j < common_chunk_hash->len; j++){
            if(!strcmp(ch.chunk_hash, vec_get(common_chunk_hash, j))){
                ch.own = 1;
            }
        }
        vec_add(chunks_to_download, &ch);
    }

    return;
}

/**
 * de-initialize the job struct
 * @param job
 */
void job_deinit(job_t *job){
    /*todo: de-intialize the job struct
     * 1. de-initialize chunks_to_download
     * 2. release all the allocated vector memeory
     * */
}


/**
 * find the masterfile name in chunk_file and copy into masterfile
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
            free(line);
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
        add_timer(job->who_has_timers, peer->ip, peer->port, &header,
                  query_msg, strlen(query_msg));
        free(packet);
    }
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

    if (!strncmp(chunk_hash, calculated_chunk_hash, strlen(calculated_chunk_hash))){
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
        if (chunk->own){
            copy_local_chunk(chunk, job);
        }
        fwrite(chunk->chunk, 1, CHUNK_LEN, newfile);
    }
    fclose(newfile);
    return;
}

/**
 * copy the chunk with chunk->chunk_hash from master data file to chunk->chunk
 * @param chunk
 * @param job
 */
void copy_local_chunk(chunk_to_download *chunk, job_t *job){
    FILE *f = Fopen(job->master_data_file, "r");
    seek_to_chunk_pos(f, chunk->chunk_id);

    chunk->chunk = Malloc(CHUNK_LEN);
    fread(f, 1, CHUNK_LEN, chunk->chunk);

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
    strcpy(req->chunk, get_query->body);

    free(get_query->body);
    free(get_query);
    return req;
}

/**
 * check out timeouts and handle accordingly
 * @param config
 */
void check_timer(bt_config_t *config){
    check_whohas_timers(config);

}


void check_whohas_timers(bt_config_t *config){
    job_t *job = config->job;
    if (job->who_has_timers->len == 0){
        return;
    }else{
        clock_t  cur_time = clock();
        vector *timers = job->who_has_timers;
        while(1){
            int i = 0;
            for (; i < timers->len; i++){
                timer *timer = vec_get(timers, i);
                clock_t time_diff = cur_time - timer->start;
                if (time_diff / 1000 >= WHOHAS_TIMEOUT_TIME){
                    //only remove timer in the job, not in config?
                    //todo: move timer and peer_utils   
                    remove_peer_by_id(job->peers, timer->peer_id);
                    remove_timer(timers, timer);
                    break;
                }
            }
            if (i == timers->len){
                // no more timers to remove
                break;
            }
        }
    }
    return;
}




/**
 * remove a peer from the peer list by its id
 * @param job
 * @param peer_id
 */
void remove_peer_by_id(vector *peers, size_t peer_id){
    for (size_t i = 0; i < peers->len; i++){
        peer_info_t *peer = vec_get(peers, i);
        if (peer->id == peer_id){
            vec_delete(peers, i);
            break;
        }
    }

    return;
}
