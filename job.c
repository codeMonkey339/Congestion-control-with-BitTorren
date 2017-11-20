#include "job.h"
#include "packet.h"

/**
 * initialize the job struct with necessary information
 * @param chunkfile
 * @param outputfile
 * @param config
 */
job_t* job_init(char *chunkfile, char *outputfile, bt_config_t *config){
    FILE *f1, *f2;
    vector v1, v2;
    job_t *job = (job_t*)malloc(sizeof(job_t));
    memset(job, 0, sizeof(job_t));

    job->chunks_to_download = (vector*)malloc(sizeof(vector));
    job->chunks_to_copy_from_local = (vector*)malloc(sizeof(vector));
    init_vector(&v1, CHUNK_HASH_SIZE);
    init_vector(&v2, CHUNK_HASH_SIZE);
    init_vector(job->chunks_to_download, sizeof(chunk_to_download));
    init_vector(job->chunks_to_copy_from_local, sizeof(chunk_to_download));



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
    job->outputfile = (char*)malloc(strlen(outputfile) + 1);
    strcpy(job->outputfile, outputfile);


    vec_free(diff_chunk_hash);
    free(diff_chunk_hash);
    vec_free(common_chunk_hash);
    free(common_chunk_hash);
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
        peer_info_t *peer = (peer_info_t*)vec_get(&peers->peer, i);
        /* strlen can be used here to find the body length */
        packet_m *packet = packet_message_builder(&header, query, strlen
                (query));
        send_packet(peer->ip, peer->port, packet);
        free(packet);
    }
    return;
}