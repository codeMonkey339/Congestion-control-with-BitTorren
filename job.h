#ifndef __JOB__
#define __JOB__
#include "constants.h"
/*
 * job module mainly handles things related to executing the download job
 * like handles timeout, peer crash
 * */

/* whether struct contains complete information to download a chunk */
typedef struct chunk_to_download{
    char chunk_hash[CHUNK_HASH_SIZE];
    /* the sorted peers which have the chunk */
    vector *has_chunk_peers;
    /* whether itself owns the chunk*/
    int own;
}chunk_to_download;

typedef struct job_t{
    vector *chunks_to_download;
    vector *chunks_to_copy_from_local;
    char *outputfile;
    char *has_chunk_file;
}job_t;

job_t* job_init(char *chunkfile, char *outputfile, bt_config_t *config);
void job_flood_whohas_msg(vector *peers, char *query_msg, job_t *job);
#endif