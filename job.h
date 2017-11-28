#ifndef __JOB__
#define __JOB__
#include "constants.h"
#include "utility.h"
#include "bt_parse.h"
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
    char *chunk;
}chunk_to_download;

typedef struct job_t{
    vector *chunks_to_download;
    vector *recv_sessions;
    vector *send_sessions;
    vector *queued_requests;
    /* a list of peers */
    vector *peers;
    /* contains all IHAVE messages received */
    vector *ihave_msgs;
    char outputfile[BT_FILENAME_LEN];
    char masterfile[BT_FILENAME_LEN];
    char has_chunk_file[BT_FILENAME_LEN];
    /* socket the current peer uses */
    int mysock;
    /* peer id for self */
    uint8_t identity;
}job_t;

typedef struct request{
    char ip[IP_STR_LEN];
    int port;
    char chunk[CHUNK_HASH_SIZE + 5];
} request_t;


job_t* job_init(char *chunkfile, char *outputfile, bt_config_t *config);
void job_flood_whohas_msg(vector *peers, char *query_msg, job_t *job);
void job_deinit(job_t *job);
void get_masterfile(char *masterfile, char *hash_chunk_file);
void copy_chunk_2_job_buf(udp_recv_session *recv_session, job_t *job, int
chunk_to_download_id);
int get_chunk_to_download_id(char *chunk_hash, vector *chunks_to_download);
int verify_hash(char *chunk_hash, char *data);
int check_all_chunks_received(vector *chunks_to_download);
void write_data_outputfile(job_t *job, char *outputfile);
request_t *build_request(char *chunk_hash, size_t peer_id, vector *peers);
#endif