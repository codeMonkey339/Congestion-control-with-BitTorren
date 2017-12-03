/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 * Implemented by Justin: justinyang339@yahoo.com
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include <ctype.h>
#include <netdb.h>
#include "packet_handler.h"
#include "peer_utils.h"
#include "utility.h"

#define DEFAULT_CHUNK_SIZE 10

//#define CHUNK_HASH_SIZE 20 /* keep hash in string format */

#define CHUNK_NUM_PER_PACK ((UDP_MAX_PACK_SIZE - strlen("whohas") - sizeof(int)) / CHUNK_HASH_SIZE)


void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
    bt_config_t config;

    bt_init(&config, argc, argv);

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    if (debug & DEBUG_INIT) {
      bt_dump_config(&config);
    }
#endif

    peer_run(&config);
    return 0;
}


/**
 * entry point to process inbound udp packets, different types of packets
 * will handled separately
 * @param sock the socket that the current packet is received from
 * @param config config file of the current peer
 */
void process_inbound_udp(int sock, bt_config_t *config) {
#define BUFLEN 1500
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN], *buf_backup, *buf_backup_ptr;
    int recv_size = 0;

    memset(buf, 0, BUFLEN);
    fromlen = sizeof(from);
    recv_size = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)
            &from, &fromlen);
    buf_backup = (char *) Malloc(BUFLEN);
    memcpy(buf_backup, buf, BUFLEN);
    buf_backup_ptr = buf_backup;
    packet_h *header = parse_packet(&buf_backup);
    if (header == NULL) {
        fprintf(stderr, "Have received an invalid packet \n");
        return;
    }
    handler_input *input = build_handler_input(sock, buf + header->headerLen,
                                               &from, fromlen, BUFLEN,
                                               recv_size, header);
    if (header->packType == WHOHAS) {
        process_whohas_packet(input, config->has_chunk_file);
    } else if (header->packType == IHAVE) {
        process_ihave_packet(input, config->job);
    } else if (header->packType == GET) {
        //todo: 1. need to initialize a sending job here. 2. add another
        // level of abstraction: jobs since one peer can have multiple
        // connections
        process_get_packet(input, config->job);
    } else if (header->packType == DATA) {
        process_data_packet(input, config->job);
    } else if (header->packType == DENIED) {
        process_ack_packet(input, config->job);
    } else if (header->packType == 5) {
        //todo: denied packet
    } else {
        //todo: corrupted message
    }
    //todo: need to release correctly
    free(buf_backup_ptr);
    free(header);
    free(input);
    return;
}


/*
 * char *peer_list_file: a filename pointing to a file that contains
 * all peers
 * vector *ihave_msgs: a vector which will contain query messages
 *
 * when loading peers, need to exclude the peer itself
 */
peers_t *load_peers(bt_config_t *config) {
    FILE *f;
    char *line = NULL, *token, line_backup[100];
    size_t line_len;
    char *peer_list_file = config->peer_list_file;
    short peer_id;
    peers_t *peers = (peers_t *) malloc(sizeof(peers_t));
    config->peer = peers;
    init_vector(&peers->peer, sizeof(peer_info_t));
    f = Fopen(peer_list_file, "r");

    while (getline(&line, &line_len, f) != -1) {
        memset(line_backup, 0, 100);
        strcpy(line_backup, line);
        token = strtok(line_backup, " ");
        peer_id = atoi(token); /* any *token has to be a char */
        /*
          format of the peer info
          1 127.0.0.1 1111
         */
        if (*token != '#' && peer_id != config->identity) {
            peer_info_t *peer = (peer_info_t *) malloc(sizeof(peer_info_t));
            peer->id = peer_id;
            token = strtok(NULL, " ");
            strcpy(peer->ip, token);
            token = strtok(NULL, " ");
            peer->port = atoi(token);
            vec_add(&peers->peer, peer);
        } else {
            fprintf(stdout, "Read a comment line in node map.\n");
        }
        free(line);
        line = NULL;
        line_len = 0;
    }
    config->peer = peers;
    return peers;
}


/**
  need to parse user's command and send requests to server and
  peers
 * @param chunkfile file contains chunks to be downloaded
 * @param outputfile
 * @param config
 */
void process_commandline_get(char *chunkfile, char *outputfile,
                             bt_config_t *config) {
    config->job = job_init(chunkfile, outputfile, config);
    char *whohas_query = build_whohas_query(((job_t*)config->job)
                                                    ->chunks_to_download);
    job_flood_whohas_msg(&config->peer->peer, whohas_query, config->job);
    free(whohas_query);

    //todo: need to free the memory for job
    return;
}


/*
 * hanldes requests coming from both command & other peers
 *
 * for requests coming from command line in the format:
 * GET /tmp/B.chunks /tmp/newB.tar
 * this command will ask your peer to fetch all chunks listed in /tmp/B.chunks
 *
 * for requests coming from other peer:
 * @param line the commandline input from user console
 * @param cbdata
 * @param config the config of current peer
 */
void handle_user_input(char *line, void *cbdata, bt_config_t *config) {
    char chunkf[128], outf[128];

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));

    /*
      format specifier: "%120s" will read no more than 120 chars !
     */
    if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
        if (strlen(outf) > 0) {
            process_commandline_get(chunkf, outf, config);
        }
    }
}


void release_all_peers(bt_config_t *config) {
    for (int i = 0; i < config->peer->peer.len; i++) {
        free(vec_get(&config->peer->peer, i));
    }
    free(config->peer);


    return;
}

/*
 * main entry point for the work horse of the bittorrent peer
 * handles both incoming & outcoming communication
 *
 * Notes:
 *
 * Regarding timer & callback
 * there is a compromise made here on timer. Since no library is
 * provided to provide the utility of time out & callback. A crude
 * approach is employed here: when a request is sent, the current
 * clock is recorded. In the main loop, all sent_packet_timers will be checked
 * constantly to ensure all timeout sent_packet_timers are processed
 */
void peer_run(bt_config_t *config) {
    int sock;
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf *userbuf;

    if ((userbuf = create_userbuf()) == NULL) {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }
    /* open UDP port instead of TCP port */
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        perror("peer_run could not create socket");
        exit(-1);
    }

    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);
    //test_vec();
    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
        perror("peer_run could not bind socket");
        exit(-1);
    }

    config->mysock = sock;
    /* load peer should be moved to a proper place */
    if (load_peers(config) == NULL) {
        fprintf(stderr, "Error loading peers from peer file \n");
        exit(1);
    }
    spiffy_init(config->identity, (struct sockaddr *) &myaddr, sizeof(myaddr));

    while (1) {
        int nfds;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        nfds = select(sock + 1, &readfds, NULL, NULL, NULL);
        if (nfds > 0) {
            if (FD_ISSET(sock, &readfds)) {
                process_inbound_udp(sock, config);
            }

            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                                   "Currently unused", config);
            }
        }
    }

    /* try to avoid double release */
    release_all_peers(config);
}
