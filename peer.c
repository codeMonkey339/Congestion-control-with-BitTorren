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




/*
 * peers_t *peers: a pointer to all peers
 * int idx: the index of the queries peer
 *
 * given a peer index, this function will return the information about that peer
 */
peer_info_t *get_peer_info(peers_t *peers, int idx) {
    peer_info_t *p;
    for (int i = 0; i < peers->peer.len; i++) {
        p = (peer_info_t *) vec_get(&peers->peer, i);
        if (p->id == idx) {
            break;
        }
    }
    return p;
}

/*
  find the peer information based on given ip & sock
 */
peer_info_t *find_peer_from_list(peers_t *peers, char *ip, int sock) {
    peer_info_t *p;
    for (int i = 0; i < peers->peer.len; i++) {
        p = (peer_info_t *) vec_get(&peers->peer, i);
        if (!strcmp(ip, p->ip) && sock == p->port) {
            return p;
        }
    }
    return NULL;
}


/*
 * bt_config_t *config: the config struct
 * char *chunk_msg: the chunk hash
 * int peer_idx: index of the peer
 * vector *chunk_data: the vector that will hold chunk data
 */
int
request_chunk(bt_config_t *config, char *chunk_msg, int peer_idx, int force) {
    packet_h header;
    char *query = (char *) malloc(strlen("GET") + CHUNK_HASH_SIZE + 2), *packet;
    int timer_exists = 0;
    memset(query, 0, strlen("GET") + CHUNK_HASH_SIZE + 2);
    strcat(query, "GET ");
    strcat(query, chunk_msg);
    build_header(&header, 15441, 1, 2, PACK_HEADER_BASE_LEN,
                 PACK_HEADER_BASE_LEN + strlen(query), 0, 0);
    packet = (char *) malloc(PACK_HEADER_BASE_LEN + strlen(query));
    peer_info_t *peer = get_peer_info(config->peer, peer_idx);
    send_packet(peer->ip, peer->port, &header, query, config->mysock,
                strlen(query));

    for (int i = 0; i < config->get_timers.len; i++) {
        timer *t = (timer *) vec_get(&config->get_timers, i);
        if (!strcmp(t->ip, peer->ip) && t->sock == peer->port) {
            timer_exists = 1;
            break;
        }
    }
    if (force) { // force request for the chunk
        timer_exists = 0;
    }
    if (timer_exists) {
        // check queued up requests through timer may not be a good idea
        request_t r;
        strcpy(r.ip, peer->ip);
        r.port = peer->port;
        strcpy(r.chunk, query);
        vec_add(&config->request_queue, &r);
    } else {
        //todo: need to handle timeout situation
        add_timer(&config->get_timers, peer->ip, peer->port, NULL, query);
    }
    free(query);
    free(packet);
    return timer_exists;
}


/*
  todo:
  release all the memories occupies by timers
 */
void release_all_timers(bt_config_t *config) {
    vector *whohas = &config->whohas_timers;
    for (int i = 0; i < whohas->len; i++) {
        timer *t = vec_get(whohas, i);
        free(t->msg);
        free(vec_get(whohas, i));
    }
    return;
}


void release_all_dynamic_memory(bt_config_t *config) {
    /* free all the ihave messages */
    for (int i = 0; i < config->ihave_msgs.len; i++) {
        ihave_t *ihave = vec_get(&config->ihave_msgs, i);
        free(ihave->msg);
        for (int j = 0; j < ihave->chunk_num; j++) {
            free(ihave->chunks[j]);
        }
        free(ihave->chunks);
        free(ihave);
    }

    return;
}


/*
  make the functio more generic?
 */
void remove_timer(vector *cur_timer, char *ip, int sock) {
    timer *t;
    for (int i = 0; i < cur_timer->len; i++) {
        t = (timer *) vec_get(cur_timer, i);
        if (!strcmp(t->ip, ip) && t->sock == sock) {
            t->start = -1; /* only need to reset the start time */
            break;
        }
    }
    return;
}

int find_chunk_idx(char *chunk, char *chunk_file, char *masterfile) {
    FILE *f;
    char *line, line_backup[BT_FILENAME_LEN], *t;
    size_t line_len = 0;
    int idx, chunk_idx;
    if ((f = fopen(chunk_file, "r")) == NULL) {
        fprintf(stderr, "Failed to open chunk file %s\n", chunk_file);
        exit(1);
    }
    while (getline(&line, &line_len, f) != -1) {
        memset(line_backup, 0, BT_FILENAME_LEN);
        strcpy(line_backup, line);
        t = strtok(line_backup, " ");
        if (!isdigit(*t)) { /* the first line */
            t = strtok(NULL, " ");
            memset(masterfile, 0, BT_FILENAME_LEN);
            strcpy(masterfile, t);
            t = strtok(NULL, " "); /* there is a remaining hash line */
            if (t != NULL) {
                idx = *(int *) t;
                t = strtok(NULL, " ");
                if (!strcmp(t, chunk) || strstr(t, chunk) != NULL) {
                    chunk_idx = idx;
                    free(line);
                    break;
                }
            }
        } else { /* chunk hash line */
            idx = atoi(t);
            t = strtok(NULL, " ");
            if (!strcmp(t, chunk) || strstr(t, chunk) != NULL) {
                chunk_idx = idx;
                free(line);
                break;
            }
        }
        free(line);
        line = NULL;
        line_len = 0;
    }
    return chunk_idx;
}


/*
  need to send DATA packet through reliable communication

  Chunk File: i.e c.masterchunks
  File: <path to the file which neeeds sharing>
  Chunks:
  id chunk-hash

  How to handle acknolwegement packet?
  main a session for each peer, extract sending data packet into a new function.

  the sequence number always starts with 1 for a new "GET" connection
  should not combine DATA packet and ACK packet. A DATA packet should
  not contain ACK, and vice versa

  GET packets don't have to be transmitted through reliabe
  transmission

  Each peer can only have 1 simultaneous download from any other peer
  in the network, meaning that IP address and UDP port will uniquely
  determine which download a DATA packet belongs to --> save the
  trouble demultiplexing packets!

  todo:
  1. what to do if no slot within the window?
*/
void process_peer_get(int sock, char *buf, struct sockaddr_in from,
                      socklen_t fromlen, int BUFLEN,
                      bt_config_t *config, packet_h *header) {
    FILE *f1;
    char *buf_backup = (char *) malloc(
            strlen(buf) + 1), *token, masterfile[BT_FILENAME_LEN], *from_ip;
    int chunk_idx;
    udp_session *session = NULL;
    short port = ntohs(from.sin_port);
    memset(buf_backup, 0, strlen(buf) + 1);
    strcpy(buf_backup, buf);
    from_ip = inet_ntoa(from.sin_addr);
    short session_exist = 1;

    if ((session = find_session(from_ip, port, &config->sessions)) == NULL) {
        session = (udp_session *) malloc(sizeof(udp_session));
        memset(session, 0, sizeof(udp_session));
        session_exist = 0;
    } else {
        /*
          todo:
          should accept only 1 simultaneous connection from a particular host
          send a DENIED packet
         */
        free(buf_backup);
        return;
    }

    token = strtok(buf_backup, " ");
    token = strtok(NULL, " "); /* token pointers to chunk hash */
    chunk_idx = find_chunk_idx(token, config->chunk_file, masterfile);
    if ((f1 = fopen(masterfile, "r")) == NULL) {
        fprintf(stderr, "Cannot open master chunk file %s \n", masterfile);
        exit(1);
    }
    // debug purpose
    uint32_t offset = chunk_idx * CHUNK_LEN;
    char *buffer = (char *) malloc(CHUNK_LEN);
    fseek(f1, offset, SEEK_SET);
    fread(buffer, 1, CHUNK_LEN, f1);
    char *new_chunk_hash = get_chunk_hash(buffer, CHUNK_LEN);
    if (strcmp(new_chunk_hash, token)) {
        fprintf(stderr, "unmatched hash, %s\n", new_chunk_hash);
    }
    if (session->f == NULL) { // init session struct
        init_session(session, 8, 8, config->identity, 0, f1, from_ip, port);
    }
    session->chunk_index = chunk_idx;
    send_udp_packet_r(session, from_ip, port, config->mysock, 0);
    if (!session_exist) {
        vec_add(&config->sessions, session);
        free(session);
    }
    return;
}

/*
  Based on acknowledgements from peers, take next step actions
*/
void
process_ack(int sock, char *buf, struct sockaddr_in from, socklen_t fromLen,
            int BUFLEN, bt_config_t *config, packet_h *header) {
    char *from_ip = inet_ntoa(from.sin_addr), file_buf[UDP_MAX_PACK_SIZE];
    short port = ntohs(from.sin_port);
    memset(file_buf, 0, UDP_MAX_PACK_SIZE);
    udp_session *session = find_session(from_ip, port, &config->sessions);
    if (header->ackNo == (uint32_t) (session->last_packet_acked + 1)) {
        session->last_packet_acked++;
        session->dup_ack = 0;
        if (session->sent_bytes >= CHUNK_LEN) {
            if (session->last_packet_acked == session->last_packet_sent) {
                vec_delete(&config->sessions, session);
            }
        } else {
            fseek(session->f, session->chunk_index * CHUNK_LEN + header->ackNo *
                                                                 (UDP_MAX_PACK_SIZE -
                                                                  PACK_HEADER_BASE_LEN),
                  SEEK_SET);
            send_udp_packet_r(session, from_ip, port, config->mysock, 0);
        }
    } else if (header->ackNo == (uint32_t) (session->last_packet_sent)) {
        /* current repeat times is 5 */
        session->dup_ack++;
        if (session->dup_ack > 5) {
            // todo: the peer is crashes, how to recover?
        } else {
            fseek(session->f, session->chunk_index * CHUNK_LEN +
                              session->last_packet_acked *
                              (UDP_MAX_PACK_SIZE - PACK_HEADER_BASE_LEN),
                  SEEK_SET);
            send_udp_packet_r(session, from_ip, port, config->mysock, 1);
        }
    }
    return;
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
        process_whohas_packet(input, config->job);
    } else if (header->packType == IHAVE) {
        process_ihave_packet(input, config->job);
    } else if (header->packType == GET) {
        process_get_packet(input, config->job);
    } else if (header->packType == DATA) {
        process_data_packet(input, config->job);
    } else if (header->packType == DENIED) {
        process_ack(sock, buf + header->headerLen, from, fromlen, BUFLEN,
                    config,
                    header);
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
    init_vector(&config->ihave_msgs, sizeof(ihave_t));
    init_vector(&peers->peer, sizeof(peer_info_t));
    init_vector(&config->sessions, sizeof(udp_session));
    init_vector(&config->desired_chunks, CHUNK_HASH_SIZE);
    init_vector(&config->recv_sessions, sizeof(udp_recv_session));
    init_vector(&config->data, sizeof(data_t));
    if ((f = fopen(peer_list_file, "r")) == NULL) {
        fprintf(stderr, "Failed to open peer_list_file %s\n", peer_list_file);
        return NULL;
    }

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
            /* insert the ihave element into vector */
            ihave_t *ihave = (ihave_t *) malloc(sizeof(ihave_t));
            vec_add(&config->ihave_msgs, ihave);
        } else {
            // comment line, do nothing here
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
void process_get(char *chunkfile, char *outputfile, bt_config_t *config) {
    config->job = job_init(chunkfile, outputfile, config);
    char *whohas_query = build_whohas_query(config->job->chunks_to_download);
    job_flood_whohas_msg(config->peers, whohas_query, config->job);
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
            process_get(chunkf, outf, config);
        }
    }
}


/*
 * checks all the timers stored in config. If there is any timeouts,
 * need to re-send the message.
 *
 * todo: need to remove the timer when the message has been received!
 */
void check_for_timeouts(bt_config_t *config) {
    // need to check timeouts in other sessions

    /* check for whohas timeouts */
    for (int i = 0; i < config->whohas_timers.len; i++) {
        clock_t cur = clock();
        timer *t = (timer *) vec_get(&config->whohas_timers, i);
        if (t->start > 0) { /* hasn't received message */
            if ((cur - t->start) * 1000 / CLOCKS_PER_SEC >=
                IHAVE_TIMEOUT_TIME) {
                t->repeat_times++;
                t->start = clock();
                //todo: need to send the message again!
                fprintf(stdout, "Sending the query to the peer again \n");
            }
        }
    }
    return;
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
 * clock is recorded. In the main loop, all timers will be checked
 * constantly to ensure all timeout timers are processed
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
        check_for_timeouts(config);
    }

    /* try to avoid double release */
    release_all_peers(config);
}
