#include "peer_utils.h"
#include "utility.h"
#include "string.h"

/**
 * get the index of the input peer
 * @param ip_port
 * @param peers
 * @return index of the input peer, or -1 on error
 */
int get_peer_id(ip_port_t *ip_port, vector *peers){
    for (size_t i = 0; i < peers->len; i++){
        peer_info_t *peer = (peer_info_t*)vec_get(peers, i);
        if (!strcmp(peer->ip, ip_port->ip) && peer->port == ip_port->port){
            return i;
        }
    }
    fprintf(stderr, "Cannot find a peer with ip %ip & port %d port",
            ip_port->ip, ip_port->port);
    return -1;
}

/**
 * given the input peer id, return the peer_info_t struct
 * @param peers
 * @param idx
 * @return
 */
peer_info_t *get_peer_info_from_id(vector *peers, int idx){
    peer_info_t *p;
    for (int i = 0; i < peers->len ;i++){
        p = (peer_info_t*)vec_get(peers, i);
        if (p->id == idx){
            break;
        }
    }
    return p;
}


/**
 * convert input peer_info_t to to ip_port_t
 * @param peer_info_t
 * @return
 */
ip_port_t *convert_peer_info_2_ip_port(peer_info_t *peer_info){
    ip_port_t *ip_port = (ip_port_t*)Malloc(sizeof(ip_port_t));
    memset(ip_port->ip, 0, IP_STR_LEN);
    strcpy(ip_port->ip, peer_info->ip);
    ip_port->port = peer_info->port;
    return ip_port;
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
            vec_delete(peers, peer);
            break;
        }
    }

    return;
}


/**
 * remove a peer from the peer list, regardless of the means
 * @param peers
 * @param timer
 */
void remove_peer(vector *peers, timer *timer){
    ip_port_t ip_port;
    build_ip_port(timer->ip, timer->port, &ip_port);

    for (size_t i = 0; i < peers->len; i++){
        peer_info_t *peer = vec_get(peers, i);
        if (strcmp(peer->ip, ip_port.ip) == 0 && peer->port == ip_port.port){
            vec_delete(peers, peer);
            break;
        }
    }
}


/**
 * helper for building ip_port struct
 * @param ip
 * @param port
 * @param ip_port
 * @return
 */
ip_port_t *build_ip_port(char *ip, int port, ip_port_t *ip_port){
    strcpy(ip_port->ip, ip);
    ip_port->port = port;

    return ip_port;
}