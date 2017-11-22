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