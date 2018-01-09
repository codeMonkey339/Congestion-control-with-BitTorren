#ifndef __PEER_UTILS_
#define __PEER_UTILS_

#include "utility.h"


typedef struct peer_info{
    int id;
    char ip[IP_STR_LEN];
    int port;
}peer_info_t;


int get_peer_id(ip_port_t *iip_port, vector *peers);
peer_info_t *get_peer_info_from_id(vector *peers, int idx);
ip_port_t *convert_peer_info_2_ip_port(peer_info_t *peer_info);
void remove_peer_by_id(vector *peers, size_t peer_id);
ip_port_t *build_ip_port(char *ip, int port, ip_port_t *ip_port);
void remove_peer(vector *peers, timer *timer);
#endif