/*
 * reliable_udp.h
 * Initial Authoer: justin <justinyang339@yahoo.com>
 *
 * implements reliable communication protocol ontop of udp
 *
 * provide features similar to TCP, but implemented ontop of udp
 */

#include <sys/socket.h>
#include <netinet/in.h>

#ifndef _RELIABLE_UDP_H
#define _RELIABLE_UDP_H


void send_udp_packet(struct sockaddr_in to, socklen_t tolen, char *msg);
void send_udp_packet_r(struct sockaddr_in to, socklen_t tolen, char *msg);
#endif /* _RELIABLE_UDP_H */
