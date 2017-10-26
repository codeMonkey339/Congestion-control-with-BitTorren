#include "reliable_udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "utility.h"
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>

/*
 * char *msg: the message to send to destination address
 *
 * send a message through udp procotol
 */
void send_udp_packet(char *ip, int port_no, char *msg){
    char port[PORT_LEN];
    struct addrinfo hints, *res = NULL;
    int sock;
    memset(&hints, 0, sizeof(hints));
    memset(port, 0, PORT_LEN);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    sprintf(port, "%d", port_no);
    int err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0){
      fprintf(stderr, "Failed to resolve remote socket address (err = %d)", err);
      exit(-1);
    }
    if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1){
      fprintf(stderr, "Failed to create the UDP socket");
      exit(-1);
    }
    if (sendto(sock, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen) == -1){
      fprintf(stderr, "Failed to send UDP data (err = %s) \n", strerror(errno));
      exit(-1);
    }
    return;
}


void send_udp_packet_with_sock(char *ip, int port_no, char *msg, int sock, int size){
    char port[PORT_LEN];
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    memset(port, 0, PORT_LEN);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    sprintf(port, "%d", port_no);
    int err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0){
      fprintf(stderr, "Failed to resolve remote socket address (err = %d)", err);
      exit(-1);
    }
    if (sendto(sock, msg, size, 0, res->ai_addr, res->ai_addrlen) == -1){
      fprintf(stderr, "Failed to send UDP data (err = %s) \n", strerror(errno));
      exit(-1);
    }
    return;
}
