#include "reliable_udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

/*
 * struct sockaddr_in to: a struct containing the destination address
 * of the udp packet
 *
 * socklen_t tolen: the length of the struct sockaddr_in. Different
 * sockaddr struct will have different length
 *
 * char *msg: the message to send to destination address
 *
 * send a message through udp procotol
 */
void send_udp_packet(struct sockaddr_in to, socklen_t tolen, char *msg){

  fprintf(stdout, "sending a udp packet unreliably \n");
  return;
}
