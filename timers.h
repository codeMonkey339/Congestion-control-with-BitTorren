#ifndef __TIMERS__
#define __TIMERS_
#include "utility.h"
#include <string.h>

void remove_timer(vector *timers, timer *t);
void remove_timer_by_ip(vector *timers, ip_port_t *ip_port);



#endif