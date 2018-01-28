#include "timers.h"
#include "utility.h"
#include <string.h>


/**
 * remove a timer from the timer list
 * @param timers
 * @param t
 */
void remove_timer(vector *timers, timer *t){
    vec_delete(timers, t);
}

/**
 * remove a timer from the list of timers by its ip & port
 * @param timers
 * @param ip_port
 */
void remove_timer_by_ip(vector *timers, ip_port_t *ip_port){
    for (size_t i = 0; i < timers->len; i++){
        timer *t = vec_get(timers, i);
        if (strcmp(t->ip, ip_port->ip) == 0 && t->port == ip_port->port){
            vec_delete(timers, t);
            break;
        }
    }

    return;
}
