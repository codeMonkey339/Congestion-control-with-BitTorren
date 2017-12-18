


/**
 * remove a timer from the timer list
 * @param timers
 * @param t
 */
void remove_timer(vector *timers, timer *t){
    vec_delete(timers, t);
}