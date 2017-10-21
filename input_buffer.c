#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "input_buffer.h"
#include "utility.h"

struct user_iobuf *create_userbuf() {
  struct user_iobuf *b;
  b = malloc(sizeof(struct user_iobuf));
  if (!b) return NULL;

  b->buf = malloc(USERBUF_SIZE + 1);
  if (!b->buf) {
    free(b);
    return NULL;
  }

  b->cur = 0;
  bzero(b->buf, USERBUF_SIZE+1);
  return b;
}

void process_user_input(int fd, struct user_iobuf *userbuf, 
			void (*handle_line)(char *, void *, bt_config_t *), void *cbdata, bt_config_t *config, vector *ihave_msgs)
{
  int nread;
  char *ret;

  assert(userbuf != NULL);
  assert(userbuf->buf != NULL);

  /* A real program would propagate this error back to the select loop or
   * implement some other form of error handling */

  if (userbuf->cur >= (USERBUF_SIZE - 1)) {
    fprintf(stderr, "process_user_input error:  buffer full;  line too long!\n");
    exit(-1);
  }

  nread = read(fd, userbuf->buf + userbuf->cur, 
	       (USERBUF_SIZE - userbuf->cur));

  /*
    ideal to be in a while loop to read required bytes
  */
  if (nread > 0) {
    userbuf->cur += nread;
  }

  /*
    handle bytes in the current request
   */
  while ((ret = strchr(userbuf->buf, '\n')) != NULL) {
    *ret = '\0';
    handle_line(userbuf->buf, cbdata, config, ihave_msgs); // function pointer
    /* Shift the remaining contents of the buffer forward */
    memmove(userbuf->buf, ret + 1, USERBUF_SIZE - (ret - userbuf->buf));
    userbuf->cur -= (ret - userbuf->buf + 1);
  }

}
