#include <stdio.h>
#include "mongoose.h"



/* wiloc server */

static const char* const wiloc_server_addr = "udp://127.0.0.1:53";

static void wiloc_ev_handler(struct mg_connection* con, int ev, void* p)
{
  struct mbuf* const io = &con->recv_mbuf;

  (void)p;

  switch (ev)
  {
  case MG_EV_RECV:
    mg_send(con, io->buf, io->len);
    mbuf_remove(io, io->len);
    /* close mongoose internal virtual UDP connection after sending */
    con->flags |= MG_F_SEND_AND_CLOSE;
    break;
  default:
    break;
  }
}


/* http server */

static const char *http_server_addr = "127.0.0.1:8000";
static struct mg_serve_http_opts http_server_opts;

static void http_ev_handler(struct mg_connection* con, int ev, void* p)
{
  if (ev == MG_EV_HTTP_REQUEST)
  {
    mg_serve_http(con, (struct http_message*)p, http_server_opts);
  }
}


/* command line */


/* main */

int main(void)
{
  struct mg_mgr mgr;
  struct mg_connection* wiloc_con;
  struct mg_connection* http_con;
  int err = -1;

  mg_mgr_init(&mgr, NULL);

  http_con = mg_bind(&mgr, http_server_addr, http_ev_handler);
  if (http_con == NULL)
  {
    printf("failed to create http server\n");
    goto on_error_0;
  }
  mg_set_protocol_http_websocket(http_con);
  http_server_opts.document_root = ".";
  http_server_opts.enable_directory_listing = "yes";

  wiloc_con = mg_bind(&mgr, wiloc_server_addr, wiloc_ev_handler);
  if (wiloc_con == NULL)
  {
    printf("failed to create wiloc server\n");
    goto on_error_0;
  }

  for (;;) mg_mgr_poll(&mgr, 1000);

  err = 0;

 on_error_0:
  mg_mgr_free(&mgr);
  return err;
}
