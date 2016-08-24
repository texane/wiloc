#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include "mongoose.h"


/* device points database */

typedef struct pointdb_entry
{
#define POINTDB_FLAG_HAS_COORDS (1 << 0)
#define POINTDB_FLAG_HAS_MACS (1 << 1)
#define POINTDB_FLAG_COORDS_FAILED (1 << 2)
  uint32_t flags;

  unsigned long time;

  /* mac addresses */
  uint8_t* macs;
  size_t nmac;

  /* lag, lng */
  float coords[2];

  struct pointdb_entry* next;

} pointdb_entry_t;


#define POINTDB_KEY_COUNT ((uint8_t)-1)
static pointdb_entry_t* g_point_heads[POINTDB_KEY_COUNT];
static pointdb_entry_t* g_point_tails[POINTDB_KEY_COUNT];


static int pointdb_init(void)
{
  size_t i;

  for (i = 0; i != POINTDB_KEY_COUNT; ++i)
  {
    g_point_heads[i] = NULL;
    g_point_tails[i] = NULL;
  }

  return 0;
}


static void pointdb_flush(size_t did)
{
  pointdb_entry_t* pe = g_point_heads[did];

  while (pe != NULL)
  {
    pointdb_entry_t* const tmp = pe;
    pe = pe->next;
    free(tmp);
  }

  g_point_heads[did] = NULL;
  g_point_tails[did] = NULL;
}


static void pointdb_fini(void)
{
  size_t did;
  for (did = 0; did != POINTDB_KEY_COUNT; ++did) pointdb_flush(did);
}


static pointdb_entry_t* pointdb_find(size_t did)
{
  return g_point_heads[did];
}


static int pointdb_get_coords(size_t did, pointdb_entry_t* pe)
{
  if (pe->flags & POINTDB_FLAG_COORDS_FAILED) return -1;
  if (pe->flags & POINTDB_FLAG_HAS_COORDS) return 0;

  if (pe->flags & POINTDB_FLAG_HAS_MACS)
  {
    /* TODO: execve(wget ...) */
    return -1;
  }

  return -1;
}


static pointdb_entry_t* pointdb_add(size_t did)
{
  pointdb_entry_t* pe;

  pe = malloc(sizeof(pointdb_entry_t));
  if (pe == NULL) return NULL;

  pe->next = NULL;

  if (g_point_heads[did] == NULL)
  {
    g_point_heads[did] = pe;
    g_point_tails[did] = pe;
  }
  else
  {
    g_point_tails[did]->next = pe;
    g_point_tails[did] = pe;
  }

  return pe;
}


/* wiloc dns udp server */

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

static void init_response(struct mg_connection* con)
{
  mg_printf(con, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
}

static void fini_response(struct mg_connection* con)
{
  /* empty chunk, end of response */
  mg_send_http_chunk(con, "", 0);
}

static void serve_one_page(struct mg_connection* con, const char* page)
{
  init_response(con);
  mg_printf_http_chunk(con, "%s", page);
  fini_response(con);
}

static int get_query_val_str
(struct http_message* hm, const char* key, const char** val, size_t* len)
{
  const struct mg_str* const qs = &hm->query_string;
  size_t key_len = strlen(key);
  size_t i;
  size_t j;

  for (i = 0; i != qs->len; ++i)
  {
    size_t off;

    if (i == 0) off = 0;
    else if (qs->p[i] == '&') off = i + 1;
    else continue ;

    if ((qs->len - off) <= key_len) return -1;

    if (memcmp(qs->p + off, key, key_len) == 0)
    {
      /* skip key equals */
      i += key_len + 1;
      break ;
    }
  }

  j = i;

  /* key = val */
  for (; i != qs->len; ++i) if (qs->p[i] == '&') break ;

  *val = qs->p + j;
  *len = i - j;

  return 0;
}

static int get_query_val_uint32
(struct http_message* hm, const char* key, uint32_t* x)
{
  const char* val;
  size_t len;
  int base;
  char buf[16];

  if (get_query_val_str(hm, key, &val, &len)) return -1;
  if (len >= (sizeof(buf) - 1)) return -1;
  memcpy(buf, val, len);
  buf[len] = 0;

  if ((len > 2) && (buf[0] == '0') && (buf[1] == 'x')) base = 16;
  else base = 10;

  *x = (uint32_t)strtoul(buf, NULL, base);

  return 0;
}

static void http_ev_handler(struct mg_connection* con, int ev, void* p)
{
#define HTML_HEADER "<html><body>"
#define HTML_FOOTER "</body></html>"

  struct http_message* const hm = (struct http_message*)p;

  static const uint8_t all_dids[] = { 0x2a, 0x3a, 0x4a, 0x5a };

  if (ev == MG_EV_HTTP_REQUEST)
  {
    if (mg_vcmp(&hm->uri, "/list") == 0)
    {
      size_t i;

      init_response(con);

      mg_printf_http_chunk(con, HTML_HEADER);

      mg_printf_http_chunk(con, "<ul>");
      for (i = 0; i != sizeof(all_dids) / sizeof(all_dids[0]); ++i)
      {
	char x[8];
	sprintf(x, "0x%02x", all_dids[i]);
	mg_printf_http_chunk(con, "<li>");
	mg_printf_http_chunk(con, "%s", x);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "<a href=\"/track?did=%s\">track</a>", x);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "<a href=\"/flush?did=%s\">flush</a>", x);
	mg_printf_http_chunk(con, "</li>");
      }
      mg_printf_http_chunk(con, "</ul>");

      mg_printf_http_chunk(con, HTML_FOOTER);

      fini_response(con);
    }
    else if (mg_vcmp(&hm->uri, "/track") == 0)
    {
      /* did=<did>, the device id (required) */
      /* ofmt={txt,gpx}, the device id (optional, default to txt) */

      uint32_t did;
      size_t i;

      if (get_query_val_uint32(hm, "did", &did)) goto on_invalid_did;

      for (i = 0; i != sizeof(all_dids) / sizeof(all_dids[0]); ++i)
	if (all_dids[i] == did) break ;

      if (i == (sizeof(all_dids) / sizeof(all_dids[0])))
      {
      on_invalid_did:
	{
	  static const char* const html =
	    HTML_HEADER "<h2> invalid device id </h2>" HTML_FOOTER;
	  serve_one_page(con, html);
	  return ;
	}
      }

      init_response(con);
      mg_printf_http_chunk(con, HTML_HEADER);
      mg_printf_http_chunk(con, "<h2> tracking 0x%02x <h2>", did);
      mg_printf_http_chunk(con, HTML_FOOTER);
      fini_response(con);
    }
    else if (mg_vcmp(&hm->uri, "/flush") == 0)
    {
      /* did=<did>, the device id (optional, default to all) */

      static const char* const html =
	HTML_HEADER " <h2> doing flush </h2>" HTML_FOOTER;

      serve_one_page(con, html);
    }
    else if (mg_vcmp(&hm->uri, "/dump") == 0)
    {
      /* did=<did>, the device id (required) */

      static const char* const html =
	HTML_HEADER " <h2> doing dump </h2>" HTML_FOOTER;

      serve_one_page(con, html);
    }
    else /* index */
    {
      static const char* const html =
	HTML_HEADER
	"<h2> available actions </h2>"
	"<ul>"
	"<li> <a href=\"/list\"> list </a> </li>"
	"<li> <a href=\"/track\"> track </a> </li>"
	"<li> <a href=\"/dump\"> dump </a> </li>"
	"<li> <a href=\"/flush\"> flush </a> </li>"
	"</ul>"
	HTML_FOOTER;

      serve_one_page(con, html);
    }
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
  http_server_opts.enable_directory_listing = "no";

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
