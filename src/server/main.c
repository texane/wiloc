#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include "mongoose.h"
#include "../common/wiloc.h"


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


#define WILOC_DID_MAX 0x100 /* not inclusive */
static pointdb_entry_t* pointdb_heads[WILOC_DID_MAX];
static pointdb_entry_t* pointdb_tails[WILOC_DID_MAX];
static size_t pointdb_counts[WILOC_DID_MAX];


static int pointdb_init(void)
{
  size_t i;

  for (i = 0; i != WILOC_DID_MAX; ++i)
  {
    pointdb_heads[i] = NULL;
    pointdb_tails[i] = NULL;
    pointdb_counts[i] = 0;
  }

  return 0;
}


static void pointdb_flush(size_t did)
{
  pointdb_entry_t* pe = pointdb_heads[did];

  while (pe != NULL)
  {
    pointdb_entry_t* const tmp = pe;
    pe = pe->next;
    if (tmp->flags & POINTDB_FLAG_HAS_MACS) free(tmp->macs);
    free(tmp);
  }

  pointdb_heads[did] = NULL;
  pointdb_tails[did] = NULL;
  pointdb_counts[did] = 0;
}


static void pointdb_fini(void)
{
  size_t did;
  for (did = 0; did != WILOC_DID_MAX; ++did) pointdb_flush(did);
}


static pointdb_entry_t* pointdb_find(size_t did)
{
  return pointdb_heads[did];
}


static int pointdb_get_coords(size_t did, pointdb_entry_t* pe)
{
  if (pe->flags & POINTDB_FLAG_COORDS_FAILED) return -1;
  if (pe->flags & POINTDB_FLAG_HAS_COORDS) return 0;

  if (pe->flags & POINTDB_FLAG_HAS_MACS)
  {
    /* TODO: execve(wget ...) */
    /* pe->flags |= POINTDB_FLAG_HAS_COORDS; */
    return -1;
  }

  return -1;
}


static pointdb_entry_t* pointdb_add_wifi
(size_t did, const uint8_t* macs, size_t nmac)
{
  pointdb_entry_t* pe;
  const size_t mac_size = nmac * 6;

  pe = malloc(sizeof(pointdb_entry_t));
  if (pe == NULL) return NULL;

  pe->flags = POINTDB_FLAG_HAS_MACS;

  pe->time = 0;

  pe->macs = malloc(mac_size * sizeof(uint8_t));
  if (pe->macs == NULL)
  {
    free(pe);
    return NULL;
  }

  memcpy(pe->macs, macs, mac_size);

  pe->next = NULL;

  if (pointdb_heads[did] == NULL)
  {
    pointdb_heads[did] = pe;
    pointdb_tails[did] = pe;
  }
  else
  {
    pointdb_tails[did]->next = pe;
    pointdb_tails[did] = pe;
  }

  ++pointdb_counts[did];

  return pe;
}


/* wiloc dns udp server */

static const char* const dns_server_addr = "udp://127.0.0.1:53";

static int decode_base64(uint8_t* in, size_t len)
{ 
  static const uint8_t d[] =
  {
    66,66,66,66,66,66,66,66,66,66,64,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,62,66,66,66,63,52,53,54,55,
    56,57,58,59,60,61,66,66,66,65,66,66,66,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,
    13,14,15,16,17,18,19,20,21,22,23,24,25,
    66,66,66,66,66,66,26,27,28,29,30,31,32,
    33,34,35,36,37,38,39,40,41,42,43,44,45,
    46,47,48,49,50,51,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66
  };

  uint8_t* out = in;
  uint8_t* const end = in + len;
  size_t iter = 0;
  uint32_t buf = 0;
    
  while (in < end)
  {
    const uint8_t c = d[(size_t)(*in++)];
        
    switch (c)
    {
    /* whitespace */
    case 64: continue;

    /* invalid */
    case 66: return -1;

   /* equals, padding meaning end of data */
    case 65:
      in = end;
      continue;

    default:
      buf = (buf << 6) | c;

      /* split full buffer into bytes */
      if ((++iter) == 4)
      {
	*(out++) = (buf >> 16) & 0xff;
	*(out++) = (buf >> 8) & 0xff;
	*(out++) = buf & 0xff;
	buf = 0;
	iter = 0;
      }
    }
  }
   
  if (iter == 3)
  {
    *(out++) = (buf >> 10) & 0xff;
    *(out++) = (buf >> 2) & 0xff;
  }
  else if (iter == 2)
  {
    *(out++) = (buf >> 4) & 0xff;
  }

  return 0;
}

static int decode_wiloc_msg(uint8_t* mbuf, size_t msize)
{
  /* decode a wiloc message */
  /* return 0 on success */

  /* decoding process */
  /* decode name */
  /* strip zone (not needed, base64 knows where to stop) */
  /* remove label dots */
  /* decode base64 */

  size_t i;
  size_t j;
  size_t k;

  i = 0;
  k = 0;
  for (j = 0; j != msize; ++j)
  {
    if (j == k) k += (size_t)mbuf[j] + 1;
    else mbuf[i++] = mbuf[j];
  }

  return decode_base64(mbuf, i);
}

static void dns_ev_handler(struct mg_connection* con, int ev, void* p)
{
  switch (ev)
  {
  case MG_DNS_MESSAGE:
    {
      struct mg_dns_message* const dnsm = (struct mg_dns_message*)p;
      size_t i;

      for (i = 0; i != (size_t)dnsm->num_questions; ++i)
      {
	const struct mg_dns_resource_record* const rr = &dnsm->questions[i];
	uint8_t mbuf[256];
	size_t msize;
	const wiloc_msg_t* const wilm = (const wiloc_msg_t*)mbuf;
	pointdb_entry_t* pe;

	msize = rr->name.len;
	if (msize >= sizeof(mbuf)) msize = sizeof(mbuf);

	memcpy(mbuf, rr->name.p, msize);
	if (decode_wiloc_msg(mbuf, msize)) break ;

	if (wilm->vers != WILOC_MSG_VERS) break ;
	if ((wilm->flags & WILOC_MSG_FLAG_WIFI) == 0) break ;

	if (((size_t)wilm->count * 6) > (msize - sizeof(wiloc_msg_t))) break ;

	pe = pointdb_add_wifi
	  ((size_t)wilm->did, mbuf + sizeof(wiloc_msg_t), (size_t)wilm->count);
	if (pe == NULL) break ;
      }

      /* mg_dns_send_reply(nc, &reply); */
      con->flags |= MG_F_SEND_AND_CLOSE;

      break;
    }

  default: break ;
  }
}


/* http server */

static const char *http_server_addr = "127.0.0.1:8000";
static struct mg_serve_http_opts http_server_opts;

#define HTML_HEADER "<html><body>"
#define HTML_FOOTER "</body></html>"

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

static void serve_success_page(struct mg_connection* con)
{
  static const char* const html =
    HTML_HEADER "<h2> operation success </h2>" HTML_FOOTER;
  serve_one_page(con, html);
}

static void serve_failure_page(struct mg_connection* con, const char* err)
{
  static const char* const html =
    HTML_HEADER "<h2> operation failure: %s </h2>" HTML_FOOTER;

  init_response(con);
  mg_printf_http_chunk(con, html, (err == NULL) ? "unspecified error" : err);
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
  struct http_message* const hm = (struct http_message*)p;

  if (ev == MG_EV_HTTP_REQUEST)
  {
    if (mg_vcmp(&hm->uri, "/list") == 0)
    serve_list_page:
    {
      size_t did;

      init_response(con);

      mg_printf_http_chunk(con, HTML_HEADER);

      mg_printf_http_chunk(con, "<ul>");
      for (did = 0; did != WILOC_DID_MAX; ++did)
      {
	char x[8];

	if (pointdb_counts[did] == 0) continue ;

	sprintf(x, "0x%02x", (uint8_t)did);
	mg_printf_http_chunk(con, "<li>");
	mg_printf_http_chunk(con, "%s", x);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "(%zu points)", pointdb_counts[did]);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "<a href=\"/track?did=%s\">track</a>", x);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "<a href=\"/flush?did=%s\">flush</a>", x);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "<a href=\"/dump?did=%s\">dump</a>", x);
	mg_printf_http_chunk(con, "</li>");
      }
      mg_printf_http_chunk(con, "</ul>");

      mg_printf_http_chunk(con, HTML_FOOTER);

      fini_response(con);

      return ;
    }
    else if (mg_vcmp(&hm->uri, "/track") == 0)
    {
      /* did=<did>, the device id (required) */
      /* ofmt={txt,gpx}, the device id (optional, default to txt) */

      uint32_t did;

      if (get_query_val_uint32(hm, "did", &did))
      {
	serve_failure_page(con, "invalid did");
	return ;
      }

      serve_failure_page(con, "not implemented");

      return ;
    }
    else if (mg_vcmp(&hm->uri, "/flush") == 0)
    {
      /* did=<did>, the device id (required) */

      uint32_t did;

      if (get_query_val_uint32(hm, "did", &did))
      {
	serve_failure_page(con, "invalid did");
	return ;
      }

      pointdb_flush((size_t)did);
      serve_success_page(con);
      return ;
    }
    else if (mg_vcmp(&hm->uri, "/dump") == 0)
    {
      /* did=<did>, the device id (required) */

      serve_failure_page(con, "not implemented");
      return ;
    }
    else /* index */
    {
      goto serve_list_page;
    }
  }
}


/* command line */


/* main */

int main(void)
{
  struct mg_mgr mgr;
  struct mg_connection* dns_con;
  struct mg_connection* http_con;
  int err = -1;

  if (pointdb_init()) goto on_error_0;

  mg_mgr_init(&mgr, NULL);

  http_con = mg_bind(&mgr, http_server_addr, http_ev_handler);
  if (http_con == NULL)
  {
    printf("failed to create http server\n");
    goto on_error_1;
  }
  mg_set_protocol_http_websocket(http_con);
  http_server_opts.document_root = ".";
  http_server_opts.enable_directory_listing = "no";

  dns_con = mg_bind(&mgr, dns_server_addr, dns_ev_handler);
  if (dns_con == NULL)
  {
    printf("failed to create wiloc server\n");
    goto on_error_1;
  }
  mg_set_protocol_dns(dns_con);

  for (;;) mg_mgr_poll(&mgr, 1000);

  err = 0;

 on_error_1:
  mg_mgr_free(&mgr);
  pointdb_fini();
 on_error_0:
  return err;
}
