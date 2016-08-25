#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "mongoose.h"
#include "../common/wiloc.h"

extern char** environ;



/* google geolocation api */

typedef struct
{
  const char* post_path;
  const char* resp_path;
  const char* wget_path;
  char* url;
  const char* av[7];
  char** env;
} geoloc_handle_t;

geoloc_handle_t g_geoloc;

static int geoloc_init(geoloc_handle_t* geoloc, const char* api_key)
{
#define GEOLOC_URL \
  "https://www.googleapis.com/geolocation/v1/geolocate?" \
  "key="

#define GEOLOC_POST_PATH "/tmp/geoloc.post"
#define GEOLOC_RESP_PATH "/tmp/geoloc.resp"
#define GEOLOC_WGET_PATH "/usr/bin/wget"

  const size_t key_len = strlen(api_key);
  const size_t url_len = sizeof(GEOLOC_URL) - 1 + key_len;

  geoloc->post_path = GEOLOC_POST_PATH;
  geoloc->resp_path = GEOLOC_RESP_PATH;

  geoloc->url = malloc((url_len + 1) * sizeof(char));
  if (geoloc->url == NULL) goto on_error_0;
  memcpy(geoloc->url, GEOLOC_URL, sizeof(GEOLOC_URL) - 1);
  strcpy(geoloc->url + sizeof(GEOLOC_URL) - 1, api_key);

  geoloc->wget_path = GEOLOC_WGET_PATH;

  geoloc->av[0] = geoloc->wget_path;
  geoloc->av[1] = "--post-file=" GEOLOC_POST_PATH;
  geoloc->av[2] = "--header=Content-Type: application/json";
  geoloc->av[3] = "--output-document=" GEOLOC_RESP_PATH;
  geoloc->av[4] = "--quiet";
  geoloc->av[5] = geoloc->url;
  geoloc->av[6] = NULL;

  geoloc->env = environ;

  return 0;

 on_error_0:
  return -1;
}


static void geoloc_fini(geoloc_handle_t* geoloc)
{
  free(geoloc->url);
}


static int geoloc_get_mac_coords
(geoloc_handle_t* geoloc, double* coords, const uint8_t* macs, size_t nmac)
{
  pid_t pid;
  int status;
  int fd;
  char buf[32];
  size_t i;
  size_t j;
  int err = -1;

  /* write macs in geoloc->post_data */

#define GEOLOC_WRITE(__fd, __s) write(__fd, __s, sizeof(__s) - 1)

  fd = open(geoloc->post_path, O_RDWR | O_TRUNC | O_CREAT, 0477);
  if (fd == -1) goto on_error_0;

  GEOLOC_WRITE(fd, "{\"wifiAccessPoints\":[");
  for (i = 0; i != nmac; ++i)
  {
    const uint8_t* const mac = macs + i * 6;
    for (j = 0; j != 6; ++j) sprintf(buf + j * 3, "%02x:", mac[j]);
    GEOLOC_WRITE(fd, "{\"macAddress\":\"");
    write(fd, buf, 17);
    GEOLOC_WRITE(fd, "\"}");
    if (i != (nmac - 1)) GEOLOC_WRITE(fd, ",");
  }
  GEOLOC_WRITE(fd, "]}");

  /* execute wget */

  pid = fork();

  if (pid == (pid_t)-1) goto on_error_1;

  if (pid == 0)
  {
    /* child process */
    execve(geoloc->av[0], (void*)geoloc->av, geoloc->env);
    exit(-1);
  }

  /* parent process */

  if (waitpid(pid, &status, 0) == (pid_t)-1) goto on_error_2;
  if (WIFEXITED(status) == 0) goto on_error_2;
  if (WEXITSTATUS(status)) goto on_error_3;

  /* status ok, parse output json file to get coords */

  err = 0;

 on_error_3: goto on_error_1;
 on_error_2:
  kill(pid, SIGTERM);
 on_error_1:
  close(fd);
 on_error_0:
  return err;
}


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
  double coords[2];

  struct pointdb_entry* next;

} pointdb_entry_t;


typedef struct
{
#define WILOC_DID_MAX 0x100 /* not inclusive */
  pointdb_entry_t* heads[WILOC_DID_MAX];
  pointdb_entry_t* tails[WILOC_DID_MAX];
  size_t counts[WILOC_DID_MAX];
} pointdb_handle_t;

static pointdb_handle_t g_pointdb;


static int pointdb_init(pointdb_handle_t* db)
{
  size_t i;

  for (i = 0; i != WILOC_DID_MAX; ++i)
  {
    db->heads[i] = NULL;
    db->tails[i] = NULL;
    db->counts[i] = 0;
  }

  return 0;
}


static void pointdb_flush(pointdb_handle_t* db, size_t did)
{
  pointdb_entry_t* pe = db->heads[did];

  while (pe != NULL)
  {
    pointdb_entry_t* const tmp = pe;
    pe = pe->next;
    if (tmp->flags & POINTDB_FLAG_HAS_MACS) free(tmp->macs);
    free(tmp);
  }

  db->heads[did] = NULL;
  db->tails[did] = NULL;
  db->counts[did] = 0;

  /* TODO: free pointdb_apiurl */
}


static void pointdb_fini(pointdb_handle_t* db)
{
  size_t did;
  for (did = 0; did != WILOC_DID_MAX; ++did) pointdb_flush(db, did);
}


static pointdb_entry_t* pointdb_find(pointdb_handle_t* db, size_t did)
{
  return db->heads[did];
}


static int pointdb_get_coords
(pointdb_handle_t* db, size_t did, double** coords, size_t* ncoord)
{
  pointdb_entry_t* pe;
  size_t i;

  *coords = NULL;
  *ncoord = db->counts[did];

  /* success, but nothing to locate */
  if (*ncoord == 0) return 0;

  *coords = malloc((*ncoord * 2) * sizeof(double));
  if (*coords == NULL) return -1;

  i = 0;
  for (pe = db->heads[did]; pe != NULL; pe = pe->next)
  {
    if (pe->flags & POINTDB_FLAG_COORDS_FAILED) continue ;

    if ((pe->flags & POINTDB_FLAG_HAS_COORDS) == 0)
    {
      if ((pe->flags & POINTDB_FLAG_HAS_MACS) == 0) continue ;

      if (geoloc_get_mac_coords(&g_geoloc, pe->coords, pe->macs, pe->nmac))
      {
	pe->flags |= POINTDB_FLAG_COORDS_FAILED;
	continue ;
      }

      pe->flags |= POINTDB_FLAG_HAS_COORDS;
    }

    (*coords)[(i * 2) + 0] = pe->coords[0];
    (*coords)[(i * 2) + 1] = pe->coords[1];

    ++i;
  }

  *ncoord = i;

  return 0;
}


static pointdb_entry_t* pointdb_add_wifi
(pointdb_handle_t* db, size_t did, const uint8_t* macs, size_t nmac)
{
  pointdb_entry_t* pe;
  const size_t mac_size = nmac * 6;

  pe = malloc(sizeof(pointdb_entry_t));
  if (pe == NULL) return NULL;

  pe->flags = POINTDB_FLAG_HAS_MACS;

  pe->time = 0;

  pe->nmac = nmac;
  pe->macs = malloc(mac_size * sizeof(uint8_t));
  if (pe->macs == NULL)
  {
    free(pe);
    return NULL;
  }

  memcpy(pe->macs, macs, mac_size);

  pe->next = NULL;

  if (db->heads[did] == NULL)
  {
    db->heads[did] = pe;
    db->tails[did] = pe;
  }
  else
  {
    db->tails[did]->next = pe;
    db->tails[did] = pe;
  }

  ++db->counts[did];

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
	(
	 &g_pointdb,
	 (size_t)wilm->did, mbuf + sizeof(wiloc_msg_t),
	 (size_t)wilm->count
	);

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

	if (g_pointdb.counts[did] == 0) continue ;

	sprintf(x, "0x%02x", (uint8_t)did);
	mg_printf_http_chunk(con, "<li>");
	mg_printf_http_chunk(con, "%s", x);
	mg_printf_http_chunk(con, "&nbsp;");
	mg_printf_http_chunk(con, "(%zu points)", g_pointdb.counts[did]);
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
      double* coords;
      size_t ncoord;
      size_t i;

      if (get_query_val_uint32(hm, "did", &did))
      {
	serve_failure_page(con, "invalid did");
	return ;
      }

      if (pointdb_get_coords(&g_pointdb, did, &coords, &ncoord))
      {
	serve_failure_page(con, "getting coordinates");
	return ;
      }

      init_response(con);

      mg_printf_http_chunk(con, HTML_HEADER);

      mg_printf_http_chunk(con, "<ul>");
      for (i = 0; i != ncoord; ++i)
      {
	const double lat = coords[i * 2 + 0];
	const double lng = coords[i * 2 + 1];
	mg_printf_http_chunk(con, "<li> %lf, %lf </li>", lat, lng);
      }
      mg_printf_http_chunk(con, "</ul>");

      mg_printf_http_chunk(con, HTML_FOOTER);

      fini_response(con);

      free(coords);

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

      pointdb_flush(&g_pointdb, (size_t)did);
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

int main(int ac, char** av)
{
  struct mg_mgr mgr;
  struct mg_connection* dns_con;
  struct mg_connection* http_con;
  int err = -1;

  if (pointdb_init(&g_pointdb)) goto on_error_0;
  if (geoloc_init(&g_geoloc, av[1])) goto on_error_1;

  mg_mgr_init(&mgr, NULL);

  http_con = mg_bind(&mgr, http_server_addr, http_ev_handler);
  if (http_con == NULL)
  {
    printf("failed to create http server\n");
    goto on_error_2;
  }
  mg_set_protocol_http_websocket(http_con);
  http_server_opts.document_root = ".";
  http_server_opts.enable_directory_listing = "no";

  dns_con = mg_bind(&mgr, dns_server_addr, dns_ev_handler);
  if (dns_con == NULL)
  {
    printf("failed to create wiloc server\n");
    goto on_error_2;
  }
  mg_set_protocol_dns(dns_con);

  for (;;) mg_mgr_poll(&mgr, 1000);

  err = 0;

 on_error_2:
  mg_mgr_free(&mgr);
  geoloc_fini(&g_geoloc);
 on_error_1:
  pointdb_fini(&g_pointdb);
 on_error_0:
  return err;
}
