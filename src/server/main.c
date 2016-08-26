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



/* debugging */

#define PERROR() printf("[ERROR] %s %u\n", __FILE__, __LINE__)
#define PERROR_GOTO(__l) do { PERROR(); goto __l; } while(0)


/* google geolocation api */

typedef struct
{
#define GEOLOC_FLAG_DISABLED (1 << 0)
  uint32_t flags;
  const char* post_path;
  const char* resp_path;
  const char* wget_path;
  char* url;
  const char* av[7];
  char** env;
} geoloc_handle_t;

geoloc_handle_t g_geoloc;

static unsigned int geoloc_is_disabled(const geoloc_handle_t* geoloc)
{
  return (unsigned int)(geoloc->flags & GEOLOC_FLAG_DISABLED);
}

static int geoloc_init(geoloc_handle_t* geoloc, const char* key)
{
#define GEOLOC_URL \
  "https://www.googleapis.com/geolocation/v1/geolocate?" \
  "key="

#define GEOLOC_POST_PATH "/tmp/geoloc.post"
#define GEOLOC_RESP_PATH "/tmp/geoloc.resp"
#define GEOLOC_WGET_PATH "/usr/bin/wget"

  size_t key_len;
  size_t url_len;
  struct stat st;

  geoloc->flags = 0;

  /* geoloc pdisabled */
  if (key == NULL) goto on_error_0;
  if (stat(GEOLOC_WGET_PATH, &st)) goto on_error_0;

  geoloc->post_path = GEOLOC_POST_PATH;
  geoloc->resp_path = GEOLOC_RESP_PATH;

  key_len = strlen(key);
  url_len = sizeof(GEOLOC_URL) - 1 + key_len;
  geoloc->url = malloc((url_len + 1) * sizeof(char));
  if (geoloc->url == NULL) PERROR_GOTO(on_error_0);
  memcpy(geoloc->url, GEOLOC_URL, sizeof(GEOLOC_URL) - 1);
  strcpy(geoloc->url + sizeof(GEOLOC_URL) - 1, key);

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
  geoloc->flags |= GEOLOC_FLAG_DISABLED;
  return -1;
}


static void geoloc_fini(geoloc_handle_t* geoloc)
{
  if (geoloc_is_disabled(geoloc)) return ;
  free(geoloc->url);
}


static int geoloc_get_mac_coords
(geoloc_handle_t* geoloc, double* coords, const uint8_t* macs, size_t nmac)
{
  pid_t pid;
  int status;
  int fd = -1;
  char buf[256];
  size_t size;
  size_t i;
  size_t j;
  int err = -1;

  if (geoloc_is_disabled(geoloc)) return -1;

  /* write macs in geoloc->post_data */

#define GEOLOC_STRLEN(__s) (sizeof(__s) - 1)
#define GEOLOC_WRITE(__fd, __s) write(__fd, __s, GEOLOC_STRLEN(__s))
#define GEOLOC_MEMCMP(__a, __b) memcmp(__a, __b, GEOLOC_STRLEN(__b))

  fd = open(geoloc->post_path, O_RDWR | O_TRUNC | O_CREAT, 0477);
  if (fd == -1) PERROR_GOTO(on_error_0);

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

  close(fd);
  fd = -1;

  /* execute wget */

  pid = fork();

  if (pid == (pid_t)-1) PERROR_GOTO(on_error_1);

  if (pid == 0)
  {
    /* child process */
    execve(geoloc->av[0], (void*)geoloc->av, geoloc->env);
    exit(-1);
  }

  /* parent process */

  if (waitpid(pid, &status, 0) == (pid_t)-1) PERROR_GOTO(on_error_2);
  if (WIFEXITED(status) == 0) PERROR_GOTO(on_error_2);
  if (WEXITSTATUS(status)) PERROR_GOTO(on_error_3);

  /* status ok, parse output file to get coords */

  fd = open(geoloc->resp_path, O_RDONLY);
  if (fd == -1) PERROR_GOTO(on_error_3);

  size = read(fd, buf, sizeof(buf) - 1);
  if (size <= 0) PERROR_GOTO(on_error_3);
  buf[size] = 0;

  for (i = 0; (size - i) > GEOLOC_STRLEN("\"lat\": "); ++i)
    if (GEOLOC_MEMCMP(buf + i, "\"lat\": ") == 0) break ;
  if ((size - i) <= (GEOLOC_STRLEN("\"lat\": "))) PERROR_GOTO(on_error_3);
  coords[0] = strtod(buf + i + GEOLOC_STRLEN("\"lat\": "), NULL);

  for (; (size - i) > GEOLOC_STRLEN("\"lng\": "); ++i)
    if (GEOLOC_MEMCMP(buf + i, "\"lng\": ") == 0) break ;
  if ((size - i) <= (GEOLOC_STRLEN("\"lng\": "))) PERROR_GOTO(on_error_3);
  coords[1] = strtod(buf + i + GEOLOC_STRLEN("\"lng\": "), NULL);

  err = 0;

 on_error_3: goto on_error_1;
 on_error_2:
  kill(pid, SIGTERM);
 on_error_1:
  if (fd != -1) close(fd);
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
#define POINTDB_NKEY 0x100
  pointdb_entry_t* heads[POINTDB_NKEY];
  pointdb_entry_t* tails[POINTDB_NKEY];
  size_t counts[POINTDB_NKEY];
} pointdb_handle_t;

static pointdb_handle_t g_pointdb;


static int pointdb_init(pointdb_handle_t* db)
{
  size_t i;

  for (i = 0; i != POINTDB_NKEY; ++i)
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
}


static void pointdb_fini(pointdb_handle_t* db)
{
  size_t did;
  for (did = 0; did != POINTDB_NKEY; ++did) pointdb_flush(db, did);
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

static struct mg_serve_http_opts http_server_opts;

#define HTML_HEADER "<html><body>"
#define HTML_FOOTER "</body></html>"
#define HTML_GOTO_MAIN "<a href=\"/\"> goto main page </a>"

static void init_response(struct mg_connection* con, const char* content_type)
{
  if (content_type == NULL) content_type = "text/html; charset=utf-8";

  mg_printf
  (
   con,
   "HTTP/1.1 200 OK\r\n"
   "Transfer-Encoding: chunked\r\n"
   "Content-Type: %s\r\n"
   "\r\n",
   content_type
  );
}

static void fini_response(struct mg_connection* con)
{
  /* empty chunk, end of response */
  mg_send_http_chunk(con, "", 0);
}

static void serve_one_page(struct mg_connection* con, const char* page)
{
  init_response(con, NULL);
  mg_printf_http_chunk(con, "%s", page);
  fini_response(con);
}

static void serve_success_page(struct mg_connection* con)
{
  static const char* const html =
    HTML_HEADER
    "<h2> success </h2>"
    HTML_GOTO_MAIN
    HTML_FOOTER;

  serve_one_page(con, html);
}

static void serve_failure_page(struct mg_connection* con, const char* err)
{
  static const char* const html =
    HTML_HEADER
    "<h2> failure: %s </h2>"
    HTML_GOTO_MAIN
    HTML_FOOTER;

  init_response(con, NULL);
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
      if (qs->p[off + key_len] == '=')
      {
	i = off + key_len + 1;
	break ;
      }
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
      size_t n;

      init_response(con, NULL);

      mg_printf_http_chunk(con, HTML_HEADER);

      mg_printf_http_chunk
      (
       con,
       "<style>"
       "table { border-collapse: collapse; }"
       "th, td { text-align: center; padding: 8px; }"
       "tr:nth-child(even){background-color: #eaeaea}"
       "</style>"
       "<table>"
       "<tr>"
       " <th> device </th>"
       " <th> npoint </th>"
       " <th colspan=\"4\"> operations </th>"
       "</tr>"
      );

      n = 0;
      for (did = 0; did != POINTDB_NKEY; ++did)
      {
	char x[8];

	if (g_pointdb.counts[did] == 0) continue ;
	++n;

	sprintf(x, "0x%02x", (uint8_t)did);

	mg_printf_http_chunk
	(
	 con,
	 "<tr>"
	 " <td> %s </td>"
	 " <td> %zu </td>"
	 " <td> <a href=\"/track?did=%s&ofmt=csv\"> track-csv </a> </td>"
	 " <td> <a href=\"/track?did=%s&ofmt=gpx\"> track-gpx </a> </td>"
	 " <td> <a href=\"/flush?did=%s\"> flush </a> </td>"
	 " <td> <a href=\"/dump?did=%s\"> dump </a> </td>"
	 "</tr>",
	 x, g_pointdb.counts[did], x, x, x, x
	);
      }

      mg_printf_http_chunk(con, "</table>");

      if (n == 0)
      {
	mg_printf_http_chunk(con, "<h2> no device points found </h2>");
      }

      mg_printf_http_chunk(con, HTML_FOOTER);

      fini_response(con);

      return ;
    }
    else if (mg_vcmp(&hm->uri, "/track") == 0)
    {
      /* did=<did>, the device id (required) */
      /* ofmt={csv,gpx}, the device id (optional, default to csv) */

      uint32_t did;
      double* coords;
      size_t ncoord;
      size_t i;
      const char* ofmt_str;
      size_t ofmt_len;
      unsigned int is_gpx;

      if (geoloc_is_disabled(&g_geoloc))
      {
	serve_failure_page(con, "geolocation is disabled");
	return ;
      }

      if (get_query_val_uint32(hm, "did", &did))
      {
	serve_failure_page(con, "invalid did");
	return ;
      }

      is_gpx = 0;
      if (get_query_val_str(hm, "ofmt", &ofmt_str, &ofmt_len) == 0)
      {
	if (strncmp(ofmt_str, "gpx", ofmt_len) == 0)
	{
	  is_gpx = 1;
	}
	else if (strncmp(ofmt_str, "csv", ofmt_len))
	{
	  serve_failure_page(con, "invalid output format");
	  return ;
	}
      }

      if (pointdb_get_coords(&g_pointdb, did, &coords, &ncoord))
      {
	serve_failure_page(con, "getting coordinates");
	return ;
      }

      if (is_gpx == 0)
      {
	init_response(con, NULL);
	mg_printf_http_chunk(con, HTML_HEADER);
	mg_printf_http_chunk(con, "<pre><code>");
      }
      else
      {
	static const char* const gpx_html_header =
	  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	  "<gpx"
	  " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	  " xmlns=\"http://www.topografix.com/GPX/1/0\""
	  " xsi:schemaLocation=\"http://www.topografix.com/GPX/1/0/gpx.xsd\""
	  " version=\"1.0\""
	  " creator=\"gpx.py -- https://github.com/tkrajina/gpxpy\""
	  ">\n"
	  "<trk>"
	  "<trkseg>\n";

	init_response(con, "application/xml");
	mg_printf_http_chunk(con, gpx_html_header);
      }

      for (i = 0; i != ncoord; ++i)
      {
	const double lat = coords[i * 2 + 0];
	const double lng = coords[i * 2 + 1];

	if (is_gpx == 1)
	{
	  mg_printf_http_chunk
	    (con, "<trkpt lat=\"%lf\" lon=\"%lf\"></trkpt>\n", lat, lng);
	}
	else /* csv */
	{
	  mg_printf_http_chunk(con, "%lf, %lf\n", lat, lng);
	}
      }

      if (is_gpx == 1)
      {
	mg_printf_http_chunk(con, "</trkseg></trk></gpx>\n");
      }

      if (is_gpx == 0)
      {
	mg_printf_http_chunk(con, "</code></pre>");
	mg_printf_http_chunk(con, HTML_FOOTER);
      }

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

typedef struct
{
  const char* key;
  const char* val;
  const char* default_val;
  const char* desc;
} opt_keyval_t;

#define OPT_KEYVAL(__key, __val, __desc) { __key, __val, __val, __desc }

static opt_keyval_t g_opt[] =
{
  OPT_KEYVAL("dns_laddr", "0.0.0.0", "DNS server local address"),
  OPT_KEYVAL("dns_lport", "53", "DNS server local port"),
  OPT_KEYVAL("http_laddr", "0.0.0.0", "HTTP server local address"),
  OPT_KEYVAL("http_lport", "80", "HTTP server local port"),
  OPT_KEYVAL("geoloc_key", NULL, "Google geolocation API key"),
  OPT_KEYVAL(NULL, NULL, NULL)
};

static void opt_print_help(const opt_keyval_t* opt)
{
  size_t i;

  printf("command line usage:\n");
  for (i = 0; opt[i].key != NULL; ++i)
  {
    const opt_keyval_t* const kv = opt + i;
    printf("-%s: %s", kv->key, kv->desc);
    if (kv->default_val != NULL) printf(" (default: %s)", kv->default_val);
    printf("\n");
  }
}

static opt_keyval_t* opt_find(opt_keyval_t* opt, const char* key)
{
  size_t i;

  for (i = 0; opt[i].key != NULL; ++i)
  {
    opt_keyval_t* const kv = opt + i;
    if (strcmp(key, kv->key) == 0) return kv;
  }
  
  return NULL;
}

static const char* opt_get(opt_keyval_t* opt, const char* key)
{
  opt_keyval_t* const kv = opt_find(opt, key);
  if (kv == NULL) return NULL;
  return kv->val;
}

static int opt_init(opt_keyval_t* opt, int ac, char** av)
{
  --ac;
  ++av;

  if (ac %  1) PERROR_GOTO(on_error_0);

  for (; ac; ac -= 2, av += 2)
  {
    const char* const k = av[0];
    const char* const v = av[1];
    opt_keyval_t* kv;
    if (k[0] != '-') goto on_error_0;
    kv = opt_find(opt, k + 1);
    if (kv == NULL) PERROR_GOTO(on_error_0);
    kv->val = v;
  }

  return 0;

 on_error_0:
  opt_print_help(opt);
  return -1;
}


/* main */

static volatile unsigned int is_sigint = 0;

static void on_sigint(int x)
{
  is_sigint = 1;
}

int main(int ac, char** av)
{
  struct mg_mgr mgr;
  struct mg_connection* dns_con;
  struct mg_connection* http_con;
  char buf[256];
  int err = -1;

  if (opt_init(g_opt, ac, av)) PERROR_GOTO(on_error_0);

  if (pointdb_init(&g_pointdb)) PERROR_GOTO(on_error_0);

  /* not an error to fail */
  geoloc_init(&g_geoloc, opt_get(g_opt, "geoloc_key"));

  mg_mgr_init(&mgr, NULL);

  snprintf
  (
   buf, sizeof(buf), "%s:%s",
   opt_get(g_opt, "http_laddr"),
   opt_get(g_opt, "http_lport")
  );
  http_con = mg_bind(&mgr, buf, http_ev_handler);
  if (http_con == NULL) PERROR_GOTO(on_error_1);

  mg_set_protocol_http_websocket(http_con);
  http_server_opts.document_root = ".";
  http_server_opts.enable_directory_listing = "no";

  snprintf
  (
   buf, sizeof(buf), "udp://%s:%s",
   opt_get(g_opt, "dns_laddr"),
   opt_get(g_opt, "dns_lport")
  );
  dns_con = mg_bind(&mgr, buf, dns_ev_handler);
  if (dns_con == NULL) PERROR_GOTO(on_error_1);

  mg_set_protocol_dns(dns_con);

  signal(SIGINT, on_sigint);
  while (is_sigint == 0) mg_mgr_poll(&mgr, 1000);

  err = 0;

 on_error_1:
  mg_mgr_free(&mgr);
  pointdb_fini(&g_pointdb);
  geoloc_fini(&g_geoloc);
 on_error_0:
  return err;
}
