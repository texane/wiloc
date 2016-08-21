#include <stdint.h>
#include "../common/dns.h"
#include "../common/wiloc.h"
#include "./config.h"


/* check configuration */
#ifndef DNS_ZONE_NAME
#error "missing DNS_ZONE_NAME (.my.zone.com)"
#endif /* DNS_ZONE_NAME */


/* wiloc message encoder */
/* implemented with 8 bits memory limited MCUs in mind */

typedef uint8_t small_size_t;
#define SMALL_SIZE_MAX ((uint8_t)-1)
#define SMALL_SIZEOF(__x) ((small_size_t)sizeof(__x))


static small_size_t encode_base64
(
 const uint8_t* sbuf, small_size_t slen,
 uint8_t* dbuf, small_size_t dlen
)
{
  static const uint8_t map[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

  small_size_t i;
  small_size_t x;

  if ((((slen + 2) / 3) * 4) > dlen) return 0;

  /* increment 3 chars at a time */
  for (i = 0, x = 0; x < slen; x += 3) 
  {
    /* turn these three chars into a 24 bits number */
    uint32_t n = ((uint32_t)sbuf[x]) << 16;
      
    if ((x + 1) < slen) n += ((uint32_t)sbuf[x + 1]) << 8;
    if ((x + 2) < slen) n += (uint32_t)sbuf[x + 2];

    /* split 24 bits into 4x 6 bits numbers */
            
    /* if 1 byte avail, its encoding is spread over 2 chars */
    dbuf[i++] = map[(uint8_t)(n >> 18) & 63];
    dbuf[i++] = map[(uint8_t)(n >> 12) & 63];

    /* if 2 bytes avail, encoding is spread over 3 chars */
    if ((x + 1) < slen) dbuf[i++] = map[(uint8_t)(n >> 6) & 63];

    /* if 3 bytes avail, encoding is spread over 4 chars */
    if ((x + 2) < slen) dbuf[i++] = map[(uint8_t)n & 63];
  }  

  /* pad if not a multiple of 3 */
  x = slen % 3;
  if (x)
  {
    for (; x != 3; ++x) dbuf[i++] = '=';
  }

  return i;
}

static small_size_t encode_wiloc_msg
(uint8_t* mbuf, small_size_t msize)
{
  /* encode a wiloc request */
  /* return the request size, including terminating 0 */

  /* encoding process */
  /* encode in base64 */
  /* add label dots */
  /* append zone */
  /* encode_name */

  static uint8_t tmp[SMALL_SIZE_MAX];
  small_size_t i;
  small_size_t j;
  small_size_t k;

  /* base64 encoding */

  j = encode_base64(mbuf, msize, tmp, SMALL_SIZEOF(tmp));

  /* add dots every 63 bytes chars */
  /* put a dot even at 0 for dns_name_encode to work in place */

  for (i = 0, k = 0; i != j; ++i, ++k)
  {
    if ((i % 63) == 0) mbuf[k++] = '.';
    mbuf[k] = tmp[i];
  }

  /* append zone */

  for (i = 0; DNS_ZONE_NAME[i]; ++i, ++k) mbuf[k] = DNS_ZONE_NAME[i];
  mbuf[k++] = 0;

  /* encode DNS name in place */

  mbuf[0] = 0;

  for (i = 1, j = 0; mbuf[i]; ++i)
  {
    if (mbuf[i] == '.')
    {
      j = i;
      mbuf[i] = 0;
    }
    else
    {
      ++mbuf[j];
    }
  }

  mbuf[i++] = 0;

  return i;
}


/* wifi api */

typedef struct
{
  /* access point information */
#define WIFI_ESSID_MAX_SIZE 32
  char essid[WIFI_ESSID_MAX_SIZE + 1];
#define WIFI_MACADDR_SIZE 6
  uint8_t macaddr[WIFI_MACADDR_SIZE];
  unsigned int rssi;
} wifi_ap_t;


#ifdef TARGET_LINUX

/* https://wireless.wiki.kernel.org/en/users/documentation/iw */
/* TODO: remove iwlib dep */

#include <string.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <iwlib.h>


#define CONFIG_DEBUG 1
#if (CONFIG_DEBUG == 1)
#include <stdio.h>
#define PRINTF(__s, ...) \
do { printf(__s, ## __VA_ARGS__); } while (0)
#define PERROR() \
printf("[!] %s:%d\n", __FILE__, __LINE__)
#define ASSUME(__x) \
do { if (!(__x)) printf("[!] %s:%d\n", __FILE__, __LINE__); } while (0)
#else
#define PRINTF(__s, ...)
#define PERROR()
#define ASSUME(__x)
#endif /* CONFIG_DEBUG */


typedef struct
{
  int sock;
  const char* ifname;
} wifi_handle_t;


static int wifi_open(wifi_handle_t* wi, const char* ifname)
{
  /* note: ifname must longlive until wifi_close */

  wi->sock = iw_sockets_open();
  if (wi->sock < 0)
  {
    PERROR();
    return -1;
  }

  wi->ifname = ifname;

  return 0;
}


static void wifi_close(wifi_handle_t* wi)
{
  iw_sockets_close(wi->sock);
}


static int wifi_get_open_aps(wifi_handle_t* wi, wifi_ap_t* aps, size_t* n)
{
  size_t i;
  int err;
  struct iwreq wrq;
  wireless_scan_head head;
  wireless_scan* pos;
  wireless_scan* next;
  iwrange range;

  err = iw_get_range_info(wi->sock, wi->ifname, &range);
  if (err < 0)
  {
    PERROR();
    err = -1;
    goto on_error_0;
  }
  
  err = iw_scan
    (wi->sock, (char*)wi->ifname, range.we_version_compiled, &head);
  if (err < 0)
  {
    PERROR();
    err = -1;
    goto on_error_0;
  }

  err = 0;
  i = 0;
  for (pos = head.result; (i != *n) && (pos != NULL); pos = next)
  {
    wifi_ap_t* const ap = &aps[i];
    unsigned int has_key;

    has_key = 1;
    if (pos->b.has_key == 0) has_key = 0;
    else if (pos->b.key_flags & IW_ENCODE_DISABLED) has_key = 0;
    else if (pos->b.key_flags & IW_ENCODE_OPEN) has_key = 0;
    if (has_key) goto skip_ap;

    if (pos->b.has_essid)
    {
      memcpy(ap->essid, pos->b.essid, WIFI_ESSID_MAX_SIZE);
      ap->essid[WIFI_ESSID_MAX_SIZE] = 0;
    }
    else
    {
      ap->essid[0] = 0;
    }

    if (pos->has_ap_addr)
    {
      const struct ether_addr* const a =
	(const struct ether_addr*)pos->ap_addr.sa_data;
      memcpy(ap->macaddr, a->ether_addr_octet, WIFI_MACADDR_SIZE);
    }

    ap->rssi = 0;
    if (iw_get_ext(wi->sock, wi->ifname, SIOCGIWSTATS, &wrq) == 0)
    {
      ap->rssi = (unsigned int)wrq.u.qual.level;
    }

    ++i;

  skip_ap:
    next = pos->next;
    free(pos);
  }

  *n = i;

  err = 0;

 on_error_0:
  return err;
}


static int wifi_assoc_ap(wifi_handle_t* wi, const wifi_ap_t* ap)
{
  struct iwreq wrq;
  int err;

  err = -1;

  wrq.u.data.pointer = (caddr_t)NULL;
  wrq.u.data.flags = 0;
  wrq.u.data.length = 0;
  wrq.u.data.flags |= (IW_ENCODE_DISABLED | IW_ENCODE_NOKEY);
  if (iw_set_ext(wi->sock, wi->ifname, SIOCSIWENCODE, &wrq) < 0)
  {
    PERROR();
    goto on_error;
  }

  wrq.u.essid.pointer = (caddr_t)ap->essid;
  wrq.u.essid.length = strlen(ap->essid) + 1;
  if (iw_set_ext(wi->sock, wi->ifname, SIOCSIWESSID, &wrq) < 0)
  {
    PERROR();
    goto on_error;
  }

  wrq.u.ap_addr.sa_family = ARPHRD_ETHER;
  memcpy(wrq.u.ap_addr.sa_data, ap->macaddr, WIFI_MACADDR_SIZE);
  if (iw_set_ext(wi->sock, wi->ifname, SIOCSIWAP, &wrq) < 0)
  {
    PERROR();
    goto on_error;
  }

  err = 0;

 on_error:
  return err;
}

__attribute__((unused))
static int wifi_main(int ac, char** av)
{
  /* TODO: avoid having to dhcp to save time */
  /* is an IP truly required ? the goal is to send the */
  /* DNS query. otherwise a full UDP stack is needed */

  /* TODO: select AP with best RSSI */

  static const char* const ifname = "wlan0";
  wifi_handle_t wi;
  wifi_ap_t aps[16];
  size_t nap;
  size_t i;
  size_t j;

  if (wifi_open(&wi, ifname)) goto on_error_0;

  nap = sizeof(aps) / sizeof(aps[0]);
  if (wifi_get_open_aps(&wi, aps, &nap)) goto on_error_1;

  for (i = 0; i != nap; ++i)
  {
    const wifi_ap_t* const ap = &aps[i];

    for (j = 0; j != WIFI_MACADDR_SIZE; ++j)
    {
      if (j) printf(":");
      printf("%02x", ap->macaddr[j]);
    }

    printf(" %s\n", ap->essid);
  }

  if (wifi_assoc_ap(&wi, &aps[3])) goto on_error_1;

 on_error_1:
  wifi_close(&wi);
 on_error_0:
  return 0;
}


#endif /* TARGET_LINUX */


#ifdef TARGET_LINUX

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../common/dns.h"

static int udp_send
(
 const char* addr, uint16_t port,
 const uint8_t* buf, size_t size
)
{
  int err = -1;
  int sock;
  size_t nsent;
  struct sockaddr sa;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) goto on_error_0;

  memset(&sa, 0, sizeof(sa));
  ((struct sockaddr_in*)&sa)->sin_family = AF_INET;
  ((struct sockaddr_in*)&sa)->sin_port = htons(port);
  ((struct sockaddr_in*)&sa)->sin_addr.s_addr = inet_addr(addr);

  nsent = (size_t)sendto
    (sock, buf, size, 0, (const struct sockaddr*)&sa, sizeof(sa));
  if (nsent != size) goto on_error_1;

  err = 0;
 on_error_1:
  close(sock);
 on_error_0:
  return err;
}


/* command line */

typedef struct
{
  const char* daddr;
  uint16_t dport;
} cmd_info_t;

static int get_cmd_info(cmd_info_t* ci, size_t ac, const char** av)
{
  size_t i;

  if (ac & 1) return -1;

  ci->daddr = "127.0.0.1";
  ci->dport = DNS_SERVER_PORT;

  for (i = 0; i != ac; i += 2)
  {
    const char* const k = av[i + 0];
    const char* const v = av[i + 1];

    if (strcmp(k, "-daddr") == 0)
    {
      ci->daddr = v;
    }
    else if (strcmp(k, "-dport") == 0)
    {
      ci->dport = (uint16_t)strtoul(v, NULL, 10);
    }
  }

  return 0;
}


/* main */

int main(int ac, char** av)
{
  uint8_t buf[SMALL_SIZE_MAX];
  dns_header_t* dnsh;
  dns_query_t* dnsq;
  wiloc_msg_t* wilm;
  uint8_t* macs;
  small_size_t size;
  small_size_t i;
  cmd_info_t ci;

  if (get_cmd_info(&ci, (size_t)ac - 1, (const char**)av + 1))
  {
    printf("error @%u\n", __LINE__);
    return -1;
  }

  dnsh = (dns_header_t*)buf;
  dnsh->id = htons(0xdead);
  dnsh->flags = htons(DNS_HDR_FLAG_RD);
  dnsh->qdcount = htons(1);
  dnsh->ancount = htons(0);
  dnsh->nscount = htons(0);
  dnsh->arcount = htons(0);

  wilm = (wiloc_msg_t*)(buf + sizeof(dns_header_t));
  wilm->vers = WILOC_MSG_VERS;
  wilm->flags = WILOC_MSG_FLAG_WIFI | WILOC_MSG_FLAG_TICK;
  wilm->did = 0x2a;
  wilm->count = 16;

  macs = (uint8_t*)wilm + sizeof(wiloc_msg_t);
  for (i = 0; i != (wilm->count * 6); ++i) macs[i] = i;
  size = encode_wiloc_msg
    ((uint8_t*)wilm, SMALL_SIZEOF(wiloc_msg_t) + wilm->count * 6);

  dnsq = (dns_query_t*)(buf + sizeof(dns_header_t) + size);
  dnsq->qtype = htons(DNS_RR_TYPE_A);
  dnsq->qclass = htons(DNS_RR_CLASS_IN);

  size += sizeof(dns_header_t) + sizeof(dns_query_t);
  if (udp_send(ci.daddr, ci.dport, buf, size))
  {
    printf("error @%u\n", __LINE__);
    return -1;
  }

  return 0;
}

#endif /* TARGET_LINUX */
