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


static void encode_coord(uint8_t* buf, const char* coord)
{
  uint16_t x;
  uint32_t y;
  uint32_t m;
  uint8_t i;

  i = 0;
  if (*coord == '-')
  {
    i = 1;
    ++coord;
  }
  else if (*coord == '+')
  {
    ++coord;
  }

  for (; *coord == '0'; ++coord) ;

  x = 0;
  for (; *coord && (*coord != '.'); ++coord)
  {
    x *= 10;
    x += (uint16_t)(*coord - '0');
  }

  if (i) x *= -1;

  y = 0;
  if ((coord[0] == 0) || (coord[1] == 0)) goto skip_decimals;
  ++coord;
  m = (uint32_t)1e4;
  for (i = 0; *coord && (i != 5); ++i, ++coord)
  {
    y += (uint32_t)(*coord - '0') * m;
    m /= 10;
  }

  y = (y * (uint32_t)(1 << 15)) / (uint32_t)1e5;

 skip_decimals:
  buf[0] = (uint8_t)(x >> 1);
  buf[1] = (uint8_t)((x << 7) | ((y >> 8) & 0x7f));
  buf[2] = (uint8_t)y;
}


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
  unsigned int is_open;
} wifi_ap_t;


#ifdef TARGET_LINUX

/* https://wireless.wiki.kernel.org/en/users/documentation/iw */
/* TODO: remove iwlib dep */

#include <string.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <iwlib.h>
#include <arpa/nameser.h>
#include <resolv.h>


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
  struct sockaddr_in nsaddr;
} wifi_handle_t;


static int wifi_open(wifi_handle_t* wi, const char* ifname)
{
  /* note: ifname must longlive until wifi_close */

  struct ifreq ifr;

  wi->sock = iw_sockets_open();
  if (wi->sock < 0)
  {
    PERROR();
    goto on_error_0;
  }

  wi->ifname = ifname;

  /* bring interface up */

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, wi->ifname, IFNAMSIZ);
  if (ioctl(wi->sock, SIOCGIFFLAGS, &ifr))
  {
    PERROR();
    goto on_error_1;
  }

  if ((ifr.ifr_flags & IFF_UP) == 0)
  {
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(wi->sock, SIOCSIFFLAGS, &ifr))
    {
      PERROR();
      goto on_error_1;
    }
  }

  return 0;

 on_error_1:
  iw_sockets_close(wi->sock);
 on_error_0:
  return -1;
}


static void wifi_close(wifi_handle_t* wi)
{
  iw_sockets_close(wi->sock);
}


static int wifi_get_aps
(wifi_handle_t* wi, wifi_ap_t* aps, size_t* n, size_t* open_index)
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
  *open_index = (size_t)-1;
  for (pos = head.result; (i != *n) && (pos != NULL); pos = next)
  {
    wifi_ap_t* const ap = &aps[i];

    ap->is_open = 0;
    if (pos->b.has_key == 0) ap->is_open = 1;
    else if (pos->b.key_flags & IW_ENCODE_DISABLED) ap->is_open = 1;
    else if (pos->b.key_flags & IW_ENCODE_OPEN) ap->is_open = 1;

    /* find at least one unencrypted ap */
    if (*open_index == (size_t)-1)
    {
      if (ap->is_open) *open_index = i;
      else if (i == (*n - 1)) goto skip_ap;
    }

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


static int wifi_do_dhclient(wifi_handle_t* wi)
{
  char cmd[128];
  int err = -1;
  size_t i;
  struct __res_state state;

  snprintf(cmd, sizeof(cmd), "dhclient %s", wi->ifname);
  if (system(cmd)) goto on_error_0;

  /* retrieve nsaddr from resolver */

  memset(&wi->nsaddr, 0, sizeof(wi->nsaddr));

  if (res_ninit(&state)) goto on_error_0;
  if (state.nscount <= 0) goto on_error_1;

  for (i = 0; i != state.nscount; ++i)
  {
    if (state.nsaddr_list[i].sin_family == AF_INET) break ;
  }

  if (i == (size_t)state.nscount) goto on_error_1;

  memcpy(&wi->nsaddr, &state.nsaddr_list[i], sizeof(wi->nsaddr));

  err = 0;

 on_error_1:
  res_nclose(&state);
 on_error_0:
  return err;
}


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


static int send_macs
(
 const uint8_t* macs, small_size_t nmac,
 const char* daddr, uint16_t dport
)
{
  uint8_t buf[SMALL_SIZE_MAX];
  dns_header_t* dnsh;
  dns_query_t* dnsq;
  wiloc_msg_t* wilm;
  small_size_t size;
  small_size_t i;

  dnsh = (dns_header_t*)buf;
  dnsh->id = htons(0xdead);
  dnsh->flags = htons(DNS_HDR_FLAG_RD);
  dnsh->qdcount = htons(1);
  dnsh->ancount = htons(0);
  dnsh->nscount = htons(0);
  dnsh->arcount = htons(0);

  wilm = (wiloc_msg_t*)(buf + sizeof(dns_header_t));
  wilm->vers = WILOC_MSG_VERS;
  wilm->flags = WILOC_MSG_FLAG_TICK;
  wilm->did = 0x2a;
  wilm->mac_count = (uint8_t)nmac;

  for (i = 0; i != (wilm->mac_count * 6); ++i)
  {
    ((uint8_t*)wilm)[SMALL_SIZEOF(wiloc_msg_t) + i] = macs[i];
  }

  size = encode_wiloc_msg
    ((uint8_t*)wilm, SMALL_SIZEOF(wiloc_msg_t) + wilm->mac_count * 6);

  dnsq = (dns_query_t*)(buf + sizeof(dns_header_t) + size);
  dnsq->qtype = htons(DNS_RR_TYPE_A);
  dnsq->qclass = htons(DNS_RR_CLASS_IN);

  size += sizeof(dns_header_t) + sizeof(dns_query_t);
  if (udp_send(daddr, dport, buf, size)) return -1;

  return 0;
}


static int wifi_main(int ac, char** av)
{
  static const char* const ifname = "wlan0";
  wifi_handle_t wi;
  wifi_ap_t aps[16];
  uint8_t macs[16 * 6];
  size_t nap;
  size_t i;
  size_t j;
  size_t open_index;
  const char* nsaddr;
  uint16_t nsport;
  int err = -1;

  if (wifi_open(&wi, ifname)) goto on_error_0;

  nap = sizeof(aps) / sizeof(aps[0]);
  if (wifi_get_aps(&wi, aps, &nap, &open_index)) goto on_error_1;

  for (i = 0; i != nap; ++i)
  {
    const wifi_ap_t* const ap = &aps[i];

    memcpy(macs + i * 6, ap->macaddr, 6);

    for (j = 0; j != WIFI_MACADDR_SIZE; ++j)
    {
      if (j) printf(":");
      printf("%02x", ap->macaddr[j]);
    }

    printf(" %s", ap->essid);
    if (i == open_index) printf(" (*)");
    else if (ap->is_open) printf(" (x)");
    printf("\n");
  }

  if (open_index == (size_t)-1) goto on_error_1;

  if (wifi_assoc_ap(&wi, &aps[open_index])) goto on_error_1;

  if (wifi_do_dhclient(&wi)) goto on_error_1;

  nsaddr = (const char*)inet_ntoa(wi.nsaddr.sin_addr);
  nsport = ntohs(wi.nsaddr.sin_port);

  if (send_macs(macs, (small_size_t)nap, nsaddr, nsport)) goto on_error_1;

  err = 0;

 on_error_1:
  wifi_close(&wi);
 on_error_0:
  return err;
}


#endif /* TARGET_LINUX */


#ifdef TARGET_LINUX

#if 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../common/dns.h"


/* command line */

typedef struct
{
  const char* daddr;
  uint16_t dport;
  uint8_t did;
  const char* coords[2];
} cmd_info_t;

static int get_cmd_info(cmd_info_t* ci, size_t ac, const char** av)
{
  size_t i;

  if (ac & 1) return -1;

  ci->daddr = "127.0.0.1";
  ci->dport = DNS_SERVER_PORT;
  ci->did = 0x2a;
  ci->coords[0] = NULL;
  ci->coords[1] = NULL;

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
    else if (strcmp(k, "-did") == 0)
    {
      ci->did = (uint8_t)strtoul(v, NULL, 16);
    }
    else if (strcmp(k, "-coords") == 0)
    {
      size_t j;
      ci->coords[0] = v;
      for (j = 0; v[j] && (v[j] != ','); ++j) ;
      if (v[j] == ',') ci->coords[1] = v + j + 1;
      else ci->coords[1] = "0.0";
      ((char*)v)[j] = 0;
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
  wilm->flags = WILOC_MSG_FLAG_TICK;
  wilm->did = ci.did;
  wilm->mac_count = 16;

  size = wilm->mac_count * 6;
  macs = (uint8_t*)wilm + sizeof(wiloc_msg_t);
  for (i = 0; i != size; ++i) macs[i] = i;

  if (ci.coords[0] != NULL)
  {
    uint8_t* const coords = macs + size;
    size += 6;
    wilm->flags |= WILOC_MSG_FLAG_COORDS;
    encode_coord(coords + 0, ci.coords[0]);
    encode_coord(coords + 3, ci.coords[1]);
  }

  size = encode_wiloc_msg
    ((uint8_t*)wilm, SMALL_SIZEOF(wiloc_msg_t) + size);

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

#else

int main(int ac, char** av)
{
  return wifi_main(ac, av);
}

#endif

#endif /* TARGET_LINUX */
