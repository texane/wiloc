#include <stdint.h>
#include "../common/dns.h"


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


#endif /* TARGET_LINUX */


int main(int ac, char** av)
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
  size_t k;

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
