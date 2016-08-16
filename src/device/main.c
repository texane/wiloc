#include <stdint.h>
#include "../common/dns.h"


typedef struct ap_info
{
#define ESSID_MAX_SIZE 32
  char essid[ESSID_MAX_SIZE + 1];
  uint8_t addr[6];
} ap_info_t;



#ifdef TARGET_LINUX


/* https://wireless.wiki.kernel.org/en/users/documentation/iw */

#include <string.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <iwlib.h>


static int wifi_get_open_aps
(const char* ifname, ap_info_t* aps, size_t* n)
{
  size_t i;
  int sok;
  int err;
  wireless_scan_head head;
  wireless_scan* pos;
  wireless_scan* next;
  iwrange range;

  sok = iw_sockets_open();
  if (sok < 0)
  {
    err = -1;
    goto on_error_0;
  }

  err = iw_get_range_info(sok, ifname, &range);
  if (err < 0)
  {
    err = -1;
    goto on_error_1;
  }
  
  err = iw_scan(sok, (char*)ifname, range.we_version_compiled, &head);
  if (err < 0)
  {
    err = -1;
    goto on_error_1;
  }

  i = 0;
  for (pos = head.result; (i != *n) && (pos != NULL); pos = next)
  {
    ap_info_t* ap = &aps[i];
    unsigned int has_key;

    has_key = 1;
    if (pos->b.has_key == 0) has_key = 0;
    else if (pos->b.key_flags & IW_ENCODE_DISABLED) has_key = 0;
    else if (pos->b.key_flags & IW_ENCODE_OPEN) has_key = 0;
    if (has_key) goto skip_ap;

    if (pos->b.has_essid)
    {
      memcpy(ap->essid, pos->b.essid, ESSID_MAX_SIZE);
      ap->essid[ESSID_MAX_SIZE] = 0;
    }
    else
    {
      ap->essid[0] = 0;
    }

    if (pos->has_ap_addr)
    {
      const struct ether_addr* const a = (struct ether_addr*)pos->ap_addr.sa_data;
      memcpy(ap->addr, a->ether_addr_octet, 6);
    }

    ++i;

  skip_ap:
    next = pos->next;
    free(pos);
  }

  *n = i;

  err = 0;

 on_error_1:
  iw_sockets_close(sok);
 on_error_0:
  return err;
}


static int wifi_assoc_ap(const char* ifname, const ap_info_t* ap)
{
  struct iwreq wrq;
  int sok;
  int err;

  err = -1;

  sok = iw_sockets_open();
  if (sok < 0)
  {
    printf("error %u\n", __LINE__);
    goto on_error_0;
  }

  wrq.u.data.pointer = (caddr_t)NULL;
  wrq.u.data.flags = 0;
  wrq.u.data.length = 0;
  wrq.u.data.flags |= (IW_ENCODE_DISABLED | IW_ENCODE_NOKEY);
  if (iw_set_ext(sok, ifname, SIOCSIWENCODE, &wrq) < 0)
  {
    printf("error %u\n", __LINE__);
    goto on_error_1;
  }

  wrq.u.essid.pointer = (caddr_t)ap->essid;
  wrq.u.essid.length = strlen(ap->essid) + 1;
  if (iw_set_ext(sok, ifname, SIOCSIWESSID, &wrq) < 0)
  {
    printf("error %u\n", __LINE__);
    goto on_error_1;
  }

  wrq.u.ap_addr.sa_family = ARPHRD_ETHER;
  memcpy(wrq.u.ap_addr.sa_data, ap->addr, 6);
  if (iw_set_ext(sok, ifname, SIOCSIWAP, &wrq) < 0)
  {
    printf("error %u\n", __LINE__);
    goto on_error_1;
  }

  err = 0;

 on_error_1:
  iw_sockets_close(sok);
 on_error_0:
  return err;
}


#endif /* TARGET_LINUX */


int main(int ac, char** av)
{
  static const char* const ifname = "wlan0";
  ap_info_t aps[16];
  size_t i;
  size_t j;
  size_t n;

  n = sizeof(aps) / sizeof(aps[0]);
  if (wifi_get_open_aps(ifname, aps, &n)) goto on_error_0;

  for (i = 0; i != n; ++i)
  {
    const ap_info_t* const ap = &aps[i];

    for (j = 0; j != 6; ++j)
    {
      if (j) printf(":");
      printf("%02x", ap->addr[j]);
    }

    printf(" %s\n", ap->essid);
  }

  if (wifi_assoc_ap(ifname, &aps[3])) goto on_error_0;

 on_error_0:
  return 0;
}
