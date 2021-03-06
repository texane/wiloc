#include "wiloc.h"
#include "../common/dns.h"
#include "../common/wiloc.h"


/* wiloc message encoder */
/* implemented with 8 bits memory limited MCUs in mind */

#ifndef CONFIG_DNS_ZONE
#error "missing CONFIG_DNS_ZONE=.my.zone.com"
#endif /* CONFIG_DNS_ZONE */

static void ICACHE_FLASH_ATTR encode_coord
(uint8_t* buf, const char* coord)
{
  static const small_size_t precision = WILOC_COORD_PRECISION;
  uint32_t x;
  small_size_t i;
  uint8_t isn;

  isn = 0;
  if (*coord == '-')
  {
    isn = 1;
    ++coord;
  }
  else if (*coord == '+')
  {
    ++coord;
  }

  for (; *coord == '0'; ++coord) ;

  x = 0;
  for (; *coord && (*coord != '.'); ++coord)
    x = x * 10 + (uint32_t)(*coord - '0');

  i = 0;
  if ((coord[0] == 0) || (coord[1] == 0)) goto skip_decimals;
  ++coord;

  /* i the maximum precision */
  for (; *coord && (i != precision); ++i, ++coord)
    x = x * 10 + (uint32_t)(*coord - '0');

 skip_decimals:
  for (; i != precision; ++i) x *= 10;
  if (isn) x *= -1;

  buf[0] = (uint8_t)(x >> 24);
  buf[1] = (uint8_t)(x >> 16);
  buf[2] = (uint8_t)(x >> 8);
  buf[3] = (uint8_t)(x >> 0);
}


static small_size_t ICACHE_FLASH_ATTR encode_base64
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

static small_size_t ICACHE_FLASH_ATTR encode_wiloc_msg
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

  for (i = 0; CONFIG_DNS_ZONE[i]; ++i, ++k) mbuf[k] = CONFIG_DNS_ZONE[i];
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


/* scan done task */

static void ICACHE_FLASH_ATTR on_scan_done
(void* p, STATUS status)
{
  if (status != OK) p = NULL;
  if (((scaninfo*)p)->pbss == NULL) p = NULL;

  /* force next state scheduling */
  wiloc_next(p);

  /* rearm timer if still disabled */
  if (os_timer_is_disabled()) os_timer_rearm(OS_TIMER_100MS);
}


/* utils */

static inline uint16_t ICACHE_FLASH_ATTR uint16_to_be(uint16_t x)
{
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  x = (x >> 8) | (x << 8);
#endif
  return x;
}


/* wiloc state machine */

typedef enum
{
  WILOC_STATE_INIT = 0,
  WILOC_STATE_START,
  WILOC_STATE_SCAN,
  WILOC_STATE_CONNECT,
  WILOC_STATE_SEND,
  WILOC_STATE_SKIP,
  WILOC_STATE_FINI,
  WILOC_STATE_DONE,
  WILOC_STATE_INVALID
} wiloc_state_t;

static wiloc_state_t wiloc_state = WILOC_STATE_INIT;
static ip_addr_t wiloc_dnsaddr;
static os_udp_t wiloc_udp;

void ICACHE_FLASH_ATTR wiloc_next(void* p)
{
  switch (wiloc_state)
  {
  case WILOC_STATE_INIT:
    {
      /* init resource once */
      /* release in WILOC_STATE_FINI */

      if (os_udp_init(&wiloc_udp))
      {
	/* fatal error */
	PERROR();
	wiloc_state = WILOC_STATE_FINI;
	return ;
      }

      wifi_set_opmode_current(STATION_MODE);
      wifi_station_set_auto_connect(0);

      wiloc_state = WILOC_STATE_START;

      break ;
    }

  case WILOC_STATE_START:
    {
      /* start a scan */

      struct scan_config scan_config;

      /* let on_scan_done rearm timer */
      os_timer_disable();

      scan_config.ssid = NULL;
      scan_config.bssid = NULL;
      scan_config.channel = 0;
      scan_config.show_hidden = 1;
      wiloc_state = WILOC_STATE_SCAN;
      wifi_station_scan(&scan_config, on_scan_done);

      break ;
    }

  case WILOC_STATE_SCAN:
    {
      /* scan completed */

      struct bss_info* bi;
      const struct bss_info* open_bi;
      struct station_config sc;
      uint8_t* buf;
      dns_header_t* dnsh;
      dns_query_t* dnsq;
      wiloc_msg_t* wilm;
      small_size_t size;
      uint8_t* macs;

      /* scan failed, next scan */
      if (bi == NULL)
      {
	PERROR();
	wiloc_state = WILOC_STATE_SKIP;
	return ;
      }

      /* fill dns query */

      buf = os_udp_get_buf_data(&wiloc_udp);
      dnsh = (dns_header_t*)buf;
      dnsh->id = uint16_to_be(0xdead);
      dnsh->flags = uint16_to_be(DNS_HDR_FLAG_RD);
      dnsh->qdcount = uint16_to_be(1);
      dnsh->ancount = uint16_to_be(0);
      dnsh->nscount = uint16_to_be(0);
      dnsh->arcount = uint16_to_be(0);

      /* prepare wiloc message */

      wilm = (wiloc_msg_t*)(buf + sizeof(dns_header_t));
      wilm->vers = WILOC_MSG_VERS;
      wilm->flags = WILOC_MSG_FLAG_TICK;
      wilm->did = 0x2a;
      wilm->mac_count = 0;
      macs = (uint8_t*)wilm + sizeof(wiloc_msg_t);

      /* detect open access point */
      /* prepare wiloc message */

      open_bi = NULL;
      STAILQ_FOREACH(bi, ((scaninfo*)p)->pbss, next)
      {
	/* TODO: remove hardcoded filter */
	if (memcmp(bi->ssid, "Free", 4) == 0)
	{
	  if ((bi->authmode == AUTH_OPEN) && (open_bi == NULL))
	    open_bi = bi;
	}

	if (wilm->mac_count != 16)
	{
	  memcpy(macs, bi->bssid, 6);
	  macs += 6;
	  ++wilm->mac_count;
	}

#if defined(CONFIG_DEBUG) && (CONFIG_DEBUG == 1)
	if (bi->ssid_len > 31) bi->ssid_len = 31;
	bi->ssid[bi->ssid_len] = 0;

	PRINTF
	(
	 "[x] new ap: " MACSTR " %u %s",
	 MAC2STR(bi->bssid), bi->authmode, bi->ssid
	);
#endif /* CONFIG_DEBUG */
      }

      if (open_bi == NULL)
      {
	PERROR();
	wiloc_state = WILOC_STATE_SKIP;
	return ;
      }

      /* complete wiloc message */

      size = wilm->mac_count * 6;
      size = encode_wiloc_msg
	((uint8_t*)wilm, SMALL_SIZEOF(wiloc_msg_t) + size);

      /* complete dns query */

      dnsq = (dns_query_t*)(buf + sizeof(dns_header_t) + size);
      dnsq->qtype = uint16_to_be(DNS_RR_TYPE_A);
      dnsq->qclass = uint16_to_be(DNS_RR_CLASS_IN);

      size += sizeof(dns_header_t) + sizeof(dns_query_t);
      os_udp_set_buf_size(&wiloc_udp, size);

      /* connect to open access point */

      memcpy(sc.ssid, open_bi->ssid, open_bi->ssid_len);
      if (open_bi->ssid_len <= 31) sc.ssid[open_bi->ssid_len] = 0;
      sc.bssid_set = 1;
      memcpy(sc.bssid, open_bi->bssid, sizeof(sc.bssid));

      if (wifi_station_set_config_current(&sc) == false)
      {
	PERROR();
	wiloc_state = WILOC_STATE_SKIP;
	return ;
      }

      if (wifi_station_dhcpc_status() == DHCP_STARTED)
	wifi_station_dhcpc_stop();

      wifi_station_dhcpc_set_maxtry(10);

      if (wifi_station_dhcpc_start() == false)
      {
	PERROR();
	wiloc_state = WILOC_STATE_SKIP;
	return ;
      }

      if (wifi_station_connect() == false)
      {
	PERROR();
	wiloc_state = WILOC_STATE_SKIP;
	return ;
      }

      wiloc_state = WILOC_STATE_CONNECT;
     
      break ;
    }

  case WILOC_STATE_CONNECT:
    {
      uint8 status;

      status = wifi_station_get_connect_status();
      switch (status)
      {
      case STATION_GOT_IP:
	{
	  struct ip_info ipi;

	  if (wifi_get_ip_info(STATION_IF, &ipi) == false)
	  {
	    PERROR();
	    wiloc_state = WILOC_STATE_SKIP;
	    return ;
	  }

	  wiloc_dnsaddr = dns_getserver(0);

	  PRINTF
	  (
	   "[x] ip = " IPSTR ", gw = " IPSTR ", dns = " IPSTR,
	   IP2STR(&ipi.ip), IP2STR(&ipi.gw), IP2STR(&wiloc_dnsaddr)
	  );

	  wiloc_state = WILOC_STATE_SEND;

	  break ;
	}

      case STATION_IDLE:
      case STATION_CONNECTING:
	{
	  /* same state */
	  break ;
	}

      case STATION_WRONG_PASSWORD:
      case STATION_NO_AP_FOUND:
      case STATION_CONNECT_FAIL:
      default:
	{
	  PERROR();
	  wiloc_state = WILOC_STATE_SKIP;
	  return ;
	}
      }

      break ;
    }

  case WILOC_STATE_SEND:
    {
      /* send the wiloc message */

      if (os_udp_sendto(&wiloc_udp, &wiloc_dnsaddr, 53))
      {
	PERROR();
	wiloc_state = WILOC_STATE_SKIP;
	return ;
      }

      /* FIXME: wait for packet transmission */
      /* FIXME: is it really usefull */
      os_timer_rearm(OS_TIMER_100MS);

      wiloc_state = WILOC_STATE_SKIP;

      break ;
    }

  case WILOC_STATE_SKIP:
    {
      wifi_station_disconnect();
      wifi_station_dhcpc_stop();

      /* set delay to 10s before rescanning */
      os_timer_rearm(100 * OS_TIMER_100MS);

      wiloc_state = WILOC_STATE_START;

      break ;
    }

  case WILOC_STATE_FINI:
    {
      os_udp_fini(&wiloc_udp);
      wiloc_state = WILOC_STATE_DONE;
      break ;
    }

  case WILOC_STATE_DONE:
  default:
    {
      /* same state */
      wiloc_state = WILOC_STATE_DONE;
      break ;
    }
  }
}
