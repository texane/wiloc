#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "../common/dns.h"
#include "../common/wiloc.h"


/* wiloc message decoder */

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
  /* decode a wiloc request */
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


/* udp server */

typedef struct
{
  int sock;
  uint8_t* buf;
  size_t off;
  size_t size;
} udp_server_t;


static int udp_server_open
(udp_server_t* serv, const char* addr, uint16_t port)
{
  struct sockaddr sa;

  serv->size = DNS_MSG_MAX_UDP_SIZE;
  serv->buf = malloc(serv->size * sizeof(uint8_t));
  if (serv->buf == NULL) goto on_error_0;
  serv->off = 0;

  serv->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (serv->sock == -1) goto on_error_1;

  memset(&sa, 0, sizeof(sa));
  ((struct sockaddr_in*)&sa)->sin_family = AF_INET;
  ((struct sockaddr_in*)&sa)->sin_port = htons(port);
  ((struct sockaddr_in*)&sa)->sin_addr.s_addr = inet_addr(addr);
  if (bind(serv->sock, &sa, sizeof(sa))) goto on_error_2;

  return 0;

 on_error_2:
  close(serv->sock);
 on_error_1:
  free(serv->buf);
 on_error_0:
  return -1;
}


static void udp_server_close
(udp_server_t* serv)
{
  close(serv->sock);
  free(serv->buf);
}


static int udp_server_recv
(udp_server_t* serv)
{
  size_t size;

  size = (size_t)recv
    (serv->sock, serv->buf + serv->off, serv->size - serv->off, 0);
  if (size <= 0) return -1;

  serv->off += size;

  return 0;
}


/* dns query handler */

static size_t handle_dns_query
(
 const uint8_t* buf, size_t size,
 uint8_t** wilm_buf, size_t* wilm_size
)
{
  /* return 0 if valid but need more data */
  /* return (size_t)-1 if invalid */
  /* return the total query size if complete */

  /* on success */
  /* wilm_buf points at the beginning of the wiloc msg */
  /* wilm_size holds the wiloc msg size */

  size_t i;

  if (size < sizeof(dns_header_t)) return 0;

  for (i = sizeof(dns_header_t); i < size; i += (size_t)buf[i] + 1)
  {
    if ((size_t)buf[i] == 0) break ;
  }

  if (i >= size) return 0;
  if ((size - i) < sizeof(dns_query_t)) return 0;

  *wilm_buf = (uint8_t*)(buf + sizeof(dns_header_t));
  *wilm_size = i - sizeof(dns_header_t);

  return sizeof(dns_header_t) + i + sizeof(dns_query_t);
}


/* command line */

typedef struct
{
  const char* laddr;
  uint16_t lport;
} cmd_info_t;

static int get_cmd_info(cmd_info_t* ci, size_t ac, const char** av)
{
  size_t i;

  if (ac & 1) return -1;

  ci->laddr = "0.0.0.0";
  ci->lport = DNS_SERVER_PORT;

  for (i = 0; i != ac; i += 2)
  {
    const char* const k = av[i + 0];
    const char* const v = av[i + 1];

    if (strcmp(k, "-laddr") == 0)
    {
      ci->laddr = v;
    }
    else if (strcmp(k, "-lport") == 0)
    {
      ci->lport = (uint16_t)strtoul(v, NULL, 10);
    }
  }

  return 0;
}


/* main */

int main(int ac, char** av)
{
  udp_server_t serv;
  wiloc_msg_t* wilm;
  size_t dnsq_size;
  size_t wilm_size;
  int err = -1;
  cmd_info_t ci;
  size_t tick;

  if (get_cmd_info(&ci, (size_t)ac - 1, (const char**)av + 1))
  {
    printf("error @%u\n", __LINE__);
    goto on_error_0;
  }

  if (udp_server_open(&serv, ci.laddr, ci.lport))
  {
    printf("error @%u\n", __LINE__);
    goto on_error_0;
  }

  tick = 0;

  while (1)
  {
    if (udp_server_recv(&serv)) break ;

    dnsq_size = handle_dns_query
      (serv.buf, serv.off, (uint8_t**)&wilm, &wilm_size);
    if (dnsq_size == 0)
    {
      continue ;
    }
    else if (dnsq_size == (size_t)-1)
    {
      serv.size = 0;
    }
    else
    {
      const uint8_t* const mac = (uint8_t*)wilm + sizeof(wiloc_msg_t);
      size_t i;
      size_t j;

      err = decode_wiloc_msg((uint8_t*)wilm, serv.off);
      if (err) goto on_error_1;

      printf("tick: %zu\n", tick);
      printf("did : 0x%02x\n", wilm->did);
      printf("macs:\n");
      for (i = 0; i != (size_t)wilm->count; ++i)
      {
	printf("%02x", mac[i * 6 + 0]);
	for (j = 1; j != 6; ++j) printf(":%02x", mac[i * 6 + j]);
	printf("\n");
      }
      printf("\n");

      if (wilm->flags & WILOC_MSG_FLAG_TICK) ++tick;

      memcpy(serv.buf, serv.buf + wilm_size, serv.off - wilm_size);
      serv.off = 0;
    }
  }

  err = 0;

 on_error_1:
  udp_server_close(&serv);
 on_error_0:
  return err;
}
