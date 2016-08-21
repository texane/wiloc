/* device side */

#include <stdint.h>
#include "../common/dns.h"
#include "../common/wiloc.h"


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
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  small_size_t i;
  small_size_t x;

  if ((((slen + 2) / 3) * 4) > dlen) return 0;

  /* increment over the length of the string, three characters at a time */

  for (i = 0, x = 0; x < slen; x += 3) 
  {
    /* turn these three chars into a 24 bits number */
    uint32_t n = ((uint32_t)sbuf[x]) << 16;
      
    if ((x + 1) < slen) n += ((uint32_t)sbuf[x + 1]) << 8;
    if ((x + 2) < slen) n += (uint32_t)sbuf[x + 2];

    /* split 24 bits into 4x 6 bits numbers */
            
    /* if we have 1 byte avail, its encoding is spread over 2 chars */
    dbuf[i++] = map[(uint8_t)(n >> 18) & 63];
    dbuf[i++] = map[(uint8_t)(n >> 12) & 63];

    /* if we have 2 bytes avail, encoding is spread over 3 chars */
    if ((x + 1) < slen) dbuf[i++] = map[(uint8_t)(n >> 6) & 63];

    /* if we have 3 bytes avail, encoding is spread over 4 chars */
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


static small_size_t encode_wiloc_req(uint8_t* rbuf, small_size_t rsize)
{
  /* encoding process */
  /* fill wiloc_query */
  /* encode in base64 */
  /* add label dots */
  /* append zone */
  /* encode_name */

  static const small_size_t mac_size = 6;
  wiloc_req_t* const req = (wiloc_req_t*)rbuf;
  uint8_t tmp[SMALL_SIZE_MAX];
  small_size_t i;
  small_size_t j;
  small_size_t k;

  /* base64 encoding */

  i = SMALL_SIZEOF(wiloc_req_t) + req->count * mac_size;
  j = encode_base64(rbuf, i, tmp, SMALL_SIZEOF(tmp));

  /* add dots every 63 bytes chars */
  /* put a dot even at 0 for dns_name_encode to work in place */

  for (i = 0, k = 0; i != j; ++i, ++k)
  {
    if ((i % 63) == 0) rbuf[k++] = '.';
    rbuf[k] = tmp[i];
  }

  /* append zone */

  for (i = 0; DNS_ZONE_NAME[i]; ++i, ++k) rbuf[k] = DNS_ZONE_NAME[i];
  rbuf[k++] = 0;

  /* encode DNS name in place */

  rbuf[0] = 0;

  for (i = 1, j = 0; rbuf[i]; ++i)
  {
    if (rbuf[i] == '.')
    {
      j = i;
      rbuf[i] = 0;
    }
    else
    {
      ++rbuf[j];
    }
  }

  rbuf[i++] = 0;

  return i;
}


/* server side */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static int decode_base64
(uint8_t* in, size_t inLen, size_t *outLen)
{ 

  static const uint8_t d[] =
  {
    66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
    54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
  };

  uint8_t* out = in;
  uint8_t* end = in + inLen;
  char iter = 0;
  size_t buf = 0, len = 0;
    
  while (in < end) {
    uint8_t c = d[(size_t)(*in++)];
        
    switch (c) {
    case WHITESPACE: continue;   /* skip whitespace */
    case INVALID:    return 1;   /* invalid input, return error */
    case EQUALS:                 /* pad character, end of data */
      in = end;
      continue;
    default:
      buf = buf << 6 | c;
      iter++; // increment the number of iteration
      /* If the buffer is full, split it into bytes */
      if (iter == 4) {
	if ((len += 3) > *outLen) return 1; /* buffer overflow */
	*(out++) = (buf >> 16) & 255;
	*(out++) = (buf >> 8) & 255;
	*(out++) = buf & 255;
	buf = 0; iter = 0;

      }   
    }
  }
   
  if (iter == 3) {
    if ((len += 2) > *outLen) return 1; /* buffer overflow */
    *(out++) = (buf >> 10) & 255;
    *(out++) = (buf >> 2) & 255;
  }
  else if (iter == 2) {
    if (++len > *outLen) return 1; /* buffer overflow */
    *(out++) = (buf >> 4) & 255;
  }

  *outLen = len; /* modify to reflect the actual output size */
  return 0;
}

static int decode_wiloc_req
(
 const uint8_t* rbuf, size_t rsize,
 uint8_t* macs, size_t* nmac
)
{
  /* decoding process */
  /* decode name */
  /* strip zone */
  /* remove label dots */
  /* decode base64 */
  /* interpret wiloc request */

  static const small_size_t mac_size = 6;
  const wiloc_req_t* req;
  uint8_t tmp[256];
  size_t i;
  size_t j;
  size_t k;

  if (rsize <= sizeof(DNS_ZONE_NAME)) return -1;
  rsize -= sizeof(DNS_ZONE_NAME);

  i = 0;
  k = 0;
  for (j = 0; j != rsize; ++j)
  {
    if (j == k) k += (size_t)rbuf[j] + 1;
    else tmp[i++] = rbuf[j];
  }
  tmp[i] = 0;

  decode_base64(tmp, i, &j);

  req = (const wiloc_req_t*)tmp;
  *nmac = (size_t)req->count;
  memcpy(macs, tmp + sizeof(wiloc_req_t), *nmac * mac_size);

  return 0;
}


/* unit test */

#include <stdio.h>

int main(int ac, char** av)
{
  static const small_size_t nmac = 16;
  static const small_size_t maclen = 6;
  uint8_t* macs;
  wiloc_req_t* req;

  uint8_t rbuf[SMALL_SIZE_MAX];
  small_size_t qlen;
  small_size_t i;
  size_t n;

  /* make request */

  req = (wiloc_req_t*)rbuf;
  req->vers = WILOC_REQ_VERS;
  req->flags = WILOC_REQ_FLAG_WIFI | WILOC_REQ_FLAG_TICK;
  req->did = 0x2a;
  req->count = nmac;
  macs = rbuf + sizeof(wiloc_req_t);
  for (i = 0; i != (nmac * maclen); ++i) macs[i] = i;

  qlen = encode_wiloc_req(rbuf, SMALL_SIZEOF(rbuf));
  printf("qlen: %u\n", qlen);

  decode_wiloc_req(rbuf, sizeof(rbuf), macs, &n);

  if (n != nmac)
  {
    printf("error\n");
    goto on_error;
  }

  for (i = 0; i != (nmac * maclen); ++i)
  {
    if (macs[i] != i)
    {
      printf("error\n");
      goto on_error;
    }
  }

 on_error:
  return 0;
}
