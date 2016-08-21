/* device side */

#include <stdint.h>
#include "../common/dns.h"
#include "../common/wiloc.h"


typedef uint8_t small_size_t;
#define SMALL_SIZE_MAX ((uint8_t)-1)
#define SMALL_SIZEOF(__x) ((small_size_t)sizeof(__x))


#define DNS_ZONE_NAME ".a.txne.gdn"


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


static small_size_t encode_wiloc_msg(uint8_t* mbuf, small_size_t msize)
{
  /* encode a wiloc request */
  /* return the request size, including terminating 0 */

  /* encoding process */
  /* encode in base64 */
  /* add label dots */
  /* append zone */
  /* encode_name */

  static const small_size_t mac_size = 6;
  wiloc_msg_t* const req = (wiloc_msg_t*)mbuf;
  uint8_t tmp[SMALL_SIZE_MAX];
  small_size_t i;
  small_size_t j;
  small_size_t k;

  /* base64 encoding */

  i = SMALL_SIZEOF(wiloc_msg_t) + req->count * mac_size;
  j = encode_base64(mbuf, i, tmp, SMALL_SIZEOF(tmp));

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


/* server side */

#include <string.h>
#include <sys/types.h>

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


/* unit test */

#include <stdio.h>

int main(int ac, char** av)
{
  static const small_size_t nmac = 16;
  static const small_size_t maclen = 6;
  uint8_t* macs;
  wiloc_msg_t* req;
  uint8_t mbuf[SMALL_SIZE_MAX];
  small_size_t rlen;
  small_size_t i;

  /* make and encode request */

  req = (wiloc_msg_t*)mbuf;
  req->vers = WILOC_MSG_VERS;
  req->flags = WILOC_MSG_FLAG_WIFI | WILOC_MSG_FLAG_TICK;
  req->did = 0x2a;
  req->count = nmac;
  macs = mbuf + sizeof(wiloc_msg_t);
  for (i = 0; i != (nmac * maclen); ++i) macs[i] = i;
  rlen = encode_wiloc_msg(mbuf, SMALL_SIZEOF(mbuf));
  if (rlen == 0)
  {
    printf("error %u\n", __LINE__);
    goto on_error;
  }

  /* decode check request */

  if (decode_wiloc_msg(mbuf, rlen))
  {
    printf("error %u\n", __LINE__);
    goto on_error;
  }

  req = (wiloc_msg_t*)mbuf;

  if (req->vers != WILOC_MSG_VERS)
  {
    printf("error %u\n", __LINE__);
    goto on_error;
  }

  if (req->flags != (WILOC_MSG_FLAG_WIFI | WILOC_MSG_FLAG_TICK))
  {
    printf("error %u\n", __LINE__);
    goto on_error;
  }

  if (req->count != nmac)
  {
    printf("error %u\n", __LINE__);
    goto on_error;
  }

  macs = mbuf + sizeof(wiloc_msg_t);
  for (i = 0; i != (nmac * maclen); ++i)
  {
    if (macs[i] != i)
    {
      printf("error %u\n", __LINE__);
      goto on_error;
    }
  }

  printf("success\n");

 on_error:
  return 0;
}
