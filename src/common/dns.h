#ifndef DNS_COMMON_H_INCLUDED
#define DNS_COMMON_H_INCLUDED



#include <stdint.h>


/* general notes */
/* big endian encoding */
/* names are 0 terminated strings */


/* server listening port */
#define DNS_SERVER_PORT 53

/* maximum size for DNS UDP based messages */
#define DNS_MSG_MAX_UDP_SIZE 512


/* header format */
/* www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm */
/* http://www.zytrax.com/books/dns/ch15/ */

/* qr set to 0 when query is generated */
/* aa set to 1 when authoritative answer */
/* tc set when message truncated. refer to DNS_UDP_MAX_SIZE. */
/* rd set when recursion desired */
/* ra set when recursion available */
/* z set to 0 */
/* rcode the response code. 0 in queries */
/* qdcount: question count */
/* ancount: answer count */
/* nscount: authority record count */
/* arcount: additional record count */

typedef struct
{
  uint16_t id: 16;
#if 0
  uint8_t qr: 1;
#define DNS_OPCODE_QUERY 0
  uint8_t opcode: 4;
  uint8_t aa: 1;
  uint8_t tc: 1;
  uint8_t rd: 1;
  uint8_t ra: 1;
  uint8_t z: 3;
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_FMT_ERROR 1
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPL 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YX_DOMAIN 6
#define DNS_RCODE_YX_RR_SET 7
#define DNS_RCODE_NX_RR_SET 8
#define DNS_RCODE_NOT_AUTH 9
#define DNS_RCODE_NOT_ZONE 10
  uint8_t rcode: 4;
#else
#define DNS_HDR_FLAG_RD (1 << 8)
  uint16_t flags: 16;
#endif
  uint16_t qdcount: 16;
  uint16_t ancount: 16;
  uint16_t nscount: 16;
  uint16_t arcount: 16;
} __attribute__((packed)) dns_header_t;


/* question section format */
/* www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat-2.htm */
/* qtype: one in DNS_RR_TYPE_xxx */
/* qclass: one in DNS_RR_CLASS_xxx */

typedef struct
{
  /* uint8_t qname[]; variable length */
  uint16_t qtype: 16;
  uint16_t qclass: 16;
} __attribute__((packed)) dns_query_t;


/* resource records */
/* www.tcpipguide.com/free/t_DNSMessageResourceRecordFieldFormats.htm */

#define DNS_RR_TYPE_A 1
#define DNS_RR_TYPE_NS 2
#define DNS_RR_TYPE_CNAME 5
#define DNS_RR_TYPE_SOA 6
#define DNS_RR_TYPE_PTR 12
#define DNS_RR_TYPE_MX 15
#define DNS_RR_TYPE_TXT 16

#define DNS_RR_CLASS_IN 1

typedef struct
{
  /* uint8_t name[]; variable length */
  uint16_t type: 16;
  uint16_t class: 16;
  uint32_t ttl: 32;
  uint16_t rdlength: 16;
  uint8_t rdata[1];
} __attribute__((packed)) dns_rr_common_t;


/* message format */

typedef struct
{
  dns_header_t header;
  /* sections start here */
  uint8_t data[1];
} __attribute__((packed)) dns_msg_t;


#endif /* DNS_COMMON_H_INCLUDED */
