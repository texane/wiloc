/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include "../common/dns.h"

#if 0

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

#elif 0

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x07
#define MY_DEST_MAC2	0xcb
#define MY_DEST_MAC3	0x9a
#define MY_DEST_MAC4	0x5e
#define MY_DEST_MAC5	0x17

#elif 1

/* SFR Fonera */
/* nameserver 109.0.66.10 */
/* nameserver 109.0.66.20 */

#define MY_DEST_MAC0	0xc2
#define MY_DEST_MAC1	0x95
#define MY_DEST_MAC2	0x04
#define MY_DEST_MAC3	0xe1
#define MY_DEST_MAC4	0x7c
#define MY_DEST_MAC5	0x85

#define MY_DEST_IP	"109.0.66.10"

#else

/* FreeWifi */
/* nameserver 212.27.40.241 */
/* nameserver 212.27.40.240 */

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x24
#define MY_DEST_MAC2	0xd4
#define MY_DEST_MAC3	0xda
#define MY_DEST_MAC4	0x20
#define MY_DEST_MAC5	0x1d

#define MY_DEST_IP	"212.27.40.241"

#endif

#if 0
#define DEFAULT_IF	"eth0"
#else
#define DEFAULT_IF	"wlan0"
#endif
#define BUF_SIZ		1024

unsigned short csum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

static size_t make_dns_query(uint8_t* buf, const char* name)
{
  dns_header_t* dnsh;
  dns_query_t* dnsq;
  uint8_t* qname_buf;
  uint8_t qname_pos;
  uint8_t qname_cnt;
  uint8_t i;

  dnsh = (dns_header_t*)buf;
  dnsh->id = htons(0xdead);
  dnsh->flags = htons(DNS_HDR_FLAG_RD);
  dnsh->qdcount = htons(1);
  dnsh->ancount = htons(0);
  dnsh->nscount = htons(0);
  dnsh->arcount = htons(0);

  qname_buf = buf + sizeof(dns_header_t);
  qname_pos = 1;
  qname_cnt = 0;
  qname_buf[qname_cnt] = 0;

  for (i = 0; name[i]; ++i, ++qname_pos)
  {
    if (name[i] == '.')
    {
      qname_cnt = qname_pos;
      qname_buf[qname_cnt] = 0;
    }
    else
    {
      qname_buf[qname_pos] = (uint8_t)name[i];
      ++qname_buf[qname_cnt];
    }
  }

  qname_buf[qname_pos++] = 0;

  dnsq = (dns_query_t*)(qname_buf + qname_pos);
  dnsq->qtype = htons(DNS_RR_TYPE_A);
  dnsq->qclass = htons(DNS_RR_CLASS_IN);

  return sizeof(dns_header_t) + qname_pos + sizeof(dns_query_t);
}


#include "../common/wiloc.h"


static int base64_encode
(const void* data_buf, size_t dataLength, char* result, size_t resultSize)
{
  /* https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64 */

  const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const uint8_t *data = (const uint8_t *)data_buf;
  size_t resultIndex = 0;
  size_t x;
  uint32_t n = 0;
  int padCount = dataLength % 3;
  uint8_t n0, n1, n2, n3;

  /* increment over the length of the string, three characters at a time */
  for (x = 0; x < dataLength; x += 3) 
    {
      /* these three 8-bit (ASCII) characters become one 24-bit number */
      n = ((uint32_t)data[x]) << 16; //parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0
      
      if((x+1) < dataLength)
	n += ((uint32_t)data[x+1]) << 8;//parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0
      
      if((x+2) < dataLength)
	n += data[x+2];

      /* this 24-bit number gets separated into four 6-bit numbers */
      n0 = (uint8_t)(n >> 18) & 63;
      n1 = (uint8_t)(n >> 12) & 63;
      n2 = (uint8_t)(n >> 6) & 63;
      n3 = (uint8_t)n & 63;
            
      /*
       * if we have one byte available, then its encoding is spread
       * out over two characters
       */
      if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = base64chars[n0];
      if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = base64chars[n1];

      /*
       * if we have only two bytes available, then their encoding is
       * spread out over three chars
       */
      if((x+1) < dataLength)
	{
	  if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
	  result[resultIndex++] = base64chars[n2];
	}

      /*
       * if we have all three bytes available, then their encoding is spread
       * out over four characters
       */
      if((x+2) < dataLength)
	{
	  if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
	  result[resultIndex++] = base64chars[n3];
	}
    }  

  /*
   * create and add padding that is required if we did not have a multiple of 3
   * number of characters available
   */
  if (padCount > 0) 
    { 
      for (; padCount < 3; padCount++) 
	{ 
	  if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
	  result[resultIndex++] = '=';
	} 
    }
  if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
  result[resultIndex] = 0;
  return 0;   /* indicate success */
}


static uint8_t labelize(uint8_t* buf, uint8_t size)
{
  uint8_t i;

  for (i = 0; i != ; )
  {
  }

  return size;
}

static uint8_t make_wiloc_query
(uint8_t* buf, uint8_t* macs, uint8_t nmac)
{
  /* http://www.zytrax.com/books/dns/ch15/#question */
  /* http://www.ietf.org/rfc/rfc1034.txt */
  /* http://www.ietf.org/rfc/rfc2181.txt */
  /* the DNS protocol allows 1 query per packet */
  /* a query is at most 256 chars */
  /* a DNS name consists of labels */
  /* due to coding, a label length is at most 63 chars */
  /* by convention, 7 bits ASCII charset */
  /* base64 used here */
  /* encoding: base64, labelize, cat_zone, dns_name_encode */
  /* decoding: dns_name_decode, strip_zone, delabelize, base64 */

#define DNS_ZONE ".a.txne.gdn"
#define DNS_MAX_LABEL_LEN 63

  static const uint8_t mac_size = 6;
  wiloc_req_t* const req = (wiloc_req_t*)buf;
  uint8_t* data;
  uint8_t size;
  uint8_t i;

  req->vers = WILOC_REQ_VERS;
  req->flags = WILOC_REQ_FLAG_WIFI | WILOC_REQ_FLAG_TICK;
  req->did = 0;

  if (nmac > 32) mac = 32;
  req->count = nmac;

  size = 0;
  data = req->data;
  for (i = 0; i != nmac; ++i, data += mac_size, macs += mac_size)
  {
    memcpy(data, mac, mac_size);
  }

  
}


int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	uint8_t sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	struct ifreq if_ip;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* source IP */
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
	  perror("SIOCGIFADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);

	/* IP Header */
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16; // Low delay
	iph->id = htons(54321);
	iph->ttl = 64;
	iph->protocol = 17; /* UDP */
	/* Source IP address, can be spoofed */
	iph->saddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
	/* iph->saddr = inet_addr("42.42.42.42"); */
	/* iph->saddr = inet_addr("10.0.0.0"); */
	/* Destination IP address */
	iph->daddr = inet_addr(MY_DEST_IP);
	tx_len += sizeof(struct iphdr);

	/* UDP Header */
	udph->source = htons(3423);
	udph->dest = htons(53);
	udph->check = 0; /* skip */
	tx_len += sizeof(struct udphdr);

	/* UDP payload */
#if 1
	tx_len += make_dns_query(sendbuf + tx_len, "fubar.a.txne.gdn");
#else
	sendbuf[tx_len++] = 'a';
	sendbuf[tx_len++] = 'b';
	sendbuf[tx_len++] = 'c';
	sendbuf[tx_len++] = 'd';
#endif

	/* Length of UDP payload and header */
	udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));

	/* Length of IP payload and header */
	iph->tot_len = htons(tx_len - sizeof(struct ether_header));
	/* Calculate IP checksum on completed header */
	iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);

	/* udp checksum, optionnal in ipv4 */
	udph->check = 0;
	/* udph->check = csum((unsigned short *)iph, (tx_len - sizeof(struct ether_header)) / 2); */

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

	return 0;
}
