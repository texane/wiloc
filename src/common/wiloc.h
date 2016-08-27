#ifndef WILOC_COMMON_H_INCLUDED
#define WILOC_COMMON_H_INCLUDED



#include <stdint.h>


typedef struct
{
  /* big endian encoding when applicable */

#define WILOC_MSG_VERS 0
  uint8_t vers;

  /* type of data */
  /* TICK: used to increment the server time */
  /* all the position records received in the */
  /* same time must be merged during the lookup */
  /* COORDS: uint24_t coords[2] is present in data */
  /* if present, always appear first in data */
  /* coordinate encoding */
  /* 9 bits for integer part (0 to 360 degrees) */
  /* 15 bits for decimal part (.00003 degrees resolution, 3m) */
  /* convenient as it results in the same size as a mac address */
#define WILOC_MSG_FLAG_TICK (1 << 0)
#define WILOC_MSG_FLAG_COORDS (1 << 1)
  uint8_t flags;

  /* device identifier */
  uint8_t did;

#if 0 /* use tick instead */
  /* unitless time */
  /* it is important to record the time when a position */
  /* record is captured, since the device may not be able */
  /* to send it directly. thus, the server may receive */
  /* multiple records at once that are not time related. */
  /* however, the time may not be related to the actual */
  /* physical time. It is only important that the device */
  /* keeps it numerically coherent (ie. incrementing). */
  /* if 0, the time is ignored and the server consider */
  /* this record as the 'next' one in time. */
  /* also, 2 records with the same time must be merged */
  /* by the server. */
  uint16_t time;
#endif /* use tick instead */

  /* mac address count */
  uint8_t mac_count;

  /* data start here */
  /* uint24_t coords[2]; */
  /* uint8_t macs[mac_count]; */

} __attribute__((packed)) wiloc_msg_t;


#endif /* WILOC_COMMON_H_INCLUDED */
