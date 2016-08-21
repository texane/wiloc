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
#define WILOC_MSG_FLAG_TICK (1 << 0)
#define WILOC_MSG_FLAG_WIFI (1 << 3)
#define WILOC_MSG_FLAG_GPS (1 << 4)
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

  /* position info count */
  uint8_t count;

  /* data start here */
  /* uint8_t data[]; */

} __attribute__((packed)) wiloc_msg_t;


typedef struct
{
  /* TODO: coordinates */
} wiloc_msg_gps_t;


typedef struct
{
  uint8_t mac[6];
} wiloc_msg_wifi_t;



#endif /* WILOC_COMMON_H_INCLUDED */
