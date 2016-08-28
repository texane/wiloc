#ifndef WILOC_COMMON_H_INCLUDED
#define WILOC_COMMON_H_INCLUDED



#include <stdint.h>


typedef struct
{
  /* big endian encoding when applicable */

#define WILOC_MSG_VERS 0
  uint8_t vers;

  /* FLAG_TICK: used to increment the server time */
  /* all the position records received in the */
  /* same time must be merged during the lookup */
  /* FLAG_COORDS: uint24_t coords[2] is present in data */
  /* if present, located after mac addresses */
  /* coordinate encoding */
  /* 9 bits for integer part (0 to 360 degrees) */
  /* 15 bits for decimal part (.00003 degrees resolution, 3m) */
  /* convenient as it results in the same size as a mac address */
#define WILOC_MSG_FLAG_TICK (1 << 0)
#define WILOC_MSG_FLAG_COORDS (1 << 1)
  uint8_t flags;

  /* device identifier */
  uint8_t did;

  /* mac address count */
  uint8_t mac_count;

  /* data start here */
  /* uint8_t macs[mac_count]; */
  /* uint24_t coords[2]; */

} __attribute__((packed)) wiloc_msg_t;


#endif /* WILOC_COMMON_H_INCLUDED */
