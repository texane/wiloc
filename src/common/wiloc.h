#ifndef WILOC_COMMON_H_INCLUDED
#define WILOC_COMMON_H_INCLUDED



#include <stdint.h>


#define WILOC_COORD_PRECISION 7
#define WILOC_COORD_EXPONENT 1e7


typedef struct
{
  /* big endian encoding when applicable */

#define WILOC_MSG_VERS 0
  uint8_t vers;

  /* FLAG_TICK: used to increment the server time */
  /* all the position records received in the */
  /* same time must be merged during the lookup */
  /* FLAG_COORDS: uint32_t coords[2] is present in data */
  /* if present, located after mac addresses */
#define WILOC_MSG_FLAG_TICK (1 << 0)
#define WILOC_MSG_FLAG_COORDS (1 << 1)
  uint8_t flags;

  /* device identifier */
  uint8_t did;

  /* mac address count */
  uint8_t mac_count;

  /* data start here */
  /* uint8_t macs[mac_count]; */
  /* uint32_t coords[2]; */

} __attribute__((packed)) wiloc_msg_t;


#endif /* WILOC_COMMON_H_INCLUDED */
