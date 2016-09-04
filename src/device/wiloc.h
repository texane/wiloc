#ifndef WILOC_H_INCLUDED
#define WILOC_H_INCLUDED


#include <stdint.h>
#include <sys/types.h>


typedef uint8_t small_size_t;
#define SMALL_SIZE_MAX ((uint8_t)-1)
#define SMALL_SIZEOF(__x) ((small_size_t)sizeof(__x))


/* os dependent */

#ifdef OS_LINUX

#ifdef CONFIG_DEBUG
#include <stdio.h>
#define os_printf printf
#endif /* CONFIG_DEBUG */

#define ICACHE_FLASH_ATTR

typedef struct
{
  int sock;
  uint8_t data[SMALL_SIZE_MAX];
  size_t size;
} os_udp_t;

#else
#ifdef OS_ESP8266

#define LWIP_OPEN_SRC
#include <lwipopts.h>
#include <lwip/api.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/dns.h>
#include <lwip/err.h>

#include <ets_sys.h>
#include <osapi.h>
#include <queue.h>
#include <os_type.h>
#include <user_interface.h>

typedef struct
{
  struct udp_pcb* pcb;
  uint8_t data[SMALL_SIZE_MAX];
  size_t size;
} os_udp_t;

#else /* OS_ESP8266 */
#error "missing or invalid OS_xxx macro"
#endif
#endif


/* common to all oses */

/* debugging macros */

#ifdef CONFIG_DEBUG
#define PERROR() os_printf("[E] %s, %u\n\r", __FILE__, __LINE__)
#define TRACE() os_printf("[T] %s, %u\n\r", __FILE__, __LINE__)
#define PRINTF(__s, ...) os_printf(__s "\n\r", ##__VA_ARGS__)
#else
#define PERROR()
#define TRACE()
#define PRINTF(__s, ...)
#endif /* CONFIG_DEBUG */


/* os_udp routines */

int ICACHE_FLASH_ATTR os_udp_init(os_udp_t*);
void ICACHE_FLASH_ATTR os_udp_fini(os_udp_t*);
void ICACHE_FLASH_ATTR os_udp_set_buf_size(os_udp_t*, size_t);
void* ICACHE_FLASH_ATTR os_udp_get_buf_data(os_udp_t*);
int ICACHE_FLASH_ATTR os_udp_sendto(os_udp_t*, ip_addr_t*, uint16_t);


/* os timer */

#define OS_TIMER_100MS 100000
unsigned int ICACHE_FLASH_ATTR os_timer_is_disabled(void);
void ICACHE_FLASH_ATTR os_timer_disable(void);
void ICACHE_FLASH_ATTR os_timer_rearm(unsigned long);


/* wiloc state machine */

void ICACHE_FLASH_ATTR wiloc_next(void*);


#endif /* WILOC_H_INCLUDED */
