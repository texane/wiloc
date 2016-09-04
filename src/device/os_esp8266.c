#include "wiloc.h"


/* os_udp routines */

int ICACHE_FLASH_ATTR os_udp_init(os_udp_t* udp)
{
  udp->pcb = udp_new();
  if (udp->pcb == NULL) return -1;
  return 0;
}

void ICACHE_FLASH_ATTR os_udp_fini(os_udp_t* udp)
{
  if (udp->pcb != NULL) udp_remove(udp->pcb);
  udp->pcb = NULL;
}

void ICACHE_FLASH_ATTR os_udp_set_buf_size
(os_udp_t* udp, size_t size)
{
  /* assume size <= sizeof(udp->data) */
  udp->size = size;
}

void* ICACHE_FLASH_ATTR os_udp_get_buf_data(os_udp_t* udp)
{
  return udp->data;
}

int ICACHE_FLASH_ATTR os_udp_sendto
(os_udp_t* udp, ip_addr_t* daddr, uint16_t dport)
{
  struct pbuf* buf;
  int err = -1;

  /* copy needed as pbuf cannot be reused */
  buf = pbuf_alloc(PBUF_TRANSPORT, (u16_t)udp->size, PBUF_RAM);
  if (buf == NULL) goto on_error_0;
  memcpy(buf->payload, udp->data, udp->size);

  if (udp_sendto(udp->pcb, buf, daddr, dport) != ERR_OK) goto on_error_1;

  err = 0;

 on_error_1:
  pbuf_free(buf);
 on_error_0:
  return err;
}


/* software timer */

#define OS_TIMER_MAX ((unsigned long)-1)

static unsigned long os_timer_top = 0;
static unsigned long os_timer_cur = 0;

unsigned int ICACHE_FLASH_ATTR os_timer_is_disabled()
{
  return os_timer_top == OS_TIMER_MAX;
}

void ICACHE_FLASH_ATTR os_timer_disable(void)
{
  os_timer_top = OS_TIMER_MAX;
  os_timer_cur = 0;
}

void ICACHE_FLASH_ATTR os_timer_rearm(unsigned long t)
{
  const unsigned int was_disabled = os_timer_is_disabled();

  os_timer_top = t;

  if (was_disabled)
  {
    /* timer was disabled, force reschedule of on_event */
    system_os_post(USER_TASK_PRIO_0, 0, 0);
  }
}


static void ICACHE_FLASH_ATTR on_event
(os_event_t* events)
{
  if (os_timer_cur == os_timer_top)
  {
    os_timer_cur = 0;
    os_timer_top = OS_TIMER_100MS;
    wiloc_next(NULL);
  }
  else
  {
    os_delay_us(OS_TIMER_100MS);
    if (os_timer_is_disabled()) os_timer_cur = 0;
    else os_timer_cur += OS_TIMER_100MS;
  }

  system_os_post(USER_TASK_PRIO_0, 0, 0);
}


void ICACHE_FLASH_ATTR user_init(void)
{
#define TASK_COUNT 1
  static os_event_t task_queue[TASK_COUNT];

  uart_div_modify(0, UART_CLK_FREQ / 115200);

  TRACE();

  ets_wdt_disable();

  system_os_task(on_event, USER_TASK_PRIO_0, task_queue, TASK_COUNT);
  system_os_post(USER_TASK_PRIO_0, 0, 0);
}
