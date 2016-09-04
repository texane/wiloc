#include "os.h"


/* os_udp routines */

int ICACHE_FLASH_ATTR os_udp_init(os_udp_t* udp)
{
  return -1;
}

void ICACHE_FLASH_ATTR os_udp_fini(os_udp_t* udp)
{
}

void ICACHE_FLASH_ATTR os_udp_set_buf_size(os_udp_t* udp, size_t size)
{
}

void* ICACHE_FLASH_ATTR os_udp_get_buf_data(os_udp_t* udp)
{
  return NULL;
}

int ICACHE_FLASH_ATTR os_udp_sendto(os_udp_t* udp, ip_addr_t* daddr, uint16_t dport)
{
  return -1;
}


#if 0 /* TODO, wifi_xxx */

wifi_set_opmode_current(STATION_MODE);
wifi_station_set_auto_connect(0);
wifi_station_scan(&scan_config, on_scan_done);
wifi_station_set_config_current(&sc);
wifi_station_dhcpc_status();
wifi_station_dhcpc_stop();
wifi_station_dhcpc_set_maxtry(10);
wifi_station_dhcpc_start();
wifi_station_connect();
wifi_station_get_connect_status();
wifi_get_ip_info(STATION_IF, &ipi);
wifi_station_disconnect();
wifi_station_dhcpc_stop();

#endif /* TODO, wifi_xxx */


#if 0 /* TODO, dns_xxx */
dns_getserver(0);
#endif /* TODO, dns_xxx */


/* os_timer routines */

#define OS_TIMER_MAX ((unsigned long)-1)
static unsigned long os_timer_val = 0;

unsigned int ICACHE_FLASH_ATTR os_timer_is_disabled(void)
{
  return os_timer_val == OS_TIMER_MAX;
}

void ICACHE_FLASH_ATTR os_timer_disable(void)
{
  os_timer_val = OS_TIMER_MAX;
}

void ICACHE_FLASH_ATTR os_timer_rearm(unsigned long t)
{
  os_timer_val = t;
}


/* main */

int main(int ac, char** av)
{
  while (1)
  {
    if (os_timer_is_disabled() == 0)
    {
      os_timer_val = OS_TIMER_100MS;
      wiloc_next(NULL);
      usleep(os_timer_val);
    }
    else
    {
      usleep(OS_TIMER_100MS);
    }
  }

  return 0;
}
