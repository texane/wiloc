#include <stdint.h>
#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
/* #include "user_config.h" */
#include "user_interface.h"


/* debugging */

#if 1
#define PERROR() os_printf("[!] %s, %u\n\r", __FILE__, __LINE__)
#define PRINTF(__s, ...) os_printf(__s, ##__VA_ARGS__)
#else
#define PERROR()
#define PRINTF(__s, ...)
#endif


/* task queue */

#define user_procTaskPrio 0
#define user_procTaskQueueLen 1
static os_event_t user_procTaskQueue[user_procTaskQueueLen];

static void loop(os_event_t *events);


//Main code function
static void ICACHE_FLASH_ATTR
loop(os_event_t *events)
{
  static uint32_t n = 0;

  PRINTF("%s %u\n", __FUNCTION__, (++n));

  os_delay_us(100000);
  system_os_post(user_procTaskPrio, 0, 0);
}

//Init function 
void ICACHE_FLASH_ATTR
user_init()
{
  uart_div_modify(0, UART_CLK_FREQ / 115200);

  wifi_set_opmode(NULL_MODE);

#if 0
  ets_wdt_disable();
  while (1)
  {
    static uint32_t n = 0;
    os_printf("%s %u\n", __FUNCTION__, (++n));
    os_delay_us(1000);
  }
#endif

#if 0
  char ssid[32] = SSID;
  char password[64] = SSID_PASSWORD;
  struct station_config stationConf;

  //Set station mode
  wifi_set_opmode( 0x1 );

  //Set ap settings
  os_memcpy(&stationConf.ssid, ssid, 32);
  os_memcpy(&stationConf.password, password, 64);
  wifi_station_set_config(&stationConf);

  //Start os task
#endif

  system_os_task(loop, user_procTaskPrio, user_procTaskQueue, user_procTaskQueueLen);
  system_os_post(user_procTaskPrio, 0, 0);
}