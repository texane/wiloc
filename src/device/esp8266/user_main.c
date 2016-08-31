#include <stdint.h>
#include <ets_sys.h>
#include <osapi.h>
#include <queue.h>
#include <os_type.h>
#include <user_interface.h>


/* debugging */

#define CONFIG_DEBUG
#ifdef CONFIG_DEBUG
#define PERROR() os_printf("[E] %s, %u\n\r", __FILE__, __LINE__)
#define TRACE() os_printf("[T] %s, %u\n\r", __FILE__, __LINE__)
#define PRINTF(__s, ...) os_printf(__s "\n\r", ##__VA_ARGS__)
#else
#define PERROR()
#define TRACE()
#define PRINTF(__s, ...)
#endif /* CONFIG_DEBUG */


/* scan done task */

static void wiloc_next(void*);

static void on_scan_done(void* p, STATUS status)
{
  if (status != OK) p = NULL;
  if (((scaninfo*)p)->pbss == NULL) p = NULL;

  wiloc_next(p);

  /* reschedule wiloc_next */
  system_os_post(USER_TASK_PRIO_0, 0, 0);
}


/* wiloc fsm */

typedef enum
{
  WILOC_STATE_INIT = 0,
  WILOC_STATE_IDLE,
  WILOC_STATE_SCAN,
  WILOC_STATE_CONNECT,
  WILOC_STATE_DISCONNECT,
  WILOC_STATE_DONE,
  WILOC_STATE_INVALID
} wiloc_state_t;

static wiloc_state_t wiloc_state = WILOC_STATE_INIT;

static void wiloc_next(void* p)
{
  switch (wiloc_state)
  {
  case WILOC_STATE_INIT:
    {
      wifi_set_opmode_current(STATION_MODE);
      wiloc_state = WILOC_STATE_IDLE;
    }

  case WILOC_STATE_IDLE:
    {
      struct scan_config scan_config;
      scan_config.ssid = NULL;
      scan_config.bssid = NULL;
      scan_config.channel = 0;
      scan_config.show_hidden = 1;
      wiloc_state = WILOC_STATE_SCAN;
      wifi_station_scan(&scan_config, on_scan_done);
      break ;
    }

  case WILOC_STATE_SCAN:
    {
      struct bss_info* bi;
      const struct bss_info* open_bi;
      struct station_config sc;

      /* scan failed */
      if (bi == NULL) goto on_error;

      open_bi = NULL;
      STAILQ_FOREACH(bi, ((scaninfo*)p)->pbss, next)
      {
	if ((bi->authmode == AUTH_OPEN) && (open_bi == NULL)) open_bi = bi;

#ifdef CONFIG_DEBUG
	if (bi->ssid_len <= 31) bi->ssid[bi->ssid_len] = 0;
	else bi->ssid[31] = 0;

	PRINTF
	(
	 "[x] new ap: " MACSTR " %u %s",
	 MAC2STR(bi->bssid), bi->authmode, bi->ssid
	);
#endif /* CONFIG_DEBUG */
      }

      if (open_bi == NULL)
      {
	wiloc_state = WILOC_STATE_IDLE;
	break ;
      }

      TRACE();

      wifi_station_disconnect();
      wifi_station_set_auto_connect(0);

      os_memcpy(sc.ssid, open_bi->ssid, open_bi->ssid_len);
      sc.bssid_set = 1;
      os_memcpy(sc.bssid, open_bi->bssid, sizeof(sc.bssid));

      if (wifi_station_set_config_current(&sc) == false)
      {
	PERROR();
	goto on_error;
      }

      if (wifi_station_dhcpc_status() == DHCP_STARTED)
	wifi_station_dhcpc_stop();

      wifi_station_dhcpc_set_maxtry(10);

      if (wifi_station_dhcpc_start() == false)
      {
	PERROR();
	goto on_error;
      }

      if (wifi_station_connect() == false)
      {
	PERROR();
	goto on_error;
      }

      wiloc_state = WILOC_STATE_CONNECT;
     
      break ;
    }

  case WILOC_STATE_CONNECT:
    {
      uint8 status;

      TRACE();

      status = wifi_station_get_connect_status();
      switch (status)
      {
      case STATION_GOT_IP:
	{
	  struct ip_info ipi;

	  if (wifi_get_ip_info(STATION_IF, &ipi) == false)
	  {
	    PERROR();
	    goto on_error;
	  }

	  PRINTF
	  (
	   "[x] ip = " IPSTR ", gw = " IPSTR,
	   IP2STR(&ipi.ip), IP2STR(&ipi.gw)
	  );

	  wiloc_state = WILOC_STATE_DISCONNECT;

	  break ;
	}

      case STATION_IDLE:
      case STATION_CONNECTING:
	{
	  /* same state */
	  break ;
	}

      case STATION_WRONG_PASSWORD:
      case STATION_NO_AP_FOUND:
      case STATION_CONNECT_FAIL:
      default:
	{
	  goto on_error;
	  break ;
	}
      }

      break ;
    }

  case WILOC_STATE_DISCONNECT:
    {
      wifi_station_disconnect();
      wifi_station_dhcpc_stop();
      wiloc_state = WILOC_STATE_DONE;
      break ;
    }

  case WILOC_STATE_DONE:
    {
      /* same state */
      break ;
    }

  case WILOC_STATE_INVALID:
  default:
    {
    on_error:
      wiloc_state = WILOC_STATE_IDLE;
      break ;
    }
  }

}


/* user task */

static void ICACHE_FLASH_ATTR on_event(os_event_t* events)
{
  if (wiloc_state != WILOC_STATE_SCAN) wiloc_next(NULL);
  os_delay_us(100000);
  system_os_post(USER_TASK_PRIO_0, 0, 0);
}


void ICACHE_FLASH_ATTR user_init()
{
#define TASK_COUNT 1
  static os_event_t task_queue[TASK_COUNT];

  uart_div_modify(0, UART_CLK_FREQ / 115200);

  TRACE();

  ets_wdt_disable();

  system_os_task(on_event, USER_TASK_PRIO_0, task_queue, TASK_COUNT);
  system_os_post(USER_TASK_PRIO_0, 0, 0);
}
