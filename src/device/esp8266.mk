ESP_SDK_DIR ?= /home/lementec/segfs/repo/esp-open-sdk/xtensa-lx106-elf
PATH := $(ESP_SDK_DIR)/bin:$(PATH)
CC := $(ESP_SDK_DIR)/bin/xtensa-lx106-elf-gcc
ESPTOOL := $(ESP_SDK_DIR)/bin/esptool.py

CFLAGS = -I. -mlongcalls
CFLAGS += -DOS_ESP8266

ifeq ($(CONFIG_DNS_ZONE),)
$(error missing CONFIG_DNS_ZONE variable)
else
CFLAGS += -DCONFIG_DNS_ZONE=\"$(CONFIG_DNS_ZONE)\"
endif

ifneq ($(CONFIG_DEBUG),)
CFLAGS += -DCONFIG_DEBUG=$(CONFIG_DEBUG)
endif

LDLIBS = -nostdlib -Wl,--start-group -lmain -lnet80211 -lwpa -llwip -lpp -lphy -Wl,--end-group -lgcc
LDFLAGS = -Teagle.app.v6.ld

wiloc-0x00000.bin: wiloc
	$(ESPTOOL) elf2image $^

wiloc: wiloc.o os_esp8266.o

wiloc.o: wiloc.c

os_esp8266.o: os_esp8266.c

flash: wiloc-0x00000.bin
	$(ESPTOOL) write_flash 0 wiloc-0x00000.bin 0x40000 wiloc-0x40000.bin

clean:
	rm -f wiloc
	rm -f wiloc.o os_esp8266.o
	rm -f wiloc-0x00000.bin wiloc-0x40000.bin
