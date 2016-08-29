ESP_SDK_DIR ?= /home/lementec/segfs/repo/esp-open-sdk/xtensa-lx106-elf
PATH := $(ESP_SDK_DIR)/bin:$(PATH)
CC := $(ESP_SDK_DIR)/bin/xtensa-lx106-elf-gcc
ESPTOOL := $(ESP_SDK_DIR)/bin/esptool.py

CFLAGS = -I. -mlongcalls
LDLIBS = -nostdlib -Wl,--start-group -lmain -lnet80211 -lwpa -llwip -lpp -lphy -Wl,--end-group -lgcc
LDFLAGS = -Teagle.app.v6.ld

user_main-0x00000.bin: user_main
	$(ESPTOOL) elf2image $^

user_main: user_main.o

user_main.o: user_main.c

flash: user_main-0x00000.bin
	$(ESPTOOL) write_flash 0 user_main-0x00000.bin 0x40000 user_main-0x40000.bin

clean:
	rm -f user_main user_main.o user_main-0x00000.bin user_main-0x40000.bin
