CROSS_COMPILE ?=

C_FILES := main.c

CC := $(CROSS_COMPILE)gcc
CFLAGS := -Wall -O2 -I.
LFLAGS :=
STRIP := $(CROSS_COMPILE)strip

O_FILES := $(C_FILES:.c=.o)

.PHONY: all clean unit

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
a.out: $(O_FILES)
	$(CC) -o $@ $(O_FILES) $(LFLAGS)
	$(STRIP) $@
clean:
	-rm $(O_FILES)
	-rm a.out
