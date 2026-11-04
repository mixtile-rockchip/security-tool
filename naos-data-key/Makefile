# SPDX-License-Identifier: MIT
CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -Wextra -Wformat=2
LDFLAGS ?=
LDLIBS ?=
SYSROOT ?=
OUTPUT ?= build/naos-data-key

SOURCES = src/naos-data-key.c src/naos-system-key-record.c
HEADERS = src/naos-system-key-record.h
SYSROOT_FLAG = $(if $(strip $(SYSROOT)),--sysroot=$(SYSROOT))

.PHONY: all clean
all: $(OUTPUT)

$(OUTPUT): $(SOURCES) $(HEADERS) Makefile
	mkdir -p $(dir $@)
	$(CC) $(SYSROOT_FLAG) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS) $(LDLIBS) -lcrypto -UNAOS_SYSTEM_KEY_TEST_FILE

clean:
	rm -f $(OUTPUT)
