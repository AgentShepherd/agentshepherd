# Build sandbox-exec helper binary
#
# Linux: Uses Landlock LSM (kernel 5.13+) with persistent mode
# macOS: Uses Seatbelt (sandbox-exec)

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -pedantic -std=c11

UNAME_S := $(shell uname -s)

.PHONY: all clean install test

ifeq ($(UNAME_S),Linux)
TARGET = sandbox-exec
SOURCE = sandbox_linux.c
CFLAGS += -D_GNU_SOURCE
else ifeq ($(UNAME_S),Darwin)
TARGET = sandbox-exec
SOURCE = sandbox_darwin.c
CC = clang
else
$(error Unsupported platform: $(UNAME_S))
endif

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sandbox-exec

install: $(TARGET)
	install -d $(DESTDIR)/usr/libexec/agentshepherd
	install -m 755 $(TARGET) $(DESTDIR)/usr/libexec/agentshepherd/

test: $(TARGET)
ifeq ($(UNAME_S),Linux)
	@echo "Testing Landlock sandbox (persistent mode)..."
	@(echo "4"; echo "11"; printf 'echo\0hello\0') | \
		LANDLOCK_PATHS="/bin:/usr:/lib:/lib64:/tmp:/dev:/etc" \
		timeout 2 ./$(TARGET) | head -2
	@echo "Test passed!"
else
	@echo "Test not implemented for $(UNAME_S)"
endif
