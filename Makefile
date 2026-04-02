# ChaosChat — Makefile
# ─────────────────────────────────────────────────────────────
# Requires: gcc, gtk+-3.0 dev headers, libpthread
#
# Debian/Ubuntu:  sudo apt install libgtk-3-dev build-essential
# Arch:           sudo pacman -S gtk3 base-devel
# Fedora/RHEL:    sudo dnf install gtk3-devel gcc make
#
# Build:  make
# Run:    ./chaoschat
# Clean:  make clean
# ─────────────────────────────────────────────────────────────

CC      := gcc
TARGET  := chaoschat
SRC     := chaoschat.c

GTK_CFLAGS  := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS    := $(shell pkg-config --libs   gtk+-3.0)

CFLAGS  := -D_GNU_SOURCE -Wall -Wextra -Wshadow -Wpedantic \
           -std=c11 -O2 $(GTK_CFLAGS)
LDFLAGS := $(GTK_LIBS) -lpthread -lcrypto

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo ""
	@echo "  Build complete → ./$(TARGET)"
	@echo ""
	@echo "  USAGE:"
	@echo "    Peer A (listen):   ./$(TARGET)"
	@echo "                       Port: 5050 | Connect To: (leave blank) | Key: MyKey!"
	@echo ""
	@echo "    Peer B (connect):  ./$(TARGET)"
	@echo "                       Port: 5051 | Connect To: 192.168.x.x:5050 | Key: MyKey!"
	@echo ""

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET)