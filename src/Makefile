SRC_DUMP := fat.c dump.c
SRC_FUSE := fat.c fat-fuse.c

OUTPUTDIR := ../build

EXE_DUMP := $(OUTPUTDIR)/vfat-dump
EXE_FUSE := $(OUTPUTDIR)/vfat-fuse

PREFIX ?= /usr/local

CC := gcc
CFLAGS_DUMP := -Wall -O2 -g $(CFLAGS)
CFLAGS_FUSE := -Wall -O2 -g $(CFLAGS) $$(pkg-config fuse3 --cflags)
LDFLAGS_DUMP := $(LDFLAGS)
LDFLAGS_FUSE := $(LDFLAGS) $$(pkg-config fuse3 --libs)

OBJS_DUMP := $(addprefix $(OUTPUTDIR)/, $(SRC_DUMP:%.c=%.o))
OBJS_FUSE := $(addprefix $(OUTPUTDIR)/, $(SRC_FUSE:%.c=%.o))

default: all

all: $(EXE_DUMP) $(EXE_FUSE)

$(EXE_DUMP): $(OBJS_DUMP) $(OUTPUTDIR)
	$(CC) -o $@ $(OBJS_DUMP) $(LDFLAGS)

$(EXE_FUSE): $(OBJS_FUSE) $(OUTPUTDIR)
	$(CC) -o $@ $(OBJS_FUSE) $(LDFLAGS_FUSE)

$(OUTPUTDIR):
	mkdir -p $(OUTPUTDIR)

$(OUTPUTDIR)/%.o: %.c | $(OUTPUTDIR)
	$(CC) $(CFLAGS_DUMP) -c -o $@ $<

$(OUTPUTDIR)/fat-fuse.o: fat-fuse.c | $(OUTPUTDIR)
	$(CC) $(CFLAGS_FUSE) -c -o $@ $<

install:
	mkdir -p $(DESTDIR)/$(PREFIX)/bin && cp $(EXE_DUMP) $(EXE_FUSE) $(DESTDIR)/$(PREFIX)/bin/

clean:
	rm -rf $(OUTPUTDIR)
