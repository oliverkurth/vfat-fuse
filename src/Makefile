SRC_DUMP := fat.c dump.c
SRC_FUSE := fat.c fatfuse_util.c fat-fuse.c
SRC_MKFS := fat.c mkfs.c
SRC_TEST := fat.c fatfuse_util.c test_security.c

OUTPUTDIR := ../build

EXE_DUMP := $(OUTPUTDIR)/vfat-dump
EXE_FUSE := $(OUTPUTDIR)/vfat-fuse
EXE_MKFS := $(OUTPUTDIR)/mkfs.vfat
EXE_TEST := $(OUTPUTDIR)/test-security

PREFIX ?= /usr/local

CC := gcc
CFLAGS_DUMP := -Wall -O2 -g $(CFLAGS)
CFLAGS_FUSE := -Wall -O2 -g $(CFLAGS) $$(pkg-config fuse3 --cflags)
CFLAGS_TEST := -Wall -O0 -g -fsanitize=address,undefined $(CFLAGS) $$(pkg-config fuse3 --cflags)
LDFLAGS_DUMP := $(LDFLAGS)
LDFLAGS_FUSE := $(LDFLAGS) $$(pkg-config fuse3 --libs)
LDFLAGS_TEST := $(LDFLAGS) -fsanitize=address,undefined $$(pkg-config fuse3 --libs)

OBJS_DUMP := $(addprefix $(OUTPUTDIR)/, $(SRC_DUMP:%.c=%.o))
OBJS_FUSE := $(addprefix $(OUTPUTDIR)/, $(SRC_FUSE:%.c=%.o))
OBJS_MKFS := $(addprefix $(OUTPUTDIR)/, $(SRC_MKFS:%.c=%.o))
OBJS_TEST := $(addprefix $(OUTPUTDIR)/, $(SRC_TEST:%.c=%.san.o))

default: all

all: $(EXE_DUMP) $(EXE_FUSE) $(EXE_MKFS)

$(EXE_DUMP): $(OBJS_DUMP) $(OUTPUTDIR)
	$(CC) -o $@ $(OBJS_DUMP) $(LDFLAGS)

$(EXE_FUSE): $(OBJS_FUSE) $(OUTPUTDIR)
	$(CC) -o $@ $(OBJS_FUSE) $(LDFLAGS_FUSE)

$(EXE_MKFS): $(OBJS_MKFS) $(OUTPUTDIR)
	$(CC) -o $@ $(OBJS_MKFS) $(LDFLAGS)

$(EXE_TEST): $(OBJS_TEST) | $(OUTPUTDIR)
	$(CC) -o $@ $(OBJS_TEST) $(LDFLAGS_TEST)

$(OUTPUTDIR):
	mkdir -p $(OUTPUTDIR)

$(OUTPUTDIR)/%.o: %.c | $(OUTPUTDIR)
	$(CC) $(CFLAGS_DUMP) -c -o $@ $<

$(OUTPUTDIR)/fat-fuse.o: fat-fuse.c | $(OUTPUTDIR)
	$(CC) $(CFLAGS_FUSE) -c -o $@ $<

$(OUTPUTDIR)/fatfuse_util.o: fatfuse_util.c | $(OUTPUTDIR)
	$(CC) $(CFLAGS_FUSE) -c -o $@ $<

$(OUTPUTDIR)/%.san.o: %.c | $(OUTPUTDIR)
	$(CC) $(CFLAGS_TEST) -c -o $@ $<

test: $(EXE_TEST)
	$(EXE_TEST)

install:
	mkdir -p $(DESTDIR)/$(PREFIX)/bin && cp $(EXE_DUMP) $(EXE_FUSE) $(DESTDIR)/$(PREFIX)/bin/
	cp $(EXE_MKFS) $(DESTDIR)/$(PREFIX)/bin/vfat-mkfs

clean:
	rm -rf $(OUTPUTDIR)

.PHONY: test
