#ifndef FATFUSE_UTIL_H
#define FATFUSE_UTIL_H

#include "fat.h"

/*
 * Decides the result of the FUSE open() callback given the resolved
 * directory entry (NULL if the path didn't resolve to one), the
 * caller's O_ACCMODE bits, and whether the whole filesystem is
 * mounted read-only. Split out from fatfuse_open() so it can be
 * unit-tested without a live FUSE request context.
 */
int fatfuse_open_check(struct fat_dir_entry *entry, int accmode, int read_only);

#endif
