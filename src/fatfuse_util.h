#ifndef FATFUSE_UTIL_H
#define FATFUSE_UTIL_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif
#include <fuse.h>

#include "fat.h"

/*
 * Decides the result of the FUSE open() callback given the resolved
 * directory entry (NULL if the path didn't resolve to one), the
 * caller's O_ACCMODE bits, and whether the whole filesystem is
 * mounted read-only. Split out from fatfuse_open() so it can be
 * unit-tested without a live FUSE request context.
 */
int fatfuse_open_check(struct fat_dir_entry *entry, int accmode, int read_only);

/*
 * The fat_dir_context tree (entries/sub_dirs arrays, which
 * fat_dir_allocate_entries() reallocs in place) has no locking around
 * it, but FUSE's default loop dispatches callbacks from a pool of
 * worker threads. Rather than hand-add fine-grained locking across
 * every recursive lookup/mutation path (real deadlock risk given how
 * much of this code recurses into itself), force single-threaded
 * dispatch so callbacks never run concurrently. Idempotent: does
 * nothing if "-s" is already present.
 */
void fatfuse_force_singlethreaded(struct fuse_args *args);

#endif
