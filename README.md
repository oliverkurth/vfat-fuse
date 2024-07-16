# VFAT Fuse Driver

This is a fuse driver for VFAT flesystems.

Supports:
* read/write access
* FAT12, FAT16 and FAT32
* VFAT (long file names)

It's almost feature complete, but at a very early stage and probably has a few bugs.

Missing is proper creation of short filenames when a long file name entry is created. This may be an issue if multiple long filenames are converted to one single short name.

`vfat-fuse` currently is not threadsafe, therefore you will need to set the `-s` option to start it in single threaded mode.

## Building

On Ubuntu, just install dependencies with `sudo apt-get -y install pkg-config libfuse3-dev`.

Then build with `make`, install with `sudo make install`.

## Usage

To mount a file system to a directory: `vfat-fuse -s <imagefile or device> <directory>`. Example: `vfat-fuse -s vfat.img mntdir`.
