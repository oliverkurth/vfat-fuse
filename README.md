# VFAT Fuse Driver

This is a fuse driver for VFAT flesystems.

Supports:
* read/write access
* FAT12, FAT16 and FAT32
* VFAT (long file names)

It's almost feature complete, but at a very early stage and probably has a few bugs.

Missing is proper creation of short file names when a long file name entry is created. This may be an issue if multiple long files names are converted to one single short name.

Also missing is thread support, therefore you will need to set the `-s` option to start it in single thread mode.

## Building

On Ubuntu, just install dependencies with `sudo apt-get -y install pkg-config libfuse3-dev`.

Then build with `make`, install with `sudo make install`.

## Usage

To mount a file system to a directory: `fat-fuse -s <imagefile or device> <directory>`. Example: `fat-fuse -s vfat.img mntdir`.