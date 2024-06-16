DIRS := src

default:: all

install all:
	for x in $(DIRS); do $(MAKE) -C $$x $@; done

clean:
	rm -rf build

.PHONY: default all clean

