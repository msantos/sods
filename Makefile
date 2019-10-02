.PHONY: all clean sods sdt ds

all: sods sdt ds

sods:
	cd $@ && ./configure
	make -C $@ all

sdt:
	cd $@ && ./configure
	make -C $@ all

ds:
	make -C $@ all

clean:
	-@rm sods/sods sdt/sdt ds/ds
