CC=gcc
RM=rm

STATIC_LIB=/usr/lib/libresolv.a

all:
	$(CC) -g -Wall -o ds ds.c iprange.c $(STATIC_LIB)

clean:
	-@$(RM) ds *.o
