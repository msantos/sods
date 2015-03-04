CC ?= cc
RM ?= rm

#LIB=/usr/lib/libresolv.a
LIB=-lresolv

all:
	$(CC) -g -Wall -o ds ds.c iprange.c $(LIB)

clean:
	-@$(RM) ds *.o
