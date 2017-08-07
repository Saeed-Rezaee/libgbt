include config.mk

all: libgbt.a
libgbt.a: libgbt.o sha1.o
libgbt.o: libgbt.c libgbt.h config.h
test: libgbt.a
	make -C tests clean run

config.h: config.def.h
	cp $< $@

.o.a:
	$(AR) rcs $@ $<

install: libgbt.a libgbt.h
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	mkdir -p $(DESTDIR)$(PREFIX)/include
	cp libgbt.a $(DESTDIR)$(PREFIX)/lib/
	cp libgbt.h $(DESTDIR)$(PREFIX)/include/

uninstall:
	rm $(DESTDIR)$(PREFIX)/lib/libgbt.a
	rm $(DESTDIR)$(PREFIX)/include/libgbt.h

clean:
	rm -f libgbt.a *.o
