include config.mk

all: libgbt.a
test: libgbt.a
	make -C tests

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
