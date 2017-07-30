CPPFLAGS = -I..
LDFLAGS = -L..
LDLIBS = -lgbt

TESTS = bencoding

run: $(TESTS) ../libgbt.a
	@for test in $<; do echo TEST $$test | tr a-z A-Z; ./$$test < $$test.input; done
clean:
	rm -f $(TESTS) *.o
