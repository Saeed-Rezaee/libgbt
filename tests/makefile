CPPFLAGS = -I.. -g
LDFLAGS = -L..
LDLIBS = -lgbt

TESTS = bencoding \
	dictionary \
	utf8

run: $(TESTS)
	@for test in $(TESTS); do echo TEST $$test | tr a-z A-Z; ./$$test; done
clean:
	rm -f $(TESTS) *.o
