CPPFLAGS = -I.. -g
LDFLAGS = -L..
LDLIBS = -lgbt

TESTS = bencoding \
	dictionary

run: $(TESTS)
	@for test in $(TESTS); do echo TEST $$test | tr a-z A-Z; ./$$test < $$test.input; done
clean:
	rm -f $(TESTS) *.o
