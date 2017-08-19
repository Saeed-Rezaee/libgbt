#include <stdlib.h>
#include <stdio.h>

#include "http.h"

void
test_httpencode()
{
	char *request;

	char *keys[3]   = { "foo", "bar", NULL };
	char *values[3] = { "1",   "2",   NULL };

	request = httpencode(keys, values, "libgbt");
	puts(request);

	free request;
}

int
main()
{
	test_httpencode();

	return 0;
}
