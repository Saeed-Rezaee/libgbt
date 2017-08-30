#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "http.h"

void
test_tcpopen()
{
	tcpopen("0.0.0.0", "1234");
}

void
test_httparseurl()
{
	char *host, *port, *path;

	assert(httpparseurl(&host, &port, &path,
		"http://irc.nixers.net:8080") == 1);

	assert(httpparseurl(&host, &port, &path,
		"https://git.nixers.net/libgbt") == 2);
}

int
main()
{
	test_tcpopen();

	return 0;
}
