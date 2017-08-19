#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Encode key/value pairs as an HTTP GET request.
 *
 * 'keys' and 'values' are NULL terminated arrays of strings.
 */
char *
httpencode(char **keys, char **values, char *host)
{
	char *request, *r;
	int i = 0;

	request = malloc(sizeof keys * (sizeof *keys + sizeof *values) + 100);
	if (!request) {
		perror("htmlencode");
		return NULL;
	}
	r = request;

	r += sprintf(r, "GET /");

	for (; *keys; i++, keys++, values++)
		r += sprintf(r, "%c%s=%s", i == 0 ? '?' : '&', *keys, *values);

	r += sprintf(r,
			" HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: libgbt/" VERSION "\r\n"
			"\r\n",
			host);

	return request;
}
