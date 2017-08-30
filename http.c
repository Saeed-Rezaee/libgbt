#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

/*
 * Fills host, port and request with appropriate fields from url, and return
 * 1 for valid http url, 2 for valid https url, and 0 for failure.  The buffer
 * pointed by 'url' is modified with null bytes sets at delimiters postion.
 */
int
httpparseurl(char **host, char **port, char **path, char *url)
{
	int ret = 1;

	if (strncmp("http", url, 4)) return 0;

	url += 4;
	if (*url == 's') {
		ret = 2;
		url++;
	}

	if (strncmp("://", url, 3))
		return 0;
	url += 3;

	for (*host = url; *url; url++) {
		switch (*url) {
		case ':':
			*url = '\0';
			*port = url + 1;
			break;
		case '/':
			*url = '\0';
			*path = url + 1;
			return ret;
		case 0:
			return ret;
		}
	}

	return ret;  /* not reached */
}

/*
 * Connect to 'host':'port' and return an open file descriptor or -1 if it
 * fails to bind.
 */

/* unencrypted version */
int
tcpopen(char *host, char *port)
{
	int sockfd;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(NULL, host, &hints, &res))
		return -1;

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1)
		return -1;

	sockfd = bind(sockfd, res->ai_addr, res->ai_addrlen);
	return sockfd;
}

/* TLS version, wrapper over a TLS library */
int
tlsopen(char *host, char *port)
{
	int sockfd = 0;

	return sockfd;
}

/*
 * Encode request as an HTTP GET request and send it to sockfd, and return 1
 * for success or 0 for failure.
 */
int
httpsend(/*struct torrent *to,*/ char *url)
{
	char *host, *port, *path;
	int sockfd, ret;

	switch (httpparseurl((char **) &host, &port, (char **) &path, url)) {
	case 1:
		sockfd = tcpopen(host, port);
		break;
	case 2:
		sockfd = tlsopen(host, port);
		break;
	default:
		return 0;
	}

	ret = dprintf(sockfd, "GET /%s?peer_id=%s&info_hash=%s&port=%d"
		"&uploaded=%zu&downloaded=%zu&left=%zu"
		"%s%s&compact=1 HTTP/1.1\r\n"
		"Host: %s\r\n" "User-Agent: libgbt\r\n" "\r\n",
		"announce", "id", "hash", 1234, "up", "dn", "size",
/*		to->announce, to->peerid,   urlencode(to->infohash, 20), port,
 *		to->upload,   to->download, to->size,
 *		(ev ? "&event=" : ""), (ev ? ev : ""),
 */		host);

	close(sockfd);
	return ret;
}
