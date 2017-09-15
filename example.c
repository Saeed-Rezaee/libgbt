#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "queue.h"
#include "libgbt.h"

#define FD_APPEND(fd) do {    \
        FD_SET((fd), &rfds);  \
        FD_SET((fd), &wfds);  \
        if ((fd) > fdmax)     \
                fdmax = (fd); \
} while (0)

void
usage(char *name)
{
	printf("usage: %s TORRENT\n", name);
	exit(1);
}

char *
peerstr(struct peer *p)
{
	static char str[32];
	memset(str, 0, 32);
	snprintf(str, 32, "%s:%d", inet_ntoa(p->peer.sin_addr), p->peer.sin_port);
	return str;
}

int
main(int argc, char *argv[])
{
	struct torrent to;
	struct peer *p;

	if (argc != 2)
		usage(argv[0]);
		
	if (!grizzly_load(&to, argv[1])) {
		fprintf(stderr, "%s: Failed to load torrent\n", argv[1]);
		return -1;
	}

	TAILQ_FOREACH(p, to.peers, entries)
		printf("%s\n", peerstr(p));

	printf("Starting download");
	while (grizzly_download(&to)) {
		putchar('.');
		fflush(stdout);
		sleep(1);
	}
	putchar('\n');

	return 0;
}
