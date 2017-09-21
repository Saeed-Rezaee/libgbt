#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "queue.h"
#include "libgbt.h"

void
usage(char *name)
{
	printf("usage: %s TORRENT\n", name);
	exit(1);
}

int
main(int argc, char *argv[])
{
	long interval;
	struct torrent to;
	struct timespec lastsent, now;

	if (argc != 2)
		usage(argv[0]);

	if (!grizzly_load(&to, argv[1], &interval)) {
		fprintf(stderr, "%s: Failed to load torrent\n", argv[1]);
		return -1;
	}
	clock_gettime(CLOCK_MONOTONIC, &lastsent);

	while (!grizzly_finished(&to)) {
		/* update peers with THP heartbeats */
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - lastsent.tv_sec > interval)
			grizzly_thpheartbeat(&to, &interval);

		/* request and download pieces */
		grizzly_leech(&to);
	}

	return 0;
}
