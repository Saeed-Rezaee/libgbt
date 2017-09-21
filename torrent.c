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

void
usage(char *name)
{
	printf("usage: %s TORRENT\n", name);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct torrent to;

	if (argc != 2)
		usage(argv[0]);
		
	if (!grizzly_load(&to, argv[1])) {
		fprintf(stderr, "%s: Failed to load torrent\n", argv[1]);
		return -1;
	}

	while (!grizzly_finished(&to))
		grizzly_leech(&to);

	return 0;
}
