#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

char *
peerstr(struct peer *p)
{
	static char str[32];
	snprintf(str, 32, "%s:%d", inet_ntoa(p->peer.sin_addr), p->peer.sin_port);
	return str;
}

int
main(int argc, char *argv[])
{
	int ev;
	long interval = 0;
	FILE *f;
	char *buf;
	struct stat sb;
	struct peer *p;
	struct torrent to;
	struct timespec last, now;

	if (argc != 2)
		usage(argv[0]);

	/* read torrent file into a memory buffer */
	if (stat(argv[1], &sb)) {
		perror(argv[1]);
		return -1;
	}
	if (!(f = fopen(argv[1], "r"))) {
		perror(argv[1]);
		return -1;
	}
	buf = malloc(sb.st_size);
	fread(buf, 1, sb.st_size, f);
	fclose(f);
		
	/* fill torrent struct from buffer */
	memset(&to, 0, sizeof(to));
	if (metainfo(&to, buf, sb.st_size) < 0) {
		fprintf(stderr, "%s: Failed to load torrent\n", argv[1]);
		free(buf);
		return -1;
	}

	/* init timespec for THP last request */
        clock_gettime(CLOCK_MONOTONIC, &last);

	/* main loop. first THP request will be the "started" event */
	for (ev = THP_STARTED;;) {

		/* perform a new THP request when interval has passed */
	        clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - last.tv_sec >= interval) {
			interval = thpsend(&to, ev);
			last = now;
			/* make next request a simple heartbeat by default */
			ev = THP_NONE;
		}

		/* send a handshake message to all new peers */
		TAILQ_FOREACH(p, to.peers, entries) {
			if (!p->connected) {
				pwpsend(&to, p, PWP_HANDSHAKE, NULL);
				printf("+ %s\n", peerstr(p));
			}
		}
	}

	return 0;
}
