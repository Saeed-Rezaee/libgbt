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
	snprintf(str, 32, "%s:%d", inet_ntoa(p->peer.sin_addr), p->peer.sin_port);
	return str;
}

int
droppeer(struct peers *ph, struct peer **p) {
	struct peer *tmp;
	tmp = TAILQ_PREV(*p, peers, entries);
	TAILQ_REMOVE(ph, *p, entries);
	free(*p);
	*p = tmp ? tmp : TAILQ_FIRST(ph);

	return 0;
}

int
main(int argc, char *argv[])
{
	int r, ev, type, fdmax;
	long interval = 0;
	ssize_t len;
	FILE *f;
	char *buf;
	uint8_t msg[MESSAGE_MAX];
	fd_set rfds, wfds;
	struct stat sb;
	struct peer *p;
	struct torrent to;
	struct timespec last, now;
	struct timeval tv;

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
			memcpy(&last, &now, sizeof(now));
			/* make next request a simple heartbeat by default */
			ev = THP_NONE;
		}

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		fdmax = -1;

		if (TAILQ_EMPTY(to.peers))
			continue;

		for (p = TAILQ_FIRST(to.peers); p; p = TAILQ_NEXT(p, entries)) {
			/* prepare all new peers for connection */
			if (p->sockfd < 0) {
				if (pwpinit(p) < 0 && errno != EINPROGRESS) {
					/* remove peers we cannot connect to */
					printf("DELPEER: %s\n", peerstr(p));
					droppeer(to.peers, &p);
					FD_CLR(p->sockfd, &rfds);
					FD_CLR(p->sockfd, &wfds);
				}
			}

			/* add all peers to the socket set */
			FD_APPEND(p->sockfd);
		}

		/* wait for one or more connections to be ready, or timeout */
		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		r = select(fdmax + 1, &rfds, &wfds, NULL, &tv);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			perror("select");
		}

		TAILQ_FOREACH(p, to.peers, entries) {
			/* send handshakes non-connected peers */
			if (!p->connected) {
				if (FD_ISSET(p->sockfd, &wfds)) {
					printf("ADDPEER: %s\n", peerstr(p));
					p->connected = 1;
					if (pwpsend(&to, p, PWP_HANDSHAKE, NULL) < 0) {
						perror(peerstr(p));
						droppeer(to.peers, &p);
						FD_CLR(p->sockfd, &rfds);
						FD_CLR(p->sockfd, &wfds);
					}
				}
			} else {
				if (FD_ISSET(p->sockfd, &wfds)) {
					pwpsend(&to, p, PWP_INTERESTED, NULL);
				}
				if (FD_ISSET(p->sockfd, &rfds)) {
					type = pwprecv(p, msg, &len);
					switch (type) {
					case -1:
						/* remove peers we cannot connect to */
						printf("DELPEER: %s\n", peerstr(p));
						droppeer(to.peers, &p);
						break;
					case PWP_HANDSHAKE:
						printf("HANDSHAKE: %s\n", peerstr(p));
						break;
					default:
						printf("MESSAGE %02d: %s\n", type, peerstr(p));
						break;
					}
				}
			}
		}
	}

	return 0;
}
