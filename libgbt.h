#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* structure defining _ANY_ type of bencoding data */
struct bdata {
	char type;
	size_t len;
	long num;
	char *str;
	char *s;
	char *e;
	struct blist *bl;
	TAILQ_ENTRY(bdata) entries;
};
TAILQ_HEAD(blist, bdata);

struct file {
	char path[PATH_MAX];
	size_t len;
};

struct piece {
	uint8_t sha1[20];
	uint8_t *data;
	size_t len;
};

struct peer {
	uint8_t choked;
	uint8_t interrested;
	uint8_t *bitfield;
	struct sockaddr_in peer;
};

struct torrent {
	char announce[PATH_MAX];
	char *buf;
	struct blist *meta;
	uint8_t peerid[21];
	uint8_t infohash[20];
	uint8_t *bitfield;
	uint8_t *pieces;
	size_t size;
	size_t filnum;
	size_t pcsnum;
	size_t peernum;
	size_t piecelen;
	size_t upload;
	size_t download;
	struct file *files;
	struct peer *peers;
};

int bfree(struct blist *);
struct blist * bdecode(char *, size_t);
struct bdata * bsearchkey(const struct blist *, const char *);

struct torrent * metainfo(const char *);
