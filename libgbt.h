#include <limits.h>

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

struct torrent {
	char announce[PATH_MAX];
	char *buf;
	struct blist *meta;
	uint8_t peerid[20];
	uint8_t infohash[20];
	uint8_t *bitfield;
	size_t filnum;
	size_t pcsnum;
	struct file *files;
	struct piece *pieces;
};

int bfree(struct blist *);
struct blist * bdecode(char *, size_t);
struct bdata * bsearchkey(const struct blist *, const char *);

struct torrent * metainfo(const char *);
