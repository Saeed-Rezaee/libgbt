#include <limits.h>

/* structure defining _ANY_ type of bencoding data */
struct bdata {
	char type;
	size_t len;
	long num;
	char *str;
	struct blist *bl;
	TAILQ_ENTRY(bdata) entries;
};
TAILQ_HEAD(blist, bdata);

struct torrent {
	char *url;
	uint8_t *bits;
	size_t filnum;
	struct file {
		char path[PATH_MAX];
		size_t len;
	} *files;
	size_t pcsnum;
	struct piece {
		uint8_t sha1[20];
		uint8_t *data;
		size_t len;
	} *pieces;
};

int bfree(struct blist *);
struct blist * bdecode(char *, size_t);
struct bdata * bsearchkey(const struct blist *, const char *);
struct torrent * metainfo(const char *);
