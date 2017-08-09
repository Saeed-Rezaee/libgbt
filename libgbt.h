/* structure defining _ANY_ type of bencoding data */
struct bdata {
	char type;
	size_t len;
	union {
		long num;
		char *str;
		struct blist *bl;
	};
	TAILQ_ENTRY(bdata) entries;
};
TAILQ_HEAD(blist, bdata);

int bfree(struct blist *);
struct blist * bdecode(FILE *);
struct bdata * bsearchkey(struct blist *, char *);
