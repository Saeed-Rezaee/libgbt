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

int bfree(struct blist *);
struct blist * bdecode(char *, size_t);
struct bdata * bsearchkey(struct blist *, const char *);
