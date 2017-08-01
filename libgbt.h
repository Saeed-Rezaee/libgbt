/* scalar and compound types available in bencoding */
enum btype {
	DICTIONARY,
	LIST,
	INTEGER,
	STRING
};

/* structure defining _ANY_ type of bencoding data */
struct bdata {
	enum btype type;
	union {
		int           number;
		char         *string;
		struct blist *list;
	};
	TAILQ_ENTRY(bdata) entries;
};
TAILQ_HEAD(blist, bdata);

static struct bdata * bparseint(FILE *);
static struct bdata * bparsestr(FILE *, int);
struct blist * bparselist(FILE *);
int bfree(struct blist *);
struct bdata * bsearchkey(struct blist *, char *);
