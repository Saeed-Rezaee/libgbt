enum btype {
	DICTIONNARY,
	LIST,
	INTEGER,
	STRING
};

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
