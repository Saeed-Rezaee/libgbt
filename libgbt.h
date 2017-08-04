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

/* definitions of blocks and pieces */
struct block {
	long off;
	size_t len;
	uint8_t data[BLOCKSIZ];
	TAILQ_ENTRY(block) entries;
};
struct piece {
	long off;
	size_t len;
	uint8_t sha1[20];
	TAILQ_HEAD(blocks, block) blocks;
	TAILQ_ENTRY(piece) entries;
};

struct blist * bparselist(FILE *);
int bfree(struct blist *);
struct bdata * bsearchkey(struct blist *, char *);
