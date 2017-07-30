/* BENCODING types */
enum betype {
	BENCODING_DICTIONNARY,
	BENCODING_LIST,
	BENCODING_INTEGER,
	BENCODING_STRING
};

/* used for "list" types in beelem declaration */
struct beelem {
	enum betype type;
	union {
		int   number;
		char *string;
		struct bedata *list;
	};
	TAILQ_ENTRY(beelem) entries;
};
TAILQ_HEAD(bedata, beelem);

static struct beelem * bencoding_parseinteger(FILE *);
static struct beelem * bencoding_parsestring(FILE *, int);
struct bedata * bencoding_parselist(FILE *);
