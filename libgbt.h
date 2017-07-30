/* BENCODING types */
enum betype {
	BENCODING_DICTIONNARY,
	BENCODING_LIST,
	BENCODING_INTEGER,
	BENCODING_STRING
};

struct beelem {
	enum betype type;
	union {
		int   number;
		char *string;
	};
	char *value;
	TAILQ_ENTRY(beelem) entries;
};
TAILQ_HEAD(bedata, beelem);

struct bedata * bencoding_parse(FILE *);
static struct beelem * bencoding_parsestring(FILE *, int);
