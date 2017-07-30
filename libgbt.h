/* BENCODING types */
enum betype {
	dictionnary,
	list,
	integer,
	string
};

struct beeelem {
	enum betype type;
	char *value;
	SLIST_ENTRY(beelem) entries;
};
SLIST_HEAD(bedata, beelem);

struct bedata * bencoding_parse(FILE *);
static char * bencoding_parsestring(FILE *, int);
