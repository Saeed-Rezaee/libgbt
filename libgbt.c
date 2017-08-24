#include <err.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>

#include "queue.h"
#include "sha1.h"
#include "libgbt.h"

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

struct buffer {
	char  *buf;
	size_t siz;
};

static void * emalloc(size_t);
static size_t curlwrite(char *, size_t, size_t, struct buffer *);

static int    isnum(char);
static char * tohex(uint8_t *, char *, size_t);
static char * tostr(char *, size_t);
static char * urlencode(uint8_t *, size_t);

static char * bparseint(struct blist *, char *, size_t);
static char * bparsestr(struct blist *, char *, size_t);
static char * bparselnd(struct blist *, char *, size_t);
static char * bparseany(struct blist *, char *, size_t);

static size_t bcountlist(const struct blist *);
static size_t bpathfmt(const struct blist *, char *);
static size_t metainfohash(struct torrent *);
static size_t metaannounce(struct torrent *);
static size_t metafiles(struct torrent *);
static size_t metapieces(struct torrent *);

static size_t bstr2peer(struct torrent *, char *, size_t);
static size_t blist2peer(struct torrent *, struct blist *);

static int thpsend(struct torrent *, char *, struct blist *);
static int peersend(struct peer *, uint8_t *, size_t);

static void *
emalloc(size_t s)
{
	void *p = NULL;
	p = malloc(s);
	if (!p)
		err(1, "malloc");

	memset(p, 0, s);
	return p;
}

static int
isnum(char c) {
	return (c >= '0' && c <= '9');
}

static char *
tohex(uint8_t *in, char *out, size_t len)
{
	size_t i, j;
	char hex[] = "0123456789ABCDEF";

	memset(out, 0, len*2 + 1);
	for (i=0, j=0; i<len; i++, j++) {
		out[j]   = hex[in[i] >> 4];
		out[++j] = hex[in[i] & 15];
	}

	return out;
}

static char *
tostr(char *in, size_t len)
{
	static char s[LINE_MAX];

	memcpy(s, in, MIN(len, LINE_MAX));
	s[MIN(len, LINE_MAX)] = 0;

	return s;
}

static char *
urlencode(uint8_t *in, size_t len)
{
	size_t i, j;
	char *out;

	out = emalloc(len * 3);

	for (i = 0, j = 0; i < len; i++) {
		if ((in[i] <= '0' && in[i] >= '9') ||
		    (in[i] <= 'A' && in[i] >= 'Z') ||
		    (in[i] <= 'a' && in[i] >= 'z') ||
		    (in[i] == '-' || in[i] == '_'  ||
		     in[i] == '.' || in[i] == '~')) {
			out[j++] = in[i];
		} else {
			out[j++] = '%';
			tohex(in + i, out + j, 1);
			j += 2;
		}
	}

	return out;
}

static char *
bparseint(struct blist *bl, char *buf, size_t len)
{
	long n = 0;
	char *p = buf;
	struct bdata *np = NULL;

	if (*p++ != 'i')
		errx(1, "not an integer\n");

	if (*p == '0' && *(p+1) != 'e')
		errx(1, "0 not followed by e\n");

	if (*p == '-' && (isnum(*p+1) && *p+1 > '0'))
		errx(1, "invalid negative number\n");

	np = emalloc(sizeof(*np));
	if (!np)
		return NULL;

	while (*p != 'e' && p < buf + len) {
		if (*p == '-') {
			n = -1;
		} else if (isnum(*p)) {
			n *= 10;
			n += *p - '0';
		} else {
			free(np);
			errx(1, "'%c': invalid character\n", *p);
		}
		p++;
	}

	np->type = 'i';
	np->num = n;
	np->s = buf;
	np->e = p;
	TAILQ_INSERT_TAIL(bl, np, entries);
	return p;
}

static char *
bparsestr(struct blist *bl, char *buf, size_t len)
{
	char *p = buf;
	struct bdata *np = NULL;

	if (!isnum(buf[0]))
		errx(1, "not a string\n");

	np = emalloc(sizeof(*np));
	if (!np)
		return NULL;

	np->len = 0;
	while (*p != ':' && p < (buf + len)) {
		np->len *= 10;
		np->len += *p++ - '0';
	}

	np->str = ++p;
	np->type = 's';
	np->s = buf;
	np->e = p + np->len - 1;
	TAILQ_INSERT_TAIL(bl, np, entries);
	return p + np->len - 1;
}

static char *
bparselnd(struct blist *bl, char *buf, size_t len)
{
	char *p = buf;
	struct bdata *np = NULL;

	if (*p != 'l' && *p != 'd')
		errx(1, "not a dictionary or list\n");

	if (*++p == 'e')
		errx(1, "dictionary or list empty\n");

	np = emalloc(sizeof(*np));
	np->bl = emalloc(sizeof(*np->bl));

	TAILQ_INIT(np->bl);

	while (*p != 'e' && p < buf + len)
		p = bparseany(np->bl, p, len - (size_t)(p - buf)) + 1;

	np->type = *buf;
	np->s = buf;
	np->e = p;
	TAILQ_INSERT_TAIL(bl, np, entries);
	return p;
}

static char *
bparseany(struct blist *bl, char *buf, size_t len)
{
	switch (buf[0]) {
	case 'l': /* FALLTHROUGH */
	case 'd':
		return bparselnd(bl, buf, len);
		break; /* NOTREACHED */
	case 'i':
		return bparseint(bl, buf, len);
		break; /* NOTREACHED */
	case 'e':
		return buf;
	default:
		if (isnum(*buf))
			return bparsestr(bl, buf, len);

		errx(1, "'%c' unexpected\n", *buf);
		break; /* NOTREACHED */
	}
	return buf;
}

int
bdecode(char *buf, size_t len, struct blist *bl)
{
	char *p = buf;
	size_t s = len;

	if (!bl)
		return -1;

	TAILQ_INIT(bl);
	while (s > 1) {
		p = bparseany(bl, p, s);
		s = len - (p - buf);
		p++;
	}

	return 0;
}

int
bfree(struct blist *bl)
{
	struct bdata *np = NULL;
	while (!TAILQ_EMPTY(bl)) {
		np = TAILQ_FIRST(bl);
		switch(np->type) {
		case 'd':
		case 'l':
			bfree(np->bl);
			break;
		}
		TAILQ_REMOVE(bl, np, entries);
		free(np);
	}
	free(bl);
	return 0;
}

/*
 * Search a key within a bencoded data structure recursively.
 * each data element has to be a string, except for the very
 * first element which CAN be a dictionary.
 *
 * When we encounter a dictionary, the function will be called on this
 * dictionary so we can find nested keys.
 *
 * Because of this search algorithm, only the first occurence of each
 * key will be retrieved.
 * This should not be an issue as torrent files are not supposed to
 * appear twice, except for multifile torrent. For them, this function
 * can be called for each element of the "files" list.
 */
struct bdata *
bsearchkey(const struct blist *bl, const char *key)
{
	struct bdata *np;
	if (key == NULL) return NULL;
	TAILQ_FOREACH(np, bl, entries) {
		switch(np->type) {
		case 's':
			if (strlen(key) == np->len && !strncmp(key, np->str, np->len))
				return TAILQ_NEXT(np, entries);
			np = TAILQ_NEXT(np, entries);
		case 'd': /* FALLTHROUGH */
			if (np->type == 'd')
				return bsearchkey(np->bl, key);
			break;
		default:
			return NULL;
		}

	}
	return NULL;
}

static size_t
bcountlist(const struct blist *bl)
{
	int n = 0;
	struct bdata *np;

	TAILQ_FOREACH(np, bl, entries)
		n++;

	return n;
}

static size_t
bpathfmt(const struct blist *bl, char *path)
{
	struct bdata *np;

	TAILQ_FOREACH(np, bl, entries) {
		path[strlen(path)] = '/';
		strncat(path, np->str, np->len);
	}

	return strlen(path);
}

static size_t
metainfohash(struct torrent *to)
{
	struct bdata *np = NULL;

	np = bsearchkey(&to->meta, "info");
	return sha1((unsigned char *)np->s, np->e - np->s + 1, to->infohash);
}

static size_t
metaannounce(struct torrent *to)
{
	struct bdata *np = NULL;

	np = bsearchkey(&to->meta, "announce");
	memset(to->announce, 0, PATH_MAX);
	memcpy(to->announce, np->str, np->len);

	return np->len;
}

static size_t
metafiles(struct torrent *to)
{
	int i = 0;
	size_t namelen = 0;
	char name[PATH_MAX];
	struct bdata *np;
	struct blist *head;

	np = bsearchkey(&to->meta, "name");
	namelen = np->len;
	memset(name, 0, PATH_MAX);
	memcpy(name, np->str, MIN(namelen, PATH_MAX - 1));

	to->size = 0;
	np = bsearchkey(&to->meta, "files");
	if (np) { /* multi-file torrent */
		head = np->bl;
		to->filnum = bcountlist(head);
		to->files = emalloc(sizeof(*to->files) * bcountlist(head));
		TAILQ_FOREACH(np, head, entries) {
			to->files[i].len  = bsearchkey(np->bl, "length")->num;
			to->size += to->files[i].len;
			memset(to->files[i].path, 0, PATH_MAX);
			memcpy(to->files[i].path, name, namelen);
			bpathfmt(bsearchkey(np->bl, "path")->bl, to->files[i].path);
			i++;
		}
	} else { /* single-file torrent */
		to->files = emalloc(sizeof(*to->files));
		to->files[0].len = bsearchkey(&to->meta, "length")->num;
		strcpy(to->files[0].path, name);
		to->filnum = 1;
	}
	return to->filnum;
}

static size_t
metapieces(struct torrent *to)
{
	to->pieces = (uint8_t *)bsearchkey(&to->meta, "pieces")->s;
	to->piecelen = bsearchkey(&to->meta, "piece length")->num;
	to->pcsnum = to->size/to->piecelen + !!(to->size%to->piecelen);
	to->bitfield = emalloc(to->pcsnum / sizeof(*to->bitfield));

	return to->pcsnum;
}

struct torrent *
metainfo(const char *path)
{
	FILE *f   = NULL;
	struct stat sb;
	struct torrent *to;

	stat(path, &sb);
	f = fopen(path, "r");
	to = emalloc(sizeof(*to));

	to->buf = emalloc(sb.st_size);
	fread(to->buf, 1, sb.st_size, f);
	fclose(f);

	bdecode(to->buf, sb.st_size, &to->meta);
	to->upload = 0;
	to->download = 0;
	memcpy(to->peerid, PEERID, 20);
	to->peerid[20] = 0;

	metainfohash(to);
	metaannounce(to);
	metafiles(to);
	metapieces(to);

	return to;
}

static size_t
blist2peer(struct torrent *to, struct blist *peers)
{
	size_t i = 0;
	struct bdata *np, *tmp;

	to->peernum = bcountlist(peers);
	to->peers = emalloc(to->peernum * sizeof(*to->peers));
	if (!to->peers)
		return -1;

	TAILQ_FOREACH(np, peers, entries) {
		to->peers[i].choked = 1;
		to->peers[i].interrested = 0;
		to->peers[i].peer.sin_family = AF_INET;

		tmp = bsearchkey(np->bl, "port");
		to->peers[i].peer.sin_port = tmp->num;

		tmp = bsearchkey(np->bl, "ip");
		inet_pton(AF_INET, tostr(tmp->str, tmp->len), &to->peers[i].peer.sin_addr);
		i++;
	}

	return to->peernum;
}

static size_t
bstr2peer(struct torrent *to, char *peers, size_t len)
{
	size_t i;

	if (len % 6)
		errx(1, "%zu: Not a multiple of 6", len);

	to->peernum = len/6;
	to->peers = emalloc(to->peernum * sizeof(*to->peers));
	if (!to->peers)
		return -1;

	for (i = 0; i < len/6; i++) {
		to->peers[i].choked = 1;
		to->peers[i].interrested = 0;
		to->peers[i].bitfield = emalloc(to->pcsnum / sizeof(to->peers[i].bitfield));
		to->peers[i].peer.sin_family      = AF_INET;
		memcpy(&to->peers[i].peer.sin_port, &peers[i*6] + 4, 2);
		memcpy(&to->peers[i].peer.sin_addr, &peers[i*6], 4);
	}

	return to->peernum;
}

static size_t
curlwrite(char *ptr, size_t size, size_t nmemb, struct buffer *userdata)
{
	userdata->buf = realloc(userdata->buf, userdata->siz + size*nmemb);
	memcpy(userdata->buf + userdata->siz, ptr, size*nmemb);
	userdata->siz += size*nmemb;
	return userdata->siz;
}

static int
thpsend(struct torrent *to, char *ev, struct blist *reply)
{
	char  url[PATH_MAX] = {0};
	struct buffer b;
	struct bdata *np = NULL;
	CURL *c;
	CURLcode r;

	c = curl_easy_init();
	if (!c)
		return -1;

	snprintf(url, PATH_MAX,
		"%s?peer_id=%s&info_hash=%s&port=%d"
		"&uploaded=%zu&downloaded=%zu&left=%zu"
		"%s%s&compact=1",
		to->announce, to->peerid, urlencode(to->infohash, 20), 65535,
		to->upload, to->download, to->size,
		(ev ? "&event=" : ""), (ev ? ev : ""));

	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlwrite);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
	r = curl_easy_perform(c);
	if (r != CURLE_OK)
		errx(1, "%s", curl_easy_strerror(r));

	bdecode(b.buf, b.siz, reply);
	np = bsearchkey(reply, "failure reason");
	if (np)
		errx(1, "%s: %s", to->announce, tostr(np->str, np->len));

	np = bsearchkey(reply, "interval");
	if (!np)
		errx(1, "Missing key 'interval'");

	return np->num;
}

int
getpeers(struct torrent *to)
{
	struct blist reply;
	struct bdata *peers = NULL;

	if (thpsend(to, "started", &reply) < 0)
		return -1;

	if (!(peers = bsearchkey(&reply, "peers")))
		return -1;

	to->peers = emalloc(sizeof(*to->peers));
	switch (peers->type) {
	case 's':
		bstr2peer(to, peers->str, peers->len);
		break;
	case 'l':
		blist2peer(to, peers->bl);
		break;
	default:
		errx(1, "'%c': Unsupported type for peers", peers->type);
	}

	return to->peernum;
}

static int
peersend(struct peer *p, uint8_t *msg, size_t len)
{
	return send(p->sockfd, msg, len, 0);
}

int
pwphandshake(struct torrent *to, off_t n)
{
	off_t off = 0;
	uint8_t msg[68];
	struct peer *p;

	msg[off++] = 19;
	memcpy(msg + off, "BitTorrent protocol", 19);
	off += 19;
	off += 8;
	memcpy(msg + off, to->infohash, 20);
	off += 20;
	memcpy(msg + off, PEERID, 20);
	off += 20;

	p = &to->peers[n];

	p->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (p->sockfd < 0)
		err(1, "socket");

	if (connect(p->sockfd, (struct sockaddr *)&p->peer, sizeof(p->peer)))
		return -1;

	return peersend(p, msg, 68);
}
