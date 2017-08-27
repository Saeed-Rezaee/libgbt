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

static int bdecode(char *, size_t, struct blist *);
static int bfree(struct blist *);
static struct bdata * bsearchkey(const struct blist *, const char *);
static size_t bcountlist(const struct blist *);
static size_t bpathfmt(const struct blist *, char *);
static size_t metainfohash(struct torrent *);
static size_t metaannounce(struct torrent *);
static size_t metafiles(struct torrent *);
static size_t metapieces(struct torrent *);

static size_t bstr2peer(struct peers *, char *, size_t);
static size_t blist2peer(struct peers *, struct blist *);

static int httpsend(struct torrent *, char *, struct blist *);
static size_t pwpmsg(uint8_t **, int, uint8_t *, uint32_t);

static int pwphandshake(struct torrent *, struct peer *);

static char *event[] = {
	[THP_NONE]      = NULL,
	[THP_STARTED]   = "started",
	[THP_STOPPED]   = "stopped",
	[THP_COMPLETED] = "completed",
};

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

static int
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

static int
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
static struct bdata *
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
blist2peer(struct peers *ph, struct blist *peers)
{
	struct bdata *np, *tmp;
	struct peer *p;

	TAILQ_FOREACH(np, peers, entries) {
		p = emalloc(sizeof(*p));
		p->choked = 1;
		p->interrested = 0;
		p->peer.sin_family = AF_INET;

		tmp = bsearchkey(np->bl, "port");
		p->peer.sin_port = tmp->num;

		tmp = bsearchkey(np->bl, "ip");
		inet_pton(AF_INET, tostr(tmp->str, tmp->len), &p->peer.sin_addr);

		TAILQ_INSERT_HEAD(ph, p, entries);
	}

	return bcountlist(peers);
}

static size_t
bstr2peer(struct peers *ph, char *buf, size_t len)
{
	size_t i;
	struct peer *p;

	if (len % 6)
		errx(1, "%zu: Not a multiple of 6", len);

	for (i = 0; i < len/6; i++) {
		p = emalloc(sizeof(*p));
		p->choked = 1;
		p->interrested = 0;
		p->peer.sin_family = AF_INET;
		memcpy(&p->peer.sin_port, &buf[i * 6] + 4, 2);
		memcpy(&p->peer.sin_addr, &buf[i * 6], 4);
		TAILQ_INSERT_TAIL(ph, p, entries);
	}

	return i;
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
httpsend(struct torrent *to, char *ev, struct blist *reply)
{
	char  url[PATH_MAX] = {0};
	struct buffer b;
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

	return bdecode(b.buf, b.siz, reply);
}

static struct peer *
findpeer(struct peers *ph, struct peer *p)
{
	struct peer *np;
	TAILQ_FOREACH(np, ph, entries) {
		if (memcmp(&np->peer, &p->peer, sizeof(np->peer)))
			return np;
	}
	return NULL;
}

static int
updatepeers(struct torrent *to, struct blist *reply)
{
	size_t n = 0;
	struct peers ph;
	struct peer *p;
	struct bdata *np;

	if (!(np = bsearchkey(reply, "peers")))
		return -1;

	if (!to->peers) {
		to->peers = emalloc(sizeof(*to->peers));
		TAILQ_INIT(to->peers);
	}

	TAILQ_INIT(&ph);

	switch (np->type) {
	case 's':
		bstr2peer(&ph, np->str, np->len);
		break;
	case 'l':
		blist2peer(&ph, np->bl);
		break;
	default:
		errx(1, "'%c': Unsupported type for peers", np->type);
	}

	/* Add new peers */
	p = TAILQ_FIRST(&ph);
	do {
		if (findpeer(to->peers, p)) {
			p = TAILQ_PREV(p, peers, entries);
			TAILQ_REMOVE(&ph, p, entries);
		}
	} while((p = TAILQ_NEXT(p, entries)));
	TAILQ_CONCAT(to->peers, &ph, entries);
	TAILQ_FOREACH(p, to->peers, entries) {
		n++;
	}

	return n;
}

int
thpsend(struct torrent *to, int ev)
{
	int interval = 0;
	struct bdata *np;
	struct blist reply;

	httpsend(to, event[ev], &reply);

	np = bsearchkey(&reply, "failure reason");
	if (np)
		errx(1, "%s: %s", to->announce, tostr(np->str, np->len));

	np = bsearchkey(&reply, "interval");
	if (!np)
		errx(1, "Missing key 'interval'");

	interval = np->num;
	updatepeers(to, &reply);

	return interval;
}

/*
 * ----------------------------------------------------------------
 * | Name Length | Protocol Name | Reserved | Info Hash | Peer ID |
 * ----------------------------------------------------------------
 *       1              19             8         20          20
 */
static int
pwphandshake(struct torrent *to, struct peer *p)
{
	off_t off = 0;
	uint8_t msg[68];

	msg[off++] = 19;
	memcpy(msg + off, "BitTorrent protocol", 19);
	off += 19;
	off += 8;
	memcpy(msg + off, to->infohash, 20);
	off += 20;
	memcpy(msg + off, PEERID, 20);
	off += 20;

	p->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (p->sockfd < 0)
		err(1, "socket");

	if (connect(p->sockfd, (struct sockaddr *)&p->peer, sizeof(p->peer)))
		return -1;

	return send(p->sockfd, msg, 68, 0);
}

static size_t
pwpmsg(uint8_t **msg, int type, uint8_t *payload, uint32_t len)
{
	size_t i;
	off_t off = 0;

	*msg[off] = htonl(len + 1);
	off += 4;
	*msg[off] = type;
	off += 1;

	for (i = 0; i < len; i++)
		*msg[off++] = payload[i];

	return off;
}

ssize_t
pwpsend(struct torrent *to, struct peer *p, int type)
{
	size_t len;
	uint8_t msg[MESSAGE_MAX];

	switch(type) {
	case PWP_CHOKE:
	case PWP_UNCHOKE:
        case PWP_INTEREST:
        case PWP_UNINTEREST:
		len = pwpmsg((uint8_t **)&msg, type, NULL, 0);
		break;
        case PWP_HAVE:
        case PWP_BITFIELD:
		len = sizeof(*to->bitfield) * to->pcsnum;
		len = pwpmsg((uint8_t **)&msg, type, to->bitfield, len);
		break;
        case PWP_REQUEST:
        case PWP_PIECE:
        case PWP_CANCEL:
		return -1;
		break; /* NOTREACHED */
	case PWP_HANDSHAKE:
		return pwphandshake(to, p);
		break; /* NOTREACHED */
	}

	return send(p->sockfd, msg, len, 0);
}

int
pwprecv(struct peer *p, uint8_t **buf, size_t *len)
{
	ssize_t r;
	static uint8_t msg[MESSAGE_MAX];

	*len = 0;

	r = recv(p->sockfd, msg, MESSAGE_MAX, 0);

	if (r < 0) perror("recv");
	if (r < 1) return -1;
	if (r < 2) errx(1, "Message too short");

	if (msg[0] > NUM_PWP_TYPES) {
		*len = r;
		*buf = msg;
		return PWP_HANDSHAKE;
	}

	*len = (size_t)msg[0];
	*buf = msg + 2;

	return msg[1];
}
