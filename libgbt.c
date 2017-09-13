#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

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
static uint8_t *setbit(uint8_t *, off_t);
static uint8_t *clrbit(uint8_t *, off_t);

static char * tohex(uint8_t *, char *, size_t);
static char * tostr(char *, size_t);
static char * urlencode(uint8_t *, size_t);

static int beinit(struct be *, char *, size_t);
static size_t beatol(char **, long *);
static size_t beint(struct be *, long *);
static size_t bestr(struct be *, char **, size_t *);
static size_t belist(struct be *, size_t *);
static size_t bedict(struct be *, size_t *);
static size_t benext(struct be *);
static int belistover(struct be *);
static int belistnext(struct be *);
static int bedictnext(struct be *, char **, size_t *, struct be *);
static char betype(struct be *);
static int bekv(struct be *, char *, size_t, struct be *);
static int bepath(struct be *, char **, size_t);

static size_t metainfohash(struct torrent *);
static size_t metaannounce(struct torrent *);
static size_t metafiles(struct torrent *);
static size_t metapieces(struct torrent *);

static size_t bstr2peer(struct peers *, char *, size_t);

static int httpsend(struct torrent *, char *, struct be *);
static size_t pwpmsg(uint8_t *, int, uint8_t *, uint32_t);

static int pwphandshake(struct torrent *, struct peer *);
static uint32_t pwphave(struct torrent *, uint8_t *, uint32_t);

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

static size_t
curlwrite(char *ptr, size_t size, size_t nmemb, struct buffer *userdata)
{
	userdata->buf = realloc(userdata->buf, userdata->siz + size*nmemb);
	memcpy(userdata->buf + userdata->siz, ptr, size*nmemb);
	userdata->siz += size*nmemb;
	return userdata->siz;
}

static uint8_t *
setbit(uint8_t *bits, off_t off)
{
	bits[off / sizeof(*bits)] |= (1 << off);
	return bits;
}

static uint8_t *
clrbit(uint8_t *bits, off_t off)
{
	bits[off / sizeof(*bits)] &= ~(1 << off);
	return bits;
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

static int
beinit(struct be *b, char *s, size_t l)
{
        if (!b || !s || !l)
                return 0;

        memset(b, 0, sizeof(*b));
        b->start = s;
        b->end = b->start + l - 1;
        b->off = b->start;

        return 1;
}

static size_t
beatol(char **str, long *l)
{
        long s = 1;
        long v = 0;
	char *sp = *str;

        if (!sp)
                return 0;

        /* define the sign of our number */
        if (*sp == '-') {
                s = -1;
                sp++;
		/* -0 is invalid, even for "-03" */
		if (*sp == '0')
			return 0;
        }

        /* 0 followed by a number is considered invalid */
        if (sp[0] == '0' && isdigit(sp[1]))
                return 0;

        /* read out number until next non-number, or end of string */
        while(isdigit(*sp)) {
                v *= 10;
                v += *sp++ - '0';
        }

        if (l)
                *l = v * s;

	/* move initial pointer to the actual read data */
	*str = sp;

        return 1;
}

static size_t
beint(struct be *b, long *n)
{
	char *sp;
        long num;

        if (!b)
                return 0;

	sp = b->off;

        if (*(sp++) != 'i')
                return 0;

        beatol(&sp, &num);

        if (*sp != 'e')
                return 0;

        if (n)
                *n = num;

        return sp - b->off + 1;
}

static size_t
bestr(struct be *b, char **s, size_t *l)
{
	char *sp;
        ssize_t len;

	if (!b)
		return 0;

	sp = b->off;

        if (!beatol(&sp, &len))
                return 0;

        if (len < 0 || *sp++ != ':')
                return 0;

        if (s)
                *s = sp;

        if (l)
                *l = (size_t)len;

        return sp - b->off + len;
}

static size_t
belist(struct be *b, size_t *n)
{
        size_t c = 0;
	struct be i;

        if (!b)
                return 0;

	beinit(&i, b->off, b->end - b->off + 1);

        while(!belistover(&i)) {
		belistnext(&i);
                c++;
	}

	if (*i.off == 'e')
		i.off++;

        if (n)
                *n = c;

        return i.off - b->off;
}

static size_t
bedict(struct be *b, size_t *n)
{
        size_t c = 0;
	struct be i;

        if (!b)
                return 0;

	beinit(&i, b->off, b->end - b->off + 1);

        while(!belistover(&i)) {
		bedictnext(&i, NULL, NULL, NULL);
                c++;
	}

        if (*i.off == 'e')
		i.off++;

        if (n)
                *n = c;

        return i.off - b->off;
}

static int
belistover(struct be *b) {
	return b->off >= b->end || *b->off == 'e';
}

static int
belistnext(struct be *b)
{
        if (!b || *b->off == 'e')
                return 0;

	if (b->off == b->start && *b->off == 'l') {
		b->off++;
		return 1;
	}

        return benext(b);
}

static int
bedictnext(struct be *b, char **k, size_t *l, struct be *v)
{
        if (!b || *b->off == 'e')
                return 0;

	/* move to first element if we're at the start */
        if (b->off == b->start && *b->off == 'd')
                b->off++;

	/* retrieve key name and length */
        if (!bestr(b, k, l))
                return 0;

	if (benext(b) && v)
		beinit(v, b->off, b->end - b->off + 1);

	return benext(b);
}

static size_t
benext(struct be *b)
{
	int r = 0;

	if (!b)
		return 0;

        /* check for end of buffer */
        if (b->off >= b->end)
                return 0;

	/* TODO: implement betype() */
        switch(betype(b)) {
        case 'i':
                r = beint(b, NULL);
                break;
        case 'l':
                r = belist(b, NULL);
                break;
        case 'd':
                r = bedict(b, NULL);
                break;
        case 's':
		r = bestr(b, NULL, NULL);
                break;
        }

	b->off += r;

        return r;
}

static char
betype(struct be *b)
{
	switch(*b->off) {
	case 'i':
	case 'l':
	case 'd':
		return *b->off;
		break; /* NOTREACHED */
	}
	return isdigit(*b->off) ? 's' : 0;
}

static int
bekv(struct be *b, char *k, size_t l, struct be *v)
{
        char *key = NULL;
        size_t klen = 0;
	struct be i;

        if (!b)
                return 0;

	if (*b->off != 'd')
		return 0;

	beinit(&i, b->off, b->end - b->off + 1);

        /* search the data 'till the end */
        while (!belistover(&i) && bedictnext(&i, &key, &klen, v)) {
                /* we found our key! */
                if (!strncmp(k, key, MIN(l, klen)))
                        return 1;

                /* recursive call to search inner dictionaries */
                if (betype(&i) == 'd' && bekv(&i, k, l, v))
                        return 1;
        }

        /* couldn't find anything, sorry */
        return 0;
}

static int
bepath(struct be *b, char **p, size_t l)
{
	char *s;
	size_t r;
	struct be i;

	if (!b || betype(b) != 'l')
		return 0;

	beinit(&i, b->off, b->end - b->off + 1);

	while(belistnext(&i) && !belistover(&i)) {
		if (!bestr(&i, &s, &r))
			continue;
		strncat(*p, "/", l);
		strncat(*p, s, r);
	}
	return 1;
}

static size_t
metainfohash(struct torrent *to)
{
	char *sp;
	struct be info;

	if (!bekv(&to->meta, "info", 4, &info))
		return 0;

	sp = info.off;
	if (!benext(&info))
		return 0;

	return sha1((unsigned char *)sp, info.off - sp, to->infohash);
}

static size_t
metaannounce(struct torrent *to)
{

	char *sp;
	size_t l;
	struct be announce;

	if (!bekv(&to->meta, "announce", 8, &announce))
		return 0;
	if (!bestr(&announce, &sp, &l))
		return 0;

	memset(to->announce, 0, PATH_MAX);
	memcpy(to->announce, sp, MIN(PATH_MAX, l));

	return l;
}

static size_t
metafiles(struct torrent *to)
{
	int i = 0;
	size_t l;
	char *sp, name[PATH_MAX];
	struct be n, f, v;

	if (!bekv(&to->meta, "name", 4, &n))
		return 0;
	if (!bestr(&n, &sp, &l))
		return 0;

	memset(name, 0, PATH_MAX);
	memcpy(name, sp, MIN(PATH_MAX, l));

	to->size = 0;
	if (bekv(&to->meta, "files", 5, &f)) { /* multi-file torrent */
		for (i = 0; belistnext(&f) && !belistover(&f); i++) {
			to->files = realloc(to->files, sizeof(*to->files) * i);
			if (!bekv(&f, "length", 6, &v))
				return 0;
			beint(&v, (long *)&to->files[i].len);
			to->size += to->files[i].len;

			memset(to->files[i].path, 0, PATH_MAX);
			memcpy(to->files[i].path, name, l);
			if (!bekv(&f, "path", 4, &v))
				return 0;
			sp = to->files[i].path;
			bepath(&v, &sp, PATH_MAX);
		}
		to->filnum = i;
	} else { /* single-file torrent */
		to->files = emalloc(sizeof(*to->files));
		if (!bekv(&f, "length", 6, &v))
			return 0;
		beint(&v, (long *)&to->files[0].len);
		to->size += to->files[0].len;
		memset(to->files[0].path, 0, PATH_MAX);
		memcpy(to->files[0].path, name, l);
		to->filnum = 1;
	}
	return to->filnum;
}

static size_t
metapieces(struct torrent *to)
{
	size_t i;
	uint8_t *sha1 = NULL;
	struct be v;

	if (!bekv(&to->meta, "piece length", 12, &v))
		return 0;

	if (!beint(&v, (long *)&to->piecelen))
		return 0;

	to->pcsnum = to->size/to->piecelen + !!(to->size%to->piecelen);
	to->bitfield = emalloc(to->pcsnum / sizeof(*to->bitfield));
	to->pieces = emalloc(to->pcsnum * sizeof(*to->pieces));

	for (i = 0; i < to->pcsnum; i++) {
		to->pieces[i].len = i == to->pcsnum ? to->size - i*to->piecelen : to->piecelen;
		to->pieces[i].data = emalloc(to->pieces[i].len);
		to->pieces[i].sha1 = sha1 + (i*20);
	}

	return to->pcsnum;
}

int
metainfo(struct torrent *to, char *buf, size_t len)
{
	to->upload = 0;
	to->download = 0;
	memcpy(to->peerid, PEERID, 20);
	to->peerid[20] = 0;
	beinit(&to->meta, buf, len);

	metainfohash(to);
	metaannounce(to);
	metafiles(to);
	metapieces(to);

	return 0;
}

struct piece
piecereqrand(struct torrent *to)
{
	uint32_t n;

	srand(time(NULL)); /* good-enough seed */
	n = rand() % (to->pcsnum + 1);

	return to->pieces[n];
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
		p->sockfd = -1;
		p->connected = 0;
		p->choked = 1;
		p->interrested = 0;
		p->peer.sin_family = AF_INET;
		memcpy(&p->peer.sin_port, &buf[i * 6] + 4, 2);
		memcpy(&p->peer.sin_addr, &buf[i * 6], 4);
		if (p->peer.sin_port != 65535)
			TAILQ_INSERT_TAIL(ph, p, entries);
	}

	return i;
}

static int
httpsend(struct torrent *to, char *ev, struct be *reply)
{
	static struct buffer b;
	char  url[PATH_MAX] = {0};
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

	memset(&b, 0, sizeof(b));
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlwrite);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
	r = curl_easy_perform(c);
	if (r != CURLE_OK)
		errx(1, "%s", curl_easy_strerror(r));

	return beinit(reply, b.buf, b.siz);
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
updatepeers(struct torrent *to, struct be *reply)
{
	char *s;
	size_t l, n = 0;
	struct peers ph;
	struct peer *p;
	struct be v;

	if (!bekv(reply, "peers", 5, &v))
		return -1;

	if (!to->peers) {
		to->peers = emalloc(sizeof(*to->peers));
		TAILQ_INIT(to->peers);
	}

	TAILQ_INIT(&ph);

	switch (betype(&v)) {
	case 's':
		if (bestr(&v, &s, &l))
			bstr2peer(&ph, s, l);
		break;
	default:
		errx(1, "'%c': Unsupported type for peers", betype(&v));
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
	char *s;
	size_t l;
	long interval = 0;
	struct be reply, v;

	httpsend(to, event[ev], &reply);

	if (bekv(&reply, "failure reason", 14, &v)) {
		bestr(&v, &s, &l);
		errx(1, "%s: %s", to->announce, tostr(s, l));
	}

	if (!bekv(&reply, "interval", 8, &v))
		errx(1, "Missing key 'interval'");

	beint(&v, &interval);
	updatepeers(to, &reply);

	return interval;
}

int
pwpinit(struct peer *p)
{
	int flags;

	if (p->connected)
		return 0;

	if ((p->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		return -1;

	if ((flags = fcntl(p->sockfd, F_GETFL, 0)) < 0)
		return -1;

	if (fcntl(p->sockfd, F_SETFL, flags|O_NONBLOCK) < 0)
		return -1;

	return connect(p->sockfd, (struct sockaddr *)&p->peer, sizeof(p->peer));
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
	uint8_t msg[68];

	msg[0] = 19;
	memcpy(msg + 1, "BitTorrent protocol", 19);
	memcpy(msg + 28, to->infohash, 20);
	memcpy(msg + 48, PEERID, 20);

	return send(p->sockfd, msg, 68, 0);
}

static uint32_t
pwphave(struct torrent *to, uint8_t *payload, uint32_t off)
{
	if (off >= to->pcsnum)
		errx(1, "Piece index too high");

	payload[0] = htonl(off);

	setbit(to->bitfield, off);
	return sizeof(off);
}

/*
 * -----------------------------------------
 * | Message Length | Message ID | Payload |
 * -----------------------------------------
 *          4             1          ...
 */
static size_t
pwpmsg(uint8_t *msg, int type, uint8_t *payload, uint32_t len)
{
	size_t i;
	off_t off = 0;

	msg[off] = htonl(len + 1);
	off += 4;
	msg[off] = type;
	off += 1;

	for (i = 0; i < len; i++)
		msg[off++] = payload[i];

	return off;
}

ssize_t
pwpsend(struct torrent *to, struct peer *p, int type, void *data)
{
	size_t len;
	uint8_t msg[MESSAGE_MAX];
	uint8_t payload[MESSAGE_MAX];

	switch(type) {
	case PWP_CHOKE:
	case PWP_UNCHOKE:
        case PWP_INTERESTED:
        case PWP_UNINTERESTED:
		len = pwpmsg(msg, type, NULL, 0);
		break;
        case PWP_BITFIELD:
		len = sizeof(*to->bitfield) * to->pcsnum;
		memcpy(payload, to->bitfield, len);
		break;
        case PWP_HAVE:
		len = pwphave(to, payload, *((uint32_t *)data));
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

	len = pwpmsg(msg, type, payload, len);
	return send(p->sockfd, msg, len, 0);
}

int
pwprecv(struct peer *p, uint8_t *buf, ssize_t *len)
{
	ssize_t r;


	while ((r = recv(p->sockfd, buf, MESSAGE_MAX, 0)) > 0)
		*len += r;

	if (r < 0) perror("recv");
	if (*len < 1) return -1;
	if (*len < 2) {
		fprintf(stderr, "Message too short: %lu\n", buf[0]);
		return -1;
	}

	if (buf[0] > NUM_PWP_TYPES)
		return PWP_HANDSHAKE;

	return buf[0];
}
