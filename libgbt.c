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
#include <sys/stat.h>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>

#include "queue.h"
#include "sha1.h"
#include "libgbt.h"

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define U32(s) ((uint32_t)((s)[0])<<24|((s)[1])<<16|((s)[2])<<8|((s)[3]))

struct buffer {
	char  *buf;
	size_t siz;
};

static void * emalloc(size_t);
static size_t curlwrite(char *, size_t, size_t, struct buffer *);
static int bit(uint8_t *, off_t);
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
static int metainfo(struct torrent *, char *, size_t);

static int checkpiece(struct piece *);
static ssize_t readpiece(struct torrent *, struct piece *, unsigned long);
static uint32_t piecelen(struct torrent *, uint32_t);
static uint32_t blocklen(struct torrent *, struct piece, uint32_t);
static long piecereqrand(struct torrent *);

static long requestblock(struct torrent *, struct peer *);

static size_t bestr2peer(struct peers *, char *, size_t);
static int httpsend(struct torrent *, char *, struct be *);
static struct peer * findpeer(struct peers *, struct peer *);
static int updatepeers(struct torrent *, struct be *);
static int thpsend(struct torrent *, int);

static int pwpinit(struct peer *);
static uint32_t pwpfmt(uint8_t *, int, uint8_t *, uint32_t);
static ssize_t pwprecv(struct peer *, uint8_t *);
static ssize_t pwpstate(struct peer *, int);
static ssize_t pwphandshake(struct torrent *, struct peer *);
static ssize_t pwphave(struct peer *, uint16_t);
static ssize_t pwpbitfield(struct peer *, uint8_t *, size_t);
static ssize_t pwprequest(struct peer *, uint32_t, uint32_t, uint32_t);
static ssize_t pwppiece(struct peer *, uint32_t, uint32_t, uint32_t, uint8_t *);
static ssize_t pwpcancel(struct peer *, off_t, off_t, size_t);
static ssize_t pwpheartbeat(struct peer *);
static int pwprecvhandler(struct torrent *, struct peer *, uint8_t *, ssize_t);

static int handshakeisvalid(struct torrent *, uint8_t *, size_t);

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
	bits[off / 8] |= (1 << (7 - off%8));
	return bits;
}

static uint8_t *
clrbit(uint8_t *bits, off_t off)
{
	bits[off / sizeof(*bits)] &= ~(1 << (7 - off%8));
	return bits;
}

static int
bit(uint8_t *bits, off_t off)
{
	return !!(bits[off / 8] & (1 << (7 - off%8)));
}

static char *
tohex(uint8_t *in, char *out, size_t len)
{
	size_t i, j;
	char hex[] = "0123456789abcdef";

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

	out = emalloc(len * 3 + 1);
	memset(out, 0, len * 3 + 1);

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

	return !sha1((unsigned char *)sp, info.off - sp, to->infohash);
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
	struct be info, n, f, v;

	if (!bekv(&to->meta, "info", 4, &info))
		return 0;
	if (!bekv(&info, "name", 4, &n))
		return 0;
	if (!bestr(&n, &sp, &l))
		return 0;

	memset(name, 0, PATH_MAX);
	memcpy(name, sp, MIN(PATH_MAX, l));

	to->size = 0;
	to->files = NULL;
	if (bekv(&info, "files", 5, &f)) { /* multi-file torrent */
		for (i = 0; belistnext(&f) && !belistover(&f); i++) {
			to->files = realloc(to->files, sizeof(*to->files) * (i+1));
			if (!to->files || !bekv(&f, "length", 6, &v))
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
		if (!bekv(&info, "length", 6, &v))
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
	struct be info, v;

	if (!bekv(&to->meta, "info", 4, &info))
		return 0;
	if (!bekv(&info, "piece length", 12, &v))
		return 0;
	if (!beint(&v, (long *)&to->piecelen))
		return 0;
	if (!bekv(&info, "pieces", 6, &v))
		return 0;
	if (!bestr(&v, &to->pieces, NULL))
		return 0;

	to->pcsnum = to->size/to->piecelen + !!(to->size%to->piecelen);
	to->bitfield = emalloc(to->pcsnum / 8 + !!(to->pcsnum % 8));

	return to->pcsnum;
}

static int
metainfo(struct torrent *to, char *buf, size_t len)
{
	to->upload = 0;
	to->download = 0;
	to->peers = NULL;
	memset(to->peerid, 0, 21);
	memcpy(to->peerid, PEERID, 20);
	beinit(&to->meta, buf, len);

	metainfohash(to);
	metaannounce(to);
	metafiles(to);
	metapieces(to);

	return 0;
}

static int
checkpiece(struct piece *pc)
{
	unsigned char hash[20];

	sha1((const unsigned char *)pc->data, pc->len, hash);
	return !memcmp(pc->sha1, hash, 20);
}

static ssize_t
writepiece(struct torrent *to, struct piece *pc)
{
	int fd;
	char *addr;
	size_t off, i;
	ssize_t l;

	off = pc->n * to->piecelen;

	/* find file where piece begins */
	for (i = 0; off > to->files[i].len && i < to->filnum; i++)
		off -= to->files[i].len;

	/* read from file until piece is full */
	l = pc->len;
	while(l > 0 && i < to->filnum) {
	        if ((fd = open(to->files[i].path, O_RDWR|O_CREAT, 0644)) < 0) {
	                perror(to->files[i].path);
	                return -1;
	        }
		ftruncate(fd, to->files[i].len);

                addr = mmap(0, to->files[i].len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
                if (addr == MAP_FAILED) {
                        perror("mmap");
                        close(fd);
		}

		memcpy(addr + off, pc->data, MIN((size_t)l, to->files[i].len - off));
		munmap(addr, to->files[i].len);
		close(fd);
		printf(":: piece %ld written to %s\n", pc->n, to->files[i].path);
		l -= MIN((size_t)l, to->files[i].len - off);
		i++;
	}

	setbit(to->bitfield, pc->n);
	return pc->len;
}

static ssize_t
readpiece(struct torrent *to, struct piece *pc, unsigned long n)
{
	FILE *f;
	ssize_t r;
	size_t off, i, l;

	off = n * to->piecelen;

	pc->n = n;
	pc->len = 0;
	pc->sha1 = to->pieces + 20 * n;
	memset(pc->data, 0, sizeof(pc->data));
	memset(pc->blocks, 0, PIECE_MAX/(8*BLOCK_MAX));

	/* find file where piece begins */
	for (i = 0; i < to->filnum && off > to->files[i].len; i++)
		off -= to->files[i].len;

	/* calculate expected piece len */
	l = (n == to->pcsnum - 1) ? (to->size % to->piecelen) : to->piecelen;
	r = 0;

	/* read from file until piece is full */
	while(pc->len < l) {
		if (i >= to->filnum)
			return 0;
		if (!(f = fopen(to->files[i].path, "r")))
			return 0;
		fseek(f, off, SEEK_SET);
		r = fread(pc->data + r, 1, MIN(l, to->files[i].len - off), f);
		pc->len += r;
		fclose(f);
		l -= r;
	}

	return checkpiece(pc) ? pc->len : 0;
}

static uint32_t
piecelen(struct torrent *to, uint32_t n)
{
	if (n >= to->pcsnum)
		return 0;

	return (n == to->pcsnum - 1) ? to->size % to->piecelen : to->piecelen;
}

static uint32_t
blocklen(struct torrent *to, struct piece pc, uint32_t o)
{
	if (pc.n >= to->pcsnum)
		return 0;

	if (o >= pc.len)
		return 0;

	return (pc.len - o) < BLOCK_MAX ? pc.len - o : BLOCK_MAX;
}

static long
piecereqrand(struct torrent *to)
{
	long n;

	srand(time(NULL)); /* good-enough seed */

	do {
		n = rand() % (to->pcsnum + 1);
	} while (!bit(to->bitfield, n));

	return to->pieces[n];
}

static long
requestblock(struct torrent *to, struct peer *p)
{
	size_t i;
	uint32_t bo, bl;

	/* reset piece request when we have the piece */
	if (bit(to->bitfield, p->req.n)) {
		p->lastreq = -1;
		memset(p->req.data, 0, to->piecelen);
		memset(p->req.blocks, 0, to->piecelen/(8*BLOCK_MAX));
	}

	/* not requesting anything from peer yet */
	for (i = 0; p->lastreq < 0 && i < to->pcsnum; i++) {
		/* find a piece in peer bitfield we don't have yet */
		if (bit(p->bitfield, i) && !bit(to->bitfield, i)) {
			p->req.n = i;
			p->req.len = piecelen(to, i);
			p->req.sha1 = to->pieces + i * 20;
			break;
		}
	}

	/* this peer is of no help for us */
	if (i >= (to->pcsnum))
		return 0;

	bo = p->lastreq < 0 ? 0 : p->lastreq + BLOCK_MAX;
	bl = blocklen(to, p->req, bo);

	if (!bl || bo >= p->req.len || bit(p->req.blocks, bo/BLOCK_MAX))
		return -1;

	if (pwprequest(p, p->req.n, bo, bl) < 0)
		return 0;

	fprintf(stderr, "> request %lu (off:%d len:%d plen:%ld)\n", p->req.n, bo, bl, p->req.len);
	p->lastreq = bo;
	return 1;
}

static size_t
bestr2peer(struct peers *ph, char *buf, size_t len)
{
	size_t i;
	struct peer *p;

	if (len % 6)
		errx(1, "%zu: Not a multiple of 6", len);

	for (i = 0; i < len/6; i++) {
		p = emalloc(sizeof(*p));
		p->conn = CONN_CLOSED;
		p->state = 0;
		p->state |= PEER_CHOKED;
		p->state |= PEER_AMCHOKED;
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

	curl_easy_cleanup(c);

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
			bestr2peer(&ph, s, l);
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
	} while(p && (p = TAILQ_NEXT(p, entries)));

	if (!TAILQ_EMPTY(&ph))
		TAILQ_CONCAT(to->peers, &ph, entries);

	TAILQ_FOREACH(p, to->peers, entries)
		n++;

	return n;
}

static int
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

static int
pwpinit(struct peer *p)
{
	int flags = 0;

	if (p->conn != CONN_CLOSED)
		return 0;

	if ((p->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		return -1;

	if ((flags = fcntl(p->sockfd, F_GETFL, 0)) < 0)
		return -1;

	if (fcntl(p->sockfd, F_SETFL, flags|O_NONBLOCK) < 0)
		return -1;

	return connect(p->sockfd, (struct sockaddr *)&p->peer, sizeof(p->peer));
}

static ssize_t
pwprecv(struct peer *p, uint8_t *buf)
{
	size_t len = 0;
	ssize_t l, s, r;

	/* read the first 4 bytes to get message length */
	if ((r = recv(p->sockfd, buf, 4, MSG_PEEK)) < 0)
		return -1;

	len = U32(buf);

	/* compute expected message length */
	l = buf[0] == 19 ? 68 : len + 4;
	s = 0;

	if (l > MESSAGE_MAX)
		return -1;

	while (l > 0 && s < MESSAGE_MAX && (r = recv(p->sockfd, buf + s, l, 0)) > 0) {
		l -= r;
		s += r;
	}

	if (r < 0) {
		return -1;
	}

	return s;
}

/*
 * -----------------------------------------
 * | Message Length | Message ID | Payload |
 * -----------------------------------------
 *          4             1          ...
 */
static uint32_t
pwpfmt(uint8_t *msg, int type, uint8_t *payload, uint32_t len)
{
	size_t i;
	off_t off = 0;

	if (!msg)
		return 0;

	memset(msg, 0, len + 5);
	msg[off++] = ((len + 1) >> 24) & 0xff;
	msg[off++] = ((len + 1) >> 16) & 0xff;
	msg[off++] = ((len + 1) >> 8) & 0xff;
	msg[off++] = ((len + 1) >> 0) & 0xff;
	msg[off++] = type;

	for (i = 0; i < len; i++)
		msg[off++] = payload[i];

	return off;
}

/*
 * type can be "PWP_(UN)CHOKE" or "PWP_(UN)INTEREST"
 */
static ssize_t
pwpstate(struct peer *p, int type)
{
	size_t l;
	uint8_t msg[5];
	uint8_t *sp = msg;

	l = pwpfmt(sp, type, NULL, 0);
	return send(p->sockfd, msg, l, MSG_NOSIGNAL);
}

static ssize_t
pwphandshake(struct torrent *to, struct peer *p)
{
	uint8_t msg[68];

	msg[0] = 19;
	memcpy(msg + 1, "BitTorrent protocol", 19);
	memset(msg + 20, 0, 8);
	memcpy(msg + 28, to->infohash, 20);
	memcpy(msg + 48, PEERID, 20);

	return send(p->sockfd, msg, 68, MSG_NOSIGNAL);
}

static ssize_t
pwphave(struct peer *p, uint16_t pn)
{
	size_t l;
	uint8_t msg[MESSAGE_MAX], pl[4];
	uint8_t *sp = msg;

	pl[0] = (pn >> 24) & 0xff;
	pl[1] = (pn >> 16) & 0xff;
	pl[2] = (pn >> 8) & 0xff;
	pl[3] = (pn >> 0) & 0xff;
	l = pwpfmt(sp, PWP_HAVE, pl, 4);

	fprintf(stderr, "> have %d\n", pn);

	return send(p->sockfd, msg, l, MSG_NOSIGNAL);
}

static ssize_t
pwpbitfield(struct peer *p, uint8_t *bf, size_t n)
{
	size_t l;
	uint8_t msg[MESSAGE_MAX];
	uint8_t *sp = msg;

	l = pwpfmt(sp, PWP_BITFIELD, bf, n/8 + !!(n%8));

	return send(p->sockfd, msg, l, MSG_NOSIGNAL);
}

static ssize_t
pwprequest(struct peer *p, uint32_t pn, uint32_t bo, uint32_t bl)
{
	size_t l;
	uint8_t msg[MESSAGE_MAX], pl[12];
	uint8_t *sp = msg;

	pl[0] = (pn >> 24) & 0xff;
	pl[1] = (pn >> 16) & 0xff;
	pl[2] = (pn >> 8) & 0xff;
	pl[3] = (pn >> 0) & 0xff;

	pl[4] = (bo >> 24) & 0xff;
	pl[5] = (bo >> 16) & 0xff;
	pl[6] = (bo >> 8) & 0xff;
	pl[7] = (bo >> 0) & 0xff;

	pl[8]  = (bl >> 24) & 0xff;
	pl[9]  = (bl >> 16) & 0xff;
	pl[10] = (bl >> 8) & 0xff;
	pl[11] = (bl >> 0) & 0xff;
	l = pwpfmt(sp, PWP_REQUEST, pl, 12);

	return send(p->sockfd, msg, l, MSG_NOSIGNAL);
}

static ssize_t
pwppiece(struct peer *p, uint32_t pn, uint32_t bo, uint32_t bl, uint8_t *b)
{
	size_t l;
	uint8_t msg[MESSAGE_MAX], pl[MESSAGE_MAX];
	uint8_t *sp = msg;

	pl[0] = (pn >> 24) & 0xff;
	pl[1] = (pn >> 16) & 0xff;
	pl[2] = (pn >> 8) & 0xff;
	pl[3] = (pn >> 0) & 0xff;

	pl[4] = (bo >> 24) & 0xff;
	pl[5] = (bo >> 16) & 0xff;
	pl[6] = (bo >> 8) & 0xff;
	pl[7] = (bo >> 0) & 0xff;
	memcpy(pl+8, b, MIN(MESSAGE_MAX - 8, bl));
	l = pwpfmt(sp, PWP_PIECE, pl, bl + 8);

	return send(p->sockfd, msg, l, MSG_NOSIGNAL);
}

static ssize_t
pwpcancel(struct peer *p, off_t op, off_t ob, size_t sb)
{
	size_t l;
	uint8_t msg[MESSAGE_MAX], pl[12];
	uint8_t *sp = msg;

	pl[0] = htonl(op);
	pl[4] = htonl(ob);
	pl[8] = htonl(sb);
	l = pwpfmt(sp, PWP_CANCEL, pl, 12);

	return send(p->sockfd, msg, l, MSG_NOSIGNAL);
}

static ssize_t
pwpheartbeat(struct peer *p)
{
	uint8_t siz = 0;
	return send(p->sockfd, &siz, 1, MSG_NOSIGNAL);
}

static int
pwprecvhandler(struct torrent *to, struct peer *p, uint8_t *msg, ssize_t l)
{
	int n;
	struct piece pc;
	char hex[41];
	uint8_t blk[BLOCK_MAX];
	uint32_t pn, bo, bl;

	if (l < 4)
		return 0;

	n = msg[4];
	switch (n) {
	case PWP_CHOKE:
		p->state |= PEER_AMCHOKED;
		fprintf(stderr, "< choke\n");
		break;
	case PWP_UNCHOKE:
		p->state &= ~PEER_AMCHOKED;
		fprintf(stderr, "< unchoke\n");
		break;
	case PWP_INTERESTED:
		p->state |= PEER_INTERESTED;
		fprintf(stderr, "< interested\n");
		break;
	case PWP_UNINTERESTED:
		p->state &= ~PEER_INTERESTED;
		fprintf(stderr, "< uninterested\n");
		break;
	case PWP_HAVE:
		pn = U32(msg + 5);
		setbit(p->bitfield, pn);
		fprintf(stderr, "< have %d\n", pn);
		break;
	case PWP_BITFIELD:
		memcpy(p->bitfield, msg + 5, l - 5);
		fprintf(stderr, "< bitfield 0x%s\n", tohex(p->bitfield, hex, l - 5));
		break;
	case PWP_REQUEST:
		pn = U32(msg + 5);
		bo = U32(msg + 9);
		bl = U32(msg + 13);
		fprintf(stderr, "< request %d (off:%d len:%d)\n", pn, bo, bl);
		if (readpiece(to, &pc, pn)) {
			if (bl > BLOCK_MAX)
				return 0;
			memcpy(blk, pc.data + bo, bl);
			if (pwppiece(p, pn, bo, bl, blk)) {
				fprintf(stderr, "> piece %d (off:%d len:%d)\n", pn, bo, bl);
				to->upload += bl;
			}
		}
		break;
	default:
		fprintf(stderr, "Message %d not handled\n", n);
		return 0;
	}
	return 1;
}

static int
handshakeisvalid(struct torrent *to, uint8_t *hs, size_t l)
{
	if (l != 68)
		return 0;

	if (hs[0] != 19)
		return 0;

	if (memcmp(hs+1, "BitTorrent protocol", 19))
		return 0;

	if (memcmp(hs+28, to->infohash, 20))
		return 0;

	if (!memcmp(hs+48, PEERID, 20))
		return 0;

	return 1;
}

int
grizzly_load(struct torrent *to, char *path, long *thpinterval)
{
	FILE *f;
	long i;
	char *buf;
	struct stat sb;
	struct peer *p;
	struct piece pc;

	/* read torrent file into a memory buffer */
	if (stat(path, &sb)) {
		perror(path);
		return -1;
	}
	if (!(f = fopen(path, "r"))) {
		perror(path);
		return -1;
	}
	buf = malloc(sb.st_size);
	fread(buf, 1, sb.st_size, f);
	buf[sb.st_size - 1] = '\0';
	fclose(f);

	if (metainfo(to, buf, sb.st_size)) {
		fprintf(stderr, "%s: Failed to load torrent\n", path);
		free(buf);
		return 0;
	}

	for (i = 0; (size_t)i < to->pcsnum; i++) {
		if (readpiece(to, &pc, i) > 0)
			setbit(to->bitfield, i);
	}

	if ((i = thpsend(to, THP_STARTED)) < 0)
		return 0;

	if (thpinterval)
		*thpinterval = i;

	TAILQ_FOREACH(p, to->peers, entries) {
		pwpinit(p);
		p->conn = CONN_INIT;
		p->bitfield = emalloc(to->pcsnum / 8 + !!(to->pcsnum % 8));
		p->lastreq = -1;
		p->req.n = 0;
	}

	return 1;
}

int
grizzly_thpheartbeat(struct torrent *to, long *thpinterval)
{
	long i;
	if ((i = thpsend(to, THP_NONE)) < 0)
		return 0;

	if (thpinterval)
		*thpinterval = i;

	return 1;
}

int
grizzly_leech(struct torrent *to)
{
	int n, fdmax;
	fd_set rfds, wfds;
	char hex[41];
	ssize_t l;
	uint8_t msg[MESSAGE_MAX];
	struct peer *p;
	struct timeval tv;

	fdmax = -1;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	TAILQ_FOREACH(p, to->peers, entries) {
		if (p->conn >= CONN_HANDSHAKE)
			FD_SET(p->sockfd, &rfds);
		FD_SET(p->sockfd, &wfds);
		if (p->sockfd > fdmax)
			fdmax = p->sockfd;
	}

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	n = select(fdmax + 1, &rfds, &wfds, NULL, &tv);
	if (n < 0) {
		if (errno == EINTR)
	                return 0;
		perror("select");
        }

	TAILQ_FOREACH(p, to->peers, entries) {
		memset(msg, 0, MESSAGE_MAX);
		switch (p->conn) {
		/* ignore dropped peers */
		case CONN_CLOSED:
			continue;
			break; /* NOTREACHED */
		/* set peer as connected */
		case CONN_INIT:
			if (FD_ISSET(p->sockfd, &wfds)) {
				pwphandshake(to, p);
				p->conn = CONN_HANDSHAKE;
				fprintf(stderr, "> handshake\n");
			}
			break;
		case CONN_HANDSHAKE:
			if (FD_ISSET(p->sockfd, &rfds)) {
				p->conn = CONN_ESTAB;
				l = pwprecv(p, msg);
				if (l < 0 || !handshakeisvalid(to, msg, l)) {
					p->conn = CONN_CLOSED;
					close(p->sockfd);
					p->sockfd = -1;
					continue;
				}
				fprintf(stderr, "< handshake\n");
				pwpbitfield(p, to->bitfield, to->pcsnum);
				fprintf(stderr, "> bitfield 0x%s\n", tohex(to->bitfield, hex, to->pcsnum/8 + !!(to->pcsnum%8)));
			}
			break;
		case CONN_ESTAB:
			if (FD_ISSET(p->sockfd, &rfds)) {
				l = pwprecv(p, msg);
				if (l < 0) {
					fprintf(stderr, "%s: closing connection\n", inet_ntoa(p->peer.sin_addr));
					p->conn = CONN_CLOSED;
					close(p->sockfd);
					p->sockfd = -1;
					continue;
				}
				pwprecvhandler(to, p, msg, l);
			}
			if (FD_ISSET(p->sockfd, &wfds)) {
				if (p->state & PEER_INTERESTED && p->state & PEER_CHOKED) {
					pwpstate(p, PWP_UNCHOKE);
					p->state &= ~(PEER_CHOKED);
					fprintf(stderr, "> unchoke\n");
				}
				if (!(p->state & PEER_AMINTERESTED)) {
					pwpstate(p, PWP_INTERESTED);
					p->state |= PEER_AMINTERESTED;
					fprintf(stderr, "> interested\n");
				}
				if (!(p->state & PEER_AMCHOKED) && (p->state & PEER_AMINTERESTED))
					requestblock(to, p);
			}
			break;
		}
	}

	return 1;
}

int
grizzly_finished(struct torrent *to)
{
	size_t i;

	for (i = 0; i < to->pcsnum; i++) {
		if (!bit(to->bitfield, i))
			return 0;
	}
	return 1;
}
