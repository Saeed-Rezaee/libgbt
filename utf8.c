/*
 * ASCII all have a leading '0' byte:
 *
 *   0xxxxxxx
 *
 * UTF-8(7) have one leading '1' and as many following '1' as there are
 * continuation bytes (with leading '1' and '0').
 *
 *   0xxxxxxx
 *   110xxxxx 10xxxxxx
 *   1110xxxx 10xxxxxx 10xxxxxx
 *   11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
 *   111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
 *   1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
 *
 * There is up to 3 continuation bytes -- up to 4 bytes per runes.
 *
 * The whole character value is retreived into an 'x' and stored into a
 * (long)[].
 *
 * Thanks to Connor Lane Smith for the idea of combining switches and
 * binary masks.
 */

#include <stdlib.h>

#include "utf8.h"


/*
 * Return the number of bytes in rune for the `n` next char in `s`,
 * or 0 if ti is misencoded.
 */
size_t
utflen(unsigned char *s, int n)
{
	int i, len = (*s == 0xff) ? 0 :  /* 11111111 */
	             (*s <= 0xfe) ? 7 :  /* 11111110  0xff - 0x01 */
	             (*s <= 0xfd) ? 6 :  /* 1111110x  0xff - 0x02 */
	             (*s <= 0xfb) ? 5 :  /* 111110xx  0xff - 0x04 */
	             (*s <= 0xf7) ? 4 :  /* 11110xxx  0xff - 0x08 */
	             (*s <= 0xef) ? 3 :  /* 1110xxxx  0xff - 0x10 */
	             (*s <= 0xdf) ? 2 :  /* 110xxxxx  0xff - 0x20 */
	             (*s <= 0xbf) ? 0 :  /* 10xxxxxx  0xff - 0x40 */
	                            1;   /* 0xxxxxxx  0xff - 0x80 */
	if (len > n)
		return 0;

	/* check if continuation bytes are 10xxxxxx */
	for (i = len; i > 0; i--, s++)
		if (*s >= 0x80)
			return 0;

	return len;
}


/*
 * Return the number of bytes required to encode `rune` into UTF-8, or
 * 0 if rune is too long.
 */
size_t
runelen(long r)
{
	return (r <= 0x0000007f) ? 1 : (r <= 0x000007ff) ? 2 :
	       (r <= 0x0000ffff) ? 3 : (r <= 0x001fffff) ? 4 :
	       (r <= 0x03ffffff) ? 5 : (r <= 0x7fffffff) ? 6 : 0;
}


/*
 * Sets 'r' to a rune corresponding to the firsts 'n' bytes of 's'.
 *
 * Return the number of bytes read or 0 if the string is misencoded.
 */
size_t
utftorune(long *r, unsigned char *s, size_t n)
{
	unsigned char mask[] = { 0x00, 0x1f, 0x0f, 0x07, 0x03, 0x01 };
	size_t i, len = utflen(s, n);

	/* misencoded */
	if (len == 0 || len > 6 || len > n) {
		*r = 0;
		return 1;
	}

	/* first byte */
	*r = *s & mask[len - 1];

	/* continuation bytes */
	for (i = 1; i < len; i++)
		*r = (*r << 6) | (s[i] & 0x3f);  /* 10xxxxxx */

	/* overlong sequences */
	if (runelen(*r) != len) {
		*r = 0;
		return 1;
	}

	return len;
}


/*
 * Convert the utf char sring `src` of size `n` to a long string
 * `dest`.
 *
 * Return the length of `i`.
 */
size_t
utftorunes(long *runes, unsigned char *utf, size_t n)
{
	size_t i, j;

	for (i = 0, j = 0; n > 0; i++, n++)
		j += utftorune(runes + i, utf + j, n);

	runes[i] = '\0';
	return i;
}


/*
 * Encode the rune 'r' in utf-8 in 's`' null-terminated.
 *
 * Return the number of bytes written, 0 if 'r' is invalid.
 */
size_t
runetoutf(unsigned char *s, long r)
{
	switch (runelen(r)) {
	case 1:
		s[0] = r;                          /* 0xxxxxxx */
		s[1] = '\0';
		return 1;
	case 2:
		s[0] = 0xc0 | (0x1f & (r >> 6));   /* 110xxxxx */
		s[1] = 0x80 | (0x3f & (r));        /* 10xxxxxx */
		s[2] = '\0';
		return 2;
	case 3:
		s[0] = 0xe0 | (0x0f & (r >> 12));  /* 1110xxxx */
		s[1] = 0x80 | (0x3f & (r >> 6));   /* 10xxxxxx */
		s[2] = 0x80 | (0x3f & (r));        /* 10xxxxxx */
		s[3] = '\0';
		return 3;
	case 4:
		s[0] = 0xf0 | (0x07 & (r >> 18));  /* 11110xxx */
		s[1] = 0x80 | (0x3f & (r >> 12));  /* 10xxxxxx */
		s[2] = 0x80 | (0x3f & (r >> 6));   /* 10xxxxxx */
		s[3] = 0x80 | (0x3f & (r));        /* 10xxxxxx */
		s[4] = '\0';
		return 4;
	case 5:
		s[0] = 0xf8 | (0x03 & (r >> 24));  /* 111110xx */
		s[1] = 0x80 | (0x3f & (r >> 18));  /* 10xxxxxx */
		s[2] = 0x80 | (0x3f & (r >> 12));  /* 10xxxxxx */
		s[3] = 0x80 | (0x3f & (r >> 6));   /* 10xxxxxx */
		s[4] = 0x80 | (0x3f & (r));        /* 10xxxxxx */
		s[5] = '\0';
		return 5;
	case 6:
		s[0] = 0xfc | (0x01 & (r >> 30));  /* 1111110x */
		s[1] = 0x80 | (0x3f & (r >> 24));  /* 10xxxxxx */
		s[2] = 0x80 | (0x3f & (r >> 18));  /* 10xxxxxx */
		s[3] = 0x80 | (0x3f & (r >> 12));  /* 10xxxxxx */
		s[4] = 0x80 | (0x3f & (r >> 6));   /* 10xxxxxx */
		s[5] = 0x80 | (0x3f & (r));        /* 10xxxxxx */
		s[6] = '\0';
		return 6;
	default:
		s[0] = '\0';
		return 0;
	}
}


/*
 * Returns 1 if the rune is a printable character and 0 if not.
 */
int
runeisprint(long r)
{
	return !(
		(r != '\t' && r < ' ')           ||  /* ascii control */
		(r == 0x7f)                      ||

		(0x80 <= r && r < 0xa0)          ||  /* unicode control */

		(r > 0x10ffff)                   ||  /* outside range */

		((r & 0x00fffe) == 0x00fffe)     ||  /* noncharacters */
		(0x00fdd0 <= r && r <= 0x00fdef) ||

		(0x00e000 <= r && r <= 0x00f8ff) ||  /* private use */
		(0x0f0000 <= r && r <= 0x0ffffd) ||
		(0x100000 <= r && r <= 0x10fffd) ||

		(0x00d800 <= r && r <= 0x00dfff)     /* surrogates */
	);
}
