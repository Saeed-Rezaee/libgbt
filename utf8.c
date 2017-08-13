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
#include <stdio.h>

#include "utf8.h"


/*
 * Return the number of bytes in rune for the `n` next char in `s`,
 * or 0 if ti is misencoded.
 */
size_t
utf8len(char *s, int n)
{
	unsigned char *sp = (unsigned char *) s;
	int i, len = (*sp < 0x80) ? 1 :  /* 0xxxxxxx < 10000000 */
	             (*sp < 0xc0) ? 0 :  /* 10xxxxxx < 11000000 */
	             (*sp < 0xe0) ? 2 :  /* 110xxxxx < 11100000 */
	             (*sp < 0xf0) ? 3 :  /* 1110xxxx < 11110000 */
	             (*sp < 0xf8) ? 4 :  /* 11110xxx < 11111000 */
	             (*sp < 0xfc) ? 5 :  /* 111110xx < 11111100 */
	             (*sp < 0xfe) ? 6 :  /* 1111110x < 11111110 */
	             (*sp < 0xff) ? 7 :  /* 11111110 < 11111111 */
	                            0;
	if (len > n) return 0;

	/* check continuation bytes */
	for (sp++, i = 1; i < len; i++, sp++)
		if ((*sp & 0xc0) != 0x80)  /* 10xxxxxx & 11000000 */
			return 0;

	return len;
}


/*
 * Return the number of bytes required to encode `rune` into UTF-8, or
 * 0 if rune is too long.
 */
size_t
utf8runelen(long r)
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
utf8torune(long *r, char *s, size_t n)
{
	char mask[] = { 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };
	size_t i, len = utf8len(s, n);

	if (len == 0 || len > 6 || len > n)
		return 0;

	/* first byte */
	*r = *s++ & mask[len - 1];

	/* continuation bytes */
	for (i = 1; i < len; i++)
		*r = (*r << 6) | (*s++ & 0x3f);  /* 10xxxxxx */

	/* overlong sequences */
	if (utf8runelen(*r) != len)
		return 0;

	return len;
}


/*
 * Returns 1 if the rune is a valid unicode code point and 0 if not.
 */
int
utf8runeisunicode(long r)
{
	return !(
		(r > 0x10ffff)                   ||  /* outside range */

		((r & 0x00fffe) == 0x00fffe)     ||  /* noncharacters */
		(0x00fdd0 <= r && r <= 0x00fdef) ||

		(0x00e000 <= r && r <= 0x00f8ff) ||  /* private use */
		(0x0f0000 <= r && r <= 0x0ffffd) ||
		(0x100000 <= r && r <= 0x10fffd) ||

		(0x00d800 <= r && r <= 0x00dfff)     /* surrogates */
	);
}


/*
 * Return 1 if '*s' is correctly encoded in UTF-8 with allowed Unicode
 * code points.
 */
int
utf8check(char *s, size_t len)
{
	size_t shift;
	long r = 0;

	while (len > 0) {
		shift = utf8torune(&r, s, len);
		if (!shift || !utf8runeisunicode(r))
			return 0;

		s   += shift;
		len -= shift;
	}

	return 1;
}
