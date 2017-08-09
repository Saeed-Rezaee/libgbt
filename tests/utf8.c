#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../utf8.h"


void
test_utflen(void)
{
	/* valid UTF-8 */
	assert(utflen("asdf",                     4) == 1);
	assert(utflen("\xc0\x8f",                 2) == 2);
	assert(utflen("\xcf\x8f",                 2) == 2);
	assert(utflen("✓",             3) == 3);
	assert(utflen("\xf0\xaf\xaf\xaf",         4) == 4);
	assert(utflen("\xfc\x9c\x9c\x9c\x9c\x9c", 6) == 6);

	/* 10xxxxxx is forbidden leading byte */
	assert(utflen("\x8f..",                   3) == 0);
}


void
test_runelen(void)
{
	assert(runelen('a')        == 1);
	assert(runelen(0x2713)     == 3);
	assert(runelen(0x7fffffff) == 6);
}


void
test_utftorune(void)
{
	long r;
	utftorune(&r, "\xe2\x9c\x93", 3);
	assert(r == 0x2713);

	/* overlong sequence: "\xfc\x80\x80\x9c\x9c\x9c" */
}


void
test_runetoutf(void)
{
	char s[8];
	long r;
	utftorune(&r, "\xE2\x9C\x93", 3);
	assert(utflen("\x8c\x9c\x93",     3) == 0);
	runetoutf(s, r);
	assert(!strcmp(s, "\xE2\x9C\x93"));
}


void
test_utf8(void)
{
	char s[1024], *sp = s;
	long r[1024], *rp = r;
	int i, l = 0;

	while (fgets(s, 1024, stdin) != NULL) {
		printf("len: %ld\n", strlen(s));
		i = strlen(s);
		for (rp = r, sp = s; i > 0 && *sp != '\0'; sp++, rp++, l++)
			i -= utftorune(rp, sp, i);
		for (sp = s, rp = r; l > 0;                sp++, rp++, l--)
			runetoutf(sp, *rp);
	}

	fputs(s, stderr);
}


int
main()
{
	test_utflen();
	test_runelen();
	test_utftorune();
	test_runetoutf();
	return 0;
}
