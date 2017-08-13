#include <stdio.h>
#include <assert.h>

#include "utf8.h"


void
test_utf8len(void)
{
	/* valid UTF-8 */
	assert(utf8len("asdf",                     4) == 1);
	assert(utf8len("\xc0\x8f",                 2) == 2);
	assert(utf8len("\xcf\x8f",                 2) == 2);
	assert(utf8len("\xe2\x9c\x93",             3) == 3);
	assert(utf8len("\xf0\xaf\xaf\xaf",         4) == 4);
	assert(utf8len("\xfc\x9c\x9c\x9c\x9c\x9c", 6) == 6);

	/* 10xxxxxx is forbidden leading byte */
	assert(utf8len("\x8f..",                   3) == 0);
}


void
test_utf8runelen(void)
{
	assert(utf8runelen('a')        == 1);
	assert(utf8runelen(0x2713)     == 3);
	assert(utf8runelen(0x7fffffff) == 6);
}


void
test_utf8torune(void)
{
	long r;

	utf8torune(&r, "\xe2\x9c\x93", 3);
	assert(r == 0x2713);

	/* overlong sequence: */
	assert(utf8torune(&r, "\xfc\x80\x80\x9c\x9c\x9c", 3) == 0);
}


void
test_utf8check(void)
{
	char *strings[] = {
		"ascii",
		"\xcf\x81",
		"⠇∀∂∈ℝ∧∪≡∞↑↗↨↻⇣┐┼╘░►☺♀ﬁ⑀₂ἠḂӥẄɐː⍎אԱა",
		"‘“”„†•…‰™œŠŸž€ΑΒΓΔΩαβγδωАБВГДабвгд",
		"\x80",                   /* forbidden leading byte          */
		"\xf0\x9f",               /* not long enough                 */
		"\xc0\xc0",               /* invalid continuation byte       */
		"\xc0\x81",               /* overlong sequence               */
		"\xff\x81\x81\x81\x81\x81\x81\x81",  /* too many             */
		"\xf1\xc1",               /* not enough                      */
	};
	int success[] = { 1, 1, 1, 1, 0, 0, 0, 0, 0, 0 };
	int i, len    = sizeof success / sizeof (int);

	for (i = 0; i < len; i++) {
		printf("%d ", i);
		assert(utf8check(strings[i], sizeof strings[i]) == success[i]);
	}
}

int
main()
{
	test_utf8len();
	test_utf8runelen();
	test_utf8torune();
	test_utf8check();

	return 0;
}
