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
	assert(utflen("\xe2\x9c\x93",             3) == 3);
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

	/* overlong sequence: */
	
	assert(utftorune(&r, "\xfc\x80\x80\x9c\x9c\x9c", 3) == 0);
}


void
test_strcheck(void)
{
	assert(strcheck("ascii"));
	assert(strcheck("\xcf\x81"));
	assert(strcheck("⠇∀∂∈ℝ∧∪≡∞↑↗↨↻⇣┐┼╘░►☺♀ﬁ⑀₂ἠḂӥẄɐː⍎אԱა"));
	assert(strcheck("‘“”„†•…‰™œŠŸž€ΑΒΓΔΩαβγδωАБВГДабвгд"));
	assert(!strcheck("\x80"));       /* forbidden leading byte          */
	assert(!strcheck("\xf0\x9f"));   /* not long enough                 */
	assert(!strcheck("\xc0\xc0"));   /* invalid continuation byte       */
	assert(!strcheck("\xc0\x81"));   /* overlong sequence               */
	assert(!strcheck("\xff\x81\x81\x81\x81\x81\x81\x81"));  /* too many */
	assert(!strcheck("\xf1\xc1"));   /* not enough                      */
}

int
main()
{
	test_utflen();
	test_runelen();
	test_utftorune();
	test_strcheck();
	return 0;
}
