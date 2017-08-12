#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "libgbt.h"

#define INPUT "d5:monthi4e4:name5:aprile"

int
main(int argc, char *argv[])
{
	struct bdata *OUTPUT = NULL;
        struct blist *head = NULL;
        head = bdecode(INPUT, strlen(INPUT));
        assert(head != NULL);
	OUTPUT = bsearchkey(head, "name");
	assert(OUTPUT != NULL);
	assert(!strncmp("april", OUTPUT->str, OUTPUT->len));
        bfree(head);
	return 0;
}
