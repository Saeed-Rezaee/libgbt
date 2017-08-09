#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "config.h"
#include "libgbt.h"

int
bdump(struct blist *head, char *pre) {
	struct bdata *np = NULL;
	char tmp[32];
	TAILQ_FOREACH(np, head, entries) {
		switch(np->type) {
		case 'i':
			printf("%s%d\n", pre, np->number);
			break;
		case 's':
			printf("%s\"%s\"\n", pre, np->string);
			break;
		case 'd':
		case 'l':
			printf("%s%s:\n", pre, np->type == 'l' ? "{" : "[");
			strcpy(tmp, pre);
			strcat(tmp, "|   ");
			bdump(np->list, tmp);
			printf("%sEND %s\n", pre, np->type == 'l' ? "}" : "]");
			break;
		default:
			return 1;
		}
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	struct blist *head = NULL;
	head = bdecode(stdin);
	assert(head != NULL);
	bdump(head, "");
	bfree(head);
	return 0;
}
