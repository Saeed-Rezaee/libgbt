#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "libgbt.h"
#include "config.h"

#define INPUT "i123e8:announceli2e3:fooei123e"

char *
bencode(struct bedata *head) {
	char * out;
	char tmp[32] = { 0 };

	out = malloc(sizeof(INPUT));
	struct beelem *np = NULL;
	TAILQ_FOREACH(np, head, entries) {
		fflush(stdout);
		switch(np->type) {
		case BENCODING_INTEGER:
			sprintf(tmp, "i%de", np->number);
			break;
		case BENCODING_STRING:
			sprintf(tmp, "%d:%s", strlen(np->string), np->string);
			break;
		case BENCODING_LIST:
			strcat(out, "l");
			strcat(out, bencode(np->list));
			sprintf(tmp, "e");
			break;
		}
		strcat(out, tmp);
	}
	return out;
}

int
main(int argc, char *argv[])
{
	char *OUTPUT = NULL;	
	struct bedata *head = NULL;
	head = bencoding_parselist(stdin);
	assert(head != NULL);
	OUTPUT = bencode(head);
	assert(strcmp(INPUT, OUTPUT) == 0);
	return 0;
}
