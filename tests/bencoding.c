#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "config.h"
#include "libgbt.h"

#define INPUT "i123e8:announceli2e3:fooed5:monthi4e4:name5:april7:shadockl2:ga2:bu2:zo3:meuee"

char *
bencode(struct blist *head) {
	char *out, *list;
	char tmp[32] = { 0 };
	struct bdata *np = NULL;

	out = malloc(sizeof(INPUT) + 1);
	if (!out)
		return NULL;
	memset(out, 0, sizeof(INPUT) + 1);
	memset(tmp, 0, 32);
	TAILQ_FOREACH(np, head, entries) {
		switch(np->type) {
		case 'i':
			sprintf(tmp, "i%de", np->num);
			break;
		case 's':
			snprintf(tmp, 32, "%zu:%s", strlen(np->str), np->str);
			break;
		case 'd':
		case 'l':
			strcat(out, np->type == 'l' ? "l" : "d");
			list = bencode(np->bl);
			strcat(out, list);
			free(list);
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
	char *OUTPUT = NULL, *res = NULL;	
	struct blist *head = NULL;
	head = bdecode(stdin);
	assert(head != NULL);
	OUTPUT = bencode(head);
	assert(strcmp(INPUT, OUTPUT) == 0);
	bfree(head);
	free(OUTPUT);
	return 0;
}
