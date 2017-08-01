#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "queue.h"
#include "libgbt.h"
#include "config.h"

/* BENCODING functions */
static struct bdata *
bparseint(FILE *stream)
{
	int r = 0;
	char *string = NULL;
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	string = malloc(32);
	if (!string)
		return NULL;

	do {
                fread(string + (r++), 1, 1, stream);
	} while (r < 32 && string[r-1] != 'e');

	string[--r] = 0;
	tmp->type = INTEGER;
	tmp->number = atoi(string);
	free(string);

	return tmp;
}


static struct bdata *
bparsestr(FILE *stream, int len)
{
	int r = 0;
	char *string = NULL;
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	string = malloc(len + 1);
	if (!string)
		return NULL;

	while (r < len)
		r += fread(string+r, 1, len - r, stream);

	string[len] = 0;

	tmp->type = STRING;
	tmp->string = string;

	return tmp;
}


struct blist *
bparselist(FILE *stream)
{
	int r = 0;
	char type[32]; /* enough to hold an integer string value */
	struct bdata *tmp = NULL;
	struct blist *behead = NULL;

	behead = malloc(sizeof(struct blist));
	if (!behead)
		return NULL;

	TAILQ_INIT(behead);

	while (!feof(stream)) {
		fread(type, 1, 1, stream);
		switch(type[0]) {
		case 'd':
			break;
		case 'l':
			tmp = malloc(sizeof(struct bdata));
			if (!tmp)
				return NULL;
			tmp->type = LIST;
			tmp->list = bparselist(stream);
			break;
		case 'i':
			tmp = bparseint(stream);
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			r = 0;
			while (*(type+r) != ':')
				fread(type + (++r), 1, 1, stream);
			tmp = bparsestr(stream, atoi(type));
			break;
		case  'e':
		case '\n':
			return behead;
			break; /* NOTREACHED */
		default:
			return NULL;
		}
		TAILQ_INSERT_TAIL(behead, tmp, entries);
	}
	return behead;
}


int
bfree(struct blist *head)
{
	struct bdata *np = NULL;
	while (!TAILQ_EMPTY(head)) {
		np = TAILQ_FIRST(head);
		switch(np->type) {
		case STRING:
			free(np->string);
			break;
		case LIST:
			bfree(np->list);
			break;
		case INTEGER:
		case DICTIONNARY:
			break;
		}
		TAILQ_REMOVE(head, np, entries);
		free(np);
	}
	free(head);
	return 0;
}
