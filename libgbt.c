#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "queue.h"
#include "libgbt.h"
#include "config.h"

/* BENCODING functions */
static struct beelem *
bencoding_parseinteger(FILE *stream)
{
	int integer, r = 0;
	char *string = NULL;
	struct beelem *tmp = NULL;

	tmp = malloc(sizeof(tmp));
	if (!tmp)
		return NULL;

	string = malloc(32);
	if (!string)
		return NULL;

	do {
                fread(string + (r++), 1, 1, stream);
	} while (r < 32 && string[r-1] != 'e');

	string[--r] = 0;
	integer = atoi(string);

	tmp->type = BENCODING_INTEGER;
	tmp->number = integer;

	return tmp;
}


static struct beelem *
bencoding_parsestring(FILE *stream, int len)
{
	int r = 0;
	char *string = NULL;
	struct beelem *tmp = NULL;

	tmp = malloc(sizeof(struct beelem));
	if (!tmp)
		return NULL;

	string = malloc(len + 1);
	if (!string)
		return NULL;

	while (r < len)
		r += fread(string+r, 1, len - r, stream);

	string[len] = 0;

	tmp->type = BENCODING_STRING;
	tmp->string = string;

	return tmp;
}


struct bedata *
bencoding_parselist(FILE *stream)
{
	int r = 0;
	char type[32]; /* enough to hold an integer string value */
	struct beelem *tmp = NULL;
	struct bedata *behead = NULL;

	behead = malloc(sizeof(struct bedata));
	if (!behead)
		return NULL;

	TAILQ_INIT(behead);

	while (!feof(stream)) {
		fread(type, 1, 1, stream);
		switch(type[0]) {
		case 'd':
			break;
		case 'l':
			tmp = malloc(sizeof(struct beelem));
			tmp->type = BENCODING_LIST;
			tmp->list = bencoding_parselist(stream);
			break;
		case 'i':
			tmp = bencoding_parseinteger(stream);
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
			tmp = bencoding_parsestring(stream, atoi(type));
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
