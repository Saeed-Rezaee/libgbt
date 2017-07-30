#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "queue.h"
#include "libgbt.h"
#include "config.h"

/* BENCODING functions */
static struct beelem *
bencoding_parsestring(FILE *stream, int len)
{
	int r = 0;
	char *string;
	struct beelem *tmp = NULL;

	string = malloc(len + 1);
	if (!string)
		return NULL;

	while (r < len)
		r += fread(string+r, 1, len - r, stream);

	string[len] = 0;
	fprintf(stderr, "BENCODING: string:%s\n", string);

	tmp = malloc(sizeof(tmp));
	if (!tmp)
		return NULL;

	tmp->type = BENCODING_STRING;
	tmp->value = string;

	return tmp;
}

struct bedata *
bencoding_parse(FILE *stream)
{
	int r = 0;
	char type[32]; /* enough to hold an integer string value */
	struct beelem *tmp = NULL;
	TAILQ_HEAD(bedata, beelem) behead = TAILQ_HEAD_INITIALIZER(behead);

	while (fread(type, 1, 1, stream)) {
		switch(type[0]) {
		case 'd':
		case 'l':
		case 'i':
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
				fread(type + ++r, 1, 1, stream);
			tmp = bencoding_parsestring(stream, atoi(type));
			TAILQ_INSERT_TAIL(&behead, tmp, entries);
			fread(type, 1, 1, stream); /* reads last 'e' */
			break;
		default:
			fprintf(stderr, "BENCODING: %c: Unknown type\n", *type);
			while (*(type+r) != 'e')
				fread(type, 1, 1, stream);
		}
	}
	return NULL;
}
