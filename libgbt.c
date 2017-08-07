#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"
#include "config.h"
#include "libgbt.h"


static struct bdata * bparseint(FILE *);
static struct bdata * bparsestr(FILE *, int);
static struct bdata * bparselst(FILE *, int);

/*
 * Reads bytes from a stream and extract an integer bencoded.
 * When calling the function, the first byte 'i' has already been
 * read, which means that we can expect only digits until the last 'e'
 *
 * Returns a bencoding INTEGER data element that can be pushed in a list
 */
static struct bdata *
bparseint(FILE *stream)
{
	int r = 0;
	char *string = NULL;
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	/*
	 * Random size for the buffer. An integer should never be 32
	 * bytes long anyway
	 */
	string = malloc(32);
	if (!string)
		return NULL;

	/* Read all bytes until we encounter an 'e' */
	do {
                fread(string + (r++), 1, 1, stream);
	} while (r < 32 && string[r-1] != 'e');

	string[--r] = 0;
	tmp->type = INTEGER;
	tmp->number = atoi(string);
	free(string);

	return tmp;
}


/*
 * Reads a given number of bytes and store it in a STRING bencoding
 * data element.
 *
 * Returns a bencoding STRING data element that can be pushed in a list
 */
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


struct bdata *
bparselst(FILE *stream, int type)
{
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	tmp->type = type;
	tmp->list = bdecode(stream);
	if (!tmp->list) {
		free(tmp);
		return NULL;
	}

	return tmp;
}

/*
 * Reads a LIST of bencoding data elements. Lists can be composed of
 * any bencoding type, including lists themselves (hence the recursive
 * call of this function.
 *
 * List are treated as a special type here, as they are TAILQs of other
 * data elements.
 *
 * Return a bencoding list that can be added into a LIST data element
 */
struct blist *
bdecode(FILE *stream)
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
		case 'd': /* FALLTHROUGH */
		case 'l':
			tmp = bparselst(stream, type[0] == 'l' ? LIST : DICTIONARY);
			if (!tmp) {
				free(behead);
				return NULL;
			}
			break;
		case 'i':
			tmp = bparseint(stream);
			if (!tmp) {
				free(behead);
				return NULL;
			}
			break;
		/*
		 * Any number denotes the presence of a string. We must
		 * then read all bytes up to the next ':' to know the length
		 * of the upcoming string.
		 */
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
			if (!tmp) {
				free(behead);
				return NULL;
			}
			break;
		/*
		 * An 'e' standing on its own means that we finished
		 * reading our sublist. In case of the main list, it
		 * will end up with an \n, or EOF, so we can safely return
		 * our list
		 */
		case  'e':
		case '\n':
			return behead;
			break; /* NOTREACHED */
		default:
			free(behead);
			return NULL;
		}
		TAILQ_INSERT_TAIL(behead, tmp, entries);
	}
	return behead;
}

/*
 * Loop through all data nodes of a list struct, and free everything
 * inside it, as well as list nodes themselves.
 * Every blist structure MUST be free'd with this function at some point.
 */
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
		case DICTIONARY:
			break;
		}
		TAILQ_REMOVE(head, np, entries);
		free(np);
	}
	free(head);
	return 0;
}


/*
 * Loop through all the keys in a dictionary and return the bencoding
 * element whose key match the given parameter.
 * Dictionaries are treated as lists, so key/values elements follow
 * each others. Keys are odd elements, values are even ones.
 */
struct bdata *
bsearchkey(struct blist *dict, char *key)
{
	struct bdata *np = NULL;
	TAILQ_FOREACH(np, dict, entries) {
		if (!strcmp(np->string, key))
			return TAILQ_NEXT(np, entries);
		np = TAILQ_NEXT(np, entries);
	}
	return NULL;
}
