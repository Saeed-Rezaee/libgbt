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
static struct bdata * bparsestr(FILE *, size_t);
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
	char *str = NULL;
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	/*
	 * Random size for the buffer. An integer should never be 32
	 * bytes long anyway
	 */
	str = malloc(32);
	if (!str)
		return NULL;

	/* Read all bytes until we encounter an 'e' */
	do {
                fread(str + (r++), 1, 1, stream);
	} while (r < 32 && str[r-1] != 'e');

	str[--r] = 0;
	tmp->type = 'i';
	tmp->num = atoi(str);
	free(str);

	return tmp;
}


/*
 * Reads a given number of bytes and store it in a STRING bencoding
 * data element.
 *
 * Returns a bencoding STRING data element that can be pushed in a list
 */
static struct bdata *
bparsestr(FILE *stream, size_t len)
{
	size_t r = 0;
	char *str = NULL;
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	str = malloc(len + 1);
	if (!str)
		return NULL;

	while (r < len)
		r += fread(str+r, 1, len - r, stream);

	str[len] = 0;

	tmp->len = len;
	tmp->type = 's';
	tmp->str = str;

	return tmp;
}


/*
 * Allocate memory for a LIST/DICTIONARY bdata element, and recurse
 * this sub-list with bencode().
 *
 * Returns a bencoding LIST/DICTIONARY data element that can be pushed in a list
 */
struct bdata *
bparselst(FILE *stream, int type)
{
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	tmp->type = type;
	tmp->bl = bdecode(stream);
	if (!tmp->bl) {
		free(tmp);
		return NULL;
	}

	return tmp;
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
		case 's':
			free(np->str);
			break;
		case 'l':
			bfree(np->bl);
			break;
		case 'i':
		case 'd':
			break;
		}
		TAILQ_REMOVE(head, np, entries);
		free(np);
	}
	free(head);
	return 0;
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
		if (fread(type, 1, 1, stream) < 1 && feof(stream))
			return behead;
		switch(type[0]) {
		case 'd': /* FALLTHROUGH */
		case 'l':
			tmp = bparselst(stream, type[0]);
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
 * Search a key within a bencoded data structure recursively.
 * each data element has to be a string, except for the very
 * first element which CAN be a dictionary.
 *
 * When we encounter a dictionary, the function will be called on this
 * dictionary so we can find nested keys.
 *
 * Because of this search algorithm, only the first occurence of each
 * key will be retrieved.
 * This should not be an issue as torrent files are not supposed to
 * appear twice, except for multifile torrent. For them, this function
 * can be called for each element of the "files" list.
 */
struct bdata *
bsearchkey(struct blist *dict, char *key)
{
	struct bdata *np;
	if (key == NULL) return NULL;
	TAILQ_FOREACH(np, dict, entries) {
		/* we only search dictionaries for string values */
		if (np->type != 'd' && np->type != 's')
			return NULL;

		if (np->type == 's') {
			if (!strcmp(np->str, key))
				return TAILQ_NEXT(np, entries);
			np = TAILQ_NEXT(np, entries);
		}
		if (np->type == 'd')
			return bsearchkey(np->bl, key);
	}
	return NULL;
}
