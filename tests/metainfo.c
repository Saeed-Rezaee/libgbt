#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "queue.h"
#include "libgbt.h"

#define INPUT "i123e8:announceli2e3:fooed5:monthi4e4:name5:april7:shadockl2:ga2:bu2:zo3:meuee"
//#include "bencoding.h"
//cc -g metainfo.c -o metainfo -L../ -I../

struct metainfo_single {
	int length; // length of file in bytes
	int piece_length; // size of every piece
	char *pieces; // concatenation of the sha1 of the pieces
	char *name; // name of the file
	char *md5sum; // OPTIONAL md5sum of the file
};

struct metainfo_multi_file {
	int length;
	char *path[2]; // [PATH, FILENAME]
	char *md5sum; // OPTIONAL
};

struct metainfo_multi {
	struct metainfo_multi_file *files;
	char *name; // name of the file
	int piece_length; // size of every piece
	char *pieces; // concatenation of the sha1 of the pieces
};

enum META_INFO_TYPE {METAINFO_SINGLE, METAINFO_MULTI};

union _metainfo_info {
	struct metainfo_single info_single;
	struct metainfo_multi info_multi;
};

struct metainfo_info {
	union _metainfo_info info;
	enum META_INFO_TYPE chosen;
};



struct bdata *
bencode_str(char *string)
{
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	tmp->type = 's';
	tmp->len = strlen(string);
	tmp->str = string;

	return tmp;
}

struct bdata *
bencode_int(int integer)
{
	struct bdata *tmp = NULL;

	tmp = malloc(sizeof(struct bdata));
	if (!tmp)
		return NULL;

	tmp->type = 'i';
	tmp->num = integer;

	return tmp;
}

// TODO: this is just a copy from the function taken in bencoding.c
// this needs to be redone
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
			//TODO: why?
			//free(list);
			sprintf(tmp, "e");
			break;
		}
		strcat(out, tmp);
	}
	return out;
}

int
bdict_push(struct blist *list, char *key, struct bdata *value)
{
	struct bdata *tmp = NULL;

	tmp = bencode_str(key);
	if (!tmp)
		return 0;

	TAILQ_INSERT_TAIL(list, tmp, entries);
	TAILQ_INSERT_TAIL(list, value, entries);

	return 1;
}

void
buildmetainfo_add_announce(char *announce, struct blist *list)
{
	struct bdata *tmp = bencode_str(announce);

	bdict_push(list, "announce", tmp);
}

void
buildmetainfo_add_info(struct metainfo_info info, struct blist *list)
{
	struct bdata *dict = NULL;
	struct bdata *tmp = NULL;
	struct bdata *tmp2 = NULL;

	// create the dictionary
	// TODO: make it easier to create such structure
	dict = malloc(sizeof(struct bdata));
	if (!dict)
		return;
	dict->type = 'd';
	dict->bl = malloc(sizeof(struct blist));
	if (!dict->bl) {
		return;
	}
	TAILQ_INIT(dict->bl);

	if (info.chosen == METAINFO_SINGLE) {
		tmp2 = bencode_int(info.info.info_single.length);
		bdict_push(dict->bl, "length", tmp2);
		tmp2 = bencode_int(info.info.info_single.piece_length);
		bdict_push(dict->bl, "piece_length", tmp2);
		tmp = bencode_str(info.info.info_single.pieces);
		bdict_push(dict->bl, "pieces", tmp);
		tmp = bencode_str(info.info.info_single.name);
		bdict_push(dict->bl, "name", tmp);
		if (info.info.info_single.md5sum != NULL) {
			bdict_push(dict->bl, "md5sum",
				bencode_str(info.info.info_single.md5sum));
		}
	} else {
	}

	puts("AGAIN");
	bdict_push(list, "info", dict);
}


char *
buildmetainfo(
	char *announce, // url of the tracker
	struct metainfo_info info, // the related info
	char *announce_list, // OPTIONAL backup tracker
	char *comment, // OPTIONAL
	char *created_by, // OPTIONAL
	int *creation_date) // OPTIONAL
{
	struct blist *behead = NULL;
	struct bdata *dict = NULL;

	behead = malloc(sizeof(struct blist));
	if (!behead)
		return NULL;

	dict = malloc(sizeof(struct bdata));
	if (!dict)
		return NULL;
	dict->type = 'd';
	dict->bl = malloc(sizeof(struct blist));
	if (!dict->bl) {
		free(dict);
		free(behead);
		return NULL;
	}

	TAILQ_INIT(dict->bl);
	TAILQ_INIT(behead);

	buildmetainfo_add_announce(announce, dict->bl);
	buildmetainfo_add_info(info, dict->bl);

	TAILQ_INSERT_TAIL(behead, dict, entries);

	return bencode(behead);
}

int
main(int argc, char **argv)
{
	struct metainfo_info info;
	info.chosen = METAINFO_SINGLE;
	info.info.info_single.length = 12;
	info.info.info_single.piece_length = 1024;
	info.info.info_single.pieces = "123123123123123123";
	info.info.info_single.name = "test.txt";
	info.info.info_single.md5sum = NULL;

	puts(buildmetainfo(
		"torrent://something", // url
		info, // info
		NULL, // backup
		NULL, // comment
		NULL, // author
		NULL // date
	));
	return 0;
}

