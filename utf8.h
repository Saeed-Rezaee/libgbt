size_t utflen(unsigned char *, int);
size_t runelen(long);

size_t utftorune(long *, unsigned char *, size_t);
size_t utftorunes(long *, unsigned char *, size_t);
size_t runetoutf(unsigned char *, long);

int runeisprint(long);
