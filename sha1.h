/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

typedef struct {
    uint64_t length;
    uint32_t state[5], curlen;
    unsigned char buf[64];
} sha1_context;

int sha1_init(sha1_context * md);
int sha1_process(sha1_context * md, const unsigned char *in, unsigned long inlen);
int sha1_done(sha1_context * md, unsigned char *hash);
int sha1(const unsigned char *in, size_t len, unsigned char *hash);
