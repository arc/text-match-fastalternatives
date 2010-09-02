/* -*- c -*- */

#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Support older versions of perl. */
#ifndef Newxz
#define Newxz(ptr, n, type) Newz(704, ptr, n, type)
#endif

struct trie {
    U32 has_unicode;
};

#define BIGNODE_MAX 256
struct bignode;
struct bignode {
    unsigned final;
    struct bignode *next[BIGNODE_MAX]; /* one for every possible byte */
};

typedef struct trie *Text__Match__FastAlternatives;

struct pool {
    void *buf;
    void *curr;
};

static struct pool pool_create(size_t n) {
    struct pool pool;
    Newxz(pool.buf, n, char);
    pool.curr = pool.buf;
    return pool;
}

static void *pool_alloc(struct pool *pool, size_t n) {
    unsigned char *region = pool->curr;
    pool->curr = region + n;
    return region;
}

static size_t pool_offset(const struct pool *pool, void *obj) {
    return ((U8 *)obj) - ((U8 *)pool->buf);
}

static void bignode_dimensions(const struct bignode *, unsigned char *, unsigned short *);
static int  bigtrie_has_unicode(const struct bignode *);

#define BITS 32
#define LIM  0xfffffffeuL
#include "trie.c"

static void
free_bigtrie(struct bignode *node) {
    unsigned int i;
    for (i = 0;  i < BIGNODE_MAX;  i++)
        if (node->next[i])
            free_bigtrie(node->next[i]);
    Safefree(node);
}

static void
bignode_dimensions(const struct bignode *node, unsigned char *pmin, unsigned short *psize) {
    int min = PERL_INT_MAX, max = 0, i;

    for (i = 0;  i < BIGNODE_MAX;  i++) {
        if (!node->next[i])
            continue;
        if (i < min)
            min = i;
        if (i > max)
            max = i;
    }

    if (min == PERL_INT_MAX)    /* empty node; force min=0, max=0 */
        min = 0;

    *pmin = min;
    *psize = max - min + 1;
}

static int
bigtrie_has_unicode(const struct bignode *node) {
    unsigned i;
    /* XXX: In principle, we ought to be able to do a non-recursive walk of
     * all the nodes in the buffer of a struct trie */
    for (i = 0x80u;  i < BIGNODE_MAX;  i++)
        if (node->next[i])
            return 1;
    for (i = 0u;  i < 0x80u;  i++)
        if (node->next[i] && bigtrie_has_unicode(node->next[i]))
            return 1;
    return 0;
}

static int get_byte_offset(pTHX_ SV *sv, int pos) {
    STRLEN len;
    const unsigned char *s, *p;
    if (!SvUTF8(sv))
        return pos;
    s = (const unsigned char *) SvPV(sv, len);
    for (p = s;  pos > 0;  pos--) {
        /* Skip the sole byte (ASCII char) or leading byte (top >=2 bits set) */
        p++;
        /* Skip any continuation bytes (top bit set but not next bit) */
        while ((*p & 0xC0u) == 0x80u)
            p++;
    }
    return p - s;
}

/* If the trie used Unicode, make sure that the target string uses the same
 * encoding.  But if the trie didn't use Unicode, it doesn't matter what
 * encoding the target uses for any supra-ASCII characters it contains,
 * because they'll never be found in the trie.
 *
 * A pleasing performance enhancement would be as follows: delay upgrading a
 * byte-encoded SV until such time as we're actually looking at a
 * supra-ASCII character; then upgrade the SV, and start again from the
 * current offset in the string.  (Since by definition there are't any
 * supra-ASCII characters before the current offset, it's guaranteed to be
 * safe to use the old characters==bytes-style offset as a byte-oriented one
 * for the upgraded SV.)  It seems a little tricky to arrange that sort of
 * switcheroo, though; the inner loop is in a function that knows nothing of
 * SVs or encodings. */
#define GET_TARGET(trie, sv, len) \
    ((unsigned char *) (trie->has_unicode ? SvPVutf8(sv, len) : SvPV(sv, len)))

MODULE = Text::Match::FastAlternatives      PACKAGE = Text::Match::FastAlternatives

PROTOTYPES: DISABLE

Text::Match::FastAlternatives
new_instance(package, keywords, onfail)
    char *package
    AV *keywords
    AV *onfail
    PREINIT:
        struct trie *trie;
        struct bignode *root;
        I32 i, n;
    CODE:
        n = av_len(keywords);
        for (i = 0;  i <= n;  i++) {
            SV **sv = av_fetch(keywords, i, 0);
            if (!sv || !SvOK(*sv))
                croak("Undefined element in %s->new", package);
        }
        Newxz(root, 1, struct bignode);
        for (i = 0;  i <= n;  i++) {
            STRLEN pos, len;
            SV *sv = *av_fetch(keywords, i, 0);
            char *s = SvPVutf8(sv, len);
            struct bignode *node = root;
            for (pos = 0;  pos < len;  pos++) {
                unsigned char c = s[pos];
                if (!node->next[c])
                    Newxz(node->next[c], 1, struct bignode);
                node = node->next[c];
            }
            node->final = 1;
        }
        trie = shrink_bigtrie_32(aTHX_ root, onfail);
        free_bigtrie(root);
        if (!trie)
            croak("Sorry, too much data for Text::Match::FastAlternatives");
        RETVAL = trie;
    OUTPUT:
        RETVAL

void
DESTROY(trie)
    Text::Match::FastAlternatives trie
    PREINIT:
        void *buf;
    CODE:
        buf = trie;
        Safefree(buf);

int
match(trie, targetsv)
    Text::Match::FastAlternatives trie
    SV *targetsv
    PREINIT:
        STRLEN target_len;
        const unsigned char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = GET_TARGET(trie, targetsv, target_len);
        if (trie_match_32(trie, target, target_len))
            XSRETURN_YES;
        XSRETURN_NO;

int
match_at(trie, targetsv, pos)
    Text::Match::FastAlternatives trie
    SV *targetsv
    int pos
    PREINIT:
        STRLEN target_len;
        const unsigned char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = GET_TARGET(trie, targetsv, target_len);
        pos = get_byte_offset(aTHX_ targetsv, pos);
        if (pos <= (int) target_len) {
            target_len -= pos;
            target += pos;
            if (trie_match_anchored_32(trie, target, target_len))
                XSRETURN_YES;
        }
        XSRETURN_NO;

int
exact_match(trie, targetsv)
    Text::Match::FastAlternatives trie
    SV *targetsv
    PREINIT:
        STRLEN target_len;
        const unsigned char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = GET_TARGET(trie, targetsv, target_len);
        if (trie_match_exact_32(trie, target, target_len))
            XSRETURN_YES;
        XSRETURN_NO;

void
dump(trie)
    Text::Match::FastAlternatives trie
    CODE:
        trie_dump_32("", 0, trie, 0);
