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
    U16 bits;
    U16 has_unicode;
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
    /* Ensure every allocation is on an even boundary, thus freeing up the
     * low-order bit of a pseudo-pointer for other purposes, even when each
     * pseudo-pointer is only 8 bits */
    if ((n & 1u))
        n++;
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

#define BITS 16
#define LIM  0xfffeu
#include "trie.c"

#define BITS 8
#define LIM  0xfeu
#include "trie.c"

#define NM_(x, y) x ## _ ## y
#define NM(name, bits) NM_(name, bits)
#define CALL(trie, name, arglist) \
    ( ((trie)->bits ==  8 ? (NM(name,  8)arglist) \
    : ((trie)->bits == 16 ? (NM(name, 16)arglist) \
    :                       (NM(name, 32)arglist))))

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

static int utf8_valid(const U8 *s, STRLEN len) {
    static const U8 width[] = { /* start at 0xC2 */
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,     /* 0xC2 .. 0xCF; two bytes */
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, /* 0xD0 .. 0xDF; two bytes */
        3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3, /* 0xE0 .. 0xEF; three bytes */
        4,4,4,4,4,0,0,0,0,0,0,0,0,0,0,0, /* 0xF0 .. 0xF4; four bytes */
    };
    static const U8 mask[] = {  /* data bitmask for leading byte of N-byte unit */
        0u, 0u, 0x1Fu, 0x0Fu, 7u,
    };
    static const U32 min[] = {  /* lowest permissible value for an N-byte unit */
        0u, 0u, 0x80u, 0x800u, 0x10000u,
    };
    const U8 *p = s, *end = s + len;
    while (p < end) {
        if (*p < 0x80u)
            p++;                /* plain ASCII */
        else if (*p < 0xC2u)
            return 0;           /* 0x80 .. 0xC1 are impossible leading bytes */
        else {
            U8 w = width[*p - 0xC2u], i;
            U32 c;
            if (w == 0)
                return 0;       /* invalid leading byte */
            else if (end - p < w)
                return 0;       /* string too short for continuation bytes */
            c = *p & mask[w];
            for (i = 1;  i < w;  i++)
                if ((p[i] & 0xC0u) != 0x80u)
                    return 0;   /* continuation byte not in range */
                else
                    c = (c << 6u) | (p[i] & 0x3Fu);
            if (c < min[w])
                return 0;       /* sequence overlong */
            if (c >= 0xD800u && c < 0xE000u)
                return 0;       /* UTF-16 surrogate */
            p += w;
        }
    }

    return 1;
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
new_instance(package, keywords)
    char *package
    AV *keywords
    PREINIT:
        struct trie *trie;
        struct bignode *root;
        STRLEN maxlen = 0;
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
            if (len > maxlen)
                maxlen = len;
            for (pos = 0;  pos < len;  pos++) {
                unsigned char c = s[pos];
                if (!node->next[c])
                    Newxz(node->next[c], 1, struct bignode);
                node = node->next[c];
            }
            node->final = 1;
        }
        trie = shrink_bigtrie_8(root, maxlen);
        if (!trie)
            trie = shrink_bigtrie_16(root, maxlen);
        if (!trie)
            trie = shrink_bigtrie_32(root, maxlen);
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
        if (CALL(trie, trie_match,(trie, target, target_len)))
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
            if (CALL(trie, trie_match_anchored,(trie, target, target_len)))
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
        if (CALL(trie, trie_match_exact,(trie, target, target_len)))
            XSRETURN_YES;
        XSRETURN_NO;

int
pointer_length(trie)
    Text::Match::FastAlternatives trie
    CODE:
        /* This is not part of the public API; it merely exposes an
         * implementation detail for testing */
        RETVAL = trie->bits;
    OUTPUT:
        RETVAL

void
dump(trie)
    Text::Match::FastAlternatives trie
    CODE:
        CALL(trie, trie_dump,("", 0, trie, 0));

int
utf8_valid(package, sv)
    char *package
    SV *sv
    PREINIT:
        STRLEN len;
        char *s;
    CODE:
        /* This is not part of the public API; it merely exposes an
         * implementation detail for testing */
        s = SvPV(sv, len);
        RETVAL = utf8_valid(s, len);
    OUTPUT:
        RETVAL
