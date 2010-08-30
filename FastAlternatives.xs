/* -*- c -*- */

#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Support older versions of perl. */
#ifndef Newxz
#define Newxz(ptr, n, type) Newz(704, ptr, n, type)
#endif

struct node;
struct node {
    unsigned short size;        /* total "next" pointers (incl static one) */
    unsigned char min;          /* codepoint of next[0] */
    unsigned char final;
    U32 fail;
    U32 next[1];                /* really a variable-length array */
};

struct trie {
    U32 has_unicode;
};

#define NODE(trie, offset) ((struct node *) ((offset) ? (((U8 *)(trie)) + (offset)) : 0))
#define ROOTNODE(trie)     NODE(trie, sizeof *trie)

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

static void *pool_alloc(struct pool *pool, U32 n) {
    unsigned char *region = pool->curr;
    pool->curr = region + n;
    return region;
}

static U32 pool_offset(const struct pool *pool, void *obj) {
    return ((U8 *)obj) - ((U8 *)pool->buf);
}

static void
free_bigtrie(struct bignode *node) {
    unsigned int i;
    for (i = 0;  i < BIGNODE_MAX;  i++)
        if (node->next[i])
            free_bigtrie(node->next[i]);
    Safefree(node);
}

#define ADVANCE_OR(NextStartChar)           \
    c = *s;                                 \
    offset = c - node->min;                 \
    if (offset > c || offset >= node->size) \
        NextStartChar;                      \
    node = NODE(trie, node->next[offset]);  \
    if (!node)                              \
        NextStartChar;                      \
    s++;                                    \
    len--;

/* "Does any part of TARGET contain any matching substring?" */
static int
trie_match(const struct trie *trie, const U8 *s, STRLEN len) {
    unsigned char c;
    const struct node *root = ROOTNODE(trie);
    const struct node *next, *node = root;

    for (;;) {
        if (node->final)
            return 1;
        if (len == 0)
            return 0;

        c = *s;

        for (;;) {
            next = c < node->min || c - node->min >= node->size ? 0
                 :           NODE(trie, node->next[c - node->min]);
            if (next || !node->fail)
                break;
            node = NODE(trie, node->fail);
        }

        node = next ? next : root;
        s++;
        len--;
    }
}

/* "Does TARGET begin with any matching substring?" */
static int
trie_match_anchored(const struct trie *trie, const U8 *s, STRLEN len) {
    unsigned char c, offset;
    const struct node *node = ROOTNODE(trie);

    for (;;) {
        if (node->final)
            return 1;
        if (len == 0)
            return 0;
        ADVANCE_OR(return 0);
    }
}

/* "Is TARGET exactly equal to any matching substring?" */
static int
trie_match_exact(const struct trie *trie, const U8 *s, STRLEN len) {
    unsigned char c, offset;
    const struct node *node = ROOTNODE(trie);

    for (;;) {
        if (len == 0)
            return node->final;
        ADVANCE_OR(return 0);
    }
}

static struct node *
trie_find_sv(pTHX_ struct trie *trie, SV *sv) {
    unsigned char c, offset;
    const U8 *s;
    STRLEN len;
    struct node *node = ROOTNODE(trie);

    s = (const U8 *) SvPVutf8(sv, len);

    for (;;) {
        if (len == 0)
            return node;
        ADVANCE_OR(croak("BUG: can't find node"));
    }
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

static size_t trie_alloc_size(const struct bignode *node) {
    unsigned char min;
    unsigned short size;
    int i;
    size_t n = sizeof(struct node);

    bignode_dimensions(node, &min, &size);

    /* -1 is because of the statically-allocated member */
    n += (size - 1) * sizeof(U32);

    for (i = 0;  i < BIGNODE_MAX;  i++)
        if (node->next[i])
            n += trie_alloc_size(node->next[i]);

    return n;
}

static struct node *
shrink_bignode(const struct bignode *big, struct pool *pool) {
    struct node *node;
    unsigned char min;
    unsigned short size;
    int i;

    bignode_dimensions(big, &min, &size);

    node = pool_alloc(pool, sizeof(struct node) + (size-1) * sizeof(U32));

    node->final = big->final;
    node->min = min;
    node->size = size;

    for (i = min;  i < BIGNODE_MAX;  i++)
        if (big->next[i])
            node->next[i - min] = pool_offset(pool, shrink_bignode(big->next[i], pool));

    return node;
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

static void add_fallback_fail_pointers(struct trie *trie, const struct pool *pool, struct node *node) {
    unsigned int i;
    if (!node->fail)
        node->fail = pool_offset(pool, ROOTNODE(trie));
    for (i = 0;  i < node->size;  i++)
        if (node->next[i])
            add_fallback_fail_pointers(trie, pool, NODE(trie, node->next[i]));
}

static void add_fail_pointers(pTHX_ struct trie *trie, const struct pool *pool, AV *onfail) {
    I32 i;
    I32 n = av_len(onfail);
    struct node *root = ROOTNODE(trie);

    if (!(n % 2))
        croak("Invalid onfail list");

    for (i = 0;  i <= n;  i += 2) {
        SV **key = av_fetch(onfail, i,   0);
        SV **val = av_fetch(onfail, i+1, 0);
        struct node *key_node, *val_node;
        if (!key || !SvOK(*key) || !val || !SvOK(*val))
            croak("Undefined element in onfail list");
        key_node = trie_find_sv(aTHX_ trie, *key);
        val_node = trie_find_sv(aTHX_ trie, *val);
        key_node->fail = pool_offset(pool, val_node);
    }

    for (i = 0;  i < root->size;  i++)
        if (root->next[i])
            add_fallback_fail_pointers(trie, pool, NODE(trie, root->next[i]));
}

static struct trie *shrink_bigtrie(pTHX_ const struct bignode *bigroot, AV *onfail) {
    size_t alloc = trie_alloc_size(bigroot) + sizeof(struct trie);
    struct pool pool;
    struct trie *trie;

    if (sizeof(U32) < sizeof(size_t) && alloc > 0xffffffffuL)
        return 0;

    /* Note that (a) the `struct trie` itself is allocated at the start of
     * the pool, and (b) the root is allocated immediately after that.
     * Property (a) guarantees that ((void *) pool->buf + 0) never points to
     * a node (so NODE() can safely treat zero as a null pointer).  Property
     * (b) makes ROOTNODE() easy to write, without having to store a
     * separate root-node offset. */

    pool = pool_create(alloc);
    trie = pool_alloc(&pool, sizeof *trie);
    shrink_bignode(bigroot, &pool);

    add_fail_pointers(aTHX_ trie, &pool, onfail);

    trie->has_unicode = bigtrie_has_unicode(bigroot);
    return trie;
}

static void
trie_dump(const char *prev, I32 prev_len, const struct trie *trie, const struct node *node) {
    unsigned int i;
    unsigned int entries = 0;
    char *state;
    for (i = 0;  i < node->size;  i++)
        if (node->next[i])
            entries++;
    /* XXX: This relies on the %lc printf format, which only works in C99,
     * so the corresponding method isn't documented at the moment. */
    printf("[%s]: min=%u[%lc] size=%u final=%u entries=%u\n", prev, node->min,
           node->min, node->size, node->final, entries);
    Newxz(state, prev_len + 3, char);
    strcpy(state, prev);
    for (i = 0;  i < node->size;  i++)
        if (node->next[i]) {
            int n = sprintf(state + prev_len, "%lc", i + node->min);
            trie_dump(state, prev_len + n, trie, NODE(trie, node->next[i]));
        }
    Safefree(state);
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
        trie = shrink_bigtrie(aTHX_ root, onfail);
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
        if (trie_match(trie, target, target_len))
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
            if (trie_match_anchored(trie, target, target_len))
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
        if (trie_match_exact(trie, target, target_len))
            XSRETURN_YES;
        XSRETURN_NO;

void
dump(trie)
    Text::Match::FastAlternatives trie
    CODE:
        trie_dump("", 0, trie, ROOTNODE(trie));
