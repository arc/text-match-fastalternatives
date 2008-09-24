/* -*- c -*- */

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
    struct node *next[1];       /* really a variable-length array */
};

struct trie {
    struct node *root;
    int has_unicode;
};

#define BIGNODE_MAX 256
struct bignode;
struct bignode {
    unsigned final;
    struct bignode *next[BIGNODE_MAX]; /* one for every possible byte */
};

typedef struct trie *Text__Match__FastAlternatives;

#define DEF_FREE(type, free_trie, limit)        \
    static void                                 \
    free_trie(type *node) {                     \
        unsigned int i;                         \
        for (i = 0;  i < limit;  i++)           \
            if (node->next[i])                  \
                free_trie(node->next[i]);       \
        Safefree(node);                         \
    }

DEF_FREE(struct    node, free_trie, node->size)
DEF_FREE(struct bignode, free_bigtrie, BIGNODE_MAX)

#define DEF_MATCH(trie_match, return_when_done)                         \
    static int                                                          \
    trie_match(const struct node *node, const U8 *s, STRLEN len) {      \
        unsigned char c, offset;                                        \
                                                                        \
        for (;;) {                                                      \
            return_when_done;                                           \
            c = *s;                                                     \
            offset = c - node->min;                                     \
            if (offset > c || offset >= node->size)                     \
                return 0;                                               \
            node = node->next[offset];                                  \
            if (!node)                                                  \
                return 0;                                               \
            s++;                                                        \
            len--;                                                      \
        }                                                               \
    }

DEF_MATCH(trie_match,
          if (node->final)
              return 1;
          if (len == 0)
              return 0)

DEF_MATCH(trie_match_exact,
          if (len == 0)
              return node->final)

static struct node *
shrink_bigtrie(const struct bignode *big) {
    int min = -1, max = -1, size;
    unsigned int i;
    struct node *node;
    void *vnode;

    for (i = 0;  i < BIGNODE_MAX;  i++) {
        if (!big->next[i])
            continue;
        if (min < 0 || i < min)
            min = i;
        if (max < 0 || i > max)
            max = i;
    }

    if (min == -1) {
        min = 0;
        max = 0;
    }

    size = max - min + 1;
    Newxz(vnode, sizeof(struct node) + (size-1) * sizeof(struct node *), char);
    node = vnode;

    node->final = big->final;
    node->min = min;
    node->size = size;

    for (i = min;  i < BIGNODE_MAX;  i++)
        if (big->next[i])
            node->next[i - min] = shrink_bigtrie(big->next[i]);

    return node;
}

static int
trie_has_unicode(const struct node *node) {
    unsigned int i;
    if (node->min + node->size > 0x7F)
        return 1;
    for (i = 0;  i < node->size;  i++)
        if (node->next[i] && trie_has_unicode(node->next[i]))
            return 1;
    return 0;
}

static void
trie_dump(const char *prev, I32 prev_len, const struct node *node) {
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
            trie_dump(state, prev_len + n, node->next[i]);
        }
    Safefree(state);
}

static int get_byte_offset(SV *sv, int pos) {
    STRLEN len;
    char *s;
    unsigned char *p;
    if (!SvUTF8(sv))
        return pos;
    s = SvPV(sv, len);
    for (p = s;  pos > 0;  pos--) {
        /* Skip the sole byte (ASCII char) or leading byte (top >=2 bits set) */
        p++;
        /* Skip any continuation bytes (top bit set but not next bit) */
        while ((*p & 0xC0u) == 0x80u)
            p++;
    }
    return p - (unsigned char *) s;
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
    trie->has_unicode ? SvPVutf8(sv, len) : SvPV(sv, len)

MODULE = Text::Match::FastAlternatives      PACKAGE = Text::Match::FastAlternatives

PROTOTYPES: DISABLE

Text::Match::FastAlternatives
new(package, ...)
    char *package
    PREINIT:
        struct bignode *root;
        struct trie *trie;
        I32 i;
    CODE:
        for (i = 1;  i < items;  i++) {
            SV *sv = ST(i);
            if (!SvOK(sv))
                croak("Undefined element in %s->new", package);
        }
        Newxz(root, 1, struct bignode);
        for (i = 1;  i < items;  i++) {
            STRLEN pos, len;
            SV *sv = ST(i);
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
        Newxz(trie, 1, struct trie);
        trie->root = shrink_bigtrie(root);
        trie->has_unicode = trie_has_unicode(trie->root);
        free_bigtrie(root);
        RETVAL = trie;
    OUTPUT:
        RETVAL

void
DESTROY(trie)
    Text::Match::FastAlternatives trie
    CODE:
        free_trie(trie->root);
        Safefree(trie);

int
match(trie, targetsv)
    Text::Match::FastAlternatives trie
    SV *targetsv
    PREINIT:
        STRLEN target_len;
        char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = GET_TARGET(trie, targetsv, target_len);
        do {
            if (trie_match(trie->root, target, target_len))
                XSRETURN_YES;
            target++;
        } while (target_len-- > 0);
        XSRETURN_NO;

int
match_at(trie, targetsv, pos)
    Text::Match::FastAlternatives trie
    SV *targetsv
    int pos
    PREINIT:
        STRLEN target_len;
        char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = GET_TARGET(trie, targetsv, target_len);
        pos = get_byte_offset(targetsv, pos);
        if (pos <= target_len) {
            target_len -= pos;
            target += pos;
            if (trie_match(trie->root, target, target_len))
                XSRETURN_YES;
        }
        XSRETURN_NO;

int
exact_match(trie, targetsv)
    Text::Match::FastAlternatives trie
    SV *targetsv
    PREINIT:
        STRLEN target_len;
        char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = GET_TARGET(trie, targetsv, target_len);
        if (trie_match_exact(trie->root, target, target_len))
            XSRETURN_YES;
        XSRETURN_NO;

void
dump(trie)
    Text::Match::FastAlternatives trie
    CODE:
        trie_dump("", 0, trie->root);
