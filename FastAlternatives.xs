/* -*- c -*- */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Support older versions of perl. */
#ifndef Newxz
#define Newxz(ptr, n, type) Newz(704, ptr, n, type)
#endif

#define MAX_NODES 95

struct trie_node;

struct map_entry {
    unsigned int codepoint;
    struct trie_node *next;
};

struct trie_node {
    unsigned final   : 1;
    unsigned entries : 31;
    struct map_entry map[1]; /* actually a variable-length array */
};

typedef struct trie_node *Text__Match__FastAlternatives;

static struct trie_node *
find_next_node(const struct trie_node *node, unsigned int c) {
    unsigned lo = 0;
    unsigned hi = node->entries; /* hi < 2**31 (because of entries bitfield) */
    while (lo < hi) {
        /* hi < 2**31 && lo < hi, so lo+hi cannot overflow */
        unsigned mid = (lo + hi) >> 1;
        if (node->map[mid].codepoint < c)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < node->entries && node->map[lo].codepoint == c)
        return node->map[lo].next;
    else
        return 0;
}

static int
compare_map_entries(const void *a, const void *b) {
    const struct map_entry *entry_a = a;
    const struct map_entry *entry_b = b;
    int codepoint_a = (int) entry_a->codepoint;
    int codepoint_b = (int) entry_b->codepoint;
    return codepoint_b - codepoint_a;
}

/* Add a link from NODE with codepoint C to NEXT; return replacement NODE */
static struct trie_node *
add_next_node(struct trie_node *node, unsigned int c, struct trie_node *next) {
    int new_size = sizeof(struct trie_node)
        + node->entries * sizeof(struct map_entry);
    Renewc(node, new_size, char, struct trie_node);
    node->map[ node->entries ].next = 0;
    node->map[ node->entries ].codepoint = c;
    node->entries++;
    /* XXX: this is asymptotically slow */
    qsort(node->map, node->entries, sizeof node->map[0], compare_map_entries);
}

static void
free_trie(struct trie_node *node) {
    unsigned int i;
    for (i = 0;  i < node->entries;  i++)
        free_trie(node->map[i].next);
    Safefree(node);
}

static int
trie_match(struct trie_node *node, U8 *s, STRLEN len) {
    UV c;
    STRLEN char_length = -1;

    for (;;) {
        if (node->final)
            return 1;
        if (len == 0)
            return 0;

        c = utf8_to_uvuni(s, &char_length);
        if (char_length == -1)
            croak("Invalid UTF-8");

        node = find_next_node(node, c);
        if (!node)
            return 0;

        s += char_length;
        len -= char_length;
    }
}

static int
trie_match_exact(struct trie_node *node, U8 *s, STRLEN len) {
    UV c;
    STRLEN char_length = -1;

    for (;;) {
        if (len == 0)
            return node->final;

        c = utf8_to_uvuni(s, &char_length);
        if (char_length == -1)
            croak("Invalid UTF-8");

        node = find_next_node(node, c);
        if (!node)
            return 0;

        s += char_length;
        len -= char_length;
    }
}

MODULE = Text::Match::FastAlternatives      PACKAGE = Text::Match::FastAlternatives

PROTOTYPES: DISABLE

Text::Match::FastAlternatives
new(package, ...)
    char *package
    PREINIT:
        struct trie_node *root;
        I32 i;
    CODE:
        for (i = 1;  i < items;  i++) {
            STRLEN len;
            STRLEN char_length = -1;
            SV *sv = ST(i);
            char *s;
            if (!SvOK(sv))
                croak("Undefined element in Text::Match::FastAlternatives->new");
            s = SvPVutf8(sv, len);
            while (len > 0) {
                unsigned c = utf8_to_uvuni(s, &char_length);
                if (char_length == -1)
                    croak("Invalid UTF-8 in Text::Match::FastAlternatives string");
                s += char_length;
                len -= char_length;
            }
        }
        Newxz(root, 1, struct trie_node);
        for (i = 1;  i < items;  i++) {
            STRLEN len;
            STRLEN char_length = -1;
            SV *sv = ST(i);
            char *s = SvPVutf8(sv, len);
            struct trie_node *node = root;

            for (;;) {
                unsigned c = utf8_to_uvuni(s, &char_length);
                /* XXX: add it here */


            for (pos = 0;  pos < len;  pos++) {
                unsigned char c = s[pos] - 32;
                if (!node->next[c])
                    Newxz(node->next[c], 1, struct trie_node);
                node = node->next[c];
            }
            node->final = 1;
        }
    RETVAL = root;
    OUTPUT:
    RETVAL

void
DESTROY(trie)
    Text::Match::FastAlternatives trie
    CODE:
        free_trie(trie);

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
        target = SvPV(targetsv, target_len);
        do {
            if (trie_match(trie, target, target_len))
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
        target = SvPV(targetsv, target_len);
        if (pos <= target_len) {
            target_len -= pos;
            target += pos;
            if (trie_match(trie, target, target_len))
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
        target = SvPV(targetsv, target_len);
        if (trie_match_exact(trie, target, target_len))
            XSRETURN_YES;
        XSRETURN_NO;
