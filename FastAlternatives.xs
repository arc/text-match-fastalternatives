/* -*- c -*- */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Support older versions of perl. */
#ifndef Newxz
#define Newxz(ptr, n, type) Newz(704, ptr, n, type)
#endif

#define MIN_NODES 256

struct node;
struct node {
    unsigned size  : 9;
    unsigned min   : 8;
    unsigned final : 1;
    struct node *next[MIN_NODES];
};

typedef struct node *Text__Match__FastAlternatives;

static void
free_trie(struct node *node) {
    unsigned int i;
    for (i = 0;  i < node->size;  i++)
        if (node->next[i])
            free_trie(node->next[i]);
    Safefree(node);
}

static int
trie_match(struct node *node, const U8 *s, STRLEN len) {
    unsigned char c;

    for (;;) {
        if (node->final)
            return 1;
        if (len == 0)
            return 0;
        c = *s;
        if (c < node->min)
            return 0;
        c -= node->min;
        if (c >= node->size)
            return 0;
        node = node->next[c];
        if (!node)
            return 0;
        s++;
        len--;
    }
}

static int
trie_match_exact(struct node *node, const U8 *s, STRLEN len) {
    unsigned char c;

    for (;;) {
        if (len == 0)
            return node->final;
        c = *s;
        if (c < node->min)
            return 0;
        c -= node->min;
        if (c >= node->size)
            return 0;
        node = node->next[c];
        if (!node)
            return 0;
        s++;
        len--;
    }
}

static void trie_dump(const char *prev, I32 prev_len, struct node *node) {
    unsigned int i;
    unsigned int entries = 0;
    char *state;
    for (i = 0;  i < node->size;  i++)
        if (node->next[i])
            entries++;
    printf("[%s]: min=%u size=%u final=%u entries=%u\n", prev, node->min,
           node->size, node->final, entries);
    Newxz(state, prev_len + 3, char);
    strcpy(state, prev);
    for (i = 0;  i < node->size;  i++)
        if (node->next[i]) {
            int n = sprintf(state + prev_len, "%lc", i + node->min);
            trie_dump(state, prev_len + n, node->next[i]);
        }
    Safefree(state);
}

MODULE = Text::Match::FastAlternatives      PACKAGE = Text::Match::FastAlternatives

PROTOTYPES: DISABLE

Text::Match::FastAlternatives
new(package, ...)
    char *package
    PREINIT:
        struct node *root;
        I32 i;
    CODE:
        for (i = 1;  i < items;  i++) {
            SV *sv = ST(i);
            if (!SvOK(sv))
                croak("Undefined element in Text::Match::FastAlternatives->new");
        }
        Newxz(root, 1, struct node);
        root->size = MIN_NODES;
        for (i = 1;  i < items;  i++) {
            STRLEN pos, len;
            SV *sv = ST(i);
            char *s = SvPVutf8(sv, len);
            struct node *node = root;
            for (pos = 0;  pos < len;  pos++) {
                unsigned char c = s[pos];
                if (!node->next[c]) {
                    Newxz(node->next[c], 1, struct node);
                    node->next[c]->min = 0;
                    node->next[c]->size = MIN_NODES;
                }
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
        target = SvPVutf8(targetsv, target_len);
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
        target = SvPVutf8(targetsv, target_len);
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

void
dump(trie)
    Text::Match::FastAlternatives trie
    CODE:
        trie_dump("", 0, trie);
