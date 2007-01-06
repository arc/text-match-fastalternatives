#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* An improvement would be to get the minimum match length of all the strings
 * being sought and verify that we have enough characters left in the target
 * string.  But in the context I'm using this, the minimum match length is 3,
 * so we'd only save two function calls per failed match. */

#define MAX_NODES 95

struct trie_node;
struct trie_node {
    int final;
    struct trie_node *next[MAX_NODES];
};

typedef struct trie_node *Text__Match__FastAlternatives;

static void free_trie(struct trie_node *node) {
    unsigned int i;
    for (i = 0;  i < MAX_NODES;  i++)
        if (node->next[i])
            free_trie(node->next[i]);
    Safefree(node);
}

static int trie_match(struct trie_node *node, const char *s, I32 len) {
    unsigned char c;
    struct trie_node *next;

    if (node->final)
        return 1;
    if (len == 0)
        return 0;
    c = *s;
    if (c < 32 || c >= 127)
        return 0;
    next = node->next[c - 32];
    return next ? trie_match(next, s + 1, len - 1) : 0;
}

MODULE = Text::Match::FastAlternatives      PACKAGE = Text::Match::FastAlternatives

PROTOTYPES: DISABLE

Text::Match::FastAlternatives
new(package, ...)
    char *package
    CODE:
        struct trie_node *root;
        I32 i;
        for (i = 1;  i < items;  i++) {
            SV *sv = ST(i);
            STRLEN pos, len;
            char *s;
            if (!SvOK(sv))
                croak("Undefined element in Text::Match::FastAlternatives->new");
            s = SvPV(sv, len);
            for (pos = 0;  pos < len;  pos++) {
                if (s[pos] >= 0 && (s[pos] < 32 || s[pos] == 127))
                    croak("Control character in Text::Match::FastAlternatives string");
                if (s[pos] < 32 || s[pos] >= 127)
                    croak("Non-ASCII character in Text::Match::FastAlternatives string");
            }
        }
        Newxz(root, 1, struct trie_node);
        for (i = 1;  i < items;  i++) {
            STRLEN pos, len;
            SV *sv = ST(i);
            char *s = SvPV(sv, len);
            struct trie_node *node = root;
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
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        STRLEN target_len;
        char *target;
        target = SvPV(targetsv, target_len);
        do {
            if (trie_match(trie, target, target_len))
                XSRETURN_YES;
            target++;
        } while (target_len-- > 0);
        XSRETURN_NO;
