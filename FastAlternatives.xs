/* -*- c -*- */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Support older versions of perl. */
#ifndef Newxz
#define Newxz(ptr, n, type) Newz(704, ptr, n, type)
#endif

struct trie_node;

struct map_entry {
    unsigned int codepoint;
    struct trie_node *next;
};

struct trie_node {
    unsigned final   : 1;
    unsigned entries : 31;
    struct map_entry *map;      /* pointer to variable-length array */
};

#define NTH_ENTRY(node, n) ((node)->map[n])

typedef struct trie_node *Text__Match__FastAlternatives;

static struct trie_node *
find_next_node(const struct trie_node *node, unsigned int c) {
    unsigned lo = 0;
    unsigned hi = node->entries; /* hi < 2**31 (because of entries bitfield) */
    while (lo < hi) {
        /* hi < 2**31 && lo < hi, so lo+hi cannot overflow */
        unsigned mid = (lo + hi) >> 1;
        if (NTH_ENTRY(node, mid).codepoint < c)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < node->entries && NTH_ENTRY(node, lo).codepoint == c)
        return NTH_ENTRY(node, lo).next;
    else
        return 0;
}

static void
trie_dump(const char *prev, I32 prev_len, struct trie_node *node) {
    unsigned int i;
    printf("[%s]: %u\n", prev, node->entries);
    char *state;
    Newxz(state, prev_len + 7, char);
    strcpy(state, prev);
    for (i = 0;  i < node->entries;  i++) {
        int n = sprintf(state + prev_len, "%lc", NTH_ENTRY(node, i).codepoint);
        trie_dump(state, prev_len + n, NTH_ENTRY(node, i).next);
    }
    Safefree(state);
}

static int
compare_map_entries(const void *a, const void *b) {
    const struct map_entry *entry_a = a;
    const struct map_entry *entry_b = b;
    int codepoint_a = (int) entry_a->codepoint;
    int codepoint_b = (int) entry_b->codepoint;
    return codepoint_a - codepoint_b;
}

/* Ensure NODE has a next node with codepoint C; return it */
static struct trie_node *
add_next_node(struct trie_node *node, unsigned int c) {
    struct trie_node *next = find_next_node(node, c);
    if (next)
        return next;

    /* Create the new NEXT */
    Newxz(next, 1, struct trie_node);

    /* Hook it into NODE */
    Renew(node->map, node->entries + 1, struct map_entry);
    NTH_ENTRY(node, node->entries).next = next;
    NTH_ENTRY(node, node->entries).codepoint = c;
    node->entries++;
    /* XXX: this is asymptotically slow */
    qsort(node->map, node->entries, sizeof NTH_ENTRY(node, 0), compare_map_entries);

    return next;
}

static void
free_trie(struct trie_node *node) {
    unsigned int i;
    for (i = 0;  i < node->entries;  i++)
        free_trie(NTH_ENTRY(node, i).next);
    if (node->map)
        Safefree(node->map);
    Safefree(node);
}

static STRLEN
utf8_char_len(const char *input) {
    const unsigned char *s = input;
    return s[0] < 0x80 ? 1
         : s[0] < 0xE0 ? 2
         : s[0] < 0xF0 ? 3
         : s[0] < 0xF8 ? 4
         : s[0] < 0xFc ? 5
         :               6;
}

static int
extract_utf8(const char *input, STRLEN *bytes) {
    const unsigned char *s = input;
    if (s[0] < 0x80) {
        *bytes = 1;
        return s[0];
    }
    else if (s[0] < 0xE0) {
        *bytes = 2;
        return ((s[0] & 0x1F) << 6) | (s[1] & 0x3F);
    }
    else if (s[0] < 0xF0) {
        *bytes = 3;
        return ((s[0] & 0x0F) << 12)
             | ((s[1] & 0x3F) << 6)
             | ((s[2] & 0x3F));
    }
    else if (s[0] < 0xF8) {
        *bytes = 4;
        return ((s[0] & 0x07) << 18)
             | ((s[1] & 0x3F) << 12)
             | ((s[2] & 0x3F) <<  6)
             | ((s[3] & 0x3F));
    }
    else if (s[0] < 0xFC) {
        *bytes = 5;
        return ((s[0] & 0x03) << 24)
             | ((s[1] & 0x3F) << 18)
             | ((s[2] & 0x3F) << 12)
             | ((s[3] & 0x3F) <<  6)
             | ((s[4] & 0x3F));
    }
    else {
        *bytes = 6;
        return ((s[0] & 0x01) << 30)
             | ((s[1] & 0x3F) << 24)
             | ((s[2] & 0x3F) << 18)
             | ((s[3] & 0x3F) << 12)
             | ((s[4] & 0x3F) <<  6)
             | ((s[5] & 0x3F));
    }
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

        c = extract_utf8(s, &char_length);

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

        c = extract_utf8(s, &char_length);

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

            while (len > 0) {
                unsigned c = utf8_to_uvuni(s, &char_length);
                node = add_next_node(node, c);
                s += char_length;
                len -= char_length;
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
        STRLEN char_len = -1;
        char *target;
    INIT:
        if (!SvOK(targetsv))
            croak("Target is not a defined scalar");
    CODE:
        target = SvPVutf8(targetsv, target_len);
        for (;;) {
            if (trie_match(trie, target, target_len))
                XSRETURN_YES;
            if (target_len == 0)
                XSRETURN_NO;
            char_len = utf8_char_len(target);
            target += char_len;
            target_len -= char_len;
        }

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
        target = SvPVutf8(targetsv, target_len);
        if (trie_match_exact(trie, target, target_len))
            XSRETURN_YES;
        XSRETURN_NO;

void
dump(trie)
    Text::Match::FastAlternatives trie
    CODE:
        trie_dump("", 0, trie);
