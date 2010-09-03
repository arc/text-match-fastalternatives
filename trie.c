#define PASTE1(x, y) x ## y
#define PASTE(x, y) PASTE1(x, y)
#define NM(tok) PASTE(tok, PASTE(_, BITS))

#define PTR   PASTE(U, BITS)

struct NM(node) {
#if BITS == 32
    U16 size;
    U8 min;
    U8 final;
    PTR fail;
#else
    U8 size;                    /* number of entries in node->next[] (incl static) */
    U8 min;                     /* codepoint of node->next[0] */
    PTR ff;                     /* fail pointer; low bit implies node->final */
#endif
    PTR next[1];                /* really a variable-length array */
};

#define NODE(trie, offset) ((struct NM(node) *) ((offset) ? (((U8 *)(trie)) + (offset)) : 0))
#define ROOTNODE(trie)     NODE(trie, sizeof *trie)

#if BITS == 32
#define NODE_FAIL(node)           ((node)->fail)
#define NODE_FINAL(node)          ((node)->final)
#define NODE_SET_FAIL(node, val)  ((node)->fail = (val))
#define NODE_SET_FINAL(node, val) ((node)->final = (val))
#else
#define NODE_FAIL(node)           ((node)->ff & ~1u)
#define NODE_FINAL(node)          ((node)->ff &  1u)
#define NODE_SET_FAIL(node, val)  ((node)->ff |= (val))
#define NODE_SET_FINAL(node, val) ((node)->ff  = (val) ? 1u : 0u)
#endif

#define for_each_edge(var, node)  for (var = 0; var < node->size; var++) if (node->next[var])

#define ADVANCE_OR(NextStartChar)                       \
    c = *s;                                             \
    offset = c - node->min;                             \
    if (offset > c || offset >= node->size)             \
        NextStartChar;                                  \
    node = NODE(trie, node->next[offset]);              \
    if (!node)                                          \
        NextStartChar;                                  \
    s++;                                                \
    len--;

/* "Does any part of TARGET contain any matching substring?" */
static int
NM(trie_match)(const struct trie *trie, const U8 *s, STRLEN len) {
    unsigned char c;
    const struct NM(node) *root = ROOTNODE(trie);
    const struct NM(node) *next, *node = root;

    for (;;) {
        if (NODE_FINAL(node))
            return 1;
        if (len == 0)
            return 0;

        c = *s;

        for (;;) {
            next = c < node->min || c - node->min >= node->size ? 0
                 :           NODE(trie, node->next[c - node->min]);
            if (next || !NODE_FAIL(node))
                break;
            node = NODE(trie, NODE_FAIL(node));
        }

        node = next ? next : root;
        s++;
        len--;
    }
}

/* "Does TARGET begin with any matching substring?" */
static int
NM(trie_match_anchored)(const struct trie *trie, const U8 *s, STRLEN len) {
    unsigned char c, offset;
    const struct NM(node) *node = ROOTNODE(trie);

    for (;;) {
        if (NODE_FINAL(node))
            return 1;
        if (len == 0)
            return 0;
        ADVANCE_OR(return 0);
    }
}

/* "Is TARGET exactly equal to any matching substring?" */
static int
NM(trie_match_exact)(const struct trie *trie, const U8 *s, STRLEN len) {
    unsigned char c, offset;
    const struct NM(node) *node = ROOTNODE(trie);

    for (;;) {
        if (len == 0)
            return NODE_FINAL(node);
        ADVANCE_OR(return 0);
    }
}

static size_t
NM(trie_alloc_size)(const struct bignode *node) {
    unsigned char min;
    unsigned short size;
    int i;
    size_t n = sizeof(struct NM(node));

    bignode_dimensions(node, &min, &size);

    /* -1 is because of the statically-allocated member */
    n += (size - 1) * sizeof(PTR);

    for (i = 0;  i < BIGNODE_MAX;  i++)
        if (node->next[i])
            n += NM(trie_alloc_size)(node->next[i]);

    return n;
}

static struct NM(node) *
NM(shrink_bignode)(const struct bignode *big, struct pool *pool) {
    struct NM(node) *node;
    unsigned char min;
    unsigned short size;
    int i;

    bignode_dimensions(big, &min, &size);

    node = pool_alloc(pool, sizeof(struct NM(node)) + (size-1) * sizeof(PTR));

    NODE_SET_FINAL(node, big->final);
    node->min  = min;
    node->size = size;

    for (i = min;  i < BIGNODE_MAX;  i++)
        if (big->next[i])
            node->next[i - min] = pool_offset(pool, NM(shrink_bignode)(big->next[i], pool));

    return node;
}

/* Finds the longest proper suffix of BUF (whose length is CUR) that
 * represents the label of a node in TRIE, and returns a pointer to that
 * node. */
static struct NM(node) *
NM(longest_suffix)(const struct trie *trie, const U8 *buf, STRLEN cur) {
    STRLEN i;
    for (i = 1;  i <= cur;  i++) {
        struct NM(node) *node = ROOTNODE(trie);
        const U8 *s = buf + i;
        STRLEN len = cur - i;
        U8 c, offset;
        for (;;) {
            ADVANCE_OR(break);
            if (len == 0)
                return node;
        }
    }
    return ROOTNODE(trie);
}

static void
NM(add_fail_pointers)(const struct trie *trie, const struct pool *pool,
                      struct NM(node) *node, U8 *buf, STRLEN cur) {
    unsigned i;

    if (node != ROOTNODE(trie)) {
        struct NM(node) *fail = NM(longest_suffix)(trie, buf, cur);
        NODE_SET_FAIL(node, pool_offset(pool, fail));
    }
    for_each_edge(i, node) {
        buf[cur] = i + node->min;
        NM(add_fail_pointers)(trie, pool, NODE(trie, node->next[i]), buf, cur+1);
    }
    buf[cur] = 0;
}

static struct trie *
NM(shrink_bigtrie)(const struct bignode *bigroot, STRLEN maxlen) {
    size_t alloc = NM(trie_alloc_size)(bigroot) + sizeof(struct trie);
    struct pool pool;
    struct trie *trie;
    U8 *buf;

    if (alloc > LIM)
        return 0;

    /* Note that (a) the `struct trie` itself is allocated at the start of
     * the pool, and (b) the root is allocated immediately after that.
     * Property (a) guarantees that ((void *) pool->buf + 0) never points to
     * a node (so NODE() can safely treat zero as a null pointer).  Property
     * (b) makes ROOTNODE() easy to write, without having to store a
     * separate root-node offset. */

    pool = pool_create(alloc);
    trie = pool_alloc(&pool, sizeof *trie);
    trie->bits = BITS;
    NM(shrink_bignode)(bigroot, &pool);

    Newxz(buf, maxlen + 1, U8);
    NM(add_fail_pointers)(trie, &pool, ROOTNODE(trie), buf, 0);
    Safefree(buf);

    trie->has_unicode = bigtrie_has_unicode(bigroot);
    return trie;
}

static void
NM(trie_dump)(const char *prev, I32 prev_len, const struct trie *trie, const struct NM(node) *node) {
    unsigned int i;
    unsigned int entries = 0;
    char *state;
    if (!node)
        node = ROOTNODE(trie);
    for_each_edge(i, node)
        entries++;
    /* XXX: This relies on the %lc printf format, which only works in C99,
     * so the corresponding method isn't documented at the moment. */
    printf("[%s]: min=0x%02X[%lc] size=%u final=%u entries=%u\n", prev, node->min,
           node->min, node->size, NODE_FINAL(node), entries);
    Newxz(state, prev_len + 3, char);
    strcpy(state, prev);
    for_each_edge(i, node) {
        int n = sprintf(state + prev_len, "%lc", i + node->min);
        NM(trie_dump)(state, prev_len + n, trie, NODE(trie, node->next[i]));
    }
    Safefree(state);
}


#undef BITS
#undef LIM

#undef NM
#undef PASTE
#undef PASTE1

#undef PTR
#undef NODE
#undef ROOTNODE
#undef NODE_FAIL
#undef NODE_FINAL
#undef NODE_SET_FAIL
#undef NODE_SET_FINAL
#undef for_each_edge
#undef ADVANCE_OR
