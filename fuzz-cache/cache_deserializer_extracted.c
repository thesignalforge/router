/*
 * Router cache-deserializer fuzz target - extracted byte-parser.
 *
 * Why not fuzz the full sf_router_unserialize?
 * --------------------------------------------
 * The production deserializer (routing_trie.c:sf_router_unserialize) needs
 * to construct `sf_router` / `sf_trie_node` / `sf_route` objects, which
 * have pthread rwlocks, PCRE2 handles, PHP zend_objects, and backrefs to
 * Router class instances. Pulling that in means compiling the 3600-line
 * routing_trie.c plus extension bootstrap plus libsodium plus PCRE2.
 *
 * The bugs we actually want to catch in fuzzing are bit-level format
 * bugs: underflow in sf_buf_read_u16, TOCTOU between size checks and
 * reads, integer overflow in 'len + pos > buf.len', missing bounds on
 * uint16_t counts, etc. Those live in the byte-reader layer plus the
 * *structural* walker that branches on flag bytes.
 *
 * So we extract a MINIMAL deserializer that:
 *   - uses the same sf_buf_read_* helpers as production (verbatim copy)
 *   - walks the same flag-byte + recursion structure
 *   - allocates stripped-down structs into ASan-watched malloc arenas
 *   - skips constraint compilation (no PCRE2), route handlers (no zvals)
 *
 * This is a valid byte-level fuzz target. It will NOT catch bugs in,
 * e.g., how zval handlers are reconstructed from the handler_type byte.
 * That requires a libphp-embed harness - see fuzz-cache/README.md.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../../fuzz-support/php_stubs.h"

/* ===== Flag / node-type constants - copied from routing_trie.c ===== */

#define SF_FLAG_TERMINAL         0x01
#define SF_FLAG_HAS_STATIC       0x02
#define SF_FLAG_HAS_PARAM        0x04
#define SF_FLAG_HAS_OPTIONAL     0x08
#define SF_FLAG_HAS_WILDCARD     0x10
#define SF_FLAG_HAS_CONSTRAINT   0x20
#define SF_FLAG_HAS_SEGMENT      0x40
#define SF_FLAG_HAS_PARAM_NAME   0x80

#define SF_NODE_ROOT             4
#define SF_METHOD_COUNT          9
#define SF_MAX_MIDDLEWARE_COUNT  1024
#define SF_VALIDATOR_UUID        5
#define SF_MAX_DESERIALIZE_DEPTH 128
#define SF_MAX_CACHE_SIZE        (256 * 1024 * 1024)
#define SF_CACHE_MAGIC           "SFRC"
#define SF_CACHE_VERSION         1

/* ===== Minimal struct stand-ins =====
 *
 * Production trie nodes carry pthread rwlocks and PCRE2 handles. Fuzz
 * nodes hold just enough to own child pointers and freed-on-destroy
 * zend_strings, so UAF / double-free regressions bite. */

typedef struct sf_fuzz_route {
    zend_string *uri;
    zend_string *name;
    zend_string *domain;
    HashTable   *middleware;
    HashTable   *wheres;
    HashTable   *defaults;
    uint8_t      method;
    uint8_t      is_fallback;
} sf_fuzz_route;

typedef struct sf_fuzz_node {
    uint8_t              type;
    uint8_t              flags;
    zend_string         *segment;
    zend_string         *param_name;
    zend_string         *constraint_pattern;
    uint8_t              validator_type;
    sf_fuzz_route       *route;
    HashTable           *static_children;  /* key -> sf_fuzz_node* stored as IS_PTR */
    struct sf_fuzz_node *param_child;
    struct sf_fuzz_node *optional_child;
    struct sf_fuzz_node *wildcard_child;
} sf_fuzz_node;

/* ===== Byte-reader helpers - verbatim from routing_trie.c ===== */

typedef struct {
    const char *data;
    size_t      len;
    size_t      pos;
} sf_read_buffer;

static zend_bool sf_buf_read_u8(sf_read_buffer *buf, uint8_t *val)
{
    if (buf->pos + 1 > buf->len) return 0;
    *val = (uint8_t)buf->data[buf->pos++];
    return 1;
}

static zend_bool sf_buf_read_u16(sf_read_buffer *buf, uint16_t *val)
{
    if (buf->pos + 2 > buf->len) return 0;
    *val = ((uint8_t)buf->data[buf->pos] << 8) | (uint8_t)buf->data[buf->pos + 1];
    buf->pos += 2;
    return 1;
}

static zend_bool sf_buf_read_u32(sf_read_buffer *buf, uint32_t *val)
{
    if (buf->pos + 4 > buf->len) return 0;
    *val = ((uint8_t)buf->data[buf->pos] << 24) |
           ((uint8_t)buf->data[buf->pos + 1] << 16) |
           ((uint8_t)buf->data[buf->pos + 2] << 8) |
           (uint8_t)buf->data[buf->pos + 3];
    buf->pos += 4;
    return 1;
}

static zend_string *sf_buf_read_string(sf_read_buffer *buf)
{
    uint16_t len;
    if (!sf_buf_read_u16(buf, &len)) return NULL;
    if (len == 0) return NULL;
    if (buf->pos + len > buf->len) return NULL;
    zend_string *str = zend_string_init(buf->data + buf->pos, len, 0);
    buf->pos += len;
    return str;
}

/* ===== Destructors for our stripped-down structs ===== */

static void fuzz_route_destroy(sf_fuzz_route *r)
{
    if (!r) return;
    if (r->uri)      zend_string_release(r->uri);
    if (r->name)     zend_string_release(r->name);
    if (r->domain)   zend_string_release(r->domain);
    if (r->middleware) { zend_hash_destroy(r->middleware); free(r->middleware); }
    if (r->wheres)     { zend_hash_destroy(r->wheres);     free(r->wheres); }
    if (r->defaults)   { zend_hash_destroy(r->defaults);   free(r->defaults); }
    free(r);
}

static void fuzz_node_destroy_recursive(sf_fuzz_node *n);

static void fuzz_node_dtor_zval(zval *z)
{
    if (z && Z_TYPE_P(z) == IS_PTR) {
        fuzz_node_destroy_recursive((sf_fuzz_node *)Z_PTR_P(z));
    }
}

static void fuzz_node_destroy_recursive(sf_fuzz_node *n)
{
    if (!n) return;
    if (n->segment) zend_string_release(n->segment);
    if (n->param_name) zend_string_release(n->param_name);
    if (n->constraint_pattern) zend_string_release(n->constraint_pattern);
    if (n->route) fuzz_route_destroy(n->route);
    if (n->static_children) {
        /* zend_hash_destroy uses the installed dtor (fuzz_node_dtor_zval)
         * to free child nodes carried as IS_PTR zvals. */
        zend_hash_destroy(n->static_children);
        free(n->static_children);
    }
    fuzz_node_destroy_recursive(n->param_child);
    fuzz_node_destroy_recursive(n->optional_child);
    fuzz_node_destroy_recursive(n->wildcard_child);
    free(n);
}

/* ===== Deserializers - mirrors routing_trie.c structure ===== */

static sf_fuzz_route *fuzz_deserialize_route(sf_read_buffer *buf)
{
    sf_fuzz_route *r = (sf_fuzz_route *)calloc(1, sizeof(*r));
    r->uri = sf_buf_read_string(buf);
    r->name = sf_buf_read_string(buf);

    uint8_t handler_type;
    if (!sf_buf_read_u8(buf, &handler_type)) { fuzz_route_destroy(r); return NULL; }

    if (handler_type == 1) {
        zend_string *h = sf_buf_read_string(buf);
        if (h) zend_string_release(h);  /* in production this becomes a zval */
    } else if (handler_type == 2) {
        zend_string *cls = sf_buf_read_string(buf);
        zend_string *mtd = sf_buf_read_string(buf);
        if (cls) zend_string_release(cls);
        if (mtd) zend_string_release(mtd);
    }

    uint8_t method;
    if (!sf_buf_read_u8(buf, &method)) { fuzz_route_destroy(r); return NULL; }
    if (method >= SF_METHOD_COUNT) { fuzz_route_destroy(r); return NULL; }
    r->method = method;

    uint16_t mw_count;
    if (!sf_buf_read_u16(buf, &mw_count)) { fuzz_route_destroy(r); return NULL; }
    if (mw_count > SF_MAX_MIDDLEWARE_COUNT) { fuzz_route_destroy(r); return NULL; }
    for (uint16_t i = 0; i < mw_count; i++) {
        zend_string *nm = sf_buf_read_string(buf);
        if (nm) zend_string_release(nm);
    }

    uint16_t where_count;
    if (!sf_buf_read_u16(buf, &where_count)) { fuzz_route_destroy(r); return NULL; }
    for (uint16_t i = 0; i < where_count; i++) {
        zend_string *p = sf_buf_read_string(buf);
        zend_string *pt = sf_buf_read_string(buf);
        if (p)  zend_string_release(p);
        if (pt) zend_string_release(pt);
    }

    uint16_t default_count;
    if (!sf_buf_read_u16(buf, &default_count)) { fuzz_route_destroy(r); return NULL; }
    for (uint16_t i = 0; i < default_count; i++) {
        zend_string *k = sf_buf_read_string(buf);
        zend_string *v = sf_buf_read_string(buf);
        if (k) zend_string_release(k);
        if (v) zend_string_release(v);
    }

    r->domain = sf_buf_read_string(buf);

    uint8_t is_fb;
    if (!sf_buf_read_u8(buf, &is_fb)) { fuzz_route_destroy(r); return NULL; }
    r->is_fallback = is_fb ? 1 : 0;

    return r;
}

static sf_fuzz_node *fuzz_deserialize_node(sf_read_buffer *buf, int depth)
{
    if (depth > SF_MAX_DESERIALIZE_DEPTH) return NULL;

    uint8_t type;
    if (!sf_buf_read_u8(buf, &type)) return NULL;
    if (type == 0xFF) return NULL;       /* null marker */

    uint8_t flags;
    if (!sf_buf_read_u8(buf, &flags)) return NULL;

    if (type > SF_NODE_ROOT) return NULL;

    sf_fuzz_node *n = (sf_fuzz_node *)calloc(1, sizeof(*n));
    n->type  = type;
    n->flags = flags;

    if (flags & SF_FLAG_HAS_SEGMENT) {
        n->segment = sf_buf_read_string(buf);
    }
    if (flags & SF_FLAG_HAS_PARAM_NAME) {
        n->param_name = sf_buf_read_string(buf);
    }
    if (flags & SF_FLAG_HAS_CONSTRAINT) {
        n->constraint_pattern = sf_buf_read_string(buf);
        uint8_t vt = 0;
        sf_buf_read_u8(buf, &vt);
        if (vt > SF_VALIDATOR_UUID) vt = 0;  /* mirror production fallback */
        n->validator_type = vt;
    }
    if (flags & SF_FLAG_TERMINAL) {
        n->route = fuzz_deserialize_route(buf);
    }

    if (flags & SF_FLAG_HAS_STATIC) {
        uint16_t count;
        if (!sf_buf_read_u16(buf, &count)) {
            fuzz_node_destroy_recursive(n);
            return NULL;
        }
        n->static_children = (HashTable *)calloc(1, sizeof(HashTable));
        /* Install a destructor that free's IS_PTR children. This mirrors
         * the production HIGH-02 fix in routing_trie.c (sf_ht_trie_node_dtor).
         * Without a dtor, duplicate-key zend_hash_add failures leak the
         * orphaned child pointer. */
        zend_hash_init(n->static_children, count, NULL, fuzz_node_dtor_zval, 0);
        for (uint16_t i = 0; i < count; i++) {
            zend_string *key = sf_buf_read_string(buf);
            sf_fuzz_node *child = fuzz_deserialize_node(buf, depth + 1);
            if (key && child) {
                zval zv;
                ZVAL_PTR(&zv, child);
                zval *ok = zend_hash_add(n->static_children, key, &zv);
                if (!ok) {
                    /* Key already present - production code also fails to
                     * catch this and orphans `child`. We free here in the
                     * fuzz harness so libFuzzer keeps running; the
                     * production bug is noted in fuzz-cache/README. */
                    fuzz_node_destroy_recursive(child);
                }
                zend_string_release(key);
            } else {
                if (key) zend_string_release(key);
                if (child) fuzz_node_destroy_recursive(child);
                if (!child) {
                    fuzz_node_destroy_recursive(n);
                    return NULL;
                }
            }
        }
    }

    if (flags & SF_FLAG_HAS_PARAM) {
        n->param_child = fuzz_deserialize_node(buf, depth + 1);
    }
    if (flags & SF_FLAG_HAS_OPTIONAL) {
        n->optional_child = fuzz_deserialize_node(buf, depth + 1);
    }
    if (flags & SF_FLAG_HAS_WILDCARD) {
        n->wildcard_child = fuzz_deserialize_node(buf, depth + 1);
    }

    return n;
}

/* Public entry point mirroring sf_router_unserialize's outer shape.
 * Returns 0 on success, nonzero on rejection. (Both are non-crashing
 * outcomes; libFuzzer only flags crashes/ASan/UBSan violations.) */
int fuzz_router_unserialize(const char *data, size_t len)
{
    if (!data || len < 16) return 1;
    if (len > SF_MAX_CACHE_SIZE) return 1;

    sf_read_buffer buf = { data, len, 0 };

    if (memcmp(data, SF_CACHE_MAGIC, 4) != 0) return 1;
    buf.pos = 4;

    uint8_t version;
    if (!sf_buf_read_u8(&buf, &version) || version != SF_CACHE_VERSION) return 1;

    buf.pos = 16;

    sf_fuzz_node *tries[SF_METHOD_COUNT];
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        tries[i] = fuzz_deserialize_node(&buf, 0);
    }

    sf_fuzz_route *fallback = NULL;
    uint8_t has_fallback;
    if (sf_buf_read_u8(&buf, &has_fallback) && has_fallback) {
        fallback = fuzz_deserialize_route(&buf);
    }

    /* Cleanup */
    for (int i = 0; i < SF_METHOD_COUNT; i++) fuzz_node_destroy_recursive(tries[i]);
    fuzz_route_destroy(fallback);
    return 0;
}
