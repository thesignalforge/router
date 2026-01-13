/*
 * Signalforge Routing Extension
 * routing_trie.h - Radix trie data structures and function declarations
 *
 * Copyright (c) 2024 Signalforge
 * License: MIT
 */

#ifndef SIGNALFORGE_ROUTING_TRIE_H
#define SIGNALFORGE_ROUTING_TRIE_H

#include "php.h"
#include "zend_API.h"
#include "zend_smart_str.h"
#include <pcre2.h>

#ifdef ZTS
#ifndef _WIN32
#include <pthread.h>
#endif
#endif

/* ============================================================================
 * Cache Line Optimization
 *
 * Modern x86/x64 CPUs have 64-byte cache lines. By aligning frequently-accessed
 * structures to cache line boundaries and grouping hot fields together, we can
 * minimize cache misses during trie traversal.
 * ============================================================================ */

#define SF_CACHE_LINE_SIZE 64

/* Alignment attribute for cache-line aligned structures */
#ifdef __GNUC__
#define SF_CACHE_ALIGNED __attribute__((aligned(SF_CACHE_LINE_SIZE)))
#elif defined(_MSC_VER)
#define SF_CACHE_ALIGNED __declspec(align(SF_CACHE_LINE_SIZE))
#else
#define SF_CACHE_ALIGNED
#endif

/* Forward declarations */
typedef struct _sf_trie_node sf_trie_node;
typedef struct _sf_route sf_route;
typedef struct _sf_route_group sf_route_group;
typedef struct _sf_match_result sf_match_result;
typedef struct _sf_router sf_router;

/* HTTP method enumeration */
typedef enum {
    SF_METHOD_GET     = 0,
    SF_METHOD_POST    = 1,
    SF_METHOD_PUT     = 2,
    SF_METHOD_PATCH   = 3,
    SF_METHOD_DELETE  = 4,
    SF_METHOD_OPTIONS = 5,
    SF_METHOD_HEAD    = 6,
    SF_METHOD_ANY     = 7,
    SF_METHOD_COUNT   = 8
} sf_http_method;

/* Trie node type enumeration */
typedef enum {
    SF_NODE_STATIC         = 0,  /* Literal path segment */
    SF_NODE_PARAM          = 1,  /* Required parameter {name} */
    SF_NODE_PARAM_OPTIONAL = 2,  /* Optional parameter {name?} */
    SF_NODE_WILDCARD       = 3,  /* Catch-all {name*} or {name...} */
    SF_NODE_ROOT           = 4   /* Root node marker */
} sf_node_type;

/*
 * Specialized validator types for common constraint patterns.
 * These bypass PCRE2 regex matching for significant performance gains.
 */
typedef enum {
    SF_VALIDATOR_REGEX       = 0,   /* Custom regex - use PCRE2 (fallback) */
    SF_VALIDATOR_NUMBER      = 1,   /* [0-9]+ - digits only */
    SF_VALIDATOR_ALPHA       = 2,   /* [a-zA-Z]+ - letters only */
    SF_VALIDATOR_ALPHANUMERIC= 3,   /* [a-zA-Z0-9]+ - letters and digits */
    SF_VALIDATOR_SLUG        = 4,   /* [a-zA-Z0-9-_]+ - URL-safe slug */
    SF_VALIDATOR_UUID        = 5,   /* UUID format (8-4-4-4-12 hex) */
} sf_validator_type;

/* Parameter constraint structure */
typedef struct _sf_param_constraint {
    zend_string *name;              /* Parameter name */
    zend_string *pattern;           /* Original regex pattern */
    pcre2_code *compiled_regex;     /* Compiled PCRE2 regex (NULL if specialized) */
    pcre2_match_data *match_data;   /* Reusable match data */
    zval default_value;             /* Default value for optional params */
    sf_validator_type validator;    /* Specialized validator type */
    zend_bool has_default;          /* Whether default is set */
    zend_bool is_optional;          /* Is this parameter optional */
} sf_param_constraint;

/* Middleware entry */
typedef struct _sf_middleware_entry {
    zend_string *name;              /* Middleware identifier */
    zval parameters;                /* Middleware parameters (array) */
    struct _sf_middleware_entry *next;
} sf_middleware_entry;

/* Route definition structure */
struct _sf_route {
    zend_string *uri;               /* Original URI pattern */
    zend_string *name;              /* Route name (nullable) */
    zend_string *action_namespace;  /* Controller namespace */
    zval handler;                   /* Callable or controller@method string */
    zend_fcall_info fci;            /* Prepared call info */
    zend_fcall_info_cache fcc;      /* Prepared call cache */
    zend_bool handler_prepared;     /* Whether fci/fcc are prepared */
    sf_middleware_entry *middleware_head; /* Linked list of middleware */
    sf_middleware_entry *middleware_tail;
    uint32_t middleware_count;
    HashTable *wheres;              /* Parameter constraints {name => pattern} */
    HashTable *defaults;            /* Default parameter values */
    zval meta;                      /* Additional metadata (array) */
    sf_http_method method;          /* HTTP method */
    zend_string *domain;            /* Domain/subdomain constraint */
    pcre2_code *domain_regex;       /* Compiled domain regex */
    uint32_t priority;              /* Route priority (lower = higher priority) */
    zend_bool is_fallback;          /* Is this a fallback route */
    zend_object *php_object;        /* Associated PHP Route object */
    uint32_t refcount;              /* Reference count */
};

/*
 * Trie node structure - cache-line optimized layout
 *
 * Fields are ordered to minimize cache misses during route matching:
 * - First cache line (bytes 0-63): All fields accessed during trie traversal
 * - Second cache line (bytes 64+): Cold fields only accessed during insertion/validation
 *
 * Hot path during matching accesses: static_children, param_child, optional_child,
 * wildcard_child, is_terminal, route, param_name, type (in roughly that order)
 */
struct _sf_trie_node {
    /* ===== HOT FIELDS - First cache line (64 bytes) ===== */
    /* These fields are accessed on every node visit during matching */

    HashTable *static_children;     /* Static segment children - checked first (8 bytes) */
    sf_trie_node *param_child;      /* Required parameter child (8 bytes) */
    sf_trie_node *optional_child;   /* Optional parameter child (8 bytes) */
    sf_trie_node *wildcard_child;   /* Wildcard catch-all child (8 bytes) */
    sf_route *route;                /* Route if terminal - accessed on match (8 bytes) */
    zend_string *param_name;        /* Parameter name - accessed when capturing (8 bytes) */
    sf_node_type type;              /* Node type enum (4 bytes) */
    uint8_t is_terminal;            /* Terminal flag - checked on every node (1 byte) */
    uint8_t _cache_line_pad[11];    /* Pad to exactly 64 bytes (11 bytes) */
    /* Total: 64 bytes = exactly one cache line */

    /* ===== COLD FIELDS - Second cache line (bytes 64+) ===== */
    /* These fields are only accessed during route registration or validation */

    zend_string *segment;           /* Path segment - only used during insertion (8 bytes) */
    sf_param_constraint *constraint;/* Parameter constraint - post-match validation (8 bytes) */
    sf_trie_node *parent;           /* Parent node - tree manipulation only (8 bytes) */
    uint32_t depth;                 /* Depth in tree - insertion/debug only (4 bytes) */
    uint8_t _cold_padding[4];       /* Padding for alignment (4 bytes) */
    /* Total cold: 32 bytes */
} SF_CACHE_ALIGNED;

/* Match result structure */
struct _sf_match_result {
    sf_route *route;                /* Matched route (borrowed reference) */
    HashTable *params;              /* Extracted parameters {name => value} */
    zend_bool matched;              /* Whether a match was found */
    zend_string *error;             /* Error message if match failed */
};

/* Route group context */
struct _sf_route_group {
    zend_string *prefix;            /* URI prefix */
    zend_string *namespace;         /* Controller namespace */
    zend_string *name_prefix;       /* Route name prefix */
    zend_string *domain;            /* Domain constraint */
    sf_middleware_entry *middleware_head;
    sf_middleware_entry *middleware_tail;
    HashTable *wheres;              /* Shared parameter constraints */
    struct _sf_route_group *parent; /* Parent group (for nesting) */
};

/* Router state */
struct _sf_router {
    sf_trie_node *method_tries[SF_METHOD_COUNT]; /* Per-method trie roots */
    HashTable *named_routes;        /* {name => route} for reverse routing */
    HashTable *all_routes;          /* All registered routes */
    sf_route_group *current_group;  /* Current group context */
    sf_route *fallback_route;       /* Fallback route */
    zend_bool is_immutable;         /* Locked during request */
    zend_bool trailing_slash_strict;/* Strict trailing slash matching */
    uint32_t route_count;           /* Total route count */

#ifdef ZTS
    /* Read-write lock for thread safety:
     * - Read lock for matching, URL generation, route lookup (concurrent reads OK)
     * - Write lock for route insertion, reset (exclusive access required)
     */
#ifdef _WIN32
    SRWLOCK lock;                   /* Windows Slim Reader/Writer Lock */
#else
    pthread_rwlock_t lock;          /* POSIX read-write lock */
#endif
#endif
};

/* ============================================================================
 * Memory Management Functions
 * ============================================================================ */

/* Trie node lifecycle */
sf_trie_node *sf_trie_node_create(sf_node_type type);
void sf_trie_node_destroy(sf_trie_node *node);
void sf_trie_node_destroy_recursive(sf_trie_node *node);

/* Route lifecycle */
sf_route *sf_route_create(void);
void sf_route_addref(sf_route *route);
void sf_route_release(sf_route *route);
void sf_route_destroy(sf_route *route);

/* Constraint lifecycle */
sf_param_constraint *sf_constraint_create(zend_string *name);
void sf_constraint_destroy(sf_param_constraint *constraint);
zend_bool sf_constraint_set_pattern(sf_param_constraint *constraint, zend_string *pattern);
zend_bool sf_constraint_validate(sf_param_constraint *constraint, zend_string *value);

/* Middleware lifecycle */
sf_middleware_entry *sf_middleware_create(zend_string *name);
void sf_middleware_destroy(sf_middleware_entry *entry);
void sf_middleware_list_destroy(sf_middleware_entry *head);
sf_middleware_entry *sf_middleware_list_clone(sf_middleware_entry *head);

/* Router lifecycle */
sf_router *sf_router_create(void);
void sf_router_destroy(sf_router *router);
void sf_router_reset(sf_router *router);

/* Match result lifecycle */
sf_match_result *sf_match_result_create(void);
void sf_match_result_destroy(sf_match_result *result);

/* Route group lifecycle */
sf_route_group *sf_route_group_create(void);
void sf_route_group_destroy(sf_route_group *group);

/* ============================================================================
 * Route Registration Functions
 * ============================================================================ */

/* Parse URI into segments */
typedef struct _sf_uri_segment {
    zend_string *value;
    sf_node_type type;
    zend_string *param_name;
    zend_bool is_optional;
    struct _sf_uri_segment *next;
} sf_uri_segment;

sf_uri_segment *sf_parse_uri(const char *uri, size_t len);
void sf_uri_segments_destroy(sf_uri_segment *head);

/* Insert route into trie */
zend_bool sf_trie_insert(sf_router *router, sf_http_method method,
                         const char *uri, size_t uri_len, sf_route *route);

/* Insert route with parsed segments */
zend_bool sf_trie_insert_segments(sf_trie_node *root, sf_uri_segment *segments,
                                  sf_route *route);

/* Register route (high-level API) */
sf_route *sf_router_add_route(sf_router *router, sf_http_method method,
                              zend_string *uri, zval *handler);

/* Route configuration */
void sf_route_set_name(sf_route *route, zend_string *name);
void sf_route_set_middleware(sf_route *route, zval *middleware);
void sf_route_add_middleware(sf_route *route, zend_string *name, zval *params);
void sf_route_set_where(sf_route *route, zend_string *param, zend_string *pattern);
void sf_route_set_default(sf_route *route, zend_string *param, zval *value);
void sf_route_set_domain(sf_route *route, zend_string *domain);

/* ============================================================================
 * Route Matching Functions
 * ============================================================================ */

/* Match URI against trie */
sf_match_result *sf_trie_match(sf_router *router, sf_http_method method,
                               const char *uri, size_t uri_len);

/* Match with domain */
sf_match_result *sf_trie_match_with_domain(sf_router *router, sf_http_method method,
                                           const char *uri, size_t uri_len,
                                           const char *domain, size_t domain_len);

/* Internal matching - returns matched node */
sf_trie_node *sf_trie_match_node(sf_trie_node *root, const char *uri, size_t uri_len,
                                 HashTable *params);

/* Validate extracted parameters against constraints */
zend_bool sf_validate_params(sf_route *route, HashTable *params);

/* ============================================================================
 * Route Group Functions
 * ============================================================================ */

/* Begin a new group context */
void sf_router_begin_group(sf_router *router, sf_route_group *group);

/* End current group context */
void sf_router_end_group(sf_router *router);

/* Apply group settings to route */
void sf_route_apply_group(sf_route *route, sf_route_group *group);

/* ============================================================================
 * URL Generation Functions
 * ============================================================================ */

/* Generate URL for named route */
zend_string *sf_router_url(sf_router *router, zend_string *name, HashTable *params);

/* Check if route exists */
zend_bool sf_router_has_route(sf_router *router, zend_string *name);

/* Get route by name */
sf_route *sf_router_get_route(sf_router *router, zend_string *name);

/* ============================================================================
 * Serialization Functions (Route Caching)
 * ============================================================================ */

/* Serialize router to string */
zend_string *sf_router_serialize(sf_router *router);

/* Unserialize router from string */
sf_router *sf_router_unserialize(const char *data, size_t len);

/* Cache to file */
zend_bool sf_router_cache_to_file(sf_router *router, const char *path);

/* Load from file cache */
sf_router *sf_router_load_from_file(const char *path);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Convert method string to enum */
sf_http_method sf_method_from_string(const char *method, size_t len);

/* Convert method enum to string */
const char *sf_method_to_string(sf_http_method method);

/* Normalize URI (trailing slash handling) */
zend_string *sf_normalize_uri(const char *uri, size_t len, zend_bool strip_trailing);

/* Debug: dump trie structure */
void sf_trie_dump(sf_trie_node *node, int depth);

/* Debug: dump route */
void sf_route_dump(sf_route *route);

/* ============================================================================
 * Thread Safety Macros
 *
 * Read-write locking strategy:
 * - SF_ROUTER_RDLOCK: Acquire read lock for read-only operations that can
 *   proceed concurrently (match, url, has_route, get_route, serialize)
 * - SF_ROUTER_WRLOCK: Acquire write lock for mutating operations that need
 *   exclusive access (reset, insert/add_route)
 * - SF_ROUTER_UNLOCK: Release either lock type
 * ============================================================================ */

#ifdef ZTS
#ifdef _WIN32
/* Windows SRWLOCK implementation */
#define SF_ROUTER_RDLOCK(router)  AcquireSRWLockShared(&(router)->lock)
#define SF_ROUTER_WRLOCK(router)  AcquireSRWLockExclusive(&(router)->lock)
#define SF_ROUTER_UNLOCK_RD(router) ReleaseSRWLockShared(&(router)->lock)
#define SF_ROUTER_UNLOCK_WR(router) ReleaseSRWLockExclusive(&(router)->lock)
#else
/* POSIX pthread_rwlock implementation */
#define SF_ROUTER_RDLOCK(router)  pthread_rwlock_rdlock(&(router)->lock)
#define SF_ROUTER_WRLOCK(router)  pthread_rwlock_wrlock(&(router)->lock)
#define SF_ROUTER_UNLOCK_RD(router) pthread_rwlock_unlock(&(router)->lock)
#define SF_ROUTER_UNLOCK_WR(router) pthread_rwlock_unlock(&(router)->lock)
#endif
/* Legacy macro for backward compatibility - defaults to write lock */
#define SF_ROUTER_LOCK(router)   SF_ROUTER_WRLOCK(router)
#define SF_ROUTER_UNLOCK(router) SF_ROUTER_UNLOCK_WR(router)
#else
/* Non-ZTS builds: no locking needed */
#define SF_ROUTER_RDLOCK(router)
#define SF_ROUTER_WRLOCK(router)
#define SF_ROUTER_UNLOCK_RD(router)
#define SF_ROUTER_UNLOCK_WR(router)
#define SF_ROUTER_LOCK(router)
#define SF_ROUTER_UNLOCK(router)
#endif

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/* Maximum URI length to prevent excessive memory allocation (8KB) */
#define SF_MAX_URI_LENGTH 8192

/* Maximum route name length */
#define SF_MAX_ROUTE_NAME_LENGTH 256

/* Maximum middleware count per route */
#define SF_MAX_MIDDLEWARE_COUNT 100

/* Maximum trie depth (prevents stack overflow in recursive functions) */
#define SF_MAX_TRIE_DEPTH 64

/* Initial hash table sizes */
#define SF_NAMED_ROUTES_INITIAL_SIZE 64
#define SF_ALL_ROUTES_INITIAL_SIZE 128
#define SF_STATIC_CHILDREN_INITIAL_SIZE 8
#define SF_CONSTRAINTS_INITIAL_SIZE 8
#define SF_DEFAULTS_INITIAL_SIZE 8
#define SF_PARAMS_INITIAL_SIZE 8

/* ============================================================================
 * Error Codes
 * ============================================================================ */

typedef enum {
    SF_OK                    = 0,
    SF_ERR_INVALID_URI       = 1,
    SF_ERR_DUPLICATE_ROUTE   = 2,
    SF_ERR_INVALID_HANDLER   = 3,
    SF_ERR_INVALID_CONSTRAINT= 4,
    SF_ERR_ROUTE_NOT_FOUND   = 5,
    SF_ERR_METHOD_NOT_ALLOWED= 6,
    SF_ERR_IMMUTABLE         = 7,
    SF_ERR_MEMORY            = 8,
    SF_ERR_DEPTH_EXCEEDED    = 9
} sf_error_code;

/* Global error state - defined in signalforge_routing.h */

#endif /* SIGNALFORGE_ROUTING_TRIE_H */
