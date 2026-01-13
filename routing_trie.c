/*
 * Signalforge Routing Extension
 * routing_trie.c - Radix trie implementation
 *
 * Copyright (c) 2024 Signalforge
 * License: MIT
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "routing_trie.h"
#include "zend_exceptions.h"
#include "zend_smart_str.h"
#include <string.h>

/* ============================================================================
 * Memory Management - Trie Nodes
 * ============================================================================ */

sf_trie_node *sf_trie_node_create(sf_node_type type)
{
    sf_trie_node *node = ecalloc(1, sizeof(sf_trie_node));
    if (!node) {
        return NULL;
    }

    node->type = type;
    node->segment = NULL;
    node->param_name = NULL;
    node->constraint = NULL;
    node->static_children = NULL;
    node->param_child = NULL;
    node->optional_child = NULL;
    node->wildcard_child = NULL;
    node->route = NULL;
    node->is_terminal = 0;
    node->depth = 0;

    return node;
}

void sf_trie_node_destroy(sf_trie_node *node)
{
    if (!node) {
        return;
    }

    if (node->segment) {
        zend_string_release(node->segment);
    }

    if (node->param_name) {
        zend_string_release(node->param_name);
    }

    if (node->constraint) {
        sf_constraint_destroy(node->constraint);
    }

    if (node->static_children) {
        zend_hash_destroy(node->static_children);
        FREE_HASHTABLE(node->static_children);
    }

    if (node->route) {
        sf_route_release(node->route);
    }

    efree(node);
}

void sf_trie_node_destroy_recursive(sf_trie_node *node)
{
    if (!node) {
        return;
    }

    /* Destroy static children */
    if (node->static_children) {
        zval *child_zv;
        ZEND_HASH_FOREACH_VAL(node->static_children, child_zv) {
            sf_trie_node *child = (sf_trie_node *)Z_PTR_P(child_zv);
            sf_trie_node_destroy_recursive(child);
        } ZEND_HASH_FOREACH_END();
    }

    /* Destroy parameter child */
    if (node->param_child) {
        sf_trie_node_destroy_recursive(node->param_child);
    }

    /* Destroy optional child */
    if (node->optional_child) {
        sf_trie_node_destroy_recursive(node->optional_child);
    }

    /* Destroy wildcard child */
    if (node->wildcard_child) {
        sf_trie_node_destroy_recursive(node->wildcard_child);
    }

    sf_trie_node_destroy(node);
}

/* ============================================================================
 * Memory Management - Routes
 * ============================================================================ */

sf_route *sf_route_create(void)
{
    sf_route *route = ecalloc(1, sizeof(sf_route));
    if (!route) {
        return NULL;
    }

    route->uri = NULL;
    route->name = NULL;
    ZVAL_UNDEF(&route->handler);
    route->middleware_head = NULL;
    route->middleware_tail = NULL;
    route->middleware_count = 0;
    route->wheres = NULL;
    route->defaults = NULL;
    route->method = SF_METHOD_GET;
    route->domain = NULL;
    route->domain_regex = NULL;
    route->priority = 0;
    route->is_fallback = 0;
    route->php_object = NULL;
    route->refcount = 1;

    return route;
}

/**
 * Increment route reference count atomically.
 *
 * Uses atomic operations in ZTS builds to prevent race conditions when
 * multiple threads access the same route simultaneously. In non-ZTS builds,
 * we still use atomics as they are cheap on modern CPUs and provide
 * consistency.
 *
 * Memory ordering: RELAXED is sufficient for increment since we only need
 * the increment itself to be atomic; no other memory operations depend on it.
 */
void sf_route_addref(sf_route *route)
{
    if (route) {
        __atomic_add_fetch(&route->refcount, 1, __ATOMIC_RELAXED);
    }
}

/**
 * Decrement route reference count atomically and destroy if zero.
 *
 * Memory ordering: ACQ_REL (acquire-release) is required because:
 * - RELEASE: Ensures all previous writes to the route are visible before
 *   the decrement, so another thread that sees refcount==0 sees a consistent state
 * - ACQUIRE: If we get refcount==0, we need to see all writes from other threads
 *   that released their references before we free the memory
 */
void sf_route_release(sf_route *route)
{
    if (route) {
        if (__atomic_sub_fetch(&route->refcount, 1, __ATOMIC_ACQ_REL) == 0) {
            sf_route_destroy(route);
        }
    }
}

void sf_route_destroy(sf_route *route)
{
    if (!route) {
        return;
    }

    if (route->uri) {
        zend_string_release(route->uri);
    }

    if (route->name) {
        zend_string_release(route->name);
    }

    if (!Z_ISUNDEF(route->handler)) {
        zval_ptr_dtor(&route->handler);
    }

    sf_middleware_list_destroy(route->middleware_head);

    if (route->wheres) {
        zend_hash_destroy(route->wheres);
        FREE_HASHTABLE(route->wheres);
    }

    if (route->defaults) {
        zend_hash_destroy(route->defaults);
        FREE_HASHTABLE(route->defaults);
    }

    if (route->domain) {
        zend_string_release(route->domain);
    }

    if (route->domain_regex) {
        pcre2_code_free(route->domain_regex);
    }

    efree(route);
}

/* ============================================================================
 * Memory Management - Constraints
 * ============================================================================ */

sf_param_constraint *sf_constraint_create(zend_string *name)
{
    sf_param_constraint *constraint = ecalloc(1, sizeof(sf_param_constraint));
    if (!constraint) {
        return NULL;
    }

    constraint->name = zend_string_copy(name);
    constraint->pattern = NULL;
    constraint->compiled_regex = NULL;
    constraint->match_data = NULL;
    ZVAL_UNDEF(&constraint->default_value);
    constraint->validator = SF_VALIDATOR_REGEX;  /* Default to regex validation */
    constraint->has_default = 0;
    constraint->is_optional = 0;

    return constraint;
}

void sf_constraint_destroy(sf_param_constraint *constraint)
{
    if (!constraint) {
        return;
    }

    if (constraint->name) {
        zend_string_release(constraint->name);
    }

    if (constraint->pattern) {
        zend_string_release(constraint->pattern);
    }

    if (constraint->compiled_regex) {
        pcre2_code_free(constraint->compiled_regex);
    }

    if (constraint->match_data) {
        pcre2_match_data_free(constraint->match_data);
    }

    if (!Z_ISUNDEF(constraint->default_value)) {
        zval_ptr_dtor(&constraint->default_value);
    }

    efree(constraint);
}

/**
 * HashTable destructor for sf_param_constraint pointers stored in wheres tables.
 * Called when entries are removed or the hash table is destroyed.
 */
static void sf_constraint_hash_dtor(zval *zv)
{
    sf_param_constraint *constraint = (sf_param_constraint *)Z_PTR_P(zv);
    if (constraint) {
        sf_constraint_destroy(constraint);
    }
}

/**
 * Detect if a pattern matches a known specialized validator.
 * Returns the validator type, or SF_VALIDATOR_REGEX if no match.
 */
static sf_validator_type sf_detect_validator_type(const char *pattern, size_t len)
{
    /* Check for common patterns - exact match required */
    if (len == 6 && memcmp(pattern, "[0-9]+", 6) == 0) {
        return SF_VALIDATOR_NUMBER;
    }
    if (len == 9 && memcmp(pattern, "[a-zA-Z]+", 9) == 0) {
        return SF_VALIDATOR_ALPHA;
    }
    if (len == 12 && memcmp(pattern, "[a-zA-Z0-9]+", 12) == 0) {
        return SF_VALIDATOR_ALPHANUMERIC;
    }
    if (len == 14 && memcmp(pattern, "[a-zA-Z0-9-_]+", 14) == 0) {
        return SF_VALIDATOR_SLUG;
    }
    /* Alternative slug pattern */
    if (len == 14 && memcmp(pattern, "[a-zA-Z0-9_-]+", 14) == 0) {
        return SF_VALIDATOR_SLUG;
    }
    /* UUID pattern - common regex format */
    if (len >= 30 && strstr(pattern, "[0-9a-fA-F]") != NULL &&
        strstr(pattern, "-") != NULL) {
        /* Rough UUID pattern detection - if it looks like a UUID regex */
        if (strstr(pattern, "{8}") && strstr(pattern, "{4}") && strstr(pattern, "{12}")) {
            return SF_VALIDATOR_UUID;
        }
    }
    /* Also accept \\d+ as number pattern */
    if (len == 3 && memcmp(pattern, "\\d+", 3) == 0) {
        return SF_VALIDATOR_NUMBER;
    }

    return SF_VALIDATOR_REGEX;
}

zend_bool sf_constraint_set_pattern(sf_param_constraint *constraint, zend_string *pattern)
{
    int errcode;
    PCRE2_SIZE erroffset;
    PCRE2_UCHAR errbuf[256];
    sf_validator_type validator_type;

    if (!constraint || !pattern) {
        return 0;
    }

    /* Free existing pattern/regex */
    if (constraint->pattern) {
        zend_string_release(constraint->pattern);
        constraint->pattern = NULL;
    }

    if (constraint->compiled_regex) {
        pcre2_code_free(constraint->compiled_regex);
        constraint->compiled_regex = NULL;
    }

    if (constraint->match_data) {
        pcre2_match_data_free(constraint->match_data);
        constraint->match_data = NULL;
    }

    /* Reset validator to default */
    constraint->validator = SF_VALIDATOR_REGEX;

    /* Check if pattern matches a specialized validator (fast path) */
    validator_type = sf_detect_validator_type(ZSTR_VAL(pattern), ZSTR_LEN(pattern));

    if (validator_type != SF_VALIDATOR_REGEX) {
        /* Use specialized validator - skip PCRE2 compilation entirely */
        constraint->validator = validator_type;
        constraint->pattern = zend_string_copy(pattern);
        constraint->compiled_regex = NULL;
        constraint->match_data = NULL;
        return 1;
    }

    /* Fall back to PCRE2 regex compilation for custom patterns */

    /* Build full anchored pattern: ^(?:pattern)$ */
    smart_str full_pattern = {0};
    smart_str_appends(&full_pattern, "^(?:");
    smart_str_append(&full_pattern, pattern);
    smart_str_appends(&full_pattern, ")$");
    smart_str_0(&full_pattern);

    /* Compile regex */
    constraint->compiled_regex = pcre2_compile(
        (PCRE2_SPTR)ZSTR_VAL(full_pattern.s),
        ZSTR_LEN(full_pattern.s),
        PCRE2_UTF | PCRE2_UCP,
        &errcode,
        &erroffset,
        NULL
    );

    if (!constraint->compiled_regex) {
        pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
        php_error_docref(NULL, E_WARNING,
            "Signalforge\\Routing: Invalid constraint pattern '%s': %s at offset %zu",
            ZSTR_VAL(pattern), errbuf, erroffset);
        smart_str_free(&full_pattern);
        return 0;
    }

    /* JIT compile for performance */
    pcre2_jit_compile(constraint->compiled_regex, PCRE2_JIT_COMPLETE);

    /* Create match data */
    constraint->match_data = pcre2_match_data_create_from_pattern(
        constraint->compiled_regex, NULL
    );

    constraint->pattern = zend_string_copy(pattern);
    smart_str_free(&full_pattern);

    return 1;
}

/*
 * Specialized validators - these are significantly faster than PCRE2 regex
 * matching for common constraint patterns. They use simple character class
 * checks instead of full regex engine execution.
 */

/**
 * Validate that string contains only digits [0-9]+
 * ~10-50x faster than PCRE2 for typical parameter lengths
 */
static zend_always_inline zend_bool sf_validate_number(const char *str, size_t len)
{
    if (UNEXPECTED(len == 0)) return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (UNEXPECTED(c < '0' || c > '9')) {
            return 0;
        }
    }
    return 1;
}

/**
 * Validate that string contains only letters [a-zA-Z]+
 */
static zend_always_inline zend_bool sf_validate_alpha(const char *str, size_t len)
{
    if (UNEXPECTED(len == 0)) return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (UNEXPECTED(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))) {
            return 0;
        }
    }
    return 1;
}

/**
 * Validate that string contains only alphanumeric [a-zA-Z0-9]+
 */
static zend_always_inline zend_bool sf_validate_alphanumeric(const char *str, size_t len)
{
    if (UNEXPECTED(len == 0)) return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (UNEXPECTED(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))) {
            return 0;
        }
    }
    return 1;
}

/**
 * Validate URL-safe slug [a-zA-Z0-9-_]+
 */
static zend_always_inline zend_bool sf_validate_slug(const char *str, size_t len)
{
    if (UNEXPECTED(len == 0)) return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (UNEXPECTED(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                         (c >= '0' && c <= '9') || c == '-' || c == '_'))) {
            return 0;
        }
    }
    return 1;
}

/**
 * Check if character is a hex digit [0-9a-fA-F]
 */
static zend_always_inline zend_bool sf_is_hex(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/**
 * Validate UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
 */
static zend_always_inline zend_bool sf_validate_uuid(const char *str, size_t len)
{
    /* UUID must be exactly 36 characters: 8-4-4-4-12 */
    if (UNEXPECTED(len != 36)) return 0;

    /* Check format: 8 hex, dash, 4 hex, dash, 4 hex, dash, 4 hex, dash, 12 hex */
    for (size_t i = 0; i < 8; i++) {
        if (UNEXPECTED(!sf_is_hex((unsigned char)str[i]))) return 0;
    }
    if (UNEXPECTED(str[8] != '-')) return 0;

    for (size_t i = 9; i < 13; i++) {
        if (UNEXPECTED(!sf_is_hex((unsigned char)str[i]))) return 0;
    }
    if (UNEXPECTED(str[13] != '-')) return 0;

    for (size_t i = 14; i < 18; i++) {
        if (UNEXPECTED(!sf_is_hex((unsigned char)str[i]))) return 0;
    }
    if (UNEXPECTED(str[18] != '-')) return 0;

    for (size_t i = 19; i < 23; i++) {
        if (UNEXPECTED(!sf_is_hex((unsigned char)str[i]))) return 0;
    }
    if (UNEXPECTED(str[23] != '-')) return 0;

    for (size_t i = 24; i < 36; i++) {
        if (UNEXPECTED(!sf_is_hex((unsigned char)str[i]))) return 0;
    }

    return 1;
}

/**
 * Main constraint validation function.
 * Uses specialized validators for known patterns, falls back to PCRE2 for custom regex.
 */
zend_bool sf_constraint_validate(sf_param_constraint *constraint, zend_string *value)
{
    const char *str;
    size_t len;

    /* Null checks - defensive, should rarely fail */
    if (UNEXPECTED(!constraint || !value)) {
        return 0;
    }

    str = ZSTR_VAL(value);
    len = ZSTR_LEN(value);

    /* Use specialized validator if available (fast path) */
    switch (constraint->validator) {
        case SF_VALIDATOR_NUMBER:
            return sf_validate_number(str, len);

        case SF_VALIDATOR_ALPHA:
            return sf_validate_alpha(str, len);

        case SF_VALIDATOR_ALPHANUMERIC:
            return sf_validate_alphanumeric(str, len);

        case SF_VALIDATOR_SLUG:
            return sf_validate_slug(str, len);

        case SF_VALIDATOR_UUID:
            return sf_validate_uuid(str, len);

        case SF_VALIDATOR_REGEX:
        default:
            /* Fall back to PCRE2 regex matching */
            if (UNEXPECTED(!constraint->compiled_regex)) {
                return 1; /* No pattern means always valid */
            }

            int rc = pcre2_match(
                constraint->compiled_regex,
                (PCRE2_SPTR)str,
                len,
                0,
                0,
                constraint->match_data,
                NULL
            );

            /* Most validation should succeed */
            return EXPECTED(rc >= 0);
    }
}

/* ============================================================================
 * Memory Management - Middleware
 * ============================================================================ */

sf_middleware_entry *sf_middleware_create(zend_string *name)
{
    sf_middleware_entry *entry = ecalloc(1, sizeof(sf_middleware_entry));
    if (!entry) {
        return NULL;
    }

    entry->name = zend_string_copy(name);
    ZVAL_UNDEF(&entry->parameters);
    entry->next = NULL;

    return entry;
}

void sf_middleware_destroy(sf_middleware_entry *entry)
{
    if (!entry) {
        return;
    }

    if (entry->name) {
        zend_string_release(entry->name);
    }

    if (!Z_ISUNDEF(entry->parameters)) {
        zval_ptr_dtor(&entry->parameters);
    }

    efree(entry);
}

void sf_middleware_list_destroy(sf_middleware_entry *head)
{
    sf_middleware_entry *current = head;
    while (current) {
        sf_middleware_entry *next = current->next;
        sf_middleware_destroy(current);
        current = next;
    }
}

sf_middleware_entry *sf_middleware_list_clone(sf_middleware_entry *head)
{
    sf_middleware_entry *new_head = NULL;
    sf_middleware_entry *new_tail = NULL;
    sf_middleware_entry *current = head;

    while (current) {
        sf_middleware_entry *clone = sf_middleware_create(current->name);
        if (!clone) {
            sf_middleware_list_destroy(new_head);
            return NULL;
        }

        if (!Z_ISUNDEF(current->parameters)) {
            ZVAL_COPY(&clone->parameters, &current->parameters);
        }

        if (!new_head) {
            new_head = clone;
            new_tail = clone;
        } else {
            new_tail->next = clone;
            new_tail = clone;
        }

        current = current->next;
    }

    return new_head;
}

/* ============================================================================
 * Memory Management - Router
 * ============================================================================ */

sf_router *sf_router_create(void)
{
    sf_router *router = ecalloc(1, sizeof(sf_router));
    if (!router) {
        return NULL;
    }

    /* Initialize method tries */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        router->method_tries[i] = sf_trie_node_create(SF_NODE_ROOT);
        if (!router->method_tries[i]) {
            sf_router_destroy(router);
            return NULL;
        }
    }

    /* Initialize named routes hash table */
    ALLOC_HASHTABLE(router->named_routes);
    zend_hash_init(router->named_routes, SF_NAMED_ROUTES_INITIAL_SIZE, NULL, NULL, 0);

    /* Initialize all routes hash table */
    ALLOC_HASHTABLE(router->all_routes);
    zend_hash_init(router->all_routes, SF_ALL_ROUTES_INITIAL_SIZE, NULL, NULL, 0);

    router->current_group = NULL;
    router->fallback_route = NULL;
    router->is_immutable = 0;
    router->trailing_slash_strict = 0;
    router->route_count = 0;

#ifdef ZTS
    /* Initialize read-write lock for thread-safe access */
#ifdef _WIN32
    InitializeSRWLock(&router->lock);
#else
    pthread_rwlock_init(&router->lock, NULL);
#endif
#endif

    return router;
}

void sf_router_destroy(sf_router *router)
{
    if (!router) {
        return;
    }

    /* Destroy method tries */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        if (router->method_tries[i]) {
            sf_trie_node_destroy_recursive(router->method_tries[i]);
        }
    }

    /* Routes are owned by tries, just destroy hash tables */
    if (router->named_routes) {
        zend_hash_destroy(router->named_routes);
        FREE_HASHTABLE(router->named_routes);
    }

    if (router->all_routes) {
        zend_hash_destroy(router->all_routes);
        FREE_HASHTABLE(router->all_routes);
    }

    /* Destroy any remaining group context */
    while (router->current_group) {
        sf_route_group *parent = router->current_group->parent;
        sf_route_group_destroy(router->current_group);
        router->current_group = parent;
    }

#ifdef ZTS
    /* Destroy read-write lock */
#ifdef _WIN32
    /* Windows SRWLOCK does not require explicit destruction */
#else
    pthread_rwlock_destroy(&router->lock);
#endif
#endif

    efree(router);
}

void sf_router_reset(sf_router *router)
{
    sf_trie_node *new_tries[SF_METHOD_COUNT] = {NULL};
    int i;

    if (!router) {
        return;
    }

    /* Pre-allocate new tries before destroying old ones for atomicity */
    for (i = 0; i < SF_METHOD_COUNT; i++) {
        new_tries[i] = sf_trie_node_create(SF_NODE_ROOT);
        if (!new_tries[i]) {
            /* Allocation failed - clean up and abort */
            for (int j = 0; j < i; j++) {
                sf_trie_node_destroy(new_tries[j]);
            }
            php_error_docref(NULL, E_WARNING,
                "Signalforge\\Routing: Failed to reset router - memory allocation failed");
            return;
        }
    }

    /* Write lock: reset modifies router state */
    SF_ROUTER_WRLOCK(router);

    /* Destroy old tries */
    for (i = 0; i < SF_METHOD_COUNT; i++) {
        if (router->method_tries[i]) {
            sf_trie_node_destroy_recursive(router->method_tries[i]);
        }
        router->method_tries[i] = new_tries[i];
    }

    /* Clear hash tables */
    zend_hash_clean(router->named_routes);
    zend_hash_clean(router->all_routes);

    /* Release fallback route if exists */
    if (router->fallback_route) {
        sf_route_release(router->fallback_route);
        router->fallback_route = NULL;
    }

    router->is_immutable = 0;
    router->route_count = 0;

    SF_ROUTER_UNLOCK_WR(router);
}

/* ============================================================================
 * Memory Management - Match Result
 * ============================================================================ */

sf_match_result *sf_match_result_create(void)
{
    sf_match_result *result = ecalloc(1, sizeof(sf_match_result));
    if (!result) {
        return NULL;
    }

    result->route = NULL;
    result->matched = 0;
    result->error = NULL;

    ALLOC_HASHTABLE(result->params);
    zend_hash_init(result->params, SF_PARAMS_INITIAL_SIZE, NULL, ZVAL_PTR_DTOR, 0);

    return result;
}

void sf_match_result_destroy(sf_match_result *result)
{
    if (!result) {
        return;
    }

    if (result->params) {
        zend_hash_destroy(result->params);
        FREE_HASHTABLE(result->params);
    }

    if (result->error) {
        zend_string_release(result->error);
    }

    efree(result);
}

/* ============================================================================
 * Memory Management - Route Group
 * ============================================================================ */

sf_route_group *sf_route_group_create(void)
{
    sf_route_group *group = ecalloc(1, sizeof(sf_route_group));
    if (!group) {
        return NULL;
    }

    group->prefix = NULL;
    group->namespace = NULL;
    group->name_prefix = NULL;
    group->domain = NULL;
    group->middleware_head = NULL;
    group->middleware_tail = NULL;
    group->wheres = NULL;
    group->parent = NULL;

    return group;
}

void sf_route_group_destroy(sf_route_group *group)
{
    if (!group) {
        return;
    }

    if (group->prefix) {
        zend_string_release(group->prefix);
    }

    if (group->namespace) {
        zend_string_release(group->namespace);
    }

    if (group->name_prefix) {
        zend_string_release(group->name_prefix);
    }

    if (group->domain) {
        zend_string_release(group->domain);
    }

    sf_middleware_list_destroy(group->middleware_head);

    if (group->wheres) {
        zend_hash_destroy(group->wheres);
        FREE_HASHTABLE(group->wheres);
    }

    efree(group);
}

/* ============================================================================
 * URI Parsing
 * ============================================================================ */

sf_uri_segment *sf_parse_uri(const char *uri, size_t len)
{
    sf_uri_segment *head = NULL;
    sf_uri_segment *tail = NULL;
    const char *ptr = uri;
    const char *end = uri + len;

    /* Validate URI length to prevent excessive memory allocation */
    if (len > SF_MAX_URI_LENGTH) {
        php_error_docref(NULL, E_WARNING,
            "Signalforge\\Routing: URI exceeds maximum length of %d bytes", SF_MAX_URI_LENGTH);
        return NULL;
    }

    /* Skip leading slash */
    if (ptr < end && *ptr == '/') {
        ptr++;
    }

    while (ptr < end) {
        const char *seg_start = ptr;
        sf_uri_segment *segment = ecalloc(1, sizeof(sf_uri_segment));
        if (!segment) {
            sf_uri_segments_destroy(head);
            return NULL;
        }

        segment->type = SF_NODE_STATIC;
        segment->is_optional = 0;
        segment->param_name = NULL;
        segment->next = NULL;

        /* Check for parameter segment */
        if (*ptr == '{') {
            ptr++; /* Skip '{' */
            const char *param_start = ptr;

            /* Find closing brace */
            while (ptr < end && *ptr != '}' && *ptr != '/') {
                ptr++;
            }

            if (ptr >= end || *ptr != '}') {
                efree(segment);
                sf_uri_segments_destroy(head);
                return NULL; /* Unclosed parameter */
            }

            size_t param_len = ptr - param_start;
            ptr++; /* Skip '}' */

            /* Check for optional marker '?' or wildcard '*' / '...' */
            if (param_len > 0 && param_start[param_len - 1] == '?') {
                segment->type = SF_NODE_PARAM_OPTIONAL;
                segment->is_optional = 1;
                param_len--;
            } else if (param_len > 0 && param_start[param_len - 1] == '*') {
                segment->type = SF_NODE_WILDCARD;
                param_len--;
            } else if (param_len > 3 &&
                       param_start[param_len - 3] == '.' &&
                       param_start[param_len - 2] == '.' &&
                       param_start[param_len - 1] == '.') {
                segment->type = SF_NODE_WILDCARD;
                param_len -= 3;
            } else {
                segment->type = SF_NODE_PARAM;
            }

            segment->param_name = zend_string_init(param_start, param_len, 0);
            segment->value = zend_string_init(seg_start, ptr - seg_start, 0);
        } else {
            /* Static segment - find next '/' or end */
            while (ptr < end && *ptr != '/') {
                ptr++;
            }

            segment->value = zend_string_init(seg_start, ptr - seg_start, 0);
        }

        /* Skip trailing slash */
        if (ptr < end && *ptr == '/') {
            ptr++;
        }

        /* Append to list */
        if (!head) {
            head = segment;
            tail = segment;
        } else {
            tail->next = segment;
            tail = segment;
        }
    }

    return head;
}

void sf_uri_segments_destroy(sf_uri_segment *head)
{
    sf_uri_segment *current = head;
    while (current) {
        sf_uri_segment *next = current->next;
        if (current->value) {
            zend_string_release(current->value);
        }
        if (current->param_name) {
            zend_string_release(current->param_name);
        }
        efree(current);
        current = next;
    }
}

/* ============================================================================
 * Trie Insertion
 * ============================================================================ */

static sf_trie_node *sf_trie_get_or_create_static_child(sf_trie_node *parent, zend_string *segment)
{
    sf_trie_node *child = NULL;

    /* Initialize children hash table if needed */
    if (!parent->static_children) {
        ALLOC_HASHTABLE(parent->static_children);
        zend_hash_init(parent->static_children, SF_STATIC_CHILDREN_INITIAL_SIZE, NULL, NULL, 0);
    }

    /* Look for existing child */
    zval *existing = zend_hash_find(parent->static_children, segment);
    if (existing) {
        return (sf_trie_node *)Z_PTR_P(existing);
    }

    /* Create new child */
    child = sf_trie_node_create(SF_NODE_STATIC);
    if (!child) {
        return NULL;
    }

    child->segment = zend_string_copy(segment);
    child->depth = parent->depth + 1;

    /* Add to parent's children */
    zval zv;
    ZVAL_PTR(&zv, child);
    zend_hash_add(parent->static_children, segment, &zv);

    return child;
}

static sf_trie_node *sf_trie_get_or_create_param_child(sf_trie_node *parent,
                                                        sf_node_type type,
                                                        zend_string *param_name)
{
    sf_trie_node **child_ptr;

    switch (type) {
        case SF_NODE_PARAM:
            child_ptr = &parent->param_child;
            break;
        case SF_NODE_PARAM_OPTIONAL:
            child_ptr = &parent->optional_child;
            break;
        case SF_NODE_WILDCARD:
            child_ptr = &parent->wildcard_child;
            break;
        default:
            return NULL;
    }

    /* Check for existing child with same type */
    if (*child_ptr) {
        /* Verify parameter name matches */
        if (!zend_string_equals((*child_ptr)->param_name, param_name)) {
            php_error_docref(NULL, E_WARNING,
                "Signalforge\\Routing: Conflicting parameter names '%s' vs '%s' at same position",
                ZSTR_VAL((*child_ptr)->param_name), ZSTR_VAL(param_name));
        }
        return *child_ptr;
    }

    /* Create new child */
    sf_trie_node *child = sf_trie_node_create(type);
    if (!child) {
        return NULL;
    }

    child->param_name = zend_string_copy(param_name);
    child->depth = parent->depth + 1;
    *child_ptr = child;

    return child;
}

zend_bool sf_trie_insert_segments(sf_trie_node *root, sf_uri_segment *segments, sf_route *route)
{
    sf_trie_node *current = root;
    sf_uri_segment *seg = segments;

    while (seg) {
        sf_trie_node *next = NULL;

        switch (seg->type) {
            case SF_NODE_STATIC:
                next = sf_trie_get_or_create_static_child(current, seg->value);
                break;

            case SF_NODE_PARAM:
            case SF_NODE_PARAM_OPTIONAL:
            case SF_NODE_WILDCARD:
                next = sf_trie_get_or_create_param_child(current, seg->type, seg->param_name);
                break;

            default:
                return 0;
        }

        if (!next) {
            return 0;
        }

        current = next;
        seg = seg->next;
    }

    /* Mark as terminal and attach route */
    if (current->is_terminal && current->route) {
        php_error_docref(NULL, E_WARNING,
            "Signalforge\\Routing: Duplicate route definition for '%s'",
            ZSTR_VAL(route->uri));
        /* Replace existing route */
        sf_route_release(current->route);
    }

    current->is_terminal = 1;
    current->route = route;
    sf_route_addref(route);

    return 1;
}

zend_bool sf_trie_insert(sf_router *router, sf_http_method method,
                         const char *uri, size_t uri_len, sf_route *route)
{
    sf_trie_node *root;
    sf_uri_segment *segments;
    zend_bool result;

    if (!router || !uri || !route) {
        return 0;
    }

    if (router->is_immutable) {
        php_error_docref(NULL, E_WARNING,
            "Signalforge\\Routing: Cannot modify router during request execution");
        return 0;
    }

    /* Parse URI into segments */
    segments = sf_parse_uri(uri, uri_len);
    if (!segments && uri_len > 1) { /* Empty/root URI is valid */
        return 0;
    }

    /* Write lock: inserting routes modifies router state */
    SF_ROUTER_WRLOCK(router);

    /* Handle ANY method - insert into all tries */
    if (method == SF_METHOD_ANY) {
        for (int i = 0; i < SF_METHOD_ANY; i++) {
            root = router->method_tries[i];
            if (!sf_trie_insert_segments(root, segments, route)) {
                sf_uri_segments_destroy(segments);
                SF_ROUTER_UNLOCK_WR(router);
                return 0;
            }
        }
    } else {
        root = router->method_tries[method];
        result = sf_trie_insert_segments(root, segments, route);
        if (!result) {
            sf_uri_segments_destroy(segments);
            SF_ROUTER_UNLOCK_WR(router);
            return 0;
        }
    }

    sf_uri_segments_destroy(segments);

    /* Track named route */
    if (route->name) {
        zval zv;
        ZVAL_PTR(&zv, route);
        zend_hash_update(router->named_routes, route->name, &zv);
    }

    /* Track in all routes */
    zval rv;
    ZVAL_PTR(&rv, route);
    zend_hash_next_index_insert(router->all_routes, &rv);
    router->route_count++;

    SF_ROUTER_UNLOCK_WR(router);

    return 1;
}

/* ============================================================================
 * Route Registration (High-Level API)
 * ============================================================================ */

sf_route *sf_router_add_route(sf_router *router, sf_http_method method,
                              zend_string *uri, zval *handler)
{
    sf_route *route;

    if (!router || !uri || !handler) {
        return NULL;
    }

    route = sf_route_create();
    if (!route) {
        return NULL;
    }

    route->uri = zend_string_copy(uri);
    route->method = method;
    ZVAL_COPY(&route->handler, handler);

    /* Apply current group settings if any */
    if (router->current_group) {
        sf_route_apply_group(route, router->current_group);
    }

    /* Build effective URI with group prefix */
    zend_string *effective_uri = uri;
    if (router->current_group && router->current_group->prefix) {
        smart_str full_uri = {0};
        smart_str_append(&full_uri, router->current_group->prefix);
        if (ZSTR_LEN(uri) > 0 && ZSTR_VAL(uri)[0] != '/') {
            smart_str_appendc(&full_uri, '/');
        }
        smart_str_append(&full_uri, uri);
        smart_str_0(&full_uri);
        effective_uri = full_uri.s;
    }

    /* Insert into trie */
    if (!sf_trie_insert(router, method, ZSTR_VAL(effective_uri), ZSTR_LEN(effective_uri), route)) {
        if (effective_uri != uri) {
            zend_string_release(effective_uri);
        }
        sf_route_release(route);
        return NULL;
    }

    if (effective_uri != uri) {
        zend_string_release(effective_uri);
    }

    return route;
}

void sf_route_set_name(sf_route *route, zend_string *name)
{
    if (!route || !name) {
        return;
    }

    if (route->name) {
        zend_string_release(route->name);
    }

    route->name = zend_string_copy(name);
}

void sf_route_add_middleware(sf_route *route, zend_string *name, zval *params)
{
    sf_middleware_entry *entry;

    if (!route || !name) {
        return;
    }

    entry = sf_middleware_create(name);
    if (!entry) {
        return;
    }

    if (params && !Z_ISUNDEF_P(params)) {
        ZVAL_COPY(&entry->parameters, params);
    }

    /* Append to list */
    if (!route->middleware_head) {
        route->middleware_head = entry;
        route->middleware_tail = entry;
    } else {
        route->middleware_tail->next = entry;
        route->middleware_tail = entry;
    }

    route->middleware_count++;
}

void sf_route_set_middleware(sf_route *route, zval *middleware)
{
    if (!route || !middleware || Z_TYPE_P(middleware) != IS_ARRAY) {
        return;
    }

    zval *entry;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(middleware), entry) {
        if (Z_TYPE_P(entry) == IS_STRING) {
            sf_route_add_middleware(route, Z_STR_P(entry), NULL);
        } else if (Z_TYPE_P(entry) == IS_ARRAY) {
            zval *name = zend_hash_index_find(Z_ARRVAL_P(entry), 0);
            zval *params = zend_hash_index_find(Z_ARRVAL_P(entry), 1);
            if (name && Z_TYPE_P(name) == IS_STRING) {
                sf_route_add_middleware(route, Z_STR_P(name), params);
            }
        }
    } ZEND_HASH_FOREACH_END();
}

void sf_route_set_where(sf_route *route, zend_string *param, zend_string *pattern)
{
    if (!route || !param || !pattern) {
        return;
    }

    /* Initialize wheres hash table if needed */
    if (!route->wheres) {
        ALLOC_HASHTABLE(route->wheres);
        zend_hash_init(route->wheres, SF_CONSTRAINTS_INITIAL_SIZE, NULL, sf_constraint_hash_dtor, 0);
    }

    /* Create constraint */
    sf_param_constraint *constraint = sf_constraint_create(param);
    if (!constraint) {
        return;
    }

    if (!sf_constraint_set_pattern(constraint, pattern)) {
        sf_constraint_destroy(constraint);
        return;
    }

    /* Store in hash table */
    zval zv;
    ZVAL_PTR(&zv, constraint);
    zend_hash_update(route->wheres, param, &zv);
}

void sf_route_set_default(sf_route *route, zend_string *param, zval *value)
{
    if (!route || !param || !value) {
        return;
    }

    /* Initialize defaults hash table if needed */
    if (!route->defaults) {
        ALLOC_HASHTABLE(route->defaults);
        zend_hash_init(route->defaults, SF_DEFAULTS_INITIAL_SIZE, NULL, ZVAL_PTR_DTOR, 0);
    }

    zval copy;
    ZVAL_COPY(&copy, value);
    zend_hash_update(route->defaults, param, &copy);
}

void sf_route_set_domain(sf_route *route, zend_string *domain)
{
    if (!route || !domain) {
        return;
    }

    if (route->domain) {
        zend_string_release(route->domain);
    }

    if (route->domain_regex) {
        pcre2_code_free(route->domain_regex);
        route->domain_regex = NULL;
    }

    route->domain = zend_string_copy(domain);

    /* Check if domain contains parameters and compile regex if needed */
    if (memchr(ZSTR_VAL(domain), '{', ZSTR_LEN(domain))) {
        /* Build regex pattern from domain with parameters */
        smart_str pattern = {0};
        smart_str_appendc(&pattern, '^');

        const char *ptr = ZSTR_VAL(domain);
        const char *end = ptr + ZSTR_LEN(domain);

        while (ptr < end) {
            if (*ptr == '{') {
                ptr++;
                const char *param_start = ptr;
                while (ptr < end && *ptr != '}') {
                    ptr++;
                }

                /* Validate we found closing brace */
                if (ptr >= end) {
                    /* Unclosed parameter - treat remaining as literal */
                    smart_str_appendc(&pattern, '{');
                    smart_str_appendl(&pattern, param_start, end - param_start);
                    break;
                }

                /* Check for optional marker */
                size_t param_len = ptr - param_start;
                zend_bool is_optional = 0;
                if (param_len > 0 && param_start[param_len - 1] == '?') {
                    is_optional = 1;
                    param_len--;
                }
                if (is_optional) {
                    smart_str_appends(&pattern, "(?P<");
                    smart_str_appendl(&pattern, param_start, param_len);
                    smart_str_appends(&pattern, ">[^.]+)?");
                } else {
                    smart_str_appends(&pattern, "(?P<");
                    smart_str_appendl(&pattern, param_start, param_len);
                    smart_str_appends(&pattern, ">[^.]+)");
                }
                ptr++; /* Skip } - now safe because we verified ptr < end above */
            } else if (*ptr == '.') {
                smart_str_appends(&pattern, "\\.");
                ptr++;
            } else {
                smart_str_appendc(&pattern, *ptr);
                ptr++;
            }
        }

        smart_str_appendc(&pattern, '$');
        smart_str_0(&pattern);

        /* Compile regex */
        int errcode;
        PCRE2_SIZE erroffset;

        route->domain_regex = pcre2_compile(
            (PCRE2_SPTR)ZSTR_VAL(pattern.s),
            ZSTR_LEN(pattern.s),
            PCRE2_UTF | PCRE2_UCP,
            &errcode,
            &erroffset,
            NULL
        );

        smart_str_free(&pattern);
    }
}

/* ============================================================================
 * Route Group Functions
 * ============================================================================ */

void sf_router_begin_group(sf_router *router, sf_route_group *group)
{
    if (!router || !group) {
        return;
    }

    /* Link to parent group */
    group->parent = router->current_group;

    /* Inherit from parent if exists */
    if (router->current_group) {
        sf_route_group *parent = router->current_group;

        /* Merge prefix */
        if (parent->prefix && group->prefix) {
            smart_str merged = {0};
            smart_str_append(&merged, parent->prefix);
            smart_str_append(&merged, group->prefix);
            smart_str_0(&merged);
            zend_string_release(group->prefix);
            group->prefix = merged.s;
        } else if (parent->prefix && !group->prefix) {
            group->prefix = zend_string_copy(parent->prefix);
        }

        /* Merge namespace */
        if (parent->namespace && group->namespace) {
            smart_str merged = {0};
            smart_str_append(&merged, parent->namespace);
            smart_str_appendc(&merged, '\\');
            smart_str_append(&merged, group->namespace);
            smart_str_0(&merged);
            zend_string_release(group->namespace);
            group->namespace = merged.s;
        } else if (parent->namespace && !group->namespace) {
            group->namespace = zend_string_copy(parent->namespace);
        }

        /* Merge name prefix */
        if (parent->name_prefix && group->name_prefix) {
            smart_str merged = {0};
            smart_str_append(&merged, parent->name_prefix);
            smart_str_append(&merged, group->name_prefix);
            smart_str_0(&merged);
            zend_string_release(group->name_prefix);
            group->name_prefix = merged.s;
        } else if (parent->name_prefix && !group->name_prefix) {
            group->name_prefix = zend_string_copy(parent->name_prefix);
        }

        /* Merge middleware (prepend parent's) */
        if (parent->middleware_head) {
            sf_middleware_entry *cloned = sf_middleware_list_clone(parent->middleware_head);
            if (cloned) {
                /* Find end of cloned list */
                sf_middleware_entry *cloned_tail = cloned;
                while (cloned_tail->next) {
                    cloned_tail = cloned_tail->next;
                }
                /* Append group's middleware */
                cloned_tail->next = group->middleware_head;
                group->middleware_head = cloned;
                if (!group->middleware_tail) {
                    group->middleware_tail = cloned_tail;
                }
            }
        }

        /* Inherit domain if not set */
        if (!group->domain && parent->domain) {
            group->domain = zend_string_copy(parent->domain);
        }
    }

    router->current_group = group;
}

void sf_router_end_group(sf_router *router)
{
    if (!router || !router->current_group) {
        return;
    }

    sf_route_group *current = router->current_group;
    router->current_group = current->parent;
    sf_route_group_destroy(current);
}

void sf_route_apply_group(sf_route *route, sf_route_group *group)
{
    if (!route || !group) {
        return;
    }

    /* Apply name prefix */
    if (group->name_prefix && route->name) {
        smart_str full_name = {0};
        smart_str_append(&full_name, group->name_prefix);
        smart_str_append(&full_name, route->name);
        smart_str_0(&full_name);
        zend_string_release(route->name);
        route->name = full_name.s;
    }

    /* Apply domain */
    if (group->domain && !route->domain) {
        sf_route_set_domain(route, group->domain);
    }

    /* Apply middleware (prepend group's) */
    if (group->middleware_head) {
        sf_middleware_entry *cloned = sf_middleware_list_clone(group->middleware_head);
        if (cloned) {
            /* Find end of cloned list and count entries */
            sf_middleware_entry *cloned_tail = cloned;
            uint16_t cloned_count = 1;
            while (cloned_tail->next) {
                cloned_tail = cloned_tail->next;
                cloned_count++;
            }
            /* Append route's middleware */
            cloned_tail->next = route->middleware_head;
            route->middleware_head = cloned;
            if (!route->middleware_tail) {
                route->middleware_tail = cloned_tail;
            }
            /* Update count */
            route->middleware_count += cloned_count;
        }
    }

    /* Apply wheres */
    if (group->wheres) {
        zend_string *key;
        zval *val;
        ZEND_HASH_FOREACH_STR_KEY_VAL(group->wheres, key, val) {
            if (key && !route->wheres) {
                sf_route_set_where(route, key, Z_STR_P(val));
            } else if (key && !zend_hash_exists(route->wheres, key)) {
                sf_route_set_where(route, key, Z_STR_P(val));
            }
        } ZEND_HASH_FOREACH_END();
    }
}

/* ============================================================================
 * Route Matching
 * ============================================================================ */

/**
 * Optimized hash table lookup with pre-computed hash.
 *
 * This function performs a hash table lookup using a raw string (char*, len)
 * by computing the hash once and doing direct bucket access. This is faster
 * than zend_hash_str_find() for our use case because:
 * 1. We compute the hash inline using the fast DJBX33A algorithm
 * 2. We can compare the pre-computed child segment_hash first (integer compare)
 * 3. String comparison only happens on hash match (collision resolution)
 *
 * Returns the child node pointer, or NULL if not found.
 */
static zend_always_inline sf_trie_node *sf_hash_find_child(
    HashTable *ht, const char *str, size_t len)
{
    zend_ulong h;
    uint32_t nIndex;
    uint32_t idx;
    Bucket *p;
    sf_trie_node *child;

    /* Compute hash using PHP's DJBX33A algorithm */
    h = zend_inline_hash_func(str, len);

    /* Direct bucket access using computed hash */
    nIndex = h | ht->nTableMask;
    idx = HT_HASH(ht, nIndex);

    while (idx != HT_INVALID_IDX) {
        p = HT_HASH_TO_BUCKET(ht, idx);

        /* First compare hash (fast integer compare) */
        if (p->h == h) {
            /* Hash match - now compare the actual key string */
            if (p->key && ZSTR_LEN(p->key) == len &&
                memcmp(ZSTR_VAL(p->key), str, len) == 0) {
                /* Found! Extract the child node pointer */
                return (sf_trie_node *)Z_PTR(p->val);
            }
        }
        idx = Z_NEXT(p->val);
    }

    return NULL;
}

/**
 * Find terminal node through chain of optional children
 * Used when path is exhausted but we may have optional params with defaults
 */
static sf_trie_node *sf_find_terminal_through_optionals(sf_trie_node *node)
{
    if (!node) {
        return NULL;
    }

    if (node->is_terminal) {
        return node;
    }

    /* Traverse through optional children to find terminal */
    if (node->optional_child) {
        return sf_find_terminal_through_optionals(node->optional_child);
    }

    return NULL;
}

/**
 * Internal recursive trie matching
 *
 * This is the core matching algorithm using pointer traversal.
 * Key design: NO regex execution during traversal. Parameters are collected
 * as raw strings and validated only at terminal nodes.
 */
static sf_trie_node *sf_trie_match_internal(sf_trie_node *node,
                                            const char *path,
                                            size_t path_len,
                                            HashTable *params,
                                            size_t depth)
{
    const char *ptr = path;
    const char *end = path + path_len;

    /* Skip leading slash - virtually all URIs have a leading slash */
    if (EXPECTED(ptr < end && *ptr == '/')) {
        ptr++;
    }

    /* Empty path (root) - check if current node is terminal */
    if (UNEXPECTED(ptr >= end || (ptr + 1 == end && *ptr == '/'))) {
        if (node->is_terminal) {
            return node;
        }
        /* Check for terminal through chain of optional children */
        sf_trie_node *terminal = sf_find_terminal_through_optionals(node->optional_child);
        if (terminal) {
            return terminal;
        }
        return NULL;
    }

    /* Find current segment */
    const char *seg_start = ptr;
    while (ptr < end && *ptr != '/') {
        ptr++;
    }
    size_t seg_len = ptr - seg_start;

    /* Remaining path after this segment */
    const char *remaining = ptr;
    size_t remaining_len = end - ptr;

    sf_trie_node *result = NULL;

    /* Priority order: Static > Param > Optional > Wildcard */

    /* 1. Try static children first (most common case - routes like /api/users/list) */
    if (EXPECTED(node->static_children != NULL)) {
        /*
         * Use optimized hash lookup with direct bucket access.
         * sf_hash_find_child() computes the hash once and does direct bucket
         * traversal, which is faster than zend_hash_str_find() for our use case.
         */
        sf_trie_node *child = sf_hash_find_child(node->static_children, seg_start, seg_len);

        if (EXPECTED(child != NULL)) {
            result = sf_trie_match_internal(child, remaining, remaining_len, params, depth + 1);
            if (EXPECTED(result != NULL)) {
                return result;
            }
        }
    }

    /* 2. Try required parameter child (common in REST APIs: /users/{id}) */
    if (node->param_child) {
        /* Store parameter value */
        zval param_val;
        ZVAL_STRINGL(&param_val, seg_start, seg_len);
        zend_hash_update(params, node->param_child->param_name, &param_val);

        result = sf_trie_match_internal(node->param_child, remaining, remaining_len, params, depth + 1);
        if (EXPECTED(result != NULL)) {
            return result;
        }

        /* Backtrack - remove parameter */
        zend_hash_del(params, node->param_child->param_name);
    }

    /* 3. Try optional parameter child - less common than required params */
    if (UNEXPECTED(node->optional_child != NULL)) {
        /* First try with parameter value */
        zval param_val;
        ZVAL_STRINGL(&param_val, seg_start, seg_len);
        zend_hash_update(params, node->optional_child->param_name, &param_val);

        result = sf_trie_match_internal(node->optional_child, remaining, remaining_len, params, depth + 1);
        if (result) {
            return result;
        }

        /* Backtrack */
        zend_hash_del(params, node->optional_child->param_name);

        /* Try skipping optional (use current segment as next node's input) */
        if (node->optional_child->is_terminal) {
            /* Match current position without consuming the segment */
            /* This handles cases like /users/{id?} matching /users */
            return NULL;
        }
    }

    /* 4. Try wildcard (consumes all remaining path) - rare, used for catch-all routes */
    if (UNEXPECTED(node->wildcard_child != NULL)) {
        /* Wildcard captures everything remaining including this segment */
        zval param_val;
        ZVAL_STRINGL(&param_val, seg_start, end - seg_start);
        zend_hash_update(params, node->wildcard_child->param_name, &param_val);

        if (node->wildcard_child->is_terminal) {
            return node->wildcard_child;
        }
    }

    return NULL;
}

sf_match_result *sf_trie_match(sf_router *router, sf_http_method method,
                               const char *uri, size_t uri_len)
{
    sf_match_result *result;
    sf_trie_node *root;
    sf_trie_node *matched_node;

    /* Null checks - should virtually never fail in production */
    if (UNEXPECTED(!router || !uri)) {
        return NULL;
    }

    result = sf_match_result_create();
    if (UNEXPECTED(!result)) {
        return NULL;
    }

    /* Get method-specific trie - invalid method is extremely rare */
    if (UNEXPECTED(method >= SF_METHOD_COUNT)) {
        result->matched = 0;
        result->error = zend_string_init("Invalid HTTP method", sizeof("Invalid HTTP method") - 1, 0);
        return result;
    }

    /* Read lock: matching is a read-only operation */
    SF_ROUTER_RDLOCK(router);

    root = router->method_tries[method];
    matched_node = sf_trie_match_internal(root, uri, uri_len, result->params, 0);

    /* Most requests should match a defined route */
    if (EXPECTED(matched_node != NULL && matched_node->is_terminal)) {
        /* Validate parameters against constraints - usually passes */
        if (EXPECTED(sf_validate_params(matched_node->route, result->params))) {
            result->matched = 1;
            result->route = matched_node->route;

            /* Apply default values for missing optional parameters */
            if (UNEXPECTED(matched_node->route->defaults != NULL)) {
                zend_string *key;
                zval *val;
                ZEND_HASH_FOREACH_STR_KEY_VAL(matched_node->route->defaults, key, val) {
                    if (key && !zend_hash_exists(result->params, key)) {
                        zval copy;
                        ZVAL_COPY(&copy, val);
                        zend_hash_add(result->params, key, &copy);
                    }
                } ZEND_HASH_FOREACH_END();
            }
        } else {
            result->matched = 0;
            result->error = zend_string_init("Parameter constraint validation failed",
                sizeof("Parameter constraint validation failed") - 1, 0);
        }
    } else {
        /* Check fallback route */
        if (router->fallback_route) {
            result->matched = 1;
            result->route = router->fallback_route;
        } else {
            result->matched = 0;
            result->error = zend_string_init("Route not found",
                sizeof("Route not found") - 1, 0);
        }
    }

    SF_ROUTER_UNLOCK_RD(router);

    return result;
}

sf_match_result *sf_trie_match_with_domain(sf_router *router, sf_http_method method,
                                           const char *uri, size_t uri_len,
                                           const char *domain, size_t domain_len)
{
    sf_match_result *result = sf_trie_match(router, method, uri, uri_len);

    if (!result || !result->matched || !result->route) {
        return result;
    }

    /* Validate domain if route has domain constraint */
    if (result->route->domain) {
        if (result->route->domain_regex) {
            /* Match against compiled regex */
            pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(
                result->route->domain_regex, NULL
            );

            int rc = pcre2_match(
                result->route->domain_regex,
                (PCRE2_SPTR)domain,
                domain_len,
                0,
                0,
                match_data,
                NULL
            );

            if (rc < 0) {
                pcre2_match_data_free(match_data);
                result->matched = 0;
                result->route = NULL;
                if (result->error) {
                    zend_string_release(result->error);
                }
                result->error = zend_string_init("Domain does not match",
                    sizeof("Domain does not match") - 1, 0);
                return result;
            }

            /* Extract named captures as parameters */
            uint32_t name_count;
            pcre2_pattern_info(result->route->domain_regex, PCRE2_INFO_NAMECOUNT, &name_count);

            if (name_count > 0) {
                PCRE2_SPTR name_table;
                uint32_t name_entry_size;
                pcre2_pattern_info(result->route->domain_regex, PCRE2_INFO_NAMETABLE, &name_table);
                pcre2_pattern_info(result->route->domain_regex, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);

                PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

                for (uint32_t i = 0; i < name_count; i++) {
                    int n = (name_table[0] << 8) | name_table[1];
                    PCRE2_SPTR name_start = name_table + 2;

                    if (ovector[2*n] != PCRE2_UNSET) {
                        zend_string *name = zend_string_init((char *)name_start,
                            strlen((char *)name_start), 0);
                        zval val;
                        ZVAL_STRINGL(&val, domain + ovector[2*n],
                            ovector[2*n+1] - ovector[2*n]);
                        zend_hash_update(result->params, name, &val);
                        zend_string_release(name);
                    }

                    name_table += name_entry_size;
                }
            }

            pcre2_match_data_free(match_data);
        } else {
            /* Simple string comparison */
            if (domain_len != ZSTR_LEN(result->route->domain) ||
                memcmp(domain, ZSTR_VAL(result->route->domain), domain_len) != 0) {
                result->matched = 0;
                result->route = NULL;
                if (result->error) {
                    zend_string_release(result->error);
                }
                result->error = zend_string_init("Domain does not match",
                    sizeof("Domain does not match") - 1, 0);
            }
        }
    }

    return result;
}

zend_bool sf_validate_params(sf_route *route, HashTable *params)
{
    /* Null checks - defensive, should rarely fail */
    if (UNEXPECTED(!route || !params)) {
        return 1; /* No constraints = always valid */
    }

    /* Most routes don't have constraints, so this is the fast path */
    if (EXPECTED(route->wheres == NULL)) {
        return 1;
    }

    zend_string *key;
    zval *constraint_zv;

    ZEND_HASH_FOREACH_STR_KEY_VAL(route->wheres, key, constraint_zv) {
        if (UNEXPECTED(!key)) continue;

        sf_param_constraint *constraint = (sf_param_constraint *)Z_PTR_P(constraint_zv);
        zval *param_val = zend_hash_find(params, key);

        if (EXPECTED(param_val != NULL && Z_TYPE_P(param_val) == IS_STRING)) {
            /* Constraints usually validate - rejection is the error case */
            if (UNEXPECTED(!sf_constraint_validate(constraint, Z_STR_P(param_val)))) {
                return 0;
            }
        }
    } ZEND_HASH_FOREACH_END();

    return 1;
}

/* ============================================================================
 * URL Generation
 * ============================================================================ */

zend_string *sf_router_url(sf_router *router, zend_string *name, HashTable *params)
{
    if (!router || !name) {
        return NULL;
    }

    /* Read lock: URL generation only reads router state */
    SF_ROUTER_RDLOCK(router);

    zval *route_zv = zend_hash_find(router->named_routes, name);
    if (!route_zv) {
        SF_ROUTER_UNLOCK_RD(router);
        return NULL;
    }

    sf_route *route = (sf_route *)Z_PTR_P(route_zv);
    if (!route || !route->uri) {
        SF_ROUTER_UNLOCK_RD(router);
        return NULL;
    }

    /* Build URL by replacing parameters */
    smart_str url = {0};
    const char *ptr = ZSTR_VAL(route->uri);
    const char *end = ptr + ZSTR_LEN(route->uri);

    while (ptr < end) {
        if (*ptr == '{') {
            ptr++;
            const char *param_start = ptr;
            while (ptr < end && *ptr != '}') {
                ptr++;
            }

            size_t param_len = ptr - param_start;
            zend_bool is_optional = 0;

            /* Handle optional marker */
            if (param_len > 0 && param_start[param_len - 1] == '?') {
                is_optional = 1;
                param_len--;
            }
            /* Handle wildcard marker */
            if (param_len > 0 && param_start[param_len - 1] == '*') {
                param_len--;
            }

            /*
             * Use zend_hash_str_find() to avoid allocating temporary zend_strings
             * for parameter lookups during URL generation.
             */
            zval *param_val = params ? zend_hash_str_find(params, param_start, param_len) : NULL;

            if (param_val) {
                if (Z_TYPE_P(param_val) == IS_STRING) {
                    smart_str_append(&url, Z_STR_P(param_val));
                } else {
                    zend_string *str_val = zval_get_string(param_val);
                    smart_str_append(&url, str_val);
                    zend_string_release(str_val);
                }
            } else if (!is_optional) {
                /* Required parameter missing - check defaults */
                zval *default_val = route->defaults ?
                    zend_hash_str_find(route->defaults, param_start, param_len) : NULL;
                if (default_val) {
                    zend_string *str_val = zval_get_string(default_val);
                    smart_str_append(&url, str_val);
                    zend_string_release(str_val);
                } else {
                    smart_str_free(&url);
                    SF_ROUTER_UNLOCK_RD(router);
                    php_error_docref(NULL, E_WARNING,
                        "Signalforge\\Routing: Missing required parameter '%.*s' for route '%s'",
                        (int)param_len, param_start, ZSTR_VAL(name));
                    return NULL;
                }
            }

            ptr++; /* Skip } */
        } else {
            smart_str_appendc(&url, *ptr);
            ptr++;
        }
    }

    smart_str_0(&url);
    SF_ROUTER_UNLOCK_RD(router);

    return url.s;
}

zend_bool sf_router_has_route(sf_router *router, zend_string *name)
{
    if (!router || !name) {
        return 0;
    }

    /* Read lock: checking route existence is read-only */
    SF_ROUTER_RDLOCK(router);
    zend_bool exists = zend_hash_exists(router->named_routes, name);
    SF_ROUTER_UNLOCK_RD(router);

    return exists;
}

sf_route *sf_router_get_route(sf_router *router, zend_string *name)
{
    sf_route *route = NULL;

    if (!router || !name) {
        return NULL;
    }

    /* Read lock: getting route is read-only */
    SF_ROUTER_RDLOCK(router);
    zval *route_zv = zend_hash_find(router->named_routes, name);
    if (route_zv) {
        route = (sf_route *)Z_PTR_P(route_zv);
        /*
         * Note: In ZTS builds, the caller should ensure the route remains
         * valid after this call. For safety, we could add a reference here
         * but that would require the caller to release it.
         */
    }
    SF_ROUTER_UNLOCK_RD(router);

    return route;
}

/* ============================================================================
 * Index Rebuilding (after cache load)
 * ============================================================================ */

static void sf_rebuild_index_node(sf_router *router, sf_trie_node *node)
{
    if (!node) return;

    /* If terminal, add to named routes and all routes */
    if (node->is_terminal && node->route) {
        if (node->route->name) {
            zval zv;
            ZVAL_PTR(&zv, node->route);
            zend_hash_update(router->named_routes, node->route->name, &zv);
        }
        zval rv;
        ZVAL_PTR(&rv, node->route);
        zend_hash_next_index_insert(router->all_routes, &rv);
        router->route_count++;
    }

    /* Traverse static children */
    if (node->static_children) {
        zval *child_zv;
        ZEND_HASH_FOREACH_VAL(node->static_children, child_zv) {
            sf_rebuild_index_node(router, (sf_trie_node *)Z_PTR_P(child_zv));
        } ZEND_HASH_FOREACH_END();
    }

    /* Traverse param children */
    sf_rebuild_index_node(router, node->param_child);
    sf_rebuild_index_node(router, node->optional_child);
    sf_rebuild_index_node(router, node->wildcard_child);
}

static void sf_router_rebuild_index(sf_router *router)
{
    if (!router) return;

    /* Clear existing indexes */
    zend_hash_clean(router->named_routes);
    zend_hash_clean(router->all_routes);
    router->route_count = 0;

    /* Traverse all method tries */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        sf_rebuild_index_node(router, router->method_tries[i]);
    }
}

/* ============================================================================
 * Binary Serialization (Route Caching)
 *
 * Binary format for fast loading:
 * - Header: "SFRC" (4) + version (1) + flags (1) + route_count (4) + reserved (6) = 16 bytes
 * - For each method trie: serialized node tree
 * - Node: type (1) + flags (1) + optional data based on flags
 * ============================================================================ */

#define SF_CACHE_MAGIC "SFRC"
#define SF_CACHE_VERSION 1

/* Node flags for binary format */
#define SF_FLAG_TERMINAL        (1 << 0)
#define SF_FLAG_HAS_SEGMENT     (1 << 1)
#define SF_FLAG_HAS_PARAM_NAME  (1 << 2)
#define SF_FLAG_HAS_CONSTRAINT  (1 << 3)
#define SF_FLAG_HAS_STATIC      (1 << 4)
#define SF_FLAG_HAS_PARAM       (1 << 5)
#define SF_FLAG_HAS_OPTIONAL    (1 << 6)
#define SF_FLAG_HAS_WILDCARD    (1 << 7)

/* Binary buffer writer helpers */
typedef struct {
    char *data;
    size_t len;
    size_t capacity;
    zend_bool failed;  /* Track allocation failures */
} sf_write_buffer;

/* Maximum buffer size to prevent excessive memory allocation (64MB) */
#define SF_MAX_BUFFER_SIZE (64 * 1024 * 1024)

/* Initial serialization buffer size (64KB) */
#define SF_INITIAL_BUFFER_SIZE (64 * 1024)

static void sf_buf_init(sf_write_buffer *buf, size_t initial_capacity)
{
    buf->data = emalloc(initial_capacity);
    buf->len = 0;
    buf->capacity = initial_capacity;
    buf->failed = 0;
}

static void sf_buf_ensure(sf_write_buffer *buf, size_t need)
{
    size_t new_capacity;
    size_t required;

    if (buf->failed) {
        return;  /* Already in error state */
    }

    /* Check for overflow in addition */
    if (need > SIZE_MAX - buf->len) {
        buf->failed = 1;
        return;
    }

    required = buf->len + need;
    if (required <= buf->capacity) {
        return;  /* Already have enough space */
    }

    /* Check if required size exceeds maximum */
    if (required > SF_MAX_BUFFER_SIZE) {
        buf->failed = 1;
        return;
    }

    /* Calculate new capacity with overflow protection */
    new_capacity = buf->capacity;
    while (new_capacity < required) {
        if (new_capacity > SF_MAX_BUFFER_SIZE / 2) {
            new_capacity = SF_MAX_BUFFER_SIZE;
            break;
        }
        new_capacity *= 2;
    }

    buf->data = erealloc(buf->data, new_capacity);
    buf->capacity = new_capacity;
}

static void sf_buf_write_u8(sf_write_buffer *buf, uint8_t val)
{
    sf_buf_ensure(buf, 1);
    if (buf->failed) return;
    buf->data[buf->len++] = val;
}

static void sf_buf_write_u16(sf_write_buffer *buf, uint16_t val)
{
    sf_buf_ensure(buf, 2);
    if (buf->failed) return;
    buf->data[buf->len++] = (val >> 8) & 0xFF;
    buf->data[buf->len++] = val & 0xFF;
}

static void sf_buf_write_u32(sf_write_buffer *buf, uint32_t val)
{
    sf_buf_ensure(buf, 4);
    if (buf->failed) return;
    buf->data[buf->len++] = (val >> 24) & 0xFF;
    buf->data[buf->len++] = (val >> 16) & 0xFF;
    buf->data[buf->len++] = (val >> 8) & 0xFF;
    buf->data[buf->len++] = val & 0xFF;
}

static void sf_buf_write_bytes(sf_write_buffer *buf, const char *data, size_t len)
{
    sf_buf_ensure(buf, len);
    if (buf->failed) return;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
}

static void sf_buf_write_string(sf_write_buffer *buf, zend_string *str)
{
    if (str && ZSTR_LEN(str) > 0) {
        uint16_t len = (uint16_t)(ZSTR_LEN(str) > 65535 ? 65535 : ZSTR_LEN(str));
        sf_buf_write_u16(buf, len);
        sf_buf_write_bytes(buf, ZSTR_VAL(str), len);
    } else {
        sf_buf_write_u16(buf, 0);
    }
}

/* Binary buffer reader helpers */
typedef struct {
    const char *data;
    size_t len;
    size_t pos;
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

/* Serialize route to binary */
static void sf_serialize_route_bin(sf_write_buffer *buf, sf_route *route)
{
    /* URI */
    sf_buf_write_string(buf, route->uri);

    /* Name */
    sf_buf_write_string(buf, route->name);

    /* Handler - only serialize if it's a string or array callable */
    if (!Z_ISUNDEF(route->handler) && Z_TYPE(route->handler) == IS_STRING) {
        sf_buf_write_u8(buf, 1); /* String handler */
        sf_buf_write_string(buf, Z_STR(route->handler));
    } else if (!Z_ISUNDEF(route->handler) && Z_TYPE(route->handler) == IS_ARRAY) {
        /* Array handler [class, method] - serialize as "class::method" */
        zval *cls = zend_hash_index_find(Z_ARRVAL(route->handler), 0);
        zval *mtd = zend_hash_index_find(Z_ARRVAL(route->handler), 1);
        if (cls && mtd && Z_TYPE_P(cls) == IS_STRING && Z_TYPE_P(mtd) == IS_STRING) {
            sf_buf_write_u8(buf, 2); /* Array handler */
            sf_buf_write_string(buf, Z_STR_P(cls));
            sf_buf_write_string(buf, Z_STR_P(mtd));
        } else {
            sf_buf_write_u8(buf, 0); /* Cannot serialize */
        }
    } else {
        sf_buf_write_u8(buf, 0); /* No serializable handler (closure) */
    }

    /* Method */
    sf_buf_write_u8(buf, (uint8_t)route->method);

    /* Middleware */
    sf_buf_write_u16(buf, route->middleware_count);
    sf_middleware_entry *mw = route->middleware_head;
    while (mw) {
        sf_buf_write_string(buf, mw->name);
        mw = mw->next;
    }

    /* Wheres (constraints) */
    uint16_t where_count = route->wheres ? zend_hash_num_elements(route->wheres) : 0;
    sf_buf_write_u16(buf, where_count);
    if (route->wheres) {
        zend_string *key;
        zval *val;
        ZEND_HASH_FOREACH_STR_KEY_VAL(route->wheres, key, val) {
            if (key) {
                sf_param_constraint *c = (sf_param_constraint *)Z_PTR_P(val);
                sf_buf_write_string(buf, key);
                sf_buf_write_string(buf, c->pattern);
            }
        } ZEND_HASH_FOREACH_END();
    }

    /* Defaults */
    uint16_t default_count = route->defaults ? zend_hash_num_elements(route->defaults) : 0;
    sf_buf_write_u16(buf, default_count);
    if (route->defaults) {
        zend_string *key;
        zval *val;
        ZEND_HASH_FOREACH_STR_KEY_VAL(route->defaults, key, val) {
            if (key) {
                sf_buf_write_string(buf, key);
                /* Serialize value as string */
                zend_string *str_val = zval_get_string(val);
                sf_buf_write_string(buf, str_val);
                zend_string_release(str_val);
            }
        } ZEND_HASH_FOREACH_END();
    }

    /* Domain */
    sf_buf_write_string(buf, route->domain);

    /* Is fallback */
    sf_buf_write_u8(buf, route->is_fallback ? 1 : 0);
}

/* Serialize trie node recursively to binary */
static void sf_serialize_node_bin(sf_write_buffer *buf, sf_trie_node *node)
{
    if (!node) {
        sf_buf_write_u8(buf, 0xFF); /* Null marker */
        return;
    }

    /* Build flags */
    uint8_t flags = 0;
    if (node->is_terminal && node->route) flags |= SF_FLAG_TERMINAL;
    if (node->segment) flags |= SF_FLAG_HAS_SEGMENT;
    if (node->param_name) flags |= SF_FLAG_HAS_PARAM_NAME;
    if (node->constraint) flags |= SF_FLAG_HAS_CONSTRAINT;
    if (node->static_children && zend_hash_num_elements(node->static_children) > 0) {
        flags |= SF_FLAG_HAS_STATIC;
    }
    if (node->param_child) flags |= SF_FLAG_HAS_PARAM;
    if (node->optional_child) flags |= SF_FLAG_HAS_OPTIONAL;
    if (node->wildcard_child) flags |= SF_FLAG_HAS_WILDCARD;

    /* Write type and flags */
    sf_buf_write_u8(buf, (uint8_t)node->type);
    sf_buf_write_u8(buf, flags);

    /* Segment */
    if (flags & SF_FLAG_HAS_SEGMENT) {
        sf_buf_write_string(buf, node->segment);
    }

    /* Param name */
    if (flags & SF_FLAG_HAS_PARAM_NAME) {
        sf_buf_write_string(buf, node->param_name);
    }

    /* Constraint pattern and validator type */
    if (flags & SF_FLAG_HAS_CONSTRAINT) {
        sf_buf_write_string(buf, node->constraint->pattern);
        sf_buf_write_u8(buf, (uint8_t)node->constraint->validator);
    }

    /* Route (if terminal) */
    if (flags & SF_FLAG_TERMINAL) {
        sf_serialize_route_bin(buf, node->route);
    }

    /* Static children */
    if (flags & SF_FLAG_HAS_STATIC) {
        uint16_t count = (uint16_t)zend_hash_num_elements(node->static_children);
        sf_buf_write_u16(buf, count);
        zend_string *key;
        zval *child_zv;
        ZEND_HASH_FOREACH_STR_KEY_VAL(node->static_children, key, child_zv) {
            if (key) {
                sf_buf_write_string(buf, key);
                sf_serialize_node_bin(buf, (sf_trie_node *)Z_PTR_P(child_zv));
            }
        } ZEND_HASH_FOREACH_END();
    }

    /* Param child */
    if (flags & SF_FLAG_HAS_PARAM) {
        sf_serialize_node_bin(buf, node->param_child);
    }

    /* Optional child */
    if (flags & SF_FLAG_HAS_OPTIONAL) {
        sf_serialize_node_bin(buf, node->optional_child);
    }

    /* Wildcard child */
    if (flags & SF_FLAG_HAS_WILDCARD) {
        sf_serialize_node_bin(buf, node->wildcard_child);
    }
}

/* Deserialize route from binary */
static sf_route *sf_deserialize_route_bin(sf_read_buffer *buf)
{
    sf_route *route = sf_route_create();
    if (!route) return NULL;

    /* URI */
    route->uri = sf_buf_read_string(buf);

    /* Name */
    route->name = sf_buf_read_string(buf);

    /* Handler */
    uint8_t handler_type;
    if (!sf_buf_read_u8(buf, &handler_type)) {
        sf_route_destroy(route);
        return NULL;
    }

    if (handler_type == 1) {
        /* String handler */
        zend_string *handler_str = sf_buf_read_string(buf);
        if (handler_str) {
            ZVAL_STR(&route->handler, handler_str);
        }
    } else if (handler_type == 2) {
        /* Array handler [class, method] */
        zend_string *cls = sf_buf_read_string(buf);
        zend_string *mtd = sf_buf_read_string(buf);
        if (cls && mtd) {
            array_init(&route->handler);
            add_next_index_str(&route->handler, cls);
            add_next_index_str(&route->handler, mtd);
        } else {
            if (cls) zend_string_release(cls);
            if (mtd) zend_string_release(mtd);
        }
    }

    /* Method */
    uint8_t method;
    if (!sf_buf_read_u8(buf, &method)) {
        sf_route_destroy(route);
        return NULL;
    }
    route->method = (sf_http_method)method;

    /* Middleware */
    uint16_t mw_count;
    if (!sf_buf_read_u16(buf, &mw_count)) {
        sf_route_destroy(route);
        return NULL;
    }
    for (uint16_t i = 0; i < mw_count; i++) {
        zend_string *mw_name = sf_buf_read_string(buf);
        if (mw_name) {
            sf_route_add_middleware(route, mw_name, NULL);
            zend_string_release(mw_name);
        }
    }

    /* Wheres */
    uint16_t where_count;
    if (!sf_buf_read_u16(buf, &where_count)) {
        sf_route_destroy(route);
        return NULL;
    }
    for (uint16_t i = 0; i < where_count; i++) {
        zend_string *param = sf_buf_read_string(buf);
        zend_string *pattern = sf_buf_read_string(buf);
        if (param && pattern) {
            sf_route_set_where(route, param, pattern);
        }
        if (param) zend_string_release(param);
        if (pattern) zend_string_release(pattern);
    }

    /* Defaults */
    uint16_t default_count;
    if (!sf_buf_read_u16(buf, &default_count)) {
        sf_route_destroy(route);
        return NULL;
    }
    for (uint16_t i = 0; i < default_count; i++) {
        zend_string *key = sf_buf_read_string(buf);
        zend_string *val_str = sf_buf_read_string(buf);
        if (key && val_str) {
            zval val;
            ZVAL_STR(&val, val_str);
            sf_route_set_default(route, key, &val);
            /* val_str is now owned by defaults table */
        } else {
            if (val_str) zend_string_release(val_str);
        }
        if (key) zend_string_release(key);
    }

    /* Domain */
    zend_string *domain = sf_buf_read_string(buf);
    if (domain) {
        sf_route_set_domain(route, domain);
        zend_string_release(domain);
    }

    /* Is fallback */
    uint8_t is_fallback;
    if (!sf_buf_read_u8(buf, &is_fallback)) {
        sf_route_destroy(route);
        return NULL;
    }
    route->is_fallback = is_fallback ? 1 : 0;

    return route;
}

/* Deserialize trie node recursively from binary */
static sf_trie_node *sf_deserialize_node_bin(sf_read_buffer *buf)
{
    uint8_t type;
    if (!sf_buf_read_u8(buf, &type)) return NULL;

    /* Check for null marker */
    if (type == 0xFF) return NULL;

    uint8_t flags;
    if (!sf_buf_read_u8(buf, &flags)) return NULL;

    sf_trie_node *node = sf_trie_node_create((sf_node_type)type);
    if (!node) return NULL;

    /* Segment */
    if (flags & SF_FLAG_HAS_SEGMENT) {
        node->segment = sf_buf_read_string(buf);
    }

    /* Param name */
    if (flags & SF_FLAG_HAS_PARAM_NAME) {
        node->param_name = sf_buf_read_string(buf);
    }

    /* Constraint */
    if (flags & SF_FLAG_HAS_CONSTRAINT) {
        zend_string *pattern = sf_buf_read_string(buf);
        uint8_t validator_type = 0;
        sf_buf_read_u8(buf, &validator_type);

        if (pattern && node->param_name) {
            node->constraint = sf_constraint_create(node->param_name);
            if (node->constraint) {
                sf_constraint_set_pattern(node->constraint, pattern);
                /* Override with serialized validator type for consistency */
                node->constraint->validator = (sf_validator_type)validator_type;
            }
            zend_string_release(pattern);
        } else if (pattern) {
            zend_string_release(pattern);
        }
    }

    /* Route */
    if (flags & SF_FLAG_TERMINAL) {
        node->route = sf_deserialize_route_bin(buf);
        node->is_terminal = node->route ? 1 : 0;
    }

    /* Static children */
    if (flags & SF_FLAG_HAS_STATIC) {
        uint16_t count;
        if (!sf_buf_read_u16(buf, &count)) {
            sf_trie_node_destroy(node);
            return NULL;
        }

        ALLOC_HASHTABLE(node->static_children);
        zend_hash_init(node->static_children, count, NULL, NULL, 0);

        for (uint16_t i = 0; i < count; i++) {
            zend_string *key = sf_buf_read_string(buf);
            sf_trie_node *child = sf_deserialize_node_bin(buf);
            if (key && child) {
                child->depth = node->depth + 1;
                zval zv;
                ZVAL_PTR(&zv, child);
                zend_hash_add(node->static_children, key, &zv);
            }
            if (key) zend_string_release(key);
        }
    }

    /* Param child */
    if (flags & SF_FLAG_HAS_PARAM) {
        node->param_child = sf_deserialize_node_bin(buf);
        if (node->param_child) {
            node->param_child->depth = node->depth + 1;
        }
    }

    /* Optional child */
    if (flags & SF_FLAG_HAS_OPTIONAL) {
        node->optional_child = sf_deserialize_node_bin(buf);
        if (node->optional_child) {
            node->optional_child->depth = node->depth + 1;
        }
    }

    /* Wildcard child */
    if (flags & SF_FLAG_HAS_WILDCARD) {
        node->wildcard_child = sf_deserialize_node_bin(buf);
        if (node->wildcard_child) {
            node->wildcard_child->depth = node->depth + 1;
        }
    }

    return node;
}

zend_string *sf_router_serialize(sf_router *router)
{
    zend_string *result;

    if (!router) {
        return NULL;
    }

    sf_write_buffer buf;
    sf_buf_init(&buf, SF_INITIAL_BUFFER_SIZE);

    /* Header: magic (4) + version (1) + flags (1) + route_count (4) + reserved (6) = 16 bytes */
    sf_buf_write_bytes(&buf, SF_CACHE_MAGIC, 4);
    sf_buf_write_u8(&buf, SF_CACHE_VERSION);
    sf_buf_write_u8(&buf, 0); /* flags - reserved */
    sf_buf_write_u32(&buf, router->route_count);
    /* 6 bytes reserved */
    sf_buf_write_u16(&buf, 0);
    sf_buf_write_u32(&buf, 0);

    /* Read lock: serialization only reads router state */
    SF_ROUTER_RDLOCK(router);

    /* Serialize each method trie */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        sf_serialize_node_bin(&buf, router->method_tries[i]);
        if (buf.failed) {
            SF_ROUTER_UNLOCK_RD(router);
            efree(buf.data);
            php_error_docref(NULL, E_WARNING,
                "Signalforge\\Routing: Route cache serialization failed - buffer overflow");
            return NULL;
        }
    }

    /* Serialize fallback route if exists */
    if (router->fallback_route) {
        sf_buf_write_u8(&buf, 1);
        sf_serialize_route_bin(&buf, router->fallback_route);
    } else {
        sf_buf_write_u8(&buf, 0);
    }

    SF_ROUTER_UNLOCK_RD(router);

    /* Check for buffer failure before creating result */
    if (buf.failed) {
        efree(buf.data);
        php_error_docref(NULL, E_WARNING,
            "Signalforge\\Routing: Route cache serialization failed - buffer overflow");
        return NULL;
    }

    /* Create zend_string from buffer */
    result = zend_string_init(buf.data, buf.len, 0);
    efree(buf.data);

    return result;
}

sf_router *sf_router_unserialize(const char *data, size_t len)
{
    if (!data || len < 16) {
        return NULL;
    }

    sf_read_buffer buf = { data, len, 0 };

    /* Verify header */
    if (memcmp(data, SF_CACHE_MAGIC, 4) != 0) {
        php_error_docref(NULL, E_WARNING, "Invalid route cache: bad magic");
        return NULL;
    }
    buf.pos = 4;

    uint8_t version;
    if (!sf_buf_read_u8(&buf, &version) || version != SF_CACHE_VERSION) {
        php_error_docref(NULL, E_WARNING, "Invalid route cache: version mismatch");
        return NULL;
    }

    /* Skip flags and route count and reserved */
    buf.pos = 16;

    /* Create router */
    sf_router *router = emalloc(sizeof(sf_router));
    if (!router) return NULL;

    memset(router, 0, sizeof(sf_router));

    /* Initialize named routes hash table */
    ALLOC_HASHTABLE(router->named_routes);
    zend_hash_init(router->named_routes, SF_NAMED_ROUTES_INITIAL_SIZE, NULL, NULL, 0);

    /* Initialize all routes hash table */
    ALLOC_HASHTABLE(router->all_routes);
    zend_hash_init(router->all_routes, SF_ALL_ROUTES_INITIAL_SIZE, NULL, NULL, 0);

#ifdef ZTS
    router->lock = tsrm_mutex_alloc();
#endif

    /* Deserialize each method trie */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        router->method_tries[i] = sf_deserialize_node_bin(&buf);
        if (!router->method_tries[i]) {
            /* Create empty root node if deserialization failed */
            router->method_tries[i] = sf_trie_node_create(SF_NODE_ROOT);
        }
    }

    /* Rebuild named routes index by traversing tries */
    sf_router_rebuild_index(router);

    /* Deserialize fallback route */
    uint8_t has_fallback;
    if (sf_buf_read_u8(&buf, &has_fallback) && has_fallback) {
        router->fallback_route = sf_deserialize_route_bin(&buf);
    }

    return router;
}

zend_bool sf_router_cache_to_file(sf_router *router, const char *path)
{
    zend_string *serialized = sf_router_serialize(router);
    if (!serialized) {
        return 0;
    }

    php_stream *stream = php_stream_open_wrapper(
        (char *)path, "wb",
        REPORT_ERRORS | STREAM_MUST_SEEK,
        NULL
    );

    if (!stream) {
        zend_string_release(serialized);
        return 0;
    }

    size_t written = php_stream_write(stream, ZSTR_VAL(serialized), ZSTR_LEN(serialized));
    php_stream_close(stream);
    zend_string_release(serialized);

    return written == ZSTR_LEN(serialized);
}

sf_router *sf_router_load_from_file(const char *path)
{
    php_stream *stream = php_stream_open_wrapper(
        (char *)path, "rb",
        REPORT_ERRORS | STREAM_MUST_SEEK,
        NULL
    );

    if (!stream) {
        return NULL;
    }

    zend_string *contents = php_stream_copy_to_mem(stream, PHP_STREAM_COPY_ALL, 0);
    php_stream_close(stream);

    if (!contents) {
        return NULL;
    }

    sf_router *router = sf_router_unserialize(ZSTR_VAL(contents), ZSTR_LEN(contents));
    zend_string_release(contents);

    return router;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

sf_http_method sf_method_from_string(const char *method, size_t len)
{
    if (len == 3) {
        if (strncasecmp(method, "GET", 3) == 0) return SF_METHOD_GET;
        if (strncasecmp(method, "PUT", 3) == 0) return SF_METHOD_PUT;
        if (strncasecmp(method, "ANY", 3) == 0) return SF_METHOD_ANY;
    } else if (len == 4) {
        if (strncasecmp(method, "POST", 4) == 0) return SF_METHOD_POST;
        if (strncasecmp(method, "HEAD", 4) == 0) return SF_METHOD_HEAD;
    } else if (len == 5) {
        if (strncasecmp(method, "PATCH", 5) == 0) return SF_METHOD_PATCH;
    } else if (len == 6) {
        if (strncasecmp(method, "DELETE", 6) == 0) return SF_METHOD_DELETE;
    } else if (len == 7) {
        if (strncasecmp(method, "OPTIONS", 7) == 0) return SF_METHOD_OPTIONS;
    }

    return SF_METHOD_GET; /* Default */
}

const char *sf_method_to_string(sf_http_method method)
{
    static const char *methods[] = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ANY"
    };

    if (method >= SF_METHOD_COUNT) {
        return "GET";
    }

    return methods[method];
}

zend_string *sf_normalize_uri(const char *uri, size_t len, zend_bool strip_trailing)
{
    if (!uri || len == 0) {
        return zend_string_init("/", 1, 0);
    }

    smart_str normalized = {0};

    /* Ensure leading slash */
    if (uri[0] != '/') {
        smart_str_appendc(&normalized, '/');
    }

    /* Copy path, collapsing multiple slashes */
    zend_bool last_was_slash = 0;
    for (size_t i = 0; i < len; i++) {
        if (uri[i] == '/') {
            if (!last_was_slash) {
                smart_str_appendc(&normalized, '/');
                last_was_slash = 1;
            }
        } else {
            smart_str_appendc(&normalized, uri[i]);
            last_was_slash = 0;
        }
    }

    smart_str_0(&normalized);

    /* Strip trailing slash if requested (but keep root) */
    if (strip_trailing && normalized.s && ZSTR_LEN(normalized.s) > 1) {
        if (ZSTR_VAL(normalized.s)[ZSTR_LEN(normalized.s) - 1] == '/') {
            ZSTR_LEN(normalized.s)--;
            ZSTR_VAL(normalized.s)[ZSTR_LEN(normalized.s)] = '\0';
        }
    }

    return normalized.s;
}

void sf_trie_dump(sf_trie_node *node, int depth)
{
    if (!node) {
        return;
    }

    /* Indent */
    for (int i = 0; i < depth; i++) {
        php_printf("  ");
    }

    /* Node info */
    const char *type_names[] = {"STATIC", "PARAM", "OPTIONAL", "WILDCARD", "ROOT"};
    php_printf("[%s]", type_names[node->type]);

    if (node->segment) {
        php_printf(" segment='%s'", ZSTR_VAL(node->segment));
    }

    if (node->param_name) {
        php_printf(" param='%s'", ZSTR_VAL(node->param_name));
    }

    if (node->is_terminal) {
        php_printf(" TERMINAL");
        if (node->route && node->route->name) {
            php_printf(" name='%s'", ZSTR_VAL(node->route->name));
        }
    }

    php_printf("\n");

    /* Dump children */
    if (node->static_children) {
        zval *child_zv;
        ZEND_HASH_FOREACH_VAL(node->static_children, child_zv) {
            sf_trie_dump((sf_trie_node *)Z_PTR_P(child_zv), depth + 1);
        } ZEND_HASH_FOREACH_END();
    }

    sf_trie_dump(node->param_child, depth + 1);
    sf_trie_dump(node->optional_child, depth + 1);
    sf_trie_dump(node->wildcard_child, depth + 1);
}

void sf_route_dump(sf_route *route)
{
    if (!route) {
        php_printf("Route: NULL\n");
        return;
    }

    php_printf("Route {\n");
    php_printf("  uri: %s\n", route->uri ? ZSTR_VAL(route->uri) : "NULL");
    php_printf("  name: %s\n", route->name ? ZSTR_VAL(route->name) : "NULL");
    php_printf("  method: %s\n", sf_method_to_string(route->method));
    php_printf("  middleware_count: %u\n", route->middleware_count);
    php_printf("  is_fallback: %d\n", route->is_fallback);
    php_printf("}\n");
}
