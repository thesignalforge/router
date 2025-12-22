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
    node->parent = NULL;
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
    route->action_namespace = NULL;
    ZVAL_UNDEF(&route->handler);
    route->handler_prepared = 0;
    route->middleware_head = NULL;
    route->middleware_tail = NULL;
    route->middleware_count = 0;
    route->wheres = NULL;
    route->defaults = NULL;
    ZVAL_UNDEF(&route->meta);
    route->method = SF_METHOD_GET;
    route->domain = NULL;
    route->domain_regex = NULL;
    route->priority = 0;
    route->is_fallback = 0;
    route->php_object = NULL;
    route->refcount = 1;

    return route;
}

void sf_route_addref(sf_route *route)
{
    if (route) {
        route->refcount++;
    }
}

void sf_route_release(sf_route *route)
{
    if (route && --route->refcount == 0) {
        sf_route_destroy(route);
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

    if (route->action_namespace) {
        zend_string_release(route->action_namespace);
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

    if (!Z_ISUNDEF(route->meta)) {
        zval_ptr_dtor(&route->meta);
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

zend_bool sf_constraint_set_pattern(sf_param_constraint *constraint, zend_string *pattern)
{
    int errcode;
    PCRE2_SIZE erroffset;
    PCRE2_UCHAR errbuf[256];

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

zend_bool sf_constraint_validate(sf_param_constraint *constraint, zend_string *value)
{
    int rc;

    if (!constraint || !value) {
        return 0;
    }

    /* No pattern means always valid */
    if (!constraint->compiled_regex) {
        return 1;
    }

    rc = pcre2_match(
        constraint->compiled_regex,
        (PCRE2_SPTR)ZSTR_VAL(value),
        ZSTR_LEN(value),
        0,
        0,
        constraint->match_data,
        NULL
    );

    return rc >= 0;
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
    zend_hash_init(router->named_routes, 64, NULL, NULL, 0);

    /* Initialize all routes hash table */
    ALLOC_HASHTABLE(router->all_routes);
    zend_hash_init(router->all_routes, 128, NULL, NULL, 0);

    router->current_group = NULL;
    router->fallback_route = NULL;
    router->is_immutable = 0;
    router->trailing_slash_strict = 0;
    router->route_count = 0;

#ifdef ZTS
    router->lock = tsrm_mutex_alloc();
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
    if (router->lock) {
        tsrm_mutex_free(router->lock);
    }
#endif

    efree(router);
}

void sf_router_reset(sf_router *router)
{
    if (!router) {
        return;
    }

    SF_ROUTER_LOCK(router);

    /* Destroy and recreate tries */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        if (router->method_tries[i]) {
            sf_trie_node_destroy_recursive(router->method_tries[i]);
        }
        router->method_tries[i] = sf_trie_node_create(SF_NODE_ROOT);
    }

    /* Clear hash tables */
    zend_hash_clean(router->named_routes);
    zend_hash_clean(router->all_routes);

    router->fallback_route = NULL;
    router->is_immutable = 0;
    router->route_count = 0;

    SF_ROUTER_UNLOCK(router);
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
    zend_hash_init(result->params, 8, NULL, ZVAL_PTR_DTOR, 0);

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
        zend_hash_init(parent->static_children, 8, NULL, NULL, 0);
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
    child->parent = parent;
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
    child->parent = parent;
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

    SF_ROUTER_LOCK(router);

    /* Handle ANY method - insert into all tries */
    if (method == SF_METHOD_ANY) {
        for (int i = 0; i < SF_METHOD_ANY; i++) {
            root = router->method_tries[i];
            if (!sf_trie_insert_segments(root, segments, route)) {
                sf_uri_segments_destroy(segments);
                SF_ROUTER_UNLOCK(router);
                return 0;
            }
        }
    } else {
        root = router->method_tries[method];
        result = sf_trie_insert_segments(root, segments, route);
        if (!result) {
            sf_uri_segments_destroy(segments);
            SF_ROUTER_UNLOCK(router);
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

    SF_ROUTER_UNLOCK(router);

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
        zend_hash_init(route->wheres, 8, NULL, ZVAL_PTR_DTOR, 0);
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
        zend_hash_init(route->defaults, 8, NULL, ZVAL_PTR_DTOR, 0);
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
                ptr++; /* Skip } */
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

    /* Apply namespace */
    if (group->namespace) {
        route->action_namespace = zend_string_copy(group->namespace);
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
            /* Find end of cloned list */
            sf_middleware_entry *cloned_tail = cloned;
            while (cloned_tail->next) {
                cloned_tail = cloned_tail->next;
            }
            /* Append route's middleware */
            cloned_tail->next = route->middleware_head;
            route->middleware_head = cloned;
            if (!route->middleware_tail) {
                route->middleware_tail = cloned_tail;
            }
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

    /* Skip leading slash */
    if (ptr < end && *ptr == '/') {
        ptr++;
    }

    /* Empty path (root) - check if current node is terminal */
    if (ptr >= end || (ptr + 1 == end && *ptr == '/')) {
        if (node->is_terminal) {
            return node;
        }
        /* Check optional parameter child */
        if (node->optional_child && node->optional_child->is_terminal) {
            return node->optional_child;
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

    /* 1. Try static children first */
    if (node->static_children) {
        zend_string *seg_str = zend_string_init(seg_start, seg_len, 0);
        zval *child_zv = zend_hash_find(node->static_children, seg_str);
        zend_string_release(seg_str);

        if (child_zv) {
            sf_trie_node *child = (sf_trie_node *)Z_PTR_P(child_zv);
            result = sf_trie_match_internal(child, remaining, remaining_len, params, depth + 1);
            if (result) {
                return result;
            }
        }
    }

    /* 2. Try required parameter child */
    if (node->param_child) {
        /* Store parameter value */
        zval param_val;
        ZVAL_STRINGL(&param_val, seg_start, seg_len);
        zend_hash_update(params, node->param_child->param_name, &param_val);

        result = sf_trie_match_internal(node->param_child, remaining, remaining_len, params, depth + 1);
        if (result) {
            return result;
        }

        /* Backtrack - remove parameter */
        zend_hash_del(params, node->param_child->param_name);
    }

    /* 3. Try optional parameter child (also try skipping it) */
    if (node->optional_child) {
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

    /* 4. Try wildcard (consumes all remaining path) */
    if (node->wildcard_child) {
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

    if (!router || !uri) {
        return NULL;
    }

    result = sf_match_result_create();
    if (!result) {
        return NULL;
    }

    /* Get method-specific trie */
    if (method >= SF_METHOD_COUNT) {
        result->matched = 0;
        result->error = zend_string_init("Invalid HTTP method", sizeof("Invalid HTTP method") - 1, 0);
        return result;
    }

    SF_ROUTER_LOCK(router);

    root = router->method_tries[method];
    matched_node = sf_trie_match_internal(root, uri, uri_len, result->params, 0);

    if (matched_node && matched_node->is_terminal) {
        /* Validate parameters against constraints */
        if (sf_validate_params(matched_node->route, result->params)) {
            result->matched = 1;
            result->route = matched_node->route;

            /* Apply default values for missing optional parameters */
            if (matched_node->route->defaults) {
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

    SF_ROUTER_UNLOCK(router);

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
    if (!route || !params) {
        return 1; /* No constraints = always valid */
    }

    if (!route->wheres) {
        return 1;
    }

    zend_string *key;
    zval *constraint_zv;

    ZEND_HASH_FOREACH_STR_KEY_VAL(route->wheres, key, constraint_zv) {
        if (!key) continue;

        sf_param_constraint *constraint = (sf_param_constraint *)Z_PTR_P(constraint_zv);
        zval *param_val = zend_hash_find(params, key);

        if (param_val && Z_TYPE_P(param_val) == IS_STRING) {
            if (!sf_constraint_validate(constraint, Z_STR_P(param_val))) {
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

    SF_ROUTER_LOCK(router);

    zval *route_zv = zend_hash_find(router->named_routes, name);
    if (!route_zv) {
        SF_ROUTER_UNLOCK(router);
        return NULL;
    }

    sf_route *route = (sf_route *)Z_PTR_P(route_zv);
    if (!route || !route->uri) {
        SF_ROUTER_UNLOCK(router);
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

            zend_string *param_name = zend_string_init(param_start, param_len, 0);
            zval *param_val = params ? zend_hash_find(params, param_name) : NULL;

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
                    zend_hash_find(route->defaults, param_name) : NULL;
                if (default_val) {
                    zend_string *str_val = zval_get_string(default_val);
                    smart_str_append(&url, str_val);
                    zend_string_release(str_val);
                } else {
                    zend_string_release(param_name);
                    smart_str_free(&url);
                    SF_ROUTER_UNLOCK(router);
                    php_error_docref(NULL, E_WARNING,
                        "Signalforge\\Routing: Missing required parameter '%.*s' for route '%s'",
                        (int)param_len, param_start, ZSTR_VAL(name));
                    return NULL;
                }
            }

            zend_string_release(param_name);
            ptr++; /* Skip } */
        } else {
            smart_str_appendc(&url, *ptr);
            ptr++;
        }
    }

    smart_str_0(&url);
    SF_ROUTER_UNLOCK(router);

    return url.s;
}

zend_bool sf_router_has_route(sf_router *router, zend_string *name)
{
    if (!router || !name) {
        return 0;
    }

    SF_ROUTER_LOCK(router);
    zend_bool exists = zend_hash_exists(router->named_routes, name);
    SF_ROUTER_UNLOCK(router);

    return exists;
}

sf_route *sf_router_get_route(sf_router *router, zend_string *name)
{
    if (!router || !name) {
        return NULL;
    }

    SF_ROUTER_LOCK(router);
    zval *route_zv = zend_hash_find(router->named_routes, name);
    SF_ROUTER_UNLOCK(router);

    if (!route_zv) {
        return NULL;
    }

    return (sf_route *)Z_PTR_P(route_zv);
}

/* ============================================================================
 * Serialization (Route Caching)
 * ============================================================================ */

/* Serialize trie node recursively */
static void sf_serialize_node(sf_trie_node *node, smart_str *buf)
{
    if (!node) {
        smart_str_appendc(buf, 'N'); /* Null marker */
        return;
    }

    /* Node type */
    smart_str_appendc(buf, 'T');
    smart_str_append_unsigned(buf, node->type);
    smart_str_appendc(buf, ':');

    /* Segment */
    if (node->segment) {
        smart_str_appendc(buf, 'S');
        smart_str_append_unsigned(buf, ZSTR_LEN(node->segment));
        smart_str_appendc(buf, ':');
        smart_str_append(buf, node->segment);
    } else {
        smart_str_appendc(buf, 's');
    }

    /* Parameter name */
    if (node->param_name) {
        smart_str_appendc(buf, 'P');
        smart_str_append_unsigned(buf, ZSTR_LEN(node->param_name));
        smart_str_appendc(buf, ':');
        smart_str_append(buf, node->param_name);
    } else {
        smart_str_appendc(buf, 'p');
    }

    /* Terminal flag and route */
    if (node->is_terminal && node->route) {
        smart_str_appendc(buf, 'R');
        /* Serialize route (simplified - just essential data) */
        smart_str_append_unsigned(buf, ZSTR_LEN(node->route->uri));
        smart_str_appendc(buf, ':');
        smart_str_append(buf, node->route->uri);
        smart_str_appendc(buf, ':');
        if (node->route->name) {
            smart_str_append_unsigned(buf, ZSTR_LEN(node->route->name));
            smart_str_appendc(buf, ':');
            smart_str_append(buf, node->route->name);
        } else {
            smart_str_appendc(buf, '0');
            smart_str_appendc(buf, ':');
        }
    } else {
        smart_str_appendc(buf, 'r');
    }

    /* Static children count */
    uint32_t child_count = node->static_children ?
        zend_hash_num_elements(node->static_children) : 0;
    smart_str_appendc(buf, 'C');
    smart_str_append_unsigned(buf, child_count);
    smart_str_appendc(buf, ':');

    /* Serialize static children */
    if (node->static_children) {
        zend_string *key;
        zval *child_zv;
        ZEND_HASH_FOREACH_STR_KEY_VAL(node->static_children, key, child_zv) {
            if (key) {
                smart_str_append_unsigned(buf, ZSTR_LEN(key));
                smart_str_appendc(buf, ':');
                smart_str_append(buf, key);
                sf_serialize_node((sf_trie_node *)Z_PTR_P(child_zv), buf);
            }
        } ZEND_HASH_FOREACH_END();
    }

    /* Param child */
    sf_serialize_node(node->param_child, buf);

    /* Optional child */
    sf_serialize_node(node->optional_child, buf);

    /* Wildcard child */
    sf_serialize_node(node->wildcard_child, buf);
}

zend_string *sf_router_serialize(sf_router *router)
{
    if (!router) {
        return NULL;
    }

    smart_str buf = {0};

    /* Magic header */
    smart_str_appends(&buf, "SFRT"); /* SignalForge RouTer */
    smart_str_appendc(&buf, 1); /* Version */

    SF_ROUTER_LOCK(router);

    /* Serialize each method trie */
    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        smart_str_appendc(&buf, 'M');
        smart_str_append_unsigned(&buf, i);
        smart_str_appendc(&buf, ':');
        sf_serialize_node(router->method_tries[i], &buf);
    }

    SF_ROUTER_UNLOCK(router);

    smart_str_0(&buf);
    return buf.s;
}

/* Note: Full unserialization implementation would mirror serialization */
/* This is a simplified placeholder - production would need complete impl */
sf_router *sf_router_unserialize(const char *data, size_t len)
{
    if (!data || len < 5) {
        return NULL;
    }

    /* Verify magic header */
    if (memcmp(data, "SFRT", 4) != 0) {
        return NULL;
    }

    /* TODO: Implement full deserialization */
    /* For now, return fresh router - caching should be handled at PHP level */
    return sf_router_create();
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
