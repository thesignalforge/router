/*
 * Signalforge Routing Extension
 * signalforge_routing.c - Main extension source
 *
 * Copyright (c) 2024 Signalforge
 * License: MIT
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "signalforge_routing.h"
#include "routing_trie.h"
#include "ext/spl/spl_exceptions.h"
#include "zend_smart_str.h"

/* Global variables */
ZEND_DECLARE_MODULE_GLOBALS(signalforge_routing)

/* Class entries */
zend_class_entry *sf_router_ce = NULL;
zend_class_entry *sf_route_ce = NULL;
zend_class_entry *sf_match_result_ce = NULL;
zend_class_entry *sf_routing_exception_ce = NULL;

/* Object handlers */
zend_object_handlers sf_router_object_handlers;
zend_object_handlers sf_route_object_handlers;
zend_object_handlers sf_match_result_object_handlers;

/* ============================================================================
 * Object Creation and Destruction
 * ============================================================================ */

zend_object *sf_router_object_create(zend_class_entry *ce)
{
    sf_router_object *intern = zend_object_alloc(sizeof(sf_router_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->router = NULL;
    intern->std.handlers = &sf_router_object_handlers;

    return &intern->std;
}

void sf_router_object_free(zend_object *obj)
{
    sf_router_object *intern = sf_router_object_from_zend_object(obj);

    if (intern->router && intern->router != SF_G(global_router)) {
        sf_router_destroy(intern->router);
    }

    zend_object_std_dtor(&intern->std);
}

zend_object *sf_route_object_create(zend_class_entry *ce)
{
    sf_route_object *intern = zend_object_alloc(sizeof(sf_route_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->route = NULL;
    intern->std.handlers = &sf_route_object_handlers;

    return &intern->std;
}

void sf_route_object_free(zend_object *obj)
{
    sf_route_object *intern = sf_route_object_from_zend_object(obj);

    if (intern->route) {
        sf_route_release(intern->route);
    }

    zend_object_std_dtor(&intern->std);
}

zend_object *sf_match_result_object_create(zend_class_entry *ce)
{
    sf_match_result_object *intern = zend_object_alloc(sizeof(sf_match_result_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->result = NULL;
    intern->std.handlers = &sf_match_result_object_handlers;

    return &intern->std;
}

void sf_match_result_object_free(zend_object *obj)
{
    sf_match_result_object *intern = sf_match_result_object_from_zend_object(obj);

    if (intern->result) {
        sf_match_result_destroy(intern->result);
    }

    zend_object_std_dtor(&intern->std);
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static sf_router *sf_get_global_router(void)
{
    if (!SF_G(global_router)) {
        SF_G(global_router) = sf_router_create();
    }
    return SF_G(global_router);
}

static sf_route_object *sf_wrap_route(sf_route *route)
{
    if (!route) {
        return NULL;
    }

    zval rv;
    object_init_ex(&rv, sf_route_ce);
    sf_route_object *obj = Z_ROUTE_OBJ_P(&rv);
    obj->route = route;
    sf_route_addref(route);
    route->php_object = Z_OBJ(rv);

    return obj;
}

static sf_match_result_object *sf_wrap_match_result(sf_match_result *result)
{
    if (!result) {
        return NULL;
    }

    zval rv;
    object_init_ex(&rv, sf_match_result_ce);
    sf_match_result_object *obj = Z_MATCH_RESULT_OBJ_P(&rv);
    obj->result = result;

    return obj;
}

/* ============================================================================
 * Router Static Methods
 * ============================================================================ */

/* Helper for HTTP method registration */
static void sf_router_register_method(INTERNAL_FUNCTION_PARAMETERS, sf_http_method method)
{
    zend_string *uri;
    zval *handler;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(uri)
        Z_PARAM_ZVAL(handler)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route *route = sf_router_add_route(router, method, uri, handler);

    if (!route) {
        zend_throw_exception(sf_routing_exception_ce,
            "Failed to register route", 0);
        RETURN_NULL();
    }

    /* Return Route object for chaining */
    object_init_ex(return_value, sf_route_ce);
    sf_route_object *route_obj = Z_ROUTE_OBJ_P(return_value);
    route_obj->route = route;
    sf_route_addref(route);
    route->php_object = Z_OBJ_P(return_value);
}

PHP_METHOD(Signalforge_Routing_Router, get)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_GET);
}

PHP_METHOD(Signalforge_Routing_Router, post)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_POST);
}

PHP_METHOD(Signalforge_Routing_Router, put)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_PUT);
}

PHP_METHOD(Signalforge_Routing_Router, patch)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_PATCH);
}

PHP_METHOD(Signalforge_Routing_Router, delete)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_DELETE);
}

PHP_METHOD(Signalforge_Routing_Router, options)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_OPTIONS);
}

PHP_METHOD(Signalforge_Routing_Router, any)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_ANY);
}

PHP_METHOD(Signalforge_Routing_Router, match)
{
    zend_string *method_str;
    zend_string *uri;
    zend_string *domain = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STR(method_str)
        Z_PARAM_STR(uri)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR_OR_NULL(domain)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_http_method method = sf_method_from_string(ZSTR_VAL(method_str), ZSTR_LEN(method_str));

    sf_match_result *result;
    if (domain) {
        result = sf_trie_match_with_domain(router, method,
            ZSTR_VAL(uri), ZSTR_LEN(uri),
            ZSTR_VAL(domain), ZSTR_LEN(domain));
    } else {
        result = sf_trie_match(router, method, ZSTR_VAL(uri), ZSTR_LEN(uri));
    }

    if (!result) {
        zend_throw_exception(sf_routing_exception_ce,
            "Match operation failed", 0);
        RETURN_NULL();
    }

    /* Return MatchResult object */
    object_init_ex(return_value, sf_match_result_ce);
    sf_match_result_object *result_obj = Z_MATCH_RESULT_OBJ_P(return_value);
    result_obj->result = result;
}

PHP_METHOD(Signalforge_Routing_Router, group)
{
    zval *attributes;
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ARRAY(attributes)
        Z_PARAM_FUNC(fci, fcc)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route_group *group = sf_route_group_create();

    if (!group) {
        zend_throw_exception(sf_routing_exception_ce,
            "Failed to create route group", 0);
        RETURN_NULL();
    }

    /* Parse attributes */
    zval *val;

    if ((val = zend_hash_str_find(Z_ARRVAL_P(attributes), "prefix", sizeof("prefix") - 1))) {
        if (Z_TYPE_P(val) == IS_STRING) {
            group->prefix = zend_string_copy(Z_STR_P(val));
        }
    }

    if ((val = zend_hash_str_find(Z_ARRVAL_P(attributes), "namespace", sizeof("namespace") - 1))) {
        if (Z_TYPE_P(val) == IS_STRING) {
            group->namespace = zend_string_copy(Z_STR_P(val));
        }
    }

    if ((val = zend_hash_str_find(Z_ARRVAL_P(attributes), "as", sizeof("as") - 1))) {
        if (Z_TYPE_P(val) == IS_STRING) {
            group->name_prefix = zend_string_copy(Z_STR_P(val));
        }
    }

    if ((val = zend_hash_str_find(Z_ARRVAL_P(attributes), "domain", sizeof("domain") - 1))) {
        if (Z_TYPE_P(val) == IS_STRING) {
            group->domain = zend_string_copy(Z_STR_P(val));
        }
    }

    if ((val = zend_hash_str_find(Z_ARRVAL_P(attributes), "middleware", sizeof("middleware") - 1))) {
        if (Z_TYPE_P(val) == IS_ARRAY) {
            zval *mw;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(val), mw) {
                if (Z_TYPE_P(mw) == IS_STRING) {
                    sf_middleware_entry *entry = sf_middleware_create(Z_STR_P(mw));
                    if (entry) {
                        if (!group->middleware_head) {
                            group->middleware_head = entry;
                            group->middleware_tail = entry;
                        } else {
                            group->middleware_tail->next = entry;
                            group->middleware_tail = entry;
                        }
                    }
                }
            } ZEND_HASH_FOREACH_END();
        } else if (Z_TYPE_P(val) == IS_STRING) {
            sf_middleware_entry *entry = sf_middleware_create(Z_STR_P(val));
            if (entry) {
                group->middleware_head = entry;
                group->middleware_tail = entry;
            }
        }
    }

    /* Enter group context */
    sf_router_begin_group(router, group);

    /* Call the callback */
    zval retval;
    fci.retval = &retval;
    if (zend_call_function(&fci, &fcc) == FAILURE) {
        sf_router_end_group(router);
        zend_throw_exception(sf_routing_exception_ce,
            "Group callback execution failed", 0);
        RETURN_NULL();
    }

    zval_ptr_dtor(&retval);

    /* Exit group context */
    sf_router_end_group(router);

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, prefix)
{
    zend_string *prefix;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(prefix)
    ZEND_PARSE_PARAMETERS_END();

    /* Create a group with just prefix and return $this for chaining */
    sf_router *router = sf_get_global_router();
    sf_route_group *group = sf_route_group_create();

    if (group) {
        group->prefix = zend_string_copy(prefix);
        sf_router_begin_group(router, group);
    }

    /* Return self (the class) for chaining */
    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, middleware)
{
    zval *middleware;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(middleware)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route_group *group = sf_route_group_create();

    if (group) {
        if (Z_TYPE_P(middleware) == IS_ARRAY) {
            zval *mw;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(middleware), mw) {
                if (Z_TYPE_P(mw) == IS_STRING) {
                    sf_middleware_entry *entry = sf_middleware_create(Z_STR_P(mw));
                    if (entry) {
                        if (!group->middleware_head) {
                            group->middleware_head = entry;
                            group->middleware_tail = entry;
                        } else {
                            group->middleware_tail->next = entry;
                            group->middleware_tail = entry;
                        }
                    }
                }
            } ZEND_HASH_FOREACH_END();
        } else if (Z_TYPE_P(middleware) == IS_STRING) {
            sf_middleware_entry *entry = sf_middleware_create(Z_STR_P(middleware));
            if (entry) {
                group->middleware_head = entry;
                group->middleware_tail = entry;
            }
        }
        sf_router_begin_group(router, group);
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, domain)
{
    zend_string *domain;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(domain)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route_group *group = sf_route_group_create();

    if (group) {
        group->domain = zend_string_copy(domain);
        sf_router_begin_group(router, group);
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, namespace_)
{
    zend_string *ns;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(ns)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route_group *group = sf_route_group_create();

    if (group) {
        group->namespace = zend_string_copy(ns);
        sf_router_begin_group(router, group);
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, name)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route_group *group = sf_route_group_create();

    if (group) {
        group->name_prefix = zend_string_copy(name);
        sf_router_begin_group(router, group);
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, fallback)
{
    zval *handler;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(handler)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();

    sf_route *route = sf_route_create();
    if (!route) {
        zend_throw_exception(sf_routing_exception_ce,
            "Failed to create fallback route", 0);
        RETURN_NULL();
    }

    route->uri = zend_string_init("*", 1, 0);
    route->is_fallback = 1;
    ZVAL_COPY(&route->handler, handler);

    router->fallback_route = route;

    /* Return Route object for chaining */
    object_init_ex(return_value, sf_route_ce);
    sf_route_object *route_obj = Z_ROUTE_OBJ_P(return_value);
    route_obj->route = route;
    sf_route_addref(route);
}

PHP_METHOD(Signalforge_Routing_Router, url)
{
    zend_string *name;
    HashTable *params = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STR(name)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_HT_OR_NULL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    zend_string *url = sf_router_url(router, name, params);

    if (!url) {
        RETURN_NULL();
    }

    RETURN_STR(url);
}

PHP_METHOD(Signalforge_Routing_Router, has)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    RETURN_BOOL(sf_router_has_route(router, name));
}

PHP_METHOD(Signalforge_Routing_Router, route)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    sf_route *route = sf_router_get_route(router, name);

    if (!route) {
        RETURN_NULL();
    }

    sf_route_object *obj = sf_wrap_route(route);
    RETURN_OBJ(&obj->std);
}

PHP_METHOD(Signalforge_Routing_Router, getRoutes)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_router *router = sf_get_global_router();

    array_init(return_value);

    if (!router->all_routes) {
        return;
    }

    zval *route_zv;
    ZEND_HASH_FOREACH_VAL(router->all_routes, route_zv) {
        sf_route *route = (sf_route *)Z_PTR_P(route_zv);
        if (route) {
            zval wrapped;
            object_init_ex(&wrapped, sf_route_ce);
            sf_route_object *obj = Z_ROUTE_OBJ_P(&wrapped);
            obj->route = route;
            sf_route_addref(route);
            add_next_index_zval(return_value, &wrapped);
        }
    } ZEND_HASH_FOREACH_END();
}

PHP_METHOD(Signalforge_Routing_Router, flush)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_router *router = sf_get_global_router();
    sf_router_reset(router);

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, cache)
{
    zend_string *path;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(path)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    RETURN_BOOL(sf_router_cache_to_file(router, ZSTR_VAL(path)));
}

PHP_METHOD(Signalforge_Routing_Router, loadCache)
{
    zend_string *path;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(path)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *loaded = sf_router_load_from_file(ZSTR_VAL(path));
    if (!loaded) {
        RETURN_FALSE;
    }

    /* Replace global router */
    if (SF_G(global_router)) {
        sf_router_destroy(SF_G(global_router));
    }
    SF_G(global_router) = loaded;

    RETURN_TRUE;
}

PHP_METHOD(Signalforge_Routing_Router, setStrictSlashes)
{
    zend_bool strict;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(strict)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();
    router->trailing_slash_strict = strict;

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, dump)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_router *router = sf_get_global_router();

    php_printf("=== Signalforge Router Dump ===\n");
    php_printf("Route count: %u\n", router->route_count);
    php_printf("Immutable: %s\n", router->is_immutable ? "yes" : "no");

    for (int i = 0; i < SF_METHOD_COUNT; i++) {
        php_printf("\n--- %s Trie ---\n", sf_method_to_string(i));
        sf_trie_dump(router->method_tries[i], 0);
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, getInstance)
{
    ZEND_PARSE_PARAMETERS_NONE();

    object_init_ex(return_value, sf_router_ce);
    sf_router_object *obj = Z_ROUTER_OBJ_P(return_value);
    obj->router = sf_get_global_router();
}

/* ============================================================================
 * Route Methods
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_Route, __construct)
{
    /* Private constructor - routes are created by Router */
    zend_throw_exception(sf_routing_exception_ce,
        "Route cannot be instantiated directly", 0);
}

PHP_METHOD(Signalforge_Routing_Route, name)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    sf_route_set_name(intern->route, name);

    /* Update named routes registry */
    sf_router *router = sf_get_global_router();
    zval zv;
    ZVAL_PTR(&zv, intern->route);
    zend_hash_update(router->named_routes, name, &zv);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, middleware)
{
    zval *middleware;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(middleware)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    if (Z_TYPE_P(middleware) == IS_ARRAY) {
        sf_route_set_middleware(intern->route, middleware);
    } else if (Z_TYPE_P(middleware) == IS_STRING) {
        sf_route_add_middleware(intern->route, Z_STR_P(middleware), NULL);
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, where)
{
    zval *param;
    zend_string *pattern = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_ZVAL(param)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR_OR_NULL(pattern)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    if (Z_TYPE_P(param) == IS_ARRAY) {
        /* Array of param => pattern pairs */
        zend_string *key;
        zval *val;
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(param), key, val) {
            if (key && Z_TYPE_P(val) == IS_STRING) {
                sf_route_set_where(intern->route, key, Z_STR_P(val));
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(param) == IS_STRING && pattern) {
        sf_route_set_where(intern->route, Z_STR_P(param), pattern);
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, whereNumber)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    zend_string *pattern = zend_string_init("[0-9]+", sizeof("[0-9]+") - 1, 0);

    if (Z_TYPE_P(params) == IS_ARRAY) {
        zval *param;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), param) {
            if (Z_TYPE_P(param) == IS_STRING) {
                sf_route_set_where(intern->route, Z_STR_P(param), pattern);
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(params) == IS_STRING) {
        sf_route_set_where(intern->route, Z_STR_P(params), pattern);
    }

    zend_string_release(pattern);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, whereAlpha)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    zend_string *pattern = zend_string_init("[a-zA-Z]+", sizeof("[a-zA-Z]+") - 1, 0);

    if (Z_TYPE_P(params) == IS_ARRAY) {
        zval *param;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), param) {
            if (Z_TYPE_P(param) == IS_STRING) {
                sf_route_set_where(intern->route, Z_STR_P(param), pattern);
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(params) == IS_STRING) {
        sf_route_set_where(intern->route, Z_STR_P(params), pattern);
    }

    zend_string_release(pattern);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, whereAlphaNumeric)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    zend_string *pattern = zend_string_init("[a-zA-Z0-9]+", sizeof("[a-zA-Z0-9]+") - 1, 0);

    if (Z_TYPE_P(params) == IS_ARRAY) {
        zval *param;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), param) {
            if (Z_TYPE_P(param) == IS_STRING) {
                sf_route_set_where(intern->route, Z_STR_P(param), pattern);
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(params) == IS_STRING) {
        sf_route_set_where(intern->route, Z_STR_P(params), pattern);
    }

    zend_string_release(pattern);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, whereUuid)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    zend_string *pattern = zend_string_init(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        sizeof("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") - 1,
        0
    );

    if (Z_TYPE_P(params) == IS_ARRAY) {
        zval *param;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), param) {
            if (Z_TYPE_P(param) == IS_STRING) {
                sf_route_set_where(intern->route, Z_STR_P(param), pattern);
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(params) == IS_STRING) {
        sf_route_set_where(intern->route, Z_STR_P(params), pattern);
    }

    zend_string_release(pattern);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, whereUlid)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    zend_string *pattern = zend_string_init(
        "[0-7][0-9A-HJKMNP-TV-Z]{25}",
        sizeof("[0-7][0-9A-HJKMNP-TV-Z]{25}") - 1,
        0
    );

    if (Z_TYPE_P(params) == IS_ARRAY) {
        zval *param;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), param) {
            if (Z_TYPE_P(param) == IS_STRING) {
                sf_route_set_where(intern->route, Z_STR_P(param), pattern);
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(params) == IS_STRING) {
        sf_route_set_where(intern->route, Z_STR_P(params), pattern);
    }

    zend_string_release(pattern);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, whereIn)
{
    zend_string *param;
    zval *values;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(param)
        Z_PARAM_ARRAY(values)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    /* Build alternation pattern: (val1|val2|val3) */
    smart_str pattern = {0};
    smart_str_appendc(&pattern, '(');

    zend_bool first = 1;
    zval *val;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(values), val) {
        if (!first) {
            smart_str_appendc(&pattern, '|');
        }
        first = 0;

        zend_string *str = zval_get_string(val);
        /* Escape regex special chars */
        for (size_t i = 0; i < ZSTR_LEN(str); i++) {
            char c = ZSTR_VAL(str)[i];
            if (strchr("[]{}()*+?\\^$|.", c)) {
                smart_str_appendc(&pattern, '\\');
            }
            smart_str_appendc(&pattern, c);
        }
        zend_string_release(str);
    } ZEND_HASH_FOREACH_END();

    smart_str_appendc(&pattern, ')');
    smart_str_0(&pattern);

    sf_route_set_where(intern->route, param, pattern.s);
    smart_str_free(&pattern);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, defaults)
{
    zend_string *param;
    zval *value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(param)
        Z_PARAM_ZVAL(value)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    sf_route_set_default(intern->route, param, value);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, domain)
{
    zend_string *domain;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(domain)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    sf_route_set_domain(intern->route, domain);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, withoutMiddleware)
{
    zval *middleware;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(middleware)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_NULL();
    }

    /* Remove specified middleware from the route's middleware list */
    HashTable *to_remove;
    ALLOC_HASHTABLE(to_remove);
    zend_hash_init(to_remove, 4, NULL, NULL, 0);

    if (Z_TYPE_P(middleware) == IS_ARRAY) {
        zval *mw;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(middleware), mw) {
            if (Z_TYPE_P(mw) == IS_STRING) {
                zend_hash_add_empty_element(to_remove, Z_STR_P(mw));
            }
        } ZEND_HASH_FOREACH_END();
    } else if (Z_TYPE_P(middleware) == IS_STRING) {
        zend_hash_add_empty_element(to_remove, Z_STR_P(middleware));
    }

    /* Filter middleware list */
    sf_middleware_entry *current = intern->route->middleware_head;
    sf_middleware_entry *prev = NULL;
    sf_middleware_entry *new_head = NULL;
    sf_middleware_entry *new_tail = NULL;

    while (current) {
        sf_middleware_entry *next = current->next;

        if (zend_hash_exists(to_remove, current->name)) {
            /* Remove this entry */
            sf_middleware_destroy(current);
            intern->route->middleware_count--;
        } else {
            /* Keep this entry */
            current->next = NULL;
            if (!new_head) {
                new_head = current;
                new_tail = current;
            } else {
                new_tail->next = current;
                new_tail = current;
            }
        }

        current = next;
    }

    intern->route->middleware_head = new_head;
    intern->route->middleware_tail = new_tail;

    zend_hash_destroy(to_remove);
    FREE_HASHTABLE(to_remove);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, getName)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || !intern->route->name) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->route->name);
}

PHP_METHOD(Signalforge_Routing_Route, getUri)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || !intern->route->uri) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->route->uri);
}

PHP_METHOD(Signalforge_Routing_Route, getMethods)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        RETURN_NULL();
    }

    array_init(return_value);
    add_next_index_string(return_value, sf_method_to_string(intern->route->method));
}

PHP_METHOD(Signalforge_Routing_Route, getHandler)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || Z_ISUNDEF(intern->route->handler)) {
        RETURN_NULL();
    }

    RETURN_ZVAL(&intern->route->handler, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, getMiddleware)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        RETURN_NULL();
    }

    array_init(return_value);

    sf_middleware_entry *current = intern->route->middleware_head;
    while (current) {
        add_next_index_str(return_value, zend_string_copy(current->name));
        current = current->next;
    }
}

PHP_METHOD(Signalforge_Routing_Route, getWheres)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || !intern->route->wheres) {
        array_init(return_value);
        return;
    }

    array_init(return_value);

    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_STR_KEY_VAL(intern->route->wheres, key, val) {
        if (key) {
            sf_param_constraint *constraint = (sf_param_constraint *)Z_PTR_P(val);
            if (constraint && constraint->pattern) {
                add_assoc_str(return_value, ZSTR_VAL(key),
                    zend_string_copy(constraint->pattern));
            }
        }
    } ZEND_HASH_FOREACH_END();
}

PHP_METHOD(Signalforge_Routing_Route, getDefaults)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || !intern->route->defaults) {
        array_init(return_value);
        return;
    }

    RETURN_ARR(zend_array_dup(intern->route->defaults));
}

PHP_METHOD(Signalforge_Routing_Route, getDomain)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || !intern->route->domain) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->route->domain);
}

/* ============================================================================
 * MatchResult Methods
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_MatchResult, __construct)
{
    /* Private constructor */
    zend_throw_exception(sf_routing_exception_ce,
        "MatchResult cannot be instantiated directly", 0);
}

PHP_METHOD(Signalforge_Routing_MatchResult, matched)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result) {
        RETURN_FALSE;
    }

    RETURN_BOOL(intern->result->matched);
}

PHP_METHOD(Signalforge_Routing_MatchResult, getRoute)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->route) {
        RETURN_NULL();
    }

    object_init_ex(return_value, sf_route_ce);
    sf_route_object *route_obj = Z_ROUTE_OBJ_P(return_value);
    route_obj->route = intern->result->route;
    sf_route_addref(intern->result->route);
}

PHP_METHOD(Signalforge_Routing_MatchResult, getHandler)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->route ||
        Z_ISUNDEF(intern->result->route->handler)) {
        RETURN_NULL();
    }

    RETURN_ZVAL(&intern->result->route->handler, 1, 0);
}

PHP_METHOD(Signalforge_Routing_MatchResult, getParams)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->params) {
        array_init(return_value);
        return;
    }

    RETURN_ARR(zend_array_dup(intern->result->params));
}

PHP_METHOD(Signalforge_Routing_MatchResult, getMiddleware)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->route) {
        array_init(return_value);
        return;
    }

    array_init(return_value);

    sf_middleware_entry *current = intern->result->route->middleware_head;
    while (current) {
        add_next_index_str(return_value, zend_string_copy(current->name));
        current = current->next;
    }
}

PHP_METHOD(Signalforge_Routing_MatchResult, getRouteName)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->route || !intern->result->route->name) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->result->route->name);
}

PHP_METHOD(Signalforge_Routing_MatchResult, getError)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->error) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->result->error);
}

PHP_METHOD(Signalforge_Routing_MatchResult, param)
{
    zend_string *name;
    zval *default_val = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STR(name)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL_OR_NULL(default_val)
    ZEND_PARSE_PARAMETERS_END();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->params) {
        if (default_val) {
            RETURN_ZVAL(default_val, 1, 0);
        }
        RETURN_NULL();
    }

    zval *val = zend_hash_find(intern->result->params, name);
    if (val) {
        RETURN_ZVAL(val, 1, 0);
    }

    if (default_val) {
        RETURN_ZVAL(default_val, 1, 0);
    }

    RETURN_NULL();
}

/* ============================================================================
 * Argument Info Definitions
 * ============================================================================ */

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_route_method, 0, 2, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, uri, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, handler, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_match, 0, 2, Signalforge\\Routing\\MatchResult, 0)
    ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, uri, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, domain, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_group, 0, 2, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, attributes, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_prefix, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, prefix, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_middleware, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, middleware, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_domain, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, domain, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_namespace, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, namespace, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_name, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_fallback, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, handler, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_url, 0, 1, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, params, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_has, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_route, 0, 1, Signalforge\\Routing\\Route, 1)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_getRoutes, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_flush, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_cache, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_loadCache, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_setStrictSlashes, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, strict, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_dump, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_getInstance, 0, 0, Signalforge\\Routing\\Router, 0)
ZEND_END_ARG_INFO()

/* Route arg info */
ZEND_BEGIN_ARG_INFO_EX(arginfo_route_construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_name, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_middleware, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, middleware, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_where, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, param, IS_MIXED, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, pattern, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_where_type, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, params, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_whereIn, 0, 2, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, param, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, values, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_defaults, 0, 2, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, param, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_domain, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, domain, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_withoutMiddleware, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, middleware, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getName, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getUri, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getMethods, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getHandler, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getMiddleware, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getWheres, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getDefaults, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getDomain, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

/* MatchResult arg info */
ZEND_BEGIN_ARG_INFO_EX(arginfo_match_construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_matched, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_match_getRoute, 0, 0, Signalforge\\Routing\\Route, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_getHandler, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_getParams, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_getMiddleware, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_getRouteName, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_getError, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_param, 0, 1, IS_MIXED, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, default, IS_MIXED, 1, "null")
ZEND_END_ARG_INFO()

/* ============================================================================
 * Method Entry Tables
 * ============================================================================ */

static const zend_function_entry sf_router_methods[] = {
    PHP_ME(Signalforge_Routing_Router, get, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, post, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, put, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, patch, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, delete, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, options, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, any, arginfo_router_route_method, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, match, arginfo_router_match, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, group, arginfo_router_group, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, prefix, arginfo_router_prefix, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, middleware, arginfo_router_middleware, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, domain, arginfo_router_domain, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(namespace, ZEND_MN(Signalforge_Routing_Router_namespace_), arginfo_router_namespace, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, name, arginfo_router_name, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, fallback, arginfo_router_fallback, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, url, arginfo_router_url, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, has, arginfo_router_has, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, route, arginfo_router_route, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, getRoutes, arginfo_router_getRoutes, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, flush, arginfo_router_flush, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, cache, arginfo_router_cache, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, loadCache, arginfo_router_loadCache, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, setStrictSlashes, arginfo_router_setStrictSlashes, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, dump, arginfo_router_dump, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, getInstance, arginfo_router_getInstance, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

static const zend_function_entry sf_route_methods[] = {
    PHP_ME(Signalforge_Routing_Route, __construct, arginfo_route_construct, ZEND_ACC_PRIVATE)
    PHP_ME(Signalforge_Routing_Route, name, arginfo_route_name, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, middleware, arginfo_route_middleware, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, where, arginfo_route_where, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, whereNumber, arginfo_route_where_type, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, whereAlpha, arginfo_route_where_type, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, whereAlphaNumeric, arginfo_route_where_type, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, whereUuid, arginfo_route_where_type, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, whereUlid, arginfo_route_where_type, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, whereIn, arginfo_route_whereIn, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, defaults, arginfo_route_defaults, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, domain, arginfo_route_domain, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, withoutMiddleware, arginfo_route_withoutMiddleware, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getName, arginfo_route_getName, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getUri, arginfo_route_getUri, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getMethods, arginfo_route_getMethods, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getHandler, arginfo_route_getHandler, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getMiddleware, arginfo_route_getMiddleware, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getWheres, arginfo_route_getWheres, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getDefaults, arginfo_route_getDefaults, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getDomain, arginfo_route_getDomain, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry sf_match_result_methods[] = {
    PHP_ME(Signalforge_Routing_MatchResult, __construct, arginfo_match_construct, ZEND_ACC_PRIVATE)
    PHP_ME(Signalforge_Routing_MatchResult, matched, arginfo_match_matched, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getRoute, arginfo_match_getRoute, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getHandler, arginfo_match_getHandler, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getParams, arginfo_match_getParams, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getMiddleware, arginfo_match_getMiddleware, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getRouteName, arginfo_match_getRouteName, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getError, arginfo_match_getError, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, param, arginfo_match_param, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* ============================================================================
 * Module Lifecycle
 * ============================================================================ */

static void php_signalforge_routing_globals_ctor(zend_signalforge_routing_globals *globals)
{
    globals->last_error = SF_OK;
    globals->last_error_msg = NULL;
    globals->global_router = NULL;
}

static void php_signalforge_routing_globals_dtor(zend_signalforge_routing_globals *globals)
{
    if (globals->last_error_msg) {
        efree(globals->last_error_msg);
        globals->last_error_msg = NULL;
    }
}

PHP_MINIT_FUNCTION(signalforge_routing)
{
    zend_class_entry ce;

    /* Initialize globals */
    ZEND_INIT_MODULE_GLOBALS(signalforge_routing, php_signalforge_routing_globals_ctor, php_signalforge_routing_globals_dtor);

    /* Register Router class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "Router", sf_router_methods);
    sf_router_ce = zend_register_internal_class(&ce);
    sf_router_ce->create_object = sf_router_object_create;
    sf_router_ce->ce_flags |= ZEND_ACC_FINAL;

    memcpy(&sf_router_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_router_object_handlers.offset = XtOffsetOf(sf_router_object, std);
    sf_router_object_handlers.free_obj = sf_router_object_free;

    /* Register Route class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "Route", sf_route_methods);
    sf_route_ce = zend_register_internal_class(&ce);
    sf_route_ce->create_object = sf_route_object_create;
    sf_route_ce->ce_flags |= ZEND_ACC_FINAL;

    memcpy(&sf_route_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_route_object_handlers.offset = XtOffsetOf(sf_route_object, std);
    sf_route_object_handlers.free_obj = sf_route_object_free;

    /* Register MatchResult class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "MatchResult", sf_match_result_methods);
    sf_match_result_ce = zend_register_internal_class(&ce);
    sf_match_result_ce->create_object = sf_match_result_object_create;
    sf_match_result_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_READONLY_CLASS;

    memcpy(&sf_match_result_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_match_result_object_handlers.offset = XtOffsetOf(sf_match_result_object, std);
    sf_match_result_object_handlers.free_obj = sf_match_result_object_free;

    /* Register exception class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "RoutingException", NULL);
    sf_routing_exception_ce = zend_register_internal_class_ex(&ce, spl_ce_RuntimeException);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(signalforge_routing)
{
    return SUCCESS;
}

PHP_RINIT_FUNCTION(signalforge_routing)
{
#if defined(ZTS) && defined(COMPILE_DL_SIGNALFORGE_ROUTING)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    /* Create fresh router for each request */
    SF_G(global_router) = NULL;
    SF_G(last_error) = SF_OK;
    SF_G(last_error_msg) = NULL;

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(signalforge_routing)
{
    /* Clean up request-specific data */
    if (SF_G(global_router)) {
        sf_router_destroy(SF_G(global_router));
        SF_G(global_router) = NULL;
    }

    if (SF_G(last_error_msg)) {
        efree(SF_G(last_error_msg));
        SF_G(last_error_msg) = NULL;
    }

    return SUCCESS;
}

PHP_MINFO_FUNCTION(signalforge_routing)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "Signalforge Routing", "enabled");
    php_info_print_table_row(2, "Version", PHP_SIGNALFORGE_ROUTING_VERSION);
    php_info_print_table_row(2, "Trie Implementation", "Compressed Radix Trie");
    php_info_print_table_row(2, "ZTS",
#ifdef ZTS
        "enabled"
#else
        "disabled"
#endif
    );
    php_info_print_table_end();
}

/* Module entry */
zend_module_entry signalforge_routing_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_SIGNALFORGE_ROUTING_EXTNAME,
    NULL,                               /* Functions (we use classes) */
    PHP_MINIT(signalforge_routing),
    PHP_MSHUTDOWN(signalforge_routing),
    PHP_RINIT(signalforge_routing),
    PHP_RSHUTDOWN(signalforge_routing),
    PHP_MINFO(signalforge_routing),
    PHP_SIGNALFORGE_ROUTING_VERSION,
    PHP_MODULE_GLOBALS(signalforge_routing),
    NULL,                               /* GINIT */
    NULL,                               /* GSHUTDOWN */
    NULL,                               /* PRSHUTDOWN */
    STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_SIGNALFORGE_ROUTING
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(signalforge_routing)
#endif
