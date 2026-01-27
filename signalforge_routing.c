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
#include "ext/standard/php_smart_string.h"
#include "main/SAPI.h"
#include "main/php_streams.h"
#include "main/php_globals.h"
#include <ctype.h>
#include "ext/standard/url.h"

/* Global variables */
ZEND_DECLARE_MODULE_GLOBALS(signalforge_routing)

/* Class entries */
zend_class_entry *sf_router_ce = NULL;
zend_class_entry *sf_route_ce = NULL;
zend_class_entry *sf_match_result_ce = NULL;
zend_class_entry *sf_routing_context_ce = NULL;
zend_class_entry *sf_routing_exception_ce = NULL;
zend_class_entry *sf_proxy_request_ce = NULL;
zend_class_entry *sf_proxy_response_ce = NULL;

/* Object handlers */
zend_object_handlers sf_router_object_handlers;
zend_object_handlers sf_route_object_handlers;
zend_object_handlers sf_match_result_object_handlers;
zend_object_handlers sf_routing_context_object_handlers;
zend_object_handlers sf_proxy_request_object_handlers;
zend_object_handlers sf_proxy_response_object_handlers;

/* ============================================================================
 * Object Creation and Destruction
 * ============================================================================ */

zend_object *sf_router_object_create(zend_class_entry *ce)
{
    sf_router_object *intern = zend_object_alloc(sizeof(sf_router_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->router = NULL;
    intern->owns_router = 0;
    intern->std.handlers = &sf_router_object_handlers;

    return &intern->std;
}

void sf_router_object_free(zend_object *obj)
{
    sf_router_object *intern = sf_router_object_from_zend_object(obj);

    if (intern->router && intern->owns_router) {
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
        intern->route->php_object = NULL;
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

zend_object *sf_routing_context_object_create(zend_class_entry *ce)
{
    sf_routing_context_object *intern = zend_object_alloc(sizeof(sf_routing_context_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->context = NULL;
    intern->std.handlers = &sf_routing_context_object_handlers;

    return &intern->std;
}

void sf_routing_context_object_free(zend_object *obj)
{
    sf_routing_context_object *intern = sf_routing_context_object_from_zend_object(obj);

    if (intern->context) {
        sf_routing_context_destroy(intern->context);
    }

    zend_object_std_dtor(&intern->std);
}

zend_object *sf_proxy_request_object_create(zend_class_entry *ce)
{
    sf_proxy_request_object *intern = zend_object_alloc(sizeof(sf_proxy_request_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->request = NULL;
    intern->std.handlers = &sf_proxy_request_object_handlers;

    return &intern->std;
}

void sf_proxy_request_object_free(zend_object *obj)
{
    sf_proxy_request_object *intern = sf_proxy_request_object_from_zend_object(obj);

    if (intern->request) {
        sf_proxy_request_destroy(intern->request);
    }

    zend_object_std_dtor(&intern->std);
}

zend_object *sf_proxy_response_object_create(zend_class_entry *ce)
{
    sf_proxy_response_object *intern = zend_object_alloc(sizeof(sf_proxy_response_object), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);

    intern->response = NULL;
    intern->std.handlers = &sf_proxy_response_object_handlers;

    return &intern->std;
}

void sf_proxy_response_object_free(zend_object *obj)
{
    sf_proxy_response_object *intern = sf_proxy_response_object_from_zend_object(obj);

    if (intern->response) {
        sf_proxy_response_destroy(intern->response);
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

/**
 * Wrap a route in a PHP Route object. Takes ownership of an existing reference
 * (the caller's ref is transferred to the PHP object — do NOT release after calling).
 */
static sf_route_object *sf_wrap_route(sf_route *route)
{
    if (!route) {
        return NULL;
    }

    zval rv;
    object_init_ex(&rv, sf_route_ce);
    sf_route_object *obj = Z_ROUTE_OBJ_P(&rv);
    obj->route = route;
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
        RETURN_THROWS();
    }

    /* Return Route object for chaining.
     * The route starts with refcount=1 from sf_route_create — this serves as
     * the PHP object's reference. The trie added its own ref via sf_trie_insert. */
    object_init_ex(return_value, sf_route_ce);
    sf_route_object *route_obj = Z_ROUTE_OBJ_P(return_value);
    route_obj->route = route;
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
        RETURN_THROWS();
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

    if ((val = zend_hash_str_find(Z_ARRVAL_P(attributes), "where", sizeof("where") - 1))) {
        if (Z_TYPE_P(val) == IS_ARRAY) {
            /* Store raw {param => pattern} strings; sf_route_apply_group
             * in routing_trie.c creates the actual constraints */
            ALLOC_HASHTABLE(group->wheres);
            zend_hash_init(group->wheres, 4, NULL, ZVAL_PTR_DTOR, 0);
            zend_string *wkey;
            zval *wval;
            ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(val), wkey, wval) {
                if (wkey && Z_TYPE_P(wval) == IS_STRING) {
                    zval copy;
                    ZVAL_STR_COPY(&copy, Z_STR_P(wval));
                    zend_hash_update(group->wheres, wkey, &copy);
                }
            } ZEND_HASH_FOREACH_END();
        }
    }

    /* Enter group context */
    sf_router_begin_group(router, group);

    /* Call the callback */
    zval retval;
    ZVAL_UNDEF(&retval);
    fci.retval = &retval;
    if (zend_call_function(&fci, &fcc) == FAILURE || EG(exception)) {
        sf_router_end_group(router);
        zval_ptr_dtor(&retval);
        if (!EG(exception)) {
            zend_throw_exception(sf_routing_exception_ce,
                "Group callback execution failed", 0);
        }
        RETURN_THROWS();
    }

    zval_ptr_dtor(&retval);

    /* Exit group context */
    sf_router_end_group(router);
}

PHP_METHOD(Signalforge_Routing_Router, prefix)
{
    zend_string *prefix;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(prefix)
    ZEND_PARSE_PARAMETERS_END();

    php_error_docref(NULL, E_WARNING,
        "Signalforge\\Routing: Router::prefix() without group() has no effect. "
        "Use Router::group(['prefix' => '...'], callback) instead");

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, middleware)
{
    zval *middleware;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(middleware)
    ZEND_PARSE_PARAMETERS_END();

    php_error_docref(NULL, E_WARNING,
        "Signalforge\\Routing: Router::middleware() without group() has no effect. "
        "Use Router::group(['middleware' => [...]], callback) instead");

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, domain)
{
    zend_string *domain;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(domain)
    ZEND_PARSE_PARAMETERS_END();

    php_error_docref(NULL, E_WARNING,
        "Signalforge\\Routing: Router::domain() without group() has no effect. "
        "Use Router::group(['domain' => '...'], callback) instead");

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, namespace_)
{
    zend_string *ns;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(ns)
    ZEND_PARSE_PARAMETERS_END();

    php_error_docref(NULL, E_WARNING,
        "Signalforge\\Routing: Router::namespace() without group() has no effect. "
        "Use Router::group(['namespace' => '...'], callback) instead");

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, name)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    php_error_docref(NULL, E_WARNING,
        "Signalforge\\Routing: Router::name() without group() has no effect. "
        "Use Router::group(['as' => '...'], callback) instead");

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
    route->uri = zend_string_init("*", 1, 0);
    route->is_fallback = 1;
    ZVAL_COPY(&route->handler, handler);

    /* Release old fallback route if exists to prevent memory leak */
    if (router->fallback_route) {
        sf_route_release(router->fallback_route);
    }
    router->fallback_route = route;

    /* Return Route object for chaining.
     * The fallback route's initial refcount=1 is the PHP object's reference.
     * The router->fallback_route pointer also needs a ref. */
    sf_route_addref(route);
    object_init_ex(return_value, sf_route_ce);
    sf_route_object *route_obj = Z_ROUTE_OBJ_P(return_value);
    route_obj->route = route;
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

PHP_METHOD(Signalforge_Routing_Router, cli)
{
    sf_router_register_method(INTERNAL_FUNCTION_PARAM_PASSTHRU, SF_METHOD_CLI);
}

/* Helper: call a resolver callable with input, store the resulting context on the router.
 * Returns SUCCESS or FAILURE (with exception set). */
static int sf_call_resolver_and_store(sf_router *router, zval *resolver, zval *input)
{
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
    char *error = NULL;

    if (zend_fcall_info_init(resolver, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        if (error) efree(error);
        zend_throw_exception(sf_routing_exception_ce,
            "Failed to initialize routing resolver", 0);
        return FAILURE;
    }
    if (error) efree(error);

    zval retval;
    zval args[1];
    ZVAL_COPY_VALUE(&args[0], input);

    fci.retval = &retval;
    fci.param_count = 1;
    fci.params = args;

    if (zend_call_function(&fci, &fcc) != SUCCESS) {
        zend_throw_exception(sf_routing_exception_ce,
            "Failed to call routing resolver", 0);
        return FAILURE;
    }

    if (EG(exception)) {
        zval_ptr_dtor(&retval);
        return FAILURE;
    }

    if (Z_TYPE(retval) != IS_OBJECT || !instanceof_function(Z_OBJCE(retval), sf_routing_context_ce)) {
        zval_ptr_dtor(&retval);
        zend_throw_exception(sf_routing_exception_ce,
            "Resolver must return a RoutingContext instance", 0);
        return FAILURE;
    }

    sf_routing_context_object *ctx_obj = sf_routing_context_object_from_zend_object(Z_OBJ(retval));
    sf_routing_context *ctx = ctx_obj->context;

    if (!ctx || !ctx->method || !ctx->path) {
        zval_ptr_dtor(&retval);
        zend_throw_exception(sf_routing_exception_ce,
            "RoutingContext has invalid state", 0);
        return FAILURE;
    }

    if (router->dispatch_method) zend_string_release(router->dispatch_method);
    if (router->dispatch_path) zend_string_release(router->dispatch_path);
    if (router->dispatch_domain) zend_string_release(router->dispatch_domain);

    router->dispatch_method = zend_string_copy(ctx->method);
    router->dispatch_path = zend_string_copy(ctx->path);
    router->dispatch_domain = ctx->domain ? zend_string_copy(ctx->domain) : NULL;

    zval_ptr_dtor(&retval);
    return SUCCESS;
}

PHP_METHOD(Signalforge_Routing_Router, routeUsing)
{
    zval *input;
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(input)
        Z_PARAM_FUNC(fci, fcc)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();

    if (sf_call_resolver_and_store(router, &fci.function_name, input) != SUCCESS) {
        RETURN_THROWS();
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_Router, resolver)
{
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, fcc)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();

    if (!Z_ISUNDEF(router->dispatch_resolver)) {
        zval_ptr_dtor(&router->dispatch_resolver);
    }

    ZVAL_COPY(&router->dispatch_resolver, &fci.function_name);
}

/* Forward declarations for proxy helpers used in dispatch() */
static void sf_proxy_send_response(sf_proxy_response *resp);
static zend_string *sf_proxy_resolve_url(zend_string *url_pattern, HashTable *params);
static sf_proxy_request *sf_proxy_build_request_from_sapi(zend_string *url, sf_http_method method);
static sf_proxy_response *sf_proxy_execute(sf_proxy_request *req, sf_proxy_options *opts);
static sf_proxy_request *sf_proxy_call_on_request(sf_proxy_options *opts, sf_proxy_request *req);
static sf_proxy_response *sf_proxy_call_on_response(sf_proxy_options *opts, sf_proxy_response *resp);

PHP_METHOD(Signalforge_Routing_Router, dispatch)
{
    zval *input = NULL;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(input)
    ZEND_PARSE_PARAMETERS_END();

    sf_router *router = sf_get_global_router();

    /* If input provided, resolve via stored resolver */
    if (input && Z_TYPE_P(input) != IS_NULL) {
        if (Z_ISUNDEF(router->dispatch_resolver)) {
            zend_throw_exception(sf_routing_exception_ce,
                "No resolver set. Call Router::resolver() before Router::dispatch($input)", 0);
            RETURN_THROWS();
        }
        /* Copy the resolver before calling — the callback could modify/free
         * the stored resolver (e.g., via Router::flush() or Router::resolver()) */
        zval resolver_copy;
        ZVAL_COPY(&resolver_copy, &router->dispatch_resolver);
        int resolve_result = sf_call_resolver_and_store(router, &resolver_copy, input);
        zval_ptr_dtor(&resolver_copy);
        if (resolve_result != SUCCESS) {
            RETURN_THROWS();
        }
    }

    if (!router->dispatch_method) {
        zend_throw_exception(sf_routing_exception_ce,
            "No routing context set. Call Router::routeUsing() or Router::resolver() before Router::dispatch()", 0);
        RETURN_THROWS();
    }

    sf_http_method method = sf_method_from_string(
        ZSTR_VAL(router->dispatch_method), ZSTR_LEN(router->dispatch_method));

    sf_match_result *result;
    if (router->dispatch_domain) {
        result = sf_trie_match_with_domain(router, method,
            ZSTR_VAL(router->dispatch_path), ZSTR_LEN(router->dispatch_path),
            ZSTR_VAL(router->dispatch_domain), ZSTR_LEN(router->dispatch_domain));
    } else {
        result = sf_trie_match(router, method,
            ZSTR_VAL(router->dispatch_path), ZSTR_LEN(router->dispatch_path));
    }

    if (!result) {
        zend_throw_exception(sf_routing_exception_ce,
            "Dispatch operation failed", 0);
        RETURN_THROWS();
    }

    /* Execute proxy if route has proxy config */
    if (result->matched && result->route && result->route->proxy) {
        sf_proxy_options *proxy = result->route->proxy;

        /* 1. Resolve URL — replace {param} placeholders from match params */
        zend_string *resolved_url = sf_proxy_resolve_url(proxy->url, result->params);

        /* 2. Validate resolved URL scheme — prevent SSRF via parameter injection */
        const char *url_str = ZSTR_VAL(resolved_url);
        if (ZSTR_LEN(resolved_url) < 8 ||
            (strncasecmp(url_str, "http://", 7) != 0 &&
             strncasecmp(url_str, "https://", 8) != 0)) {
            zend_string_release(resolved_url);
            zend_throw_exception(sf_routing_exception_ce,
                "Resolved proxy URL must use http:// or https:// scheme", 0);
            goto proxy_done;
        }

        /* 3. Build ProxyRequest from SAPI globals */
        sf_proxy_request *req = sf_proxy_build_request_from_sapi(resolved_url, result->route->method);
        zend_string_release(resolved_url);

        /* 4. Call onRequest hook if set */
        if (!Z_ISUNDEF(proxy->on_request)) {
            sf_proxy_request *modified = sf_proxy_call_on_request(proxy, req);
            if (modified) {
                sf_proxy_request_destroy(req);
                req = modified;
            }
            if (EG(exception)) {
                sf_proxy_request_destroy(req);
                goto proxy_done;
            }
        }

        /* 5. Execute HTTP request via PHP streams */
        sf_proxy_response *resp = sf_proxy_execute(req, proxy);
        sf_proxy_request_destroy(req);

        if (!resp) {
            goto proxy_done;
        }

        /* 6. Call onResponse hook if set */
        if (!Z_ISUNDEF(proxy->on_response)) {
            sf_proxy_response *modified = sf_proxy_call_on_response(proxy, resp);
            if (modified) {
                sf_proxy_response_destroy(resp);
                resp = modified;
            }
            if (EG(exception)) {
                sf_proxy_response_destroy(resp);
                goto proxy_done;
            }
        }

        /* 7. Auto-send response to browser */
        sf_proxy_send_response(resp);

        /* 8. Store in match result for inspection */
        result->proxy_response = resp;
    }
proxy_done:

    /* Return MatchResult object */
    object_init_ex(return_value, sf_match_result_ce);
    sf_match_result_object *result_obj = Z_MATCH_RESULT_OBJ_P(return_value);
    result_obj->result = result;
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
        RETURN_THROWS();
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
        RETURN_THROWS();
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
        RETURN_THROWS();
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

/**
 * Helper: Apply a fixed constraint pattern to one or more params.
 * Accepts params as string (single) or array (multiple).
 */
static void sf_route_where_with_pattern(INTERNAL_FUNCTION_PARAMETERS,
                                         const char *pat, size_t pat_len)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(params)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_THROWS();
    }

    zend_string *pattern = zend_string_init(pat, pat_len, 0);

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

PHP_METHOD(Signalforge_Routing_Route, whereNumber)
{
    sf_route_where_with_pattern(INTERNAL_FUNCTION_PARAM_PASSTHRU,
        "[0-9]+", sizeof("[0-9]+") - 1);
}

PHP_METHOD(Signalforge_Routing_Route, whereAlpha)
{
    sf_route_where_with_pattern(INTERNAL_FUNCTION_PARAM_PASSTHRU,
        "[a-zA-Z]+", sizeof("[a-zA-Z]+") - 1);
}

PHP_METHOD(Signalforge_Routing_Route, whereAlphaNumeric)
{
    sf_route_where_with_pattern(INTERNAL_FUNCTION_PARAM_PASSTHRU,
        "[a-zA-Z0-9]+", sizeof("[a-zA-Z0-9]+") - 1);
}

PHP_METHOD(Signalforge_Routing_Route, whereUuid)
{
    sf_route_where_with_pattern(INTERNAL_FUNCTION_PARAM_PASSTHRU,
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        sizeof("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") - 1);
}

PHP_METHOD(Signalforge_Routing_Route, whereUlid)
{
    sf_route_where_with_pattern(INTERNAL_FUNCTION_PARAM_PASSTHRU,
        "[0-7][0-9A-HJKMNP-TV-Z]{25}",
        sizeof("[0-7][0-9A-HJKMNP-TV-Z]{25}") - 1);
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
        RETURN_THROWS();
    }

    /* Reject empty values array */
    if (zend_hash_num_elements(Z_ARRVAL_P(values)) == 0) {
        zend_throw_exception(sf_routing_exception_ce,
            "whereIn() requires a non-empty values array", 0);
        RETURN_THROWS();
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
        RETURN_THROWS();
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
        RETURN_THROWS();
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
        RETURN_THROWS();
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

PHP_METHOD(Signalforge_Routing_Route, proxy)
{
    zend_string *url;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(url)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_THROWS();
    }

    /* Validate URL scheme — only http:// and https:// are allowed.
     * URLs with {param} placeholders are also checked after substitution. */
    const char *s = ZSTR_VAL(url);
    if (ZSTR_LEN(url) < 8 ||
        (strncasecmp(s, "http://", 7) != 0 && strncasecmp(s, "https://", 8) != 0)) {
        /* Allow {param} at start — will be validated after substitution at dispatch time */
        if (s[0] != '{') {
            zend_throw_exception(sf_routing_exception_ce,
                "Proxy URL must use http:// or https:// scheme", 0);
            RETURN_THROWS();
        }
    }

    if (intern->route->proxy) {
        sf_proxy_options_destroy(intern->route->proxy);
    }
    intern->route->proxy = sf_proxy_options_create(url);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, onRequest)
{
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, fcc)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_THROWS();
    }
    if (!intern->route->proxy) {
        zend_throw_exception(sf_routing_exception_ce,
            "Call proxy() before onRequest()", 0);
        RETURN_THROWS();
    }

    zval_ptr_dtor(&intern->route->proxy->on_request);
    ZVAL_COPY(&intern->route->proxy->on_request, &fci.function_name);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, onResponse)
{
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_FUNC(fci, fcc)
    ZEND_PARSE_PARAMETERS_END();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid route", 0);
        RETURN_THROWS();
    }
    if (!intern->route->proxy) {
        zend_throw_exception(sf_routing_exception_ce,
            "Call proxy() before onResponse()", 0);
        RETURN_THROWS();
    }

    zval_ptr_dtor(&intern->route->proxy->on_response);
    ZVAL_COPY(&intern->route->proxy->on_response, &fci.function_name);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Signalforge_Routing_Route, getProxyUrl)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_route_object *intern = Z_ROUTE_OBJ_P(ZEND_THIS);
    if (!intern->route || !intern->route->proxy) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->route->proxy->url);
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

PHP_METHOD(Signalforge_Routing_MatchResult, isProxy)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result) {
        RETURN_FALSE;
    }

    RETURN_BOOL(intern->result->proxy_response != NULL);
}

PHP_METHOD(Signalforge_Routing_MatchResult, getProxyResponse)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_match_result_object *intern = Z_MATCH_RESULT_OBJ_P(ZEND_THIS);
    if (!intern->result || !intern->result->proxy_response) {
        RETURN_NULL();
    }

    object_init_ex(return_value, sf_proxy_response_ce);
    sf_proxy_response_object *resp_obj = Z_PROXY_RESPONSE_OBJ_P(return_value);
    resp_obj->response = sf_proxy_response_clone(intern->result->proxy_response);
}

/* ============================================================================
 * ProxyRequest Methods
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_ProxyRequest, __construct)
{
    /* Private constructor */
    zend_throw_exception(sf_routing_exception_ce,
        "ProxyRequest cannot be instantiated directly", 0);
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, getMethod)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request || !intern->request->method) {
        RETURN_EMPTY_STRING();
    }

    RETURN_STR_COPY(intern->request->method);
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, getUrl)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request || !intern->request->url) {
        RETURN_EMPTY_STRING();
    }

    RETURN_STR_COPY(intern->request->url);
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, getHeaders)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request || !intern->request->headers) {
        array_init(return_value);
        return;
    }

    array_init_size(return_value, zend_hash_num_elements(intern->request->headers));
    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_STR_KEY_VAL(intern->request->headers, key, val) {
        if (key) {
            zval copy;
            ZVAL_COPY(&copy, val);
            zend_hash_update(Z_ARRVAL_P(return_value), key, &copy);
        }
    } ZEND_HASH_FOREACH_END();
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, getHeader)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request || !intern->request->headers) {
        RETURN_NULL();
    }

    zend_string *lower = zend_string_tolower(name);
    zval *val = zend_hash_find(intern->request->headers, lower);
    zend_string_release(lower);

    if (val && Z_TYPE_P(val) == IS_STRING) {
        RETURN_STR_COPY(Z_STR_P(val));
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, getBody)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request || !intern->request->body) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->request->body);
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, withMethod)
{
    zend_string *method;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(method)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy request", 0);
        RETURN_THROWS();
    }

    sf_proxy_request *new_req = sf_proxy_request_clone(intern->request);
    zend_string_release(new_req->method);
    new_req->method = zend_string_copy(method);

    object_init_ex(return_value, sf_proxy_request_ce);
    sf_proxy_request_object *new_obj = Z_PROXY_REQUEST_OBJ_P(return_value);
    new_obj->request = new_req;
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, withUrl)
{
    zend_string *url;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(url)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy request", 0);
        RETURN_THROWS();
    }

    sf_proxy_request *new_req = sf_proxy_request_clone(intern->request);
    zend_string_release(new_req->url);
    new_req->url = zend_string_copy(url);

    object_init_ex(return_value, sf_proxy_request_ce);
    sf_proxy_request_object *new_obj = Z_PROXY_REQUEST_OBJ_P(return_value);
    new_obj->request = new_req;
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, withHeader)
{
    zend_string *name, *value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(name)
        Z_PARAM_STR(value)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy request", 0);
        RETURN_THROWS();
    }

    sf_proxy_request *new_req = sf_proxy_request_clone(intern->request);

    zend_string *lower = zend_string_tolower(name);
    zval val;
    ZVAL_STR_COPY(&val, value);
    zend_hash_update(new_req->headers, lower, &val);
    zend_string_release(lower);

    object_init_ex(return_value, sf_proxy_request_ce);
    sf_proxy_request_object *new_obj = Z_PROXY_REQUEST_OBJ_P(return_value);
    new_obj->request = new_req;
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, withBody)
{
    zend_string *body;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(body)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy request", 0);
        RETURN_THROWS();
    }

    sf_proxy_request *new_req = sf_proxy_request_clone(intern->request);
    if (new_req->body) {
        zend_string_release(new_req->body);
    }
    new_req->body = zend_string_copy(body);

    object_init_ex(return_value, sf_proxy_request_ce);
    sf_proxy_request_object *new_obj = Z_PROXY_REQUEST_OBJ_P(return_value);
    new_obj->request = new_req;
}

PHP_METHOD(Signalforge_Routing_ProxyRequest, withoutHeader)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_request_object *intern = Z_PROXY_REQUEST_OBJ_P(ZEND_THIS);
    if (!intern->request) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy request", 0);
        RETURN_THROWS();
    }

    sf_proxy_request *new_req = sf_proxy_request_clone(intern->request);

    zend_string *lower = zend_string_tolower(name);
    zend_hash_del(new_req->headers, lower);
    zend_string_release(lower);

    object_init_ex(return_value, sf_proxy_request_ce);
    sf_proxy_request_object *new_obj = Z_PROXY_REQUEST_OBJ_P(return_value);
    new_obj->request = new_req;
}

/* ============================================================================
 * ProxyResponse Methods
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_ProxyResponse, __construct)
{
    /* Private constructor */
    zend_throw_exception(sf_routing_exception_ce,
        "ProxyResponse cannot be instantiated directly", 0);
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, getStatusCode)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response) {
        RETURN_LONG(0);
    }

    RETURN_LONG(intern->response->status_code);
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, getHeaders)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response || !intern->response->headers) {
        array_init(return_value);
        return;
    }

    array_init_size(return_value, zend_hash_num_elements(intern->response->headers));
    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_STR_KEY_VAL(intern->response->headers, key, val) {
        if (key) {
            zval copy;
            ZVAL_COPY(&copy, val);
            zend_hash_update(Z_ARRVAL_P(return_value), key, &copy);
        }
    } ZEND_HASH_FOREACH_END();
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, getHeader)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response || !intern->response->headers) {
        RETURN_NULL();
    }

    zend_string *lower = zend_string_tolower(name);
    zval *val = zend_hash_find(intern->response->headers, lower);
    zend_string_release(lower);

    if (val && Z_TYPE_P(val) == IS_STRING) {
        RETURN_STR_COPY(Z_STR_P(val));
    }

    RETURN_NULL();
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, getBody)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response || !intern->response->body) {
        RETURN_EMPTY_STRING();
    }

    RETURN_STR_COPY(intern->response->body);
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, withStatus)
{
    zend_long code;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(code)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy response", 0);
        RETURN_THROWS();
    }

    if (code < SF_PROXY_MIN_STATUS || code > SF_PROXY_MAX_STATUS) {
        zend_throw_exception_ex(sf_routing_exception_ce, 0,
            "HTTP status code must be between %d and %d, got " ZEND_LONG_FMT,
            SF_PROXY_MIN_STATUS, SF_PROXY_MAX_STATUS, code);
        RETURN_THROWS();
    }

    sf_proxy_response *new_resp = sf_proxy_response_clone(intern->response);
    new_resp->status_code = (uint16_t)code;

    object_init_ex(return_value, sf_proxy_response_ce);
    sf_proxy_response_object *new_obj = Z_PROXY_RESPONSE_OBJ_P(return_value);
    new_obj->response = new_resp;
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, withHeader)
{
    zend_string *name, *value;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(name)
        Z_PARAM_STR(value)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy response", 0);
        RETURN_THROWS();
    }

    sf_proxy_response *new_resp = sf_proxy_response_clone(intern->response);

    zend_string *lower = zend_string_tolower(name);
    zval val;
    ZVAL_STR_COPY(&val, value);
    zend_hash_update(new_resp->headers, lower, &val);
    zend_string_release(lower);

    object_init_ex(return_value, sf_proxy_response_ce);
    sf_proxy_response_object *new_obj = Z_PROXY_RESPONSE_OBJ_P(return_value);
    new_obj->response = new_resp;
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, withBody)
{
    zend_string *body;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(body)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy response", 0);
        RETURN_THROWS();
    }

    sf_proxy_response *new_resp = sf_proxy_response_clone(intern->response);
    if (new_resp->body) {
        zend_string_release(new_resp->body);
    }
    new_resp->body = zend_string_copy(body);

    object_init_ex(return_value, sf_proxy_response_ce);
    sf_proxy_response_object *new_obj = Z_PROXY_RESPONSE_OBJ_P(return_value);
    new_obj->response = new_resp;
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, withoutHeader)
{
    zend_string *name;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy response", 0);
        RETURN_THROWS();
    }

    sf_proxy_response *new_resp = sf_proxy_response_clone(intern->response);

    zend_string *lower = zend_string_tolower(name);
    zend_hash_del(new_resp->headers, lower);
    zend_string_release(lower);

    object_init_ex(return_value, sf_proxy_response_ce);
    sf_proxy_response_object *new_obj = Z_PROXY_RESPONSE_OBJ_P(return_value);
    new_obj->response = new_resp;
}

static void sf_proxy_send_response(sf_proxy_response *resp)
{
    if (!resp) {
        return;
    }

    SG(sapi_headers).http_response_code = resp->status_code;

    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_STR_KEY_VAL(resp->headers, key, val) {
        if (key && Z_TYPE_P(val) == IS_STRING) {
            sapi_header_line ctr = {0};
            smart_str header_str = {0};
            smart_str_append(&header_str, key);
            smart_str_appends(&header_str, ": ");
            smart_str_append(&header_str, Z_STR_P(val));
            smart_str_0(&header_str);

            ctr.line = ZSTR_VAL(header_str.s);
            ctr.line_len = ZSTR_LEN(header_str.s);
            sapi_header_op(SAPI_HEADER_REPLACE, &ctr);
            smart_str_free(&header_str);
        }
    } ZEND_HASH_FOREACH_END();

    if (resp->body && ZSTR_LEN(resp->body) > 0) {
        php_write(ZSTR_VAL(resp->body), ZSTR_LEN(resp->body));
    }
}

PHP_METHOD(Signalforge_Routing_ProxyResponse, send)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_proxy_response_object *intern = Z_PROXY_RESPONSE_OBJ_P(ZEND_THIS);
    if (!intern->response) {
        zend_throw_exception(sf_routing_exception_ce, "Invalid proxy response", 0);
        RETURN_THROWS();
    }

    sf_proxy_send_response(intern->response);
}

/* ============================================================================
 * Proxy Execution Helpers
 * ============================================================================ */

static zend_string *sf_proxy_resolve_url(zend_string *url_pattern, HashTable *params)
{
    if (!params || zend_hash_num_elements(params) == 0) {
        return zend_string_copy(url_pattern);
    }

    smart_str result = {0};
    const char *p = ZSTR_VAL(url_pattern);
    const char *end = p + ZSTR_LEN(url_pattern);

    while (p < end) {
        if (*p == '{') {
            const char *close = memchr(p + 1, '}', end - p - 1);
            if (close) {
                zend_string *param_name = zend_string_init(p + 1, close - p - 1, 0);
                zval *val = zend_hash_find(params, param_name);
                zend_string_release(param_name);

                if (val && Z_TYPE_P(val) == IS_STRING) {
                    /* URL-encode the parameter value to prevent query/fragment injection */
                    zend_string *encoded = php_raw_url_encode(
                        ZSTR_VAL(Z_STR_P(val)), ZSTR_LEN(Z_STR_P(val)));
                    smart_str_append(&result, encoded);
                    zend_string_release(encoded);
                } else {
                    /* Unresolved placeholder — keep literal */
                    smart_str_appendl(&result, p, close - p + 1);
                }
                p = close + 1;
                continue;
            }
        }
        smart_str_appendc(&result, *p);
        p++;
    }

    if (result.s) {
        smart_str_0(&result);
        return result.s; /* caller takes ownership */
    }
    return zend_string_copy(url_pattern);
}

static zend_string *sf_server_key_to_header(zend_string *key)
{
    /* Strip HTTP_ prefix, replace _ with -, lowercase */
    const char *src = ZSTR_VAL(key) + SF_HTTP_PREFIX_LEN;
    size_t len = ZSTR_LEN(key) - SF_HTTP_PREFIX_LEN;

    zend_string *header = zend_string_alloc(len, 0);
    char *dst = ZSTR_VAL(header);

    for (size_t i = 0; i < len; i++) {
        if (src[i] == '_') {
            dst[i] = '-';
        } else {
            dst[i] = (char)tolower((unsigned char)src[i]);
        }
    }
    dst[len] = '\0';

    return header;
}

/* Check if a header value contains \r or \n (HTTP header injection) */
static zend_bool sf_header_value_is_safe(const char *val, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (val[i] == '\r' || val[i] == '\n') {
            return 0;
        }
    }
    return 1;
}

/* Headers that must not be forwarded to the upstream */
static zend_bool sf_is_sensitive_header(const char *name, size_t len)
{
    /* Hop-by-hop and security-sensitive headers */
    static const struct { const char *name; size_t len; } blocked[] = {
        { "cookie",            6 },
        { "authorization",    13 },
        { "proxy-authorization", 19 },
        { "connection",       10 },
        { "keep-alive",        10 },
        { "transfer-encoding", 17 },
        { "te",                2 },
        { "upgrade",           7 },
    };

    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        if (len == blocked[i].len && memcmp(name, blocked[i].name, len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Extract host from URL: "https://api.example.com:8080/path" -> "api.example.com:8080" */
static zend_string *sf_extract_host_from_url(zend_string *url)
{
    const char *s = ZSTR_VAL(url);
    const char *host_start = strstr(s, "://");
    if (!host_start) {
        return NULL;
    }
    host_start += 3; /* skip "://" */

    const char *host_end = strchr(host_start, '/');
    size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
    if (host_len == 0) {
        return NULL;
    }

    return zend_string_init(host_start, host_len, 0);
}

static sf_proxy_request *sf_proxy_build_request_from_sapi(zend_string *url, sf_http_method method)
{
    const char *method_name = sf_method_to_string(method);
    zend_string *method_str = zend_string_init(method_name, strlen(method_name), 0);

    HashTable *headers;
    ALLOC_HASHTABLE(headers);
    zend_hash_init(headers, SF_HEADERS_INITIAL_SIZE, NULL, ZVAL_PTR_DTOR, 0);

    zend_string *original_host = NULL;
    zend_string *original_proto = NULL;

    zval *server = &PG(http_globals)[TRACK_VARS_SERVER];
    if (server && Z_TYPE_P(server) == IS_ARRAY) {
        zend_string *key;
        zval *val;
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(server), key, val) {
            if (key && Z_TYPE_P(val) == IS_STRING &&
                ZSTR_LEN(key) > SF_HTTP_PREFIX_LEN &&
                memcmp(ZSTR_VAL(key), SF_HTTP_PREFIX, SF_HTTP_PREFIX_LEN) == 0) {

                zend_string *header_name = sf_server_key_to_header(key);

                /* Capture original host before filtering */
                if (ZSTR_LEN(header_name) == 4 &&
                    memcmp(ZSTR_VAL(header_name), "host", 4) == 0) {
                    original_host = zend_string_copy(Z_STR_P(val));
                    zend_string_release(header_name);
                    continue; /* Don't forward original Host */
                }

                /* Strip sensitive and hop-by-hop headers */
                if (sf_is_sensitive_header(ZSTR_VAL(header_name), ZSTR_LEN(header_name))) {
                    zend_string_release(header_name);
                    continue;
                }

                /* Reject values containing \r or \n (header injection) */
                if (!sf_header_value_is_safe(Z_STRVAL_P(val), Z_STRLEN_P(val))) {
                    zend_string_release(header_name);
                    continue;
                }

                zval header_val;
                ZVAL_STR_COPY(&header_val, Z_STR_P(val));
                zend_hash_update(headers, header_name, &header_val);
                zend_string_release(header_name);
            }
        } ZEND_HASH_FOREACH_END();

        zval *ct = zend_hash_str_find(Z_ARRVAL_P(server), "CONTENT_TYPE", sizeof("CONTENT_TYPE") - 1);
        if (ct && Z_TYPE_P(ct) == IS_STRING &&
            sf_header_value_is_safe(Z_STRVAL_P(ct), Z_STRLEN_P(ct))) {
            zval v;
            ZVAL_STR_COPY(&v, Z_STR_P(ct));
            zend_hash_str_update(headers, "content-type", sizeof("content-type") - 1, &v);
        }
        zval *cl = zend_hash_str_find(Z_ARRVAL_P(server), "CONTENT_LENGTH", sizeof("CONTENT_LENGTH") - 1);
        if (cl && Z_TYPE_P(cl) == IS_STRING &&
            sf_header_value_is_safe(Z_STRVAL_P(cl), Z_STRLEN_P(cl))) {
            zval v;
            ZVAL_STR_COPY(&v, Z_STR_P(cl));
            zend_hash_str_update(headers, "content-length", sizeof("content-length") - 1, &v);
        }

        /* Detect original protocol */
        zval *https = zend_hash_str_find(Z_ARRVAL_P(server), "HTTPS", sizeof("HTTPS") - 1);
        if (https && Z_TYPE_P(https) == IS_STRING &&
            !(ZSTR_LEN(Z_STR_P(https)) == 3 && memcmp(ZSTR_VAL(Z_STR_P(https)), "off", 3) == 0)) {
            original_proto = zend_string_init("https", sizeof("https") - 1, 0);
        } else {
            original_proto = zend_string_init("http", sizeof("http") - 1, 0);
        }
    }

    /* Set Host header to match upstream URL */
    zend_string *upstream_host = sf_extract_host_from_url(url);
    if (upstream_host) {
        zval host_val;
        ZVAL_STR(&host_val, upstream_host); /* transfers ownership */
        zend_hash_str_update(headers, "host", sizeof("host") - 1, &host_val);
    }

    /* Add X-Forwarded-* headers */
    if (original_host) {
        zval v;
        ZVAL_STR(&v, original_host); /* transfers ownership */
        zend_hash_str_update(headers, "x-forwarded-host", sizeof("x-forwarded-host") - 1, &v);
    }
    if (original_proto) {
        zval v;
        ZVAL_STR(&v, original_proto); /* transfers ownership */
        zend_hash_str_update(headers, "x-forwarded-proto", sizeof("x-forwarded-proto") - 1, &v);
    }

    /* Add X-Forwarded-For from REMOTE_ADDR */
    if (server && Z_TYPE_P(server) == IS_ARRAY) {
        zval *remote = zend_hash_str_find(Z_ARRVAL_P(server), "REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1);
        if (remote && Z_TYPE_P(remote) == IS_STRING &&
            sf_header_value_is_safe(Z_STRVAL_P(remote), Z_STRLEN_P(remote))) {
            zval v;
            ZVAL_STR_COPY(&v, Z_STR_P(remote));
            zend_hash_str_update(headers, "x-forwarded-for", sizeof("x-forwarded-for") - 1, &v);
        }
    }

    zend_string *body = NULL;
    php_stream *input = php_stream_open_wrapper("php://input", "rb", 0, NULL);
    if (input) {
        body = php_stream_copy_to_mem(input, PHP_STREAM_COPY_ALL, 0);
        php_stream_close(input);
    }

    sf_proxy_request *req = sf_proxy_request_create(method_str, url, headers, body);

    zend_string_release(method_str);
    zend_hash_destroy(headers);
    FREE_HASHTABLE(headers);
    if (body) {
        zend_string_release(body);
    }

    return req;
}

static sf_proxy_response *sf_proxy_execute(sf_proxy_request *req, sf_proxy_options *opts)
{
    /* Validate URL scheme — defense-in-depth against onRequest SSRF bypass */
    const char *url_check = ZSTR_VAL(req->url);
    if (ZSTR_LEN(req->url) < 8 ||
        (strncasecmp(url_check, "http://", 7) != 0 &&
         strncasecmp(url_check, "https://", 8) != 0)) {
        zend_throw_exception(sf_routing_exception_ce,
            "Proxy request URL must use http:// or https:// scheme", 0);
        return NULL;
    }

    zval http_opts;
    array_init(&http_opts);

    add_assoc_str(&http_opts, "method", zend_string_copy(req->method));

    /* Build headers string, stripping values containing \r\n to prevent injection */
    smart_str header_str = {0};
    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_STR_KEY_VAL(req->headers, key, val) {
        if (key && Z_TYPE_P(val) == IS_STRING &&
            sf_header_value_is_safe(Z_STRVAL_P(val), Z_STRLEN_P(val))) {
            smart_str_append(&header_str, key);
            smart_str_appends(&header_str, ": ");
            smart_str_append(&header_str, Z_STR_P(val));
            smart_str_appends(&header_str, "\r\n");
        }
    } ZEND_HASH_FOREACH_END();
    if (header_str.s) {
        smart_str_0(&header_str);
        add_assoc_str(&http_opts, "header", header_str.s);
        header_str.s = NULL; /* ownership transferred to array */
    }

    if (req->body && ZSTR_LEN(req->body) > 0) {
        add_assoc_str(&http_opts, "content", zend_string_copy(req->body));
    }

    add_assoc_double(&http_opts, "timeout", opts->timeout);
    add_assoc_bool(&http_opts, "ignore_errors", 1);

    zval ssl_opts;
    array_init(&ssl_opts);
    add_assoc_bool(&ssl_opts, "verify_peer", opts->verify_ssl);
    add_assoc_bool(&ssl_opts, "verify_peer_name", opts->verify_ssl);

    php_stream_context *ctx = php_stream_context_alloc();
    php_stream_context_set_option(ctx, "http", NULL, &http_opts);
    php_stream_context_set_option(ctx, "ssl", NULL, &ssl_opts);

    zval_ptr_dtor(&http_opts);
    zval_ptr_dtor(&ssl_opts);

    php_stream *stream = php_stream_open_wrapper_ex(
        ZSTR_VAL(req->url), "rb",
        REPORT_ERRORS,
        NULL, ctx);

    if (!stream) {
        return NULL;
    }

    /* Read response body with size limit to prevent memory exhaustion */
    zend_string *resp_body = php_stream_copy_to_mem(stream, SF_PROXY_MAX_RESPONSE_BODY, 0);

    uint16_t status_code = 200;
    HashTable *resp_headers;
    ALLOC_HASHTABLE(resp_headers);
    zend_hash_init(resp_headers, SF_HEADERS_INITIAL_SIZE, NULL, ZVAL_PTR_DTOR, 0);

    if (Z_TYPE(stream->wrapperdata) == IS_ARRAY) {
        zval *line;
        zend_bool first = 1;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL(stream->wrapperdata), line) {
            if (Z_TYPE_P(line) != IS_STRING) continue;
            if (first) {
                /* Parse "HTTP/1.1 200 OK" */
                const char *s = Z_STRVAL_P(line);
                const char *space = strchr(s, ' ');
                if (space) {
                    char *endptr;
                    long parsed = strtol(space + 1, &endptr, 10);
                    if (endptr != space + 1 &&
                        parsed >= SF_PROXY_MIN_STATUS && parsed <= SF_PROXY_MAX_STATUS) {
                        status_code = (uint16_t)parsed;
                    }
                }
                first = 0;
            } else {
                /* Parse "Header-Name: value" */
                const char *line_str = Z_STRVAL_P(line);
                size_t line_len = Z_STRLEN_P(line);
                const char *colon = memchr(line_str, ':', line_len);
                if (colon && colon > line_str) {
                    size_t name_len = (size_t)(colon - line_str);
                    const char *value_start = colon + 1;
                    const char *line_end = line_str + line_len;

                    /* Skip leading spaces with bounds check */
                    while (value_start < line_end && *value_start == ' ') {
                        value_start++;
                    }
                    size_t value_len = (size_t)(line_end - value_start);

                    zend_string *header_name = zend_string_init(line_str, name_len, 0);
                    zend_str_tolower(ZSTR_VAL(header_name), ZSTR_LEN(header_name));

                    zval header_val;
                    ZVAL_STRINGL(&header_val, value_start, value_len);
                    zend_hash_update(resp_headers, header_name, &header_val);
                    zend_string_release(header_name);
                }
            }
        } ZEND_HASH_FOREACH_END();
    }

    php_stream_close(stream);

    sf_proxy_response *resp = sf_proxy_response_create(
        status_code, resp_headers, resp_body ? resp_body : ZSTR_EMPTY_ALLOC());

    zend_hash_destroy(resp_headers);
    FREE_HASHTABLE(resp_headers);
    if (resp_body) {
        zend_string_release(resp_body);
    }

    return resp;
}

static sf_proxy_request *sf_proxy_call_on_request(sf_proxy_options *opts, sf_proxy_request *req)
{
    zval request_zv;
    object_init_ex(&request_zv, sf_proxy_request_ce);
    sf_proxy_request_object *req_obj = Z_PROXY_REQUEST_OBJ_P(&request_zv);
    req_obj->request = sf_proxy_request_clone(req);

    zval retval;
    ZVAL_UNDEF(&retval);
    zval args[1];
    ZVAL_COPY_VALUE(&args[0], &request_zv);

    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
    char *error = NULL;
    if (zend_fcall_info_init(&opts->on_request, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        zval_ptr_dtor(&request_zv);
        if (error) efree(error);
        return NULL;
    }
    if (error) efree(error);

    fci.retval = &retval;
    fci.param_count = 1;
    fci.params = args;

    if (zend_call_function(&fci, &fcc) != SUCCESS || EG(exception)) {
        zval_ptr_dtor(&request_zv);
        if (!Z_ISUNDEF(retval)) zval_ptr_dtor(&retval);
        return NULL;
    }

    sf_proxy_request *result = NULL;
    if (Z_TYPE(retval) == IS_OBJECT && instanceof_function(Z_OBJCE(retval), sf_proxy_request_ce)) {
        sf_proxy_request_object *ret_obj = sf_proxy_request_object_from_zend_object(Z_OBJ(retval));
        result = sf_proxy_request_clone(ret_obj->request);
    } else if (!EG(exception)) {
        zend_throw_exception(sf_routing_exception_ce,
            "onRequest callback must return a ProxyRequest instance", 0);
    }

    zval_ptr_dtor(&request_zv);
    zval_ptr_dtor(&retval);

    return result;
}

static sf_proxy_response *sf_proxy_call_on_response(sf_proxy_options *opts, sf_proxy_response *resp)
{
    zval response_zv;
    object_init_ex(&response_zv, sf_proxy_response_ce);
    sf_proxy_response_object *resp_obj = Z_PROXY_RESPONSE_OBJ_P(&response_zv);
    resp_obj->response = sf_proxy_response_clone(resp);

    zval retval;
    ZVAL_UNDEF(&retval);
    zval args[1];
    ZVAL_COPY_VALUE(&args[0], &response_zv);

    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
    char *error = NULL;
    if (zend_fcall_info_init(&opts->on_response, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        zval_ptr_dtor(&response_zv);
        if (error) efree(error);
        return NULL;
    }
    if (error) efree(error);

    fci.retval = &retval;
    fci.param_count = 1;
    fci.params = args;

    if (zend_call_function(&fci, &fcc) != SUCCESS || EG(exception)) {
        zval_ptr_dtor(&response_zv);
        if (!Z_ISUNDEF(retval)) zval_ptr_dtor(&retval);
        return NULL;
    }

    sf_proxy_response *result = NULL;
    if (Z_TYPE(retval) == IS_OBJECT && instanceof_function(Z_OBJCE(retval), sf_proxy_response_ce)) {
        sf_proxy_response_object *ret_obj = sf_proxy_response_object_from_zend_object(Z_OBJ(retval));
        result = sf_proxy_response_clone(ret_obj->response);
    } else if (!EG(exception)) {
        zend_throw_exception(sf_routing_exception_ce,
            "onResponse callback must return a ProxyResponse instance", 0);
    }

    zval_ptr_dtor(&response_zv);
    zval_ptr_dtor(&retval);

    return result;
}

/* ============================================================================
 * RoutingContext Methods
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_RoutingContext, __construct)
{
    zend_string *method;
    zend_string *path;
    zend_string *domain = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STR(method)
        Z_PARAM_STR(path)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR_OR_NULL(domain)
    ZEND_PARSE_PARAMETERS_END();

    sf_routing_context_object *intern = Z_ROUTING_CONTEXT_OBJ_P(ZEND_THIS);
    intern->context = sf_routing_context_create(method, path, domain);
}

PHP_METHOD(Signalforge_Routing_RoutingContext, getMethod)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_routing_context_object *intern = Z_ROUTING_CONTEXT_OBJ_P(ZEND_THIS);
    if (!intern->context || !intern->context->method) {
        RETURN_STRING("");
    }

    RETURN_STR_COPY(intern->context->method);
}

PHP_METHOD(Signalforge_Routing_RoutingContext, getPath)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_routing_context_object *intern = Z_ROUTING_CONTEXT_OBJ_P(ZEND_THIS);
    if (!intern->context || !intern->context->path) {
        RETURN_STRING("");
    }

    RETURN_STR_COPY(intern->context->path);
}

PHP_METHOD(Signalforge_Routing_RoutingContext, getDomain)
{
    ZEND_PARSE_PARAMETERS_NONE();

    sf_routing_context_object *intern = Z_ROUTING_CONTEXT_OBJ_P(ZEND_THIS);
    if (!intern->context || !intern->context->domain) {
        RETURN_NULL();
    }

    RETURN_STR_COPY(intern->context->domain);
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

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_dump, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_getInstance, 0, 0, Signalforge\\Routing\\Router, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_cli, 0, 2, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, command, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, handler, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_routeUsing, 0, 2, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, input, IS_MIXED, 0)
    ZEND_ARG_TYPE_INFO(0, resolver, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_router_resolver, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, resolver, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_router_dispatch, 0, 0, Signalforge\\Routing\\MatchResult, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, input, IS_MIXED, 1, "null")
ZEND_END_ARG_INFO()

/* RoutingContext arg info */
ZEND_BEGIN_ARG_INFO_EX(arginfo_routing_context_construct, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, domain, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_routing_context_getMethod, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_routing_context_getPath, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_routing_context_getDomain, 0, 0, IS_STRING, 1)
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

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_proxy, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, url, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_onRequest, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_route_onResponse, 0, 1, Signalforge\\Routing\\Route, 0)
    ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_route_getProxyUrl, 0, 0, IS_STRING, 1)
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

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_match_isProxy, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_match_getProxyResponse, 0, 0, Signalforge\\Routing\\ProxyResponse, 1)
ZEND_END_ARG_INFO()

/* ProxyRequest arg info */
ZEND_BEGIN_ARG_INFO_EX(arginfo_proxy_request_construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_request_getMethod, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_request_getUrl, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_request_getHeaders, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_request_getHeader, 0, 1, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_request_getBody, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_request_withMethod, 0, 1, Signalforge\\Routing\\ProxyRequest, 0)
    ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_request_withUrl, 0, 1, Signalforge\\Routing\\ProxyRequest, 0)
    ZEND_ARG_TYPE_INFO(0, url, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_request_withHeader, 0, 2, Signalforge\\Routing\\ProxyRequest, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_request_withBody, 0, 1, Signalforge\\Routing\\ProxyRequest, 0)
    ZEND_ARG_TYPE_INFO(0, body, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_request_withoutHeader, 0, 1, Signalforge\\Routing\\ProxyRequest, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

/* ProxyResponse arg info */
ZEND_BEGIN_ARG_INFO_EX(arginfo_proxy_response_construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_response_getStatusCode, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_response_getHeaders, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_response_getHeader, 0, 1, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_response_getBody, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_response_withStatus, 0, 1, Signalforge\\Routing\\ProxyResponse, 0)
    ZEND_ARG_TYPE_INFO(0, code, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_response_withHeader, 0, 2, Signalforge\\Routing\\ProxyResponse, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_response_withBody, 0, 1, Signalforge\\Routing\\ProxyResponse, 0)
    ZEND_ARG_TYPE_INFO(0, body, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_proxy_response_withoutHeader, 0, 1, Signalforge\\Routing\\ProxyResponse, 0)
    ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_proxy_response_send, 0, 0, IS_VOID, 0)
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
    PHP_ME(Signalforge_Routing_Router, dump, arginfo_router_dump, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, getInstance, arginfo_router_getInstance, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, cli, arginfo_router_cli, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, routeUsing, arginfo_router_routeUsing, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, resolver, arginfo_router_resolver, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Signalforge_Routing_Router, dispatch, arginfo_router_dispatch, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
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
    PHP_ME(Signalforge_Routing_Route, proxy, arginfo_route_proxy, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, onRequest, arginfo_route_onRequest, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, onResponse, arginfo_route_onResponse, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_Route, getProxyUrl, arginfo_route_getProxyUrl, ZEND_ACC_PUBLIC)
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
    PHP_ME(Signalforge_Routing_MatchResult, isProxy, arginfo_match_isProxy, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_MatchResult, getProxyResponse, arginfo_match_getProxyResponse, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry sf_proxy_request_methods[] = {
    PHP_ME(Signalforge_Routing_ProxyRequest, __construct, arginfo_proxy_request_construct, ZEND_ACC_PRIVATE)
    PHP_ME(Signalforge_Routing_ProxyRequest, getMethod, arginfo_proxy_request_getMethod, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, getUrl, arginfo_proxy_request_getUrl, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, getHeaders, arginfo_proxy_request_getHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, getHeader, arginfo_proxy_request_getHeader, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, getBody, arginfo_proxy_request_getBody, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, withMethod, arginfo_proxy_request_withMethod, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, withUrl, arginfo_proxy_request_withUrl, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, withHeader, arginfo_proxy_request_withHeader, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, withBody, arginfo_proxy_request_withBody, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyRequest, withoutHeader, arginfo_proxy_request_withoutHeader, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry sf_proxy_response_methods[] = {
    PHP_ME(Signalforge_Routing_ProxyResponse, __construct, arginfo_proxy_response_construct, ZEND_ACC_PRIVATE)
    PHP_ME(Signalforge_Routing_ProxyResponse, getStatusCode, arginfo_proxy_response_getStatusCode, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, getHeaders, arginfo_proxy_response_getHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, getHeader, arginfo_proxy_response_getHeader, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, getBody, arginfo_proxy_response_getBody, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, withStatus, arginfo_proxy_response_withStatus, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, withHeader, arginfo_proxy_response_withHeader, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, withBody, arginfo_proxy_response_withBody, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, withoutHeader, arginfo_proxy_response_withoutHeader, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_ProxyResponse, send, arginfo_proxy_response_send, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry sf_routing_context_methods[] = {
    PHP_ME(Signalforge_Routing_RoutingContext, __construct, arginfo_routing_context_construct, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_RoutingContext, getMethod, arginfo_routing_context_getMethod, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_RoutingContext, getPath, arginfo_routing_context_getPath, ZEND_ACC_PUBLIC)
    PHP_ME(Signalforge_Routing_RoutingContext, getDomain, arginfo_routing_context_getDomain, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* ============================================================================
 * Module Lifecycle
 * ============================================================================ */

static void php_signalforge_routing_globals_ctor(zend_signalforge_routing_globals *globals)
{
    globals->global_router = NULL;
}

PHP_MINIT_FUNCTION(signalforge_routing)
{
    zend_class_entry ce;

    /* Initialize globals */
    ZEND_INIT_MODULE_GLOBALS(signalforge_routing, php_signalforge_routing_globals_ctor, NULL);

    /* Register Router class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "Router", sf_router_methods);
    sf_router_ce = zend_register_internal_class(&ce);
    sf_router_ce->create_object = sf_router_object_create;
    sf_router_ce->ce_flags |= ZEND_ACC_FINAL;

    memcpy(&sf_router_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_router_object_handlers.offset = XtOffsetOf(sf_router_object, std);
    sf_router_object_handlers.free_obj = sf_router_object_free;
    sf_router_object_handlers.clone_obj = NULL;

    /* Register Route class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "Route", sf_route_methods);
    sf_route_ce = zend_register_internal_class(&ce);
    sf_route_ce->create_object = sf_route_object_create;
    sf_route_ce->ce_flags |= ZEND_ACC_FINAL;

    memcpy(&sf_route_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_route_object_handlers.offset = XtOffsetOf(sf_route_object, std);
    sf_route_object_handlers.free_obj = sf_route_object_free;
    sf_route_object_handlers.clone_obj = NULL;

    /* Register MatchResult class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "MatchResult", sf_match_result_methods);
    sf_match_result_ce = zend_register_internal_class(&ce);
    sf_match_result_ce->create_object = sf_match_result_object_create;
    sf_match_result_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_READONLY_CLASS;

    memcpy(&sf_match_result_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_match_result_object_handlers.offset = XtOffsetOf(sf_match_result_object, std);
    sf_match_result_object_handlers.free_obj = sf_match_result_object_free;
    sf_match_result_object_handlers.clone_obj = NULL;

    /* Register RoutingContext class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "RoutingContext", sf_routing_context_methods);
    sf_routing_context_ce = zend_register_internal_class(&ce);
    sf_routing_context_ce->create_object = sf_routing_context_object_create;
    sf_routing_context_ce->ce_flags |= ZEND_ACC_FINAL;

    memcpy(&sf_routing_context_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_routing_context_object_handlers.offset = XtOffsetOf(sf_routing_context_object, std);
    sf_routing_context_object_handlers.free_obj = sf_routing_context_object_free;
    sf_routing_context_object_handlers.clone_obj = NULL;

    /* Register ProxyRequest class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "ProxyRequest", sf_proxy_request_methods);
    sf_proxy_request_ce = zend_register_internal_class(&ce);
    sf_proxy_request_ce->create_object = sf_proxy_request_object_create;
    sf_proxy_request_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_READONLY_CLASS;

    memcpy(&sf_proxy_request_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_proxy_request_object_handlers.offset = XtOffsetOf(sf_proxy_request_object, std);
    sf_proxy_request_object_handlers.free_obj = sf_proxy_request_object_free;
    sf_proxy_request_object_handlers.clone_obj = NULL;

    /* Register ProxyResponse class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\Routing", "ProxyResponse", sf_proxy_response_methods);
    sf_proxy_response_ce = zend_register_internal_class(&ce);
    sf_proxy_response_ce->create_object = sf_proxy_response_object_create;
    sf_proxy_response_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_READONLY_CLASS;

    memcpy(&sf_proxy_response_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    sf_proxy_response_object_handlers.offset = XtOffsetOf(sf_proxy_response_object, std);
    sf_proxy_response_object_handlers.free_obj = sf_proxy_response_object_free;
    sf_proxy_response_object_handlers.clone_obj = NULL;

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

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(signalforge_routing)
{
    /* Clean up request-specific data */
    if (SF_G(global_router)) {
        sf_router_destroy(SF_G(global_router));
        SF_G(global_router) = NULL;
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
