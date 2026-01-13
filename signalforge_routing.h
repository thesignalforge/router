/*
 * Signalforge Routing Extension
 * signalforge_routing.h - Main extension header
 *
 * Copyright (c) 2024 Signalforge
 * License: MIT
 */

#ifndef PHP_SIGNALFORGE_ROUTING_H
#define PHP_SIGNALFORGE_ROUTING_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "routing_trie.h"

/* Extension version */
#define PHP_SIGNALFORGE_ROUTING_VERSION "1.0.0"
#define PHP_SIGNALFORGE_ROUTING_EXTNAME "signalforge_routing"

/* Module entry */
extern zend_module_entry signalforge_routing_module_entry;
#define phpext_signalforge_routing_ptr &signalforge_routing_module_entry

/* Class entries */
extern zend_class_entry *sf_router_ce;
extern zend_class_entry *sf_route_ce;
extern zend_class_entry *sf_match_result_ce;
extern zend_class_entry *sf_routing_exception_ce;

/* Object handlers */
extern zend_object_handlers sf_router_object_handlers;
extern zend_object_handlers sf_route_object_handlers;
extern zend_object_handlers sf_match_result_object_handlers;

/* ============================================================================
 * PHP Object Structures
 * ============================================================================ */

/* Router PHP object */
typedef struct _sf_router_object {
    sf_router *router;
    zend_object std;
} sf_router_object;

/* Route PHP object */
typedef struct _sf_route_object {
    sf_route *route;
    zend_object std;
} sf_route_object;

/* MatchResult PHP object */
typedef struct _sf_match_result_object {
    sf_match_result *result;
    zend_object std;
} sf_match_result_object;

/* ============================================================================
 * Object Accessor Macros
 * ============================================================================ */

static inline sf_router_object *sf_router_object_from_zend_object(zend_object *obj) {
    return (sf_router_object *)((char *)obj - XtOffsetOf(sf_router_object, std));
}
#define Z_ROUTER_OBJ_P(zv) sf_router_object_from_zend_object(Z_OBJ_P(zv))

static inline sf_route_object *sf_route_object_from_zend_object(zend_object *obj) {
    return (sf_route_object *)((char *)obj - XtOffsetOf(sf_route_object, std));
}
#define Z_ROUTE_OBJ_P(zv) sf_route_object_from_zend_object(Z_OBJ_P(zv))

static inline sf_match_result_object *sf_match_result_object_from_zend_object(zend_object *obj) {
    return (sf_match_result_object *)((char *)obj - XtOffsetOf(sf_match_result_object, std));
}
#define Z_MATCH_RESULT_OBJ_P(zv) sf_match_result_object_from_zend_object(Z_OBJ_P(zv))

/* ============================================================================
 * Object Create/Free Functions
 * ============================================================================ */

zend_object *sf_router_object_create(zend_class_entry *ce);
void sf_router_object_free(zend_object *obj);

zend_object *sf_route_object_create(zend_class_entry *ce);
void sf_route_object_free(zend_object *obj);

zend_object *sf_match_result_object_create(zend_class_entry *ce);
void sf_match_result_object_free(zend_object *obj);

/* ============================================================================
 * Module Lifecycle Functions
 * ============================================================================ */

PHP_MINIT_FUNCTION(signalforge_routing);
PHP_MSHUTDOWN_FUNCTION(signalforge_routing);
PHP_RINIT_FUNCTION(signalforge_routing);
PHP_RSHUTDOWN_FUNCTION(signalforge_routing);
PHP_MINFO_FUNCTION(signalforge_routing);

/* ============================================================================
 * Globals Declaration
 * ============================================================================ */

ZEND_BEGIN_MODULE_GLOBALS(signalforge_routing)
    sf_error_code last_error;
    char *last_error_msg;
    sf_router *global_router;
ZEND_END_MODULE_GLOBALS(signalforge_routing)

ZEND_EXTERN_MODULE_GLOBALS(signalforge_routing)

#ifdef ZTS
#include "TSRM.h"
#define SF_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(signalforge_routing, v)
#else
#define SF_G(v) (signalforge_routing_globals.v)
#endif

/* ============================================================================
 * Static Method Declarations - Router
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_Router, get);
PHP_METHOD(Signalforge_Routing_Router, post);
PHP_METHOD(Signalforge_Routing_Router, put);
PHP_METHOD(Signalforge_Routing_Router, patch);
PHP_METHOD(Signalforge_Routing_Router, delete);
PHP_METHOD(Signalforge_Routing_Router, options);
PHP_METHOD(Signalforge_Routing_Router, any);
PHP_METHOD(Signalforge_Routing_Router, match);
PHP_METHOD(Signalforge_Routing_Router, group);
PHP_METHOD(Signalforge_Routing_Router, prefix);
PHP_METHOD(Signalforge_Routing_Router, middleware);
PHP_METHOD(Signalforge_Routing_Router, domain);
PHP_METHOD(Signalforge_Routing_Router, namespace_);
PHP_METHOD(Signalforge_Routing_Router, name);
PHP_METHOD(Signalforge_Routing_Router, fallback);
PHP_METHOD(Signalforge_Routing_Router, url);
PHP_METHOD(Signalforge_Routing_Router, has);
PHP_METHOD(Signalforge_Routing_Router, route);
PHP_METHOD(Signalforge_Routing_Router, getRoutes);
PHP_METHOD(Signalforge_Routing_Router, flush);
PHP_METHOD(Signalforge_Routing_Router, cache);
PHP_METHOD(Signalforge_Routing_Router, loadCache);
PHP_METHOD(Signalforge_Routing_Router, setStrictSlashes);
PHP_METHOD(Signalforge_Routing_Router, dump);
PHP_METHOD(Signalforge_Routing_Router, getInstance);

/* ============================================================================
 * Method Declarations - Route
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_Route, __construct);
PHP_METHOD(Signalforge_Routing_Route, name);
PHP_METHOD(Signalforge_Routing_Route, middleware);
PHP_METHOD(Signalforge_Routing_Route, where);
PHP_METHOD(Signalforge_Routing_Route, whereNumber);
PHP_METHOD(Signalforge_Routing_Route, whereAlpha);
PHP_METHOD(Signalforge_Routing_Route, whereAlphaNumeric);
PHP_METHOD(Signalforge_Routing_Route, whereUuid);
PHP_METHOD(Signalforge_Routing_Route, whereUlid);
PHP_METHOD(Signalforge_Routing_Route, whereIn);
PHP_METHOD(Signalforge_Routing_Route, defaults);
PHP_METHOD(Signalforge_Routing_Route, domain);
PHP_METHOD(Signalforge_Routing_Route, withoutMiddleware);
PHP_METHOD(Signalforge_Routing_Route, getName);
PHP_METHOD(Signalforge_Routing_Route, getUri);
PHP_METHOD(Signalforge_Routing_Route, getMethods);
PHP_METHOD(Signalforge_Routing_Route, getHandler);
PHP_METHOD(Signalforge_Routing_Route, getMiddleware);
PHP_METHOD(Signalforge_Routing_Route, getWheres);
PHP_METHOD(Signalforge_Routing_Route, getDefaults);
PHP_METHOD(Signalforge_Routing_Route, getDomain);

/* ============================================================================
 * Method Declarations - MatchResult
 * ============================================================================ */

PHP_METHOD(Signalforge_Routing_MatchResult, __construct);
PHP_METHOD(Signalforge_Routing_MatchResult, matched);
PHP_METHOD(Signalforge_Routing_MatchResult, getRoute);
PHP_METHOD(Signalforge_Routing_MatchResult, getHandler);
PHP_METHOD(Signalforge_Routing_MatchResult, getParams);
PHP_METHOD(Signalforge_Routing_MatchResult, getMiddleware);
PHP_METHOD(Signalforge_Routing_MatchResult, getRouteName);
PHP_METHOD(Signalforge_Routing_MatchResult, getError);
PHP_METHOD(Signalforge_Routing_MatchResult, param);

#endif /* PHP_SIGNALFORGE_ROUTING_H */
