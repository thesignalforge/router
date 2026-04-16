# Signalforge Router - PHP Extension

High-performance routing extension for PHP using a compressed radix trie for O(k) route matching.

## Project Structure

```
├── signalforge_routing.c/h    # PHP extension glue code, class definitions
├── routing_trie.c/h           # Core radix trie data structure and matching
├── Signalforge/Routing/       # IDE stub files (for autocompletion)
│   ├── Router.stub.php
│   ├── Route.stub.php
│   └── MatchResult.stub.php
├── examples/                  # Usage examples
├── tests/                     # PHPT test files
├── config.m4                  # Autoconf build configuration
└── modules/                   # Compiled .so output
```

## Building

```bash
phpize
./configure
make
make test
```

## Running Tests

```bash
php -d extension=./modules/signalforge_routing.so run-tests.php -d extension=./modules/signalforge_routing.so tests/
```

## Key Classes

- **Router** - Instance-based interface for route registration and matching (`new Router()`)
- **Route** - Represents a registered route, supports method chaining for configuration
- **MatchResult** - Immutable result from `$router->match()`, contains handler, params, middleware

## Route Handler Format

Handlers use PHP's native callable syntax:
- Array callable: `[UserController::class, 'index']`
- Closure: `fn() => 'hello'` or `function() { return 'hello'; }`
- Function name: `'myFunction'`

**Note:** Laravel-style `'Controller@method'` syntax is NOT used.

## Route Features

- **Parameters**: `/users/{id}` - required, `/users/{id?}` - optional
- **Wildcards**: `/docs/{path*}` or `/docs/{path...}` - catch-all
- **Constraints**: `->whereNumber('id')`, `->whereAlpha('slug')`, `->where('sku', '[A-Z]{2}-\d{4}')`
- **Defaults**: `->defaults('page', 1)`
- **Middleware**: `->middleware(['auth', 'throttle'])`
- **Named routes**: `->name('users.show')` for URL generation
- **Domain routing**: `->domain('{tenant}.example.com')`
- **Groups**: Shared prefix, middleware, name prefix, domain

## Binary Caching

Routes can be cached to a binary file for production:
```php
$router->cache('/path/to/cache.bin');
$router->loadCache('/path/to/cache.bin');
```

**Important:** Closures cannot be serialized - only array callables `[class, method]` survive caching.

## C Code Architecture

### routing_trie.h
- `sf_trie_node` - Radix trie node with children, route reference
- `sf_route` - Route struct with URI, handler (zval), middleware, constraints, defaults
- Node types: `SF_NODE_STATIC`, `SF_NODE_PARAM`, `SF_NODE_PARAM_OPTIONAL`, `SF_NODE_WILDCARD`

### routing_trie.c
Key functions:
- `sf_router_add_route()` - Insert route into trie
- `sf_router_match()` - Match URI against trie, extract parameters
- `sf_router_serialize()` / `sf_router_deserialize()` - Binary cache format
- `sf_parse_uri()` - Parse URI into segments

### signalforge_routing.c
- PHP class definitions (Router, Route, MatchResult)
- Method implementations mapping PHP calls to C functions
- Memory management, zval handling

## Handler Storage

Handlers are stored as `zval` in the route struct:
- **Array handlers** `[class, method]` - serialized as two strings
- **String handlers** - serialized as-is (for backwards compat)
- **Closures** - stored but cannot be cached (type marker 0)

## Coding Style

- C99 standard
- Function prefix: `sf_` for internal, `sf_router_` for router operations
- PHP class methods: `sf_router_*` or `sf_route_*`
- Use `zend_string` for strings, proper refcounting
- Memory: `emalloc`/`efree` for request-bound, `pemalloc`/`pefree` for persistent

## Recent Work (January 2026)

### Security Audit Fixes (commit 9de5e0a)

All 13 findings from C code audit addressed:

**HIGH severity (2):**
- H-1: Fixed resolver use-after-free in `dispatch()` — copy zval before invoking callback
- H-2: Added `clone_obj = NULL` to Router, Route, MatchResult, RoutingContext object handlers

**MEDIUM severity (3):**
- M-1: Group `where` constraints now propagate to child routes (route-specific overrides group)
- M-2: Added depth limit (`SF_MAX_TRIE_DEPTH`) to `sf_find_terminal_through_optionals`
- M-3: Added http/https scheme validation in `sf_proxy_execute` against SSRF bypass

**LOW severity (5):**
- L-1: Removed dead `priority` field from `sf_route`
- L-2: Removed dead `trailing_slash_strict` and `setStrictSlashes` method
- L-3: Removed dead `sf_error_code` enum and `last_error`/`last_error_msg` globals
- L-4: Use cached `validator_type` during deserialization
- L-5: Upgraded unknown HTTP method from `E_NOTICE` to `E_WARNING`
- L-6: Use `zend_string_truncate` instead of direct `ZSTR_LEN` mutation

### PHP 8.5 Compatibility

Removed unused `#include "ext/standard/php_smart_string.h"` — header was dropped in PHP 8.5.
Extension now builds and passes all 10 tests on both PHP 8.4 and 8.5.

### Windows Build Status

The codebase is mostly Windows-ready:
- `config.w32` exists with PCRE2 configuration
- File locking has `#ifdef PHP_WIN32` paths
- Thread locks use `SRWLOCK` on Windows vs `pthread_rwlock_t` on POSIX
- Cache-line alignment uses `__declspec(align(...))` for MSVC

**One blocker:** GCC atomic builtins at `routing_trie.c:137,148` need MSVC `InterlockedIncrement`/`InterlockedDecrement` alternatives:
```c
// Current (GCC-only):
__atomic_add_fetch(&route->refcount, 1, __ATOMIC_RELAXED);
// Needs MSVC alternative:
InterlockedIncrement((LONG volatile *)&route->refcount);
```

### Pure PHP Port Assessment

A pure PHP port is feasible (~2,000-2,500 lines, 9 classes) but would be 20-50x slower for matching due to:
- Object reference overhead vs pointer arithmetic
- `preg_match` vs hand-rolled character validators
- No cache-line alignment or branch prediction hints
- 3-5x higher memory usage per route

Recommended only for environments where C extension can't be installed.

## Test Commands

```bash
# PHP 8.4
make clean && phpize && ./configure && make
php8.4 -d extension=./modules/signalforge_routing.so run-tests.php -d extension=./modules/signalforge_routing.so tests/

# PHP 8.5
make clean && phpize8.5 --clean && phpize8.5 && ./configure --with-php-config=php-config8.5 && make
php8.5 -d extension=./modules/signalforge_routing.so run-tests.php -d extension=./modules/signalforge_routing.so tests/
```
