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

- **Router** - Static interface for route registration and matching
- **Route** - Represents a registered route, supports method chaining for configuration
- **MatchResult** - Immutable result from `Router::match()`, contains handler, params, middleware

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
Router::cache('/path/to/cache.bin');
Router::loadCache('/path/to/cache.bin');
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
