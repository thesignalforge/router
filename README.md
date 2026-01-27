# Signalforge Router

A native PHP extension for high-performance HTTP and CLI routing, written in C.

## Installation

### Requirements

- PHP 8.3+
- Linux (tested on x86_64)
- PCRE2 development headers
- PHP development headers

On Debian/Ubuntu:

```bash
apt install php-dev libpcre2-dev
```

### Build from source

```bash
git clone https://github.com/niccolosanaworkinprogress/signalforge-router.git
cd signalforge-router

phpize
./configure --enable-signalforge-routing
make
make test
sudo make install
```

Add to your `php.ini`:

```ini
extension=signalforge_routing.so
```

Verify:

```bash
php -m | grep signalforge
```

---

## HTTP Routing

### Registering routes

Every HTTP method has a corresponding static method on `Router`. Each returns a `Route` object for chaining.

```php
use Signalforge\Routing\Router;

Router::get('/users', [UserController::class, 'index']);
Router::post('/users', [UserController::class, 'store']);
Router::put('/users/{id}', [UserController::class, 'update']);
Router::patch('/users/{id}', [UserController::class, 'patch']);
Router::delete('/users/{id}', [UserController::class, 'destroy']);
Router::options('/users', [UserController::class, 'options']);
Router::any('/health', fn() => 'ok');
```

### Matching requests

`Router::match()` takes an HTTP method and URI, returns a `MatchResult`:

```php
$result = Router::match('GET', '/users/42');

if ($result->matched()) {
    $handler = $result->getHandler();   // [UserController::class, 'update']
    $params  = $result->getParams();    // ['id' => '42']
    $name    = $result->getRouteName(); // 'users.update' or null
}
```

You can also retrieve a single parameter with a default:

```php
$id = $result->param('id');
$page = $result->param('page', 1);
```

### Framework-agnostic dispatch

Instead of calling `Router::match()` directly, you can bind any request source — a framework request object, `$_SERVER`, or anything else — and let a resolver extract the routing data:

```php
use Signalforge\Routing\{Router, RoutingContext};

// Using $_SERVER
Router::routeUsing($_SERVER, function(array $server): RoutingContext {
    return new RoutingContext(
        $server['REQUEST_METHOD'],
        parse_url($server['REQUEST_URI'], PHP_URL_PATH)
    );
});

$result = Router::dispatch();
```

This works with any request object. The router never depends on a specific framework:

```php
// Symfony HttpFoundation
Router::routeUsing($request, function(Request $req): RoutingContext {
    return new RoutingContext(
        $req->getMethod(),
        $req->getPathInfo(),
        $req->getHost()
    );
});

// Laravel
Router::routeUsing($request, function(IlluminateRequest $req): RoutingContext {
    return new RoutingContext($req->method(), $req->path(), $req->getHost());
});

// PSR-7
Router::routeUsing($request, function(ServerRequestInterface $req): RoutingContext {
    $uri = $req->getUri();
    return new RoutingContext($req->getMethod(), $uri->getPath(), $uri->getHost());
});
```

`RoutingContext` is a simple value object with three fields: method, path, and an optional domain. The resolver creates one, the router consumes it. Nothing else is coupled.

### Route parameters

Parameters are enclosed in curly braces. They capture the corresponding URI segment.

```php
// Required parameter
Router::get('/users/{id}', $handler);

// Optional parameter (trailing ? inside the braces)
Router::get('/posts/{slug?}', $handler);

// Wildcard — captures the entire remaining path
Router::get('/docs/{path*}', $handler);
// /docs/api/v2/users → ['path' => 'api/v2/users']
```

### Constraints

Constraints restrict what a parameter will accept. The route only matches if every constrained parameter passes validation.

```php
Router::get('/users/{id}', $handler)->whereNumber('id');
Router::get('/posts/{slug}', $handler)->whereAlpha('slug');
Router::get('/items/{code}', $handler)->whereAlphaNumeric('code');
Router::get('/orders/{uuid}', $handler)->whereUuid('uuid');
Router::get('/records/{ulid}', $handler)->whereUlid('ulid');

// Enumerated values
Router::get('/status/{type}', $handler)->whereIn('type', ['active', 'pending', 'closed']);

// Custom regex
Router::get('/products/{sku}', $handler)->where('sku', '[A-Z]{2}-\d{4}');

// Multiple constraints at once
Router::get('/users/{id}/posts/{slug}', $handler)
    ->where(['id' => '\d+', 'slug' => '[a-z0-9-]+']);
```

The built-in validators (`whereNumber`, `whereAlpha`, `whereUuid`, etc.) bypass PCRE2 entirely and use optimized C checks. Custom `where()` patterns compile to PCRE2 once at registration and are never recompiled.

### Default values

When an optional parameter is not present in the URI, a default value is used:

```php
Router::get('/posts/{page?}', $handler)->defaults('page', 1);

$result = Router::match('GET', '/posts');
$result->param('page'); // 1
```

### Named routes and URL generation

```php
Router::get('/users/{id}/posts/{slug}', $handler)
    ->name('users.posts.show')
    ->whereNumber('id')
    ->whereAlpha('slug');

// Generate a URL from a name + parameters
$url = Router::url('users.posts.show', ['id' => 42, 'slug' => 'hello']);
// → /users/42/posts/hello

// Check existence
Router::has('users.posts.show'); // true

// Retrieve the Route object
$route = Router::route('users.posts.show');
$route->getUri();     // /users/{id}/posts/{slug}
$route->getMethods(); // ['GET']
```

### Middleware

Middleware names are attached to routes and returned in match results. The router does not execute middleware — that is your application's responsibility.

```php
Router::get('/admin', $handler)->middleware(['auth', 'admin']);

$result = Router::match('GET', '/admin');
$result->getMiddleware(); // ['auth', 'admin']
```

### Route groups

Groups apply shared configuration to every route registered inside them:

```php
Router::group([
    'prefix'     => '/api/v1',
    'middleware' => ['auth', 'throttle'],
    'as'         => 'api.',
    'domain'     => '{tenant}.example.com',
], function () {
    Router::get('/users', [UserController::class, 'index']);
    // URI: /api/v1/users
    // Name: api.users (if ->name('users') is chained)
    // Middleware: auth, throttle
    // Domain: {tenant}.example.com

    // Groups nest
    Router::group(['prefix' => '/admin', 'middleware' => ['admin']], function () {
        Router::get('/stats', [AdminController::class, 'stats']);
        // URI: /api/v1/admin/stats
        // Middleware: auth, throttle, admin
    });
});
```

### Domain routing

Routes can be scoped to a domain pattern. Domain parameters are extracted just like path parameters:

```php
Router::get('/dashboard', $handler)->domain('{tenant}.example.com');

$result = Router::match('GET', '/dashboard', 'acme.example.com');
$result->param('tenant'); // 'acme'
```

When using `routeUsing`, pass the domain as the third argument to `RoutingContext`:

```php
Router::routeUsing($request, function($req): RoutingContext {
    return new RoutingContext($req->method, $req->path, $req->host);
});
```

### Fallback route

A fallback handler is invoked when no registered route matches:

```php
Router::fallback(function () {
    http_response_code(404);
    return 'Not Found';
});

$result = Router::match('GET', '/nonexistent');
$result->matched(); // true (matched the fallback)
```

### Route caching

For production, routes can be serialized to a binary file and loaded without re-registration. Closures cannot be cached — use array callables `[Class::class, 'method']`.

```php
// Save (e.g., during deployment)
Router::cache('/var/cache/routes.bin');

// Load (at bootstrap)
Router::loadCache('/var/cache/routes.bin');
```

### Flushing state

`Router::flush()` clears all routes, named routes, groups, dispatch context, and fallback:

```php
Router::flush();
```

---

## CLI Routing

The same router handles CLI command dispatch. Commands use colon-separated segments instead of slashes, and the method is `CLI`.

### Registering CLI routes

```php
Router::cli('cache:clear', [CacheCommand::class, 'handle']);
Router::cli('migrate:fresh', [MigrateCommand::class, 'fresh']);
Router::cli('users:{id}:delete', [UserCommand::class, 'delete'])->whereNumber('id');
Router::cli('deploy:{env}', [DeployCommand::class, 'run'])->whereIn('env', ['staging', 'production']);
```

Parameters, constraints, middleware, naming — everything works the same way as HTTP routes. Internally, `cache:clear` is normalized to `/cache/clear` and stored in a dedicated CLI trie, completely separate from the HTTP tries.

### Matching CLI commands

Direct matching:

```php
$result = Router::match('CLI', 'users:42:delete');
$result->matched();      // true
$result->param('id');    // '42'
$result->getHandler();   // [UserCommand::class, 'delete']
```

### CLI dispatch with routeUsing

For a full CLI application, parse `$argv` through a resolver:

```php
// Given: php app.php users:42:delete --force

Router::cli('cache:clear', [CacheCommand::class, 'handle']);
Router::cli('users:{id}:delete', [UserCommand::class, 'delete'])->whereNumber('id');
Router::cli('migrate:{direction?}', [MigrateCommand::class, 'run']);

Router::routeUsing($argv, function(array $argv): RoutingContext {
    return new RoutingContext('CLI', $argv[1] ?? '');
});

$result = Router::dispatch();

if ($result->matched()) {
    $handler = $result->getHandler();
    $params  = $result->getParams();
    // Call $handler with $params + remaining $argv flags
}
```

### Optional CLI parameters

```php
Router::cli('logs:{level?}', [LogCommand::class, 'show'])
    ->defaults('level', 'info');

$result = Router::match('CLI', 'logs');
$result->param('level'); // 'info'

$result = Router::match('CLI', 'logs:error');
$result->param('level'); // 'error'
```

### Named CLI routes

```php
Router::cli('deploy:{env}', [DeployCommand::class, 'run'])
    ->name('deploy')
    ->whereIn('env', ['staging', 'production']);

$url = Router::url('deploy', ['env' => 'staging']);
// → /deploy/staging (internal normalized form)
```

### Combining HTTP and CLI

HTTP and CLI routes coexist in the same router without collision. Each HTTP method and CLI have their own trie:

```php
Router::get('/users/{id}', [UserController::class, 'show'])->whereNumber('id');
Router::cli('users:{id}:show', [UserCommand::class, 'show'])->whereNumber('id');

// HTTP
$http = Router::match('GET', '/users/42');
$http->getHandler(); // [UserController::class, 'show']

// CLI
$cli = Router::match('CLI', 'users:42:show');
$cli->getHandler(); // [UserCommand::class, 'show']
```

---

## API Reference

### Router (static)

| Method | Returns | Description |
|--------|---------|-------------|
| `get($uri, $handler)` | `Route` | Register GET route |
| `post($uri, $handler)` | `Route` | Register POST route |
| `put($uri, $handler)` | `Route` | Register PUT route |
| `patch($uri, $handler)` | `Route` | Register PATCH route |
| `delete($uri, $handler)` | `Route` | Register DELETE route |
| `options($uri, $handler)` | `Route` | Register OPTIONS route |
| `any($uri, $handler)` | `Route` | Register route for any method |
| `cli($command, $handler)` | `Route` | Register CLI command |
| `match($method, $uri, $domain?)` | `MatchResult` | Match a request |
| `routeUsing($input, $resolver)` | `void` | Bind input + resolver for dispatch |
| `dispatch()` | `MatchResult` | Dispatch using bound context |
| `group($attrs, $callback)` | `void` | Group routes with shared config |
| `fallback($handler)` | `Route` | Set fallback handler |
| `url($name, $params?)` | `?string` | Generate URL for named route |
| `has($name)` | `bool` | Check if named route exists |
| `route($name)` | `?Route` | Get route by name |
| `getRoutes()` | `array` | Get all routes |
| `flush()` | `void` | Clear all state |
| `cache($path)` | `bool` | Save routes to binary file |
| `loadCache($path)` | `bool` | Load routes from binary file |
| `setStrictSlashes($strict)` | `void` | Toggle trailing slash behavior |

### Route (chaining)

| Method | Description |
|--------|-------------|
| `name($name)` | Set route name |
| `middleware($middleware)` | Add middleware (string or array) |
| `where($param, $pattern?)` | Custom regex constraint |
| `whereNumber($params)` | Numeric constraint |
| `whereAlpha($params)` | Alphabetic constraint |
| `whereAlphaNumeric($params)` | Alphanumeric constraint |
| `whereUuid($params)` | UUID format constraint |
| `whereUlid($params)` | ULID format constraint |
| `whereIn($param, $values)` | Enumerated values |
| `defaults($param, $value)` | Default for optional param |
| `domain($domain)` | Domain constraint |
| `withoutMiddleware($middleware)` | Remove middleware |

### MatchResult

| Method | Returns | Description |
|--------|---------|-------------|
| `matched()` | `bool` | Whether a route matched |
| `getHandler()` | `mixed` | The handler callable |
| `getParams()` | `array` | All extracted parameters |
| `param($name, $default?)` | `mixed` | Single parameter with default |
| `getMiddleware()` | `array` | Middleware stack |
| `getRouteName()` | `?string` | Route name |
| `getRoute()` | `?Route` | The Route object |
| `getError()` | `?string` | Error message on failure |

### RoutingContext

| Method | Returns | Description |
|--------|---------|-------------|
| `__construct($method, $path, $domain?)` | | Create context |
| `getMethod()` | `string` | HTTP method or `"CLI"` |
| `getPath()` | `string` | Request path |
| `getDomain()` | `?string` | Domain if set |

---

## Thread Safety

The extension works with PHP ZTS builds. Each request gets isolated router state. The trie is protected by a read-write lock: concurrent reads during matching, exclusive writes during registration.

---

## Benchmarks

Tested against FastRoute, Symfony Routing, and Laravel Router with complex multi-parameter routes (1-10 parameters per route, numeric constraints, optional segments).

| Routes | Signalforge | FastRoute | Symfony | Laravel |
|--------|-------------|-----------|---------|---------|
| 10 | 3.18 ms | 6.34 ms | 24.98 ms | 99.44 ms |
| 100 | 15.39 ms | 44.21 ms | 388.04 ms | 765.96 ms |
| 1,000 | 7.81 ms | 174.45 ms | 2.95 s | 3.31 s |

At 1,000 routes: **22x faster than FastRoute**, **424x faster than Laravel**.

Matching time stays flat or decreases as routes scale, because shared prefixes are stored once in the trie. Adding more routes under `/api/v1/` costs nothing extra at lookup time — the trie already has those prefix nodes.

Full benchmark data: [benchmark.md](benchmark.md)

---

## How the Radix Trie Works

Most PHP routers iterate over every registered route and test each one against the incoming URI. This is O(n) in the number of routes. Some compile routes into a single large regex, which is faster but still scales poorly as route count grows.

Signalforge uses a compressed radix trie (also called a Patricia tree). Each node in the tree represents a path segment. Routes that share a common prefix share the same nodes:

```
GET trie:

/
├── api/
│   └── v1/
│       └── users/
│           ├── {id}            → UserController@show
│           │   └── posts/
│           │       └── {postId} → PostController@show
│           └── (terminal)       → UserController@index
├── docs/
│   └── {path*}                 → DocsController@page
└── health                      → fn() => 'ok'
```

When a request arrives for `/api/v1/users/42/posts/7`:

1. Start at root, match `api` — follow the static child
2. Match `v1` — follow the static child
3. Match `users` — follow the static child
4. Hit the `{id}` param node — capture `42`, continue
5. Match `posts` — follow the static child
6. Hit the `{postId}` param node — capture `7`, hit terminal
7. Validate constraints: `id` is `\d+` — passes. `postId` is `\d+` — passes
8. Return handler + `['id' => '42', 'postId' => '7']`

The cost is proportional to the number of segments in the URI (O(k)), not the number of registered routes. Whether you have 10 routes or 10,000, a 4-segment URI still traverses exactly 4 nodes.

### Why matching gets faster with more routes

The benchmark numbers show an apparent paradox: matching 1,000 routes (7.81 ms) is faster than matching 100 routes (15.39 ms). This happens because routes with shared prefixes (e.g., all `/api/v1/...` routes) share the same trie nodes. More routes means more prefix sharing, which means fewer unique nodes relative to the total route count. The trie compresses the routing table.

### Separate tries per method

Each HTTP method and CLI get their own trie. A `GET` request never inspects `POST` routes. This halves the effective trie size for typical applications and removes cross-method false matches entirely.

### Constraint checking is deferred

Constraints (`whereNumber`, `whereAlpha`, custom regex) are only checked after a terminal node is reached. During traversal, the router only does string comparison against static segments and captures parameter values. This means constraints never slow down non-matching routes — they only run on the single candidate that structurally matched.

### Cache-line optimized nodes

Trie node fields are ordered so that everything accessed during traversal (`static_children`, `param_child`, `optional_child`, `wildcard_child`, `route`, `is_terminal`) fits in the first 64-byte CPU cache line. Cold fields like `segment` and `constraint` are pushed to the second cache line. This can be disabled with `-DSF_COMPACT_MODE` to reduce per-node memory at the cost of some throughput.

### CLI normalization

CLI commands use colons as separators (`cache:clear`, `users:{id}:delete`). Internally, the router normalizes these to slash-separated paths (`/cache/clear`, `/users/{id}/delete`) so they can be stored in the same trie structure. This normalization is transparent — `Route::getUri()` returns the original colon form, and `Router::match('CLI', 'cache:clear')` works without the caller needing to know about the internal representation.

---

## License

MIT
