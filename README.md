# Signalforge Router

A PHP routing extension written in C. It uses a compressed radix trie internally so route matching is O(k) where k is the number of URI segments, not the number of registered routes. It handles HTTP routing, CLI command dispatch, and reverse proxying to upstream servers.

## Table of Contents

- [Full Example](#full-example)
- [Setting Up Routes](#setting-up-routes)
  - [HTTP Methods](#http-methods)
  - [Parameters](#parameters)
  - [Constraints](#constraints)
  - [Default Values](#default-values)
  - [Named Routes](#named-routes)
  - [Groups](#groups)
  - [Domain Routing](#domain-routing)
  - [Fallback](#fallback)
  - [CLI Commands](#cli-commands)
- [Feeding the Request](#feeding-the-request)
  - [Using $_SERVER](#using-_server)
  - [Using a Framework Request Object](#using-a-framework-request-object)
  - [Direct Matching](#direct-matching)
- [Dispatching and Running Handlers](#dispatching-and-running-handlers)
  - [Getting the Handler](#getting-the-handler)
  - [Working with Middleware](#working-with-middleware)
  - [Full Dispatch Loop](#full-dispatch-loop)
- [Reverse Proxy](#reverse-proxy)
  - [Basic Proxy](#basic-proxy)
  - [URL Parameter Substitution](#url-parameter-substitution)
  - [Request and Response Hooks](#request-and-response-hooks)
  - [ProxyRequest](#proxyrequest)
  - [ProxyResponse](#proxyresponse)
  - [Proxy Security](#proxy-security)
- [Route Caching](#route-caching)
- [Worker Runtimes](#worker-runtimes)
- [How It's Built](#how-its-built)
  - [The Radix Trie](#the-radix-trie)
  - [Why It Gets Faster with More Routes](#why-it-gets-faster-with-more-routes)
  - [Benchmarks](#benchmarks)
- [Installation](#installation)
- [API Reference](#api-reference)
- [License](#license)

---

## Full Example

This is a complete working application. It registers some routes, feeds in the incoming HTTP request, dispatches it, runs middleware, and calls the matched handler.

```php
<?php
// index.php

use Signalforge\Routing\{Router, RoutingContext, MatchResult};

// 1. Define your routes
Router::get('/', [HomeController::class, 'index']);

Router::group(['prefix' => '/api', 'middleware' => ['auth']], function () {
    Router::get('/users', [UserController::class, 'list']);
    Router::get('/users/{id}', [UserController::class, 'show'])
        ->whereNumber('id')
        ->name('users.show');
    Router::post('/users', [UserController::class, 'create']);
    Router::put('/users/{id}', [UserController::class, 'update'])
        ->whereNumber('id');
    Router::delete('/users/{id}', [UserController::class, 'destroy'])
        ->whereNumber('id');
});

Router::get('/health', fn() => json_encode(['status' => 'ok']));

Router::fallback(fn() => 'Not Found');

// 2. Tell the router how to read the incoming request
Router::routeUsing($_SERVER, function (array $server): RoutingContext {
    return new RoutingContext(
        $server['REQUEST_METHOD'],
        parse_url($server['REQUEST_URI'], PHP_URL_PATH)
    );
});

// 3. Dispatch
$result = Router::dispatch();

// 4. Run middleware (your responsibility — the router just gives you the names)
$middleware = $result->getMiddleware(); // e.g. ['auth']
foreach ($middleware as $name) {
    // however your app resolves and runs middleware
    $mw = resolve_middleware($name);
    $mw->handle();
}

// 5. Call the handler
$handler = $result->getHandler();
$params  = $result->getParams();

if (is_array($handler)) {
    [$class, $method] = $handler;
    $controller = new $class();
    $response = $controller->$method(...array_values($params));
} elseif (is_callable($handler)) {
    $response = $handler(...array_values($params));
}

echo $response;
```

That's the whole flow. The rest of this README goes into the details.

---

## Setting Up Routes

### HTTP Methods

Every HTTP method has a static method on `Router`. Each one returns a `Route` object you can chain configuration onto.

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

Handlers can be anything callable in PHP: an array `[Class::class, 'method']`, a closure, or a function name. The router stores them as-is and returns them when a route matches. It never calls them for you.

### Parameters

Curly braces capture a URI segment into a named parameter.

```php
// Required — must be present
Router::get('/users/{id}', $handler);

// Optional — trailing ? means the segment can be missing
Router::get('/posts/{slug?}', $handler);

// Wildcard — captures everything after this point as a single string
Router::get('/docs/{path*}', $handler);
// /docs/api/v2/users → params['path'] = 'api/v2/users'
```

### Constraints

Constraints restrict what values a parameter will accept. If a parameter fails its constraint, the route does not match.

```php
Router::get('/users/{id}', $handler)->whereNumber('id');
Router::get('/posts/{slug}', $handler)->whereAlpha('slug');
Router::get('/items/{code}', $handler)->whereAlphaNumeric('code');
Router::get('/orders/{uuid}', $handler)->whereUuid('uuid');
Router::get('/records/{ulid}', $handler)->whereUlid('ulid');

// Only match specific values
Router::get('/status/{type}', $handler)
    ->whereIn('type', ['active', 'pending', 'closed']);

// Custom regex
Router::get('/products/{sku}', $handler)
    ->where('sku', '[A-Z]{2}-\d{4}');

// Multiple at once
Router::get('/users/{id}/posts/{slug}', $handler)
    ->where(['id' => '\d+', 'slug' => '[a-z0-9-]+']);
```

The built-in validators (`whereNumber`, `whereAlpha`, `whereUuid`, etc.) run as optimized C checks and don't use regex at all. Custom `where()` patterns compile to PCRE2 once at registration time.

### Default Values

When an optional parameter is missing from the URI, the default kicks in.

```php
Router::get('/posts/{page?}', $handler)->defaults('page', 1);

$result = Router::match('GET', '/posts');
$result->param('page'); // 1
```

### Named Routes

Give routes a name and generate URLs from them later.

```php
Router::get('/users/{id}/posts/{slug}', $handler)
    ->name('users.posts.show')
    ->whereNumber('id')
    ->whereAlpha('slug');

// Generate URL
$url = Router::url('users.posts.show', ['id' => 42, 'slug' => 'hello']);
// → /users/42/posts/hello

// Check if a named route exists
Router::has('users.posts.show'); // true

// Get the Route object by name
$route = Router::route('users.posts.show');
$route->getUri();     // /users/{id}/posts/{slug}
$route->getMethods(); // ['GET']
```

### Groups

Groups let you apply shared configuration to a set of routes. They nest.

```php
Router::group([
    'prefix'     => '/api/v1',
    'middleware'  => ['auth', 'throttle'],
    'as'         => 'api.',
    'domain'     => '{tenant}.example.com',
], function () {
    Router::get('/users', [UserController::class, 'index']);
    // URI: /api/v1/users
    // Middleware: auth, throttle
    // Name prefix: api. (so ->name('users') becomes 'api.users')

    Router::group(['prefix' => '/admin', 'middleware' => ['admin']], function () {
        Router::get('/stats', [AdminController::class, 'stats']);
        // URI: /api/v1/admin/stats
        // Middleware: auth, throttle, admin
    });
});
```

### Domain Routing

Routes can be scoped to a domain pattern. Domain parameters work like path parameters.

```php
Router::get('/dashboard', $handler)->domain('{tenant}.example.com');

$result = Router::match('GET', '/dashboard', 'acme.example.com');
$result->param('tenant'); // 'acme'
```

### Fallback

A catch-all that matches when nothing else does.

```php
Router::fallback(function () {
    http_response_code(404);
    return 'Not Found';
});

$result = Router::match('GET', '/nonexistent');
$result->matched(); // true — matched the fallback
```

### CLI Commands

The router also handles CLI command dispatch. Commands use colon-separated segments instead of slashes. Internally they share the same trie structure but are kept in a separate trie so there's no collision with HTTP routes.

```php
Router::cli('cache:clear', [CacheCommand::class, 'handle']);
Router::cli('migrate:fresh', [MigrateCommand::class, 'fresh']);
Router::cli('users:{id}:delete', [UserCommand::class, 'delete'])
    ->whereNumber('id');
Router::cli('deploy:{env}', [DeployCommand::class, 'run'])
    ->whereIn('env', ['staging', 'production']);
```

Parameters, constraints, middleware, naming — all the same API as HTTP routes.

```php
// Direct matching
$result = Router::match('CLI', 'users:42:delete');
$result->param('id');  // '42'
$result->getHandler(); // [UserCommand::class, 'delete']

// Or use dispatch with argv
Router::routeUsing($argv, function (array $argv): RoutingContext {
    return new RoutingContext('CLI', $argv[1] ?? '');
});

$result = Router::dispatch();
```

HTTP and CLI routes coexist. Each HTTP method and CLI get their own trie, so `GET /users/{id}` and `users:{id}:show` never interfere with each other.

---

## Feeding the Request

Before you can call `Router::dispatch()`, you need to tell the router where the request is coming from. `routeUsing()` takes two arguments: some input (anything — an array, an object, whatever you want), and a resolver callback that turns that input into a `RoutingContext`.

A `RoutingContext` is a simple value object: method, path, and an optional domain. That's all the router needs.

### Using $_SERVER

The simplest setup for vanilla PHP:

```php
use Signalforge\Routing\{Router, RoutingContext};

Router::routeUsing($_SERVER, function (array $server): RoutingContext {
    return new RoutingContext(
        $server['REQUEST_METHOD'],
        parse_url($server['REQUEST_URI'], PHP_URL_PATH)
    );
});
```

### Using a Framework Request Object

The router doesn't care what kind of request object you have. You just pull the method, path, and optionally domain out of it.

```php
// Symfony
Router::routeUsing($request, function (Request $req): RoutingContext {
    return new RoutingContext(
        $req->getMethod(),
        $req->getPathInfo(),
        $req->getHost()
    );
});

// Laravel
Router::routeUsing($request, function (IlluminateRequest $req): RoutingContext {
    return new RoutingContext($req->method(), '/' . $req->path(), $req->getHost());
});

// PSR-7
Router::routeUsing($request, function (ServerRequestInterface $req): RoutingContext {
    $uri = $req->getUri();
    return new RoutingContext($req->getMethod(), $uri->getPath(), $uri->getHost());
});
```

This design means the router has zero coupling to any framework. You can swap request objects without touching any route definitions.

### Direct Matching

If you don't want the `routeUsing`/`dispatch` pattern, you can match directly:

```php
$result = Router::match('GET', '/users/42');
$result = Router::match('GET', '/dashboard', 'acme.example.com'); // with domain
$result = Router::match('CLI', 'cache:clear');
```

---

## Dispatching and Running Handlers

### Getting the Handler

After dispatching (or matching directly), you get a `MatchResult`. It tells you whether something matched, what the handler is, what parameters were extracted, and what middleware applies.

```php
$result = Router::dispatch();

if (!$result->matched()) {
    http_response_code(404);
    exit('Not Found');
}

$handler    = $result->getHandler();    // whatever you registered
$params     = $result->getParams();     // ['id' => '42', ...]
$middleware  = $result->getMiddleware(); // ['auth', 'throttle']
$routeName  = $result->getRouteName();  // 'users.show' or null

// Single param with a default
$page = $result->param('page', 1);
```

### Working with Middleware

The router stores middleware names on routes and returns them in match results. It does not execute them. That's your application's job, because only your application knows what "auth" or "throttle" actually means.

Here's a typical pattern:

```php
// Define routes with middleware
Router::group(['middleware' => ['auth']], function () {
    Router::get('/dashboard', [DashboardController::class, 'index']);
    Router::get('/settings', [SettingsController::class, 'index'])
        ->middleware('verified'); // adds on top of the group's middleware
});

// After dispatch
$result = Router::dispatch();
$middlewareStack = $result->getMiddleware(); // ['auth', 'verified']

// Your middleware runner — this is application code, not the router
$middlewareMap = [
    'auth'     => AuthMiddleware::class,
    'verified' => VerifiedMiddleware::class,
    'throttle' => ThrottleMiddleware::class,
];

foreach ($middlewareStack as $name) {
    $mw = new $middlewareMap[$name]();
    $mw->handle(); // throw or redirect if it fails
}
```

You can also remove middleware from specific routes:

```php
Router::group(['middleware' => ['auth', 'throttle']], function () {
    Router::get('/public-stats', [StatsController::class, 'public'])
        ->withoutMiddleware('auth'); // only 'throttle' remains
});
```

### Full Dispatch Loop

Putting it all together for a real application:

```php
<?php
// bootstrap.php

use Signalforge\Routing\{Router, RoutingContext};

// Load routes (or load from cache in production)
require __DIR__ . '/routes.php';

// Feed in the request
Router::routeUsing($_SERVER, function (array $s): RoutingContext {
    return new RoutingContext(
        $s['REQUEST_METHOD'],
        parse_url($s['REQUEST_URI'], PHP_URL_PATH),
        $s['HTTP_HOST'] ?? null
    );
});

// Dispatch
$result = Router::dispatch();

if (!$result->matched()) {
    http_response_code(404);
    echo json_encode(['error' => 'Not Found']);
    exit;
}

// If it was a proxy route, dispatch already handled the response
if ($result->isProxy()) {
    exit;
}

// Run middleware
foreach ($result->getMiddleware() as $name) {
    $mw = $container->get("middleware.$name");
    $mw->handle();
}

// Call the handler
$handler = $result->getHandler();
$params  = $result->getParams();

if (is_array($handler)) {
    [$class, $method] = $handler;
    $controller = $container->get($class);
    $response = $controller->$method(...array_values($params));
} else {
    $response = $handler(...array_values($params));
}

// Send response (however your app does it)
if (is_string($response)) {
    echo $response;
} elseif (is_array($response)) {
    header('Content-Type: application/json');
    echo json_encode($response);
}
```

```php
<?php
// routes.php

use Signalforge\Routing\Router;

Router::get('/', [HomeController::class, 'index']);
Router::get('/health', fn() => ['status' => 'ok']);

Router::group(['prefix' => '/api/v1', 'middleware' => ['auth', 'throttle']], function () {
    Router::get('/users', [UserController::class, 'list'])
        ->name('users.list');
    Router::get('/users/{id}', [UserController::class, 'show'])
        ->name('users.show')
        ->whereNumber('id');
    Router::post('/users', [UserController::class, 'create']);
    Router::put('/users/{id}', [UserController::class, 'update'])
        ->whereNumber('id');
    Router::delete('/users/{id}', [UserController::class, 'destroy'])
        ->whereNumber('id');

    Router::get('/products/{sku}', [ProductController::class, 'show'])
        ->where('sku', '[A-Z]{2}-\d{4}');

    Router::get('/docs/{path*}', [DocsController::class, 'page']);
});

Router::fallback(fn() => ['error' => 'Not Found']);
```

---

## Reverse Proxy

Routes can proxy incoming requests to an upstream server. When `dispatch()` hits a proxy route, it builds an HTTP request from the incoming SAPI globals, optionally lets you modify it, sends it to the upstream via PHP streams, and writes the response directly to the browser. You don't have to do anything — it's handled inside `dispatch()`.

### Basic Proxy

```php
Router::get('/api/status', fn() => null)
    ->proxy('https://api.internal/status');
```

The handler (`fn() => null`) is required by the method signature but is never called for proxy routes. When someone hits `GET /api/status`, `dispatch()` forwards the request to `https://api.internal/status` and sends the upstream response straight to the browser.

### URL Parameter Substitution

Proxy URLs can contain `{param}` placeholders. They get replaced with the matched route parameters.

```php
Router::get('/api/users/{id}', fn($id) => null)
    ->whereNumber('id')
    ->proxy('https://api.internal/users/{id}');

// GET /api/users/42 → proxies to https://api.internal/users/42
```

Parameter values are URL-encoded before substitution.

### Request and Response Hooks

`onRequest` lets you modify the outgoing request before it leaves. `onResponse` lets you modify the upstream response before it reaches the browser. Both receive immutable value objects — you use `with*()` methods and return a new instance.

```php
use Signalforge\Routing\{Router, ProxyRequest, ProxyResponse};

Router::get('/api/data', fn() => null)
    ->proxy('https://backend.internal/data')
    ->onRequest(function (ProxyRequest $req): ProxyRequest {
        return $req->withHeader('Authorization', 'Bearer ' . getToken());
    })
    ->onResponse(function (ProxyResponse $resp): ProxyResponse {
        return $resp->withHeader('X-Via', 'signalforge');
    });
```

You must call `proxy()` before `onRequest()` or `onResponse()`. Calling them on a non-proxy route throws a `RoutingException`.

### ProxyRequest

Immutable value object for the outgoing HTTP request to the upstream.

```php
// Read
$req->getMethod();                   // 'GET'
$req->getUrl();                      // 'https://...'
$req->getHeaders();                  // ['accept' => '...', ...]
$req->getHeader('content-type');     // 'application/json' or null
$req->getBody();                     // request body or null

// Modify (returns a new instance each time)
$req = $req->withMethod('POST');
$req = $req->withUrl('https://other.internal/path');
$req = $req->withHeader('X-Custom', 'value');
$req = $req->withBody('{"key":"val"}');
$req = $req->withoutHeader('accept');
```

### ProxyResponse

Immutable value object for the upstream HTTP response.

```php
// Read
$resp->getStatusCode();              // 200
$resp->getHeaders();                 // ['content-type' => '...', ...]
$resp->getHeader('content-type');    // 'application/json' or null
$resp->getBody();                    // response body

// Modify (returns a new instance each time)
$resp = $resp->withStatus(201);
$resp = $resp->withHeader('X-Cache', 'HIT');
$resp = $resp->withBody('modified');
$resp = $resp->withoutHeader('server');

// Send to browser manually (dispatch does this automatically)
$resp->send();
```

After dispatch, you can check whether the route was a proxy and inspect the response:

```php
$result = Router::dispatch();

if ($result->isProxy()) {
    // Response was already sent to the browser.
    // You can still inspect it:
    $proxyResp = $result->getProxyResponse();
    error_log('Upstream returned ' . $proxyResp->getStatusCode());
}
```

### Proxy Security

The proxy strips and rewrites headers to prevent common issues:

- **SSRF prevention** — only `http://` and `https://` URLs are accepted. Validated both at registration time and after parameter substitution.
- **Header injection** — any header value containing `\r` or `\n` is silently dropped.
- **Sensitive headers stripped** — `Cookie`, `Authorization`, `Proxy-Authorization`, and hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Upgrade`) from the incoming request are not forwarded upstream.
- **Host rewriting** — the `Host` header is set to the upstream server's hostname, not the original request's.
- **Forwarding headers** — `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-For` are set from the original request automatically.
- **Parameter encoding** — route parameters substituted into proxy URLs are URL-encoded.
- **Response size limit** — upstream response bodies are capped at 64 MB.

---

## Route Caching

For production, routes can be serialized to a binary file and loaded without re-registration. This skips all the parsing and trie building on every request.

```php
// During deployment: serialize all routes to disk
Router::cache('/var/cache/routes.bin');

// At runtime: load the pre-built trie
Router::loadCache('/var/cache/routes.bin');
```

Closures can't be serialized. If you want caching, use array callables: `[Controller::class, 'method']`.

`Router::flush()` clears all routes, named routes, groups, dispatch context, the stored resolver, and the fallback.

---

## Worker Runtimes

For RoadRunner, FrankenPHP, and other long-running PHP runtimes, RINIT/RSHUTDOWN fire once per worker lifetime instead of per request. Routes and the resolver are registered once at boot; only the request changes per iteration.

The `Router::resolver()` + `Router::dispatch($input)` pattern is designed for this. Set the resolver once, then call `dispatch($input)` in the request loop. The existing `routeUsing($input, $resolver)` + `dispatch()` pattern still works — this is an alternative, not a replacement.

### RoadRunner

```php
<?php
// worker.php

use Signalforge\Routing\{Router, RoutingContext};
use Spiral\RoadRunner\Http\HttpWorker;
use Spiral\RoadRunner\Worker;

// Boot — runs once per worker
require __DIR__ . '/routes.php';

Router::resolver(function (\Nyholm\Psr7\ServerRequest $request): RoutingContext {
    $uri = $request->getUri();
    return new RoutingContext(
        $request->getMethod(),
        $uri->getPath(),
        $uri->getHost()
    );
});

$worker = new HttpWorker(Worker::create());

// Request loop — runs per request
while ($req = $worker->waitRequest()) {
    $result = Router::dispatch($req);

    if (!$result->matched()) {
        $worker->respond(404, 'Not Found');
        continue;
    }

    $handler = $result->getHandler();
    $params  = $result->getParams();

    if (is_array($handler)) {
        [$class, $method] = $handler;
        $response = (new $class())->$method(...array_values($params));
    } else {
        $response = $handler(...array_values($params));
    }

    $worker->respond(200, (string) $response);
}
```

### FrankenPHP

```php
<?php
// worker.php

use Signalforge\Routing\{Router, RoutingContext};

// Boot — runs once per worker
require __DIR__ . '/routes.php';

Router::resolver(function (array $server): RoutingContext {
    return new RoutingContext(
        $server['REQUEST_METHOD'],
        parse_url($server['REQUEST_URI'], PHP_URL_PATH),
        $server['HTTP_HOST'] ?? null
    );
});

// Request loop — FrankenPHP calls this per request
$handler = static function (): void {
    $result = Router::dispatch($_SERVER);

    if (!$result->matched()) {
        http_response_code(404);
        echo 'Not Found';
        return;
    }

    $handler = $result->getHandler();
    $params  = $result->getParams();

    if (is_array($handler)) {
        [$class, $method] = $handler;
        echo (new $class())->$method(...array_values($params));
    } else {
        echo $handler(...array_values($params));
    }
};

// FrankenPHP worker mode
do {
    $handler();
} while (\frankenphp_handle_request($handler));
```

The key difference from the standard `routeUsing()` pattern: with `resolver()`, the callable is stored once and reused. With `routeUsing()`, you pass both the input and the resolver on every call, which is fine for traditional PHP-FPM but redundant in a worker loop where the resolver never changes.

---

## How It's Built

This is a native PHP extension written in C. It compiles into a `.so` file that PHP loads at startup, so there's no autoloading, no Composer, and no PHP overhead on the hot path. The route matching itself happens in compiled C code.

### The Radix Trie

Most PHP routers iterate every registered route and test each one against the incoming URI (O(n)). Some compile routes into one big regex, which helps but still degrades as route count grows.

This router uses a compressed radix trie. Each node represents a path segment. Routes sharing a common prefix share the same nodes:

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

Matching `/api/v1/users/42/posts/7` walks 6 nodes. The cost depends on the number of segments in the URI, not the number of registered routes. 10 routes or 10,000 — a 4-segment URI still traverses 4 nodes.

Each HTTP method and CLI get their own trie, so a GET request never touches POST routes. Constraints are only checked after a structural match is found, so they never slow down non-matching routes.

Trie node fields are ordered so that hot data (child pointers, route reference, terminal flag) fits in the first 64-byte CPU cache line.

### Why It Gets Faster with More Routes

The benchmarks show something that looks wrong at first: matching 1,000 routes is faster per-match than matching 100 routes. It happens because routes with shared prefixes (all your `/api/v1/...` routes, for example) share the same trie nodes. More routes means more prefix sharing, which means the trie compresses better. The data structure gets more efficient the more you use it.

### Benchmarks

Tested against FastRoute, Symfony Routing, and Laravel Router. All routes use complex multi-parameter patterns with numeric constraints and optional segments.

| Routes | Signalforge | FastRoute | Symfony | Laravel |
|--------|-------------|-----------|---------|---------|
| 10 | 3.18 ms | 6.34 ms | 24.98 ms | 99.44 ms |
| 100 | 15.39 ms | 44.21 ms | 388.04 ms | 765.96 ms |
| 1,000 | 7.81 ms | 174.45 ms | 2.95 s | 3.31 s |

At 1,000 routes: **22x faster than FastRoute**, **424x faster than Laravel**.

Full benchmark data: [benchmark.md](benchmark.md)

---

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

### Build from Source

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

### Thread Safety

The extension works with PHP ZTS builds. Each request gets isolated router state. The trie is protected by a read-write lock: concurrent reads during matching, exclusive writes during registration.

---

## API Reference

### Router

All methods are static.

| Method | Returns | Description |
|--------|---------|-------------|
| `get($uri, $handler)` | `Route` | Register GET route |
| `post($uri, $handler)` | `Route` | Register POST route |
| `put($uri, $handler)` | `Route` | Register PUT route |
| `patch($uri, $handler)` | `Route` | Register PATCH route |
| `delete($uri, $handler)` | `Route` | Register DELETE route |
| `options($uri, $handler)` | `Route` | Register OPTIONS route |
| `any($uri, $handler)` | `Route` | Register route for all methods |
| `cli($command, $handler)` | `Route` | Register CLI command |
| `match($method, $uri, $domain?)` | `MatchResult` | Match a request |
| `routeUsing($input, $resolver)` | `void` | Bind input + resolver for dispatch |
| `resolver($resolver)` | `void` | Store resolver for dispatch($input) |
| `dispatch($input?)` | `MatchResult` | Dispatch using bound context or stored resolver |
| `group($attrs, $callback)` | `void` | Group routes with shared config |
| `fallback($handler)` | `Route` | Set fallback handler |
| `url($name, $params?)` | `?string` | Generate URL from named route |
| `has($name)` | `bool` | Check if named route exists |
| `route($name)` | `?Route` | Get route by name |
| `getRoutes()` | `array` | Get all registered routes |
| `flush()` | `void` | Clear all state |
| `cache($path)` | `bool` | Serialize routes to file |
| `loadCache($path)` | `bool` | Load routes from file |
| `setStrictSlashes($strict)` | `void` | Toggle trailing slash behavior |

### Route

All methods return `$this` for chaining unless noted.

| Method | Returns | Description |
|--------|---------|-------------|
| `name($name)` | `self` | Set route name |
| `middleware($middleware)` | `self` | Add middleware (string or array) |
| `where($param, $pattern?)` | `self` | Custom regex constraint |
| `whereNumber($params)` | `self` | Numeric constraint |
| `whereAlpha($params)` | `self` | Alphabetic constraint |
| `whereAlphaNumeric($params)` | `self` | Alphanumeric constraint |
| `whereUuid($params)` | `self` | UUID format constraint |
| `whereUlid($params)` | `self` | ULID format constraint |
| `whereIn($param, $values)` | `self` | Enumerated values constraint |
| `defaults($param, $value)` | `self` | Default for optional param |
| `domain($domain)` | `self` | Domain constraint |
| `withoutMiddleware($middleware)` | `self` | Remove middleware |
| `proxy($url)` | `self` | Proxy to upstream URL |
| `onRequest($callback)` | `self` | Modify outgoing proxy request |
| `onResponse($callback)` | `self` | Modify upstream proxy response |
| `getName()` | `?string` | Get route name |
| `getUri()` | `?string` | Get URI pattern |
| `getMethods()` | `array` | Get HTTP methods |
| `getHandler()` | `mixed` | Get handler |
| `getMiddleware()` | `array` | Get middleware stack |
| `getWheres()` | `array` | Get constraints |
| `getDefaults()` | `array` | Get default values |
| `getDomain()` | `?string` | Get domain pattern |
| `getProxyUrl()` | `?string` | Get proxy URL |

### MatchResult

| Method | Returns | Description |
|--------|---------|-------------|
| `matched()` | `bool` | Whether a route matched |
| `getHandler()` | `mixed` | The handler callable |
| `getParams()` | `array` | All extracted parameters |
| `param($name, $default?)` | `mixed` | Single parameter with default |
| `getMiddleware()` | `array` | Middleware stack |
| `getRouteName()` | `?string` | Route name |
| `getRoute()` | `?Route` | The matched Route object |
| `getError()` | `?string` | Error message on failure |
| `isProxy()` | `bool` | Whether proxy was executed |
| `getProxyResponse()` | `?ProxyResponse` | Upstream response after proxy |

### ProxyRequest

Immutable. All `with*()` methods return a new instance.

| Method | Returns | Description |
|--------|---------|-------------|
| `getMethod()` | `string` | HTTP method |
| `getUrl()` | `string` | Upstream URL |
| `getHeaders()` | `array` | All headers |
| `getHeader($name)` | `?string` | Single header by name |
| `getBody()` | `?string` | Request body |
| `withMethod($method)` | `self` | Clone with changed method |
| `withUrl($url)` | `self` | Clone with changed URL |
| `withHeader($name, $value)` | `self` | Clone with added/replaced header |
| `withBody($body)` | `self` | Clone with changed body |
| `withoutHeader($name)` | `self` | Clone with header removed |

### ProxyResponse

Immutable. All `with*()` methods return a new instance.

| Method | Returns | Description |
|--------|---------|-------------|
| `getStatusCode()` | `int` | HTTP status code |
| `getHeaders()` | `array` | All headers |
| `getHeader($name)` | `?string` | Single header by name |
| `getBody()` | `string` | Response body |
| `withStatus($code)` | `self` | Clone with changed status |
| `withHeader($name, $value)` | `self` | Clone with added/replaced header |
| `withBody($body)` | `self` | Clone with changed body |
| `withoutHeader($name)` | `self` | Clone with header removed |
| `send()` | `void` | Send status + headers + body to browser |

### RoutingContext

| Method | Returns | Description |
|--------|---------|-------------|
| `__construct($method, $path, $domain?)` | | Create context |
| `getMethod()` | `string` | HTTP method or `"CLI"` |
| `getPath()` | `string` | Request path |
| `getDomain()` | `?string` | Domain if set |

---

## License

MIT
