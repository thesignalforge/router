--TEST--
Router::resolver() and Router::dispatch($input) for worker runtimes
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext};

// Test 1: Basic resolver() + dispatch($input) flow
Router::flush();
Router::get('/users/{id}', fn($id) => $id)->whereNumber('id');
Router::get('/health', fn() => 'ok');

Router::resolver(function (array $req): RoutingContext {
    return new RoutingContext($req['method'], $req['path']);
});

$r = Router::dispatch(['method' => 'GET', 'path' => '/users/42']);
var_dump($r->matched());
var_dump($r->param('id'));

// Test 2: dispatch($input) without resolver() throws
Router::flush();
Router::get('/test', fn() => 'ok');
try {
    Router::dispatch(['method' => 'GET', 'path' => '/test']);
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "No resolver: " . $e->getMessage() . "\n";
}

// Test 3: dispatch() without args still works after routeUsing() (backward compat)
Router::flush();
Router::get('/compat', fn() => 'compat');
Router::routeUsing(
    ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/compat'],
    function (array $s): RoutingContext {
        return new RoutingContext($s['REQUEST_METHOD'], $s['REQUEST_URI']);
    }
);
$r = Router::dispatch();
var_dump($r->matched());

// Test 4: Resolver persists across multiple dispatch($input) calls (worker loop)
Router::flush();
Router::get('/users/{id}', fn($id) => $id)->whereNumber('id');
Router::get('/health', fn() => 'ok');

Router::resolver(function (array $req): RoutingContext {
    return new RoutingContext($req['method'], $req['path']);
});

$requests = [
    ['method' => 'GET', 'path' => '/users/1'],
    ['method' => 'GET', 'path' => '/users/2'],
    ['method' => 'GET', 'path' => '/health'],
    ['method' => 'GET', 'path' => '/users/99'],
];

foreach ($requests as $req) {
    $r = Router::dispatch($req);
    echo ($r->matched() ? 'matched' : 'miss') . ' ' . ($r->param('id') ?? 'n/a') . "\n";
}

// Test 5: flush() clears the resolver
Router::flush();
Router::get('/test', fn() => 'ok');
Router::resolver(function (array $req): RoutingContext {
    return new RoutingContext($req['method'], $req['path']);
});
Router::flush();
try {
    Router::dispatch(['method' => 'GET', 'path' => '/test']);
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "Flushed: ok\n";
}

// Test 6: resolver() replaces previous resolver
Router::flush();
Router::get('/users/{id}', fn($id) => $id)->whereNumber('id');

// First resolver uses 'method'/'path' keys
Router::resolver(function (array $req): RoutingContext {
    return new RoutingContext($req['method'], $req['path']);
});
$r = Router::dispatch(['method' => 'GET', 'path' => '/users/1']);
var_dump($r->param('id'));

// Replace with resolver that uses 'm'/'p' keys
Router::resolver(function (array $req): RoutingContext {
    return new RoutingContext($req['m'], $req['p']);
});
$r = Router::dispatch(['m' => 'GET', 'p' => '/users/2']);
var_dump($r->param('id'));

// Test 7: dispatch($input) with domain routing
Router::flush();
Router::get('/dashboard', fn() => 'admin')->domain('{tenant}.example.com');

Router::resolver(function (array $req): RoutingContext {
    return new RoutingContext($req['method'], $req['path'], $req['domain'] ?? null);
});

$r = Router::dispatch(['method' => 'GET', 'path' => '/dashboard', 'domain' => 'acme.example.com']);
var_dump($r->matched());
var_dump($r->param('tenant'));

echo "OK\n";
?>
--EXPECT--
bool(true)
string(2) "42"
No resolver: No resolver set. Call Router::resolver() before Router::dispatch($input)
bool(true)
matched 1
matched 2
matched n/a
matched 99
Flushed: ok
string(1) "1"
string(1) "2"
bool(true)
string(4) "acme"
OK
