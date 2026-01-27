--TEST--
RoutingContext, routeUsing, dispatch, and CLI routing
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext};

// Test 1: RoutingContext construction and getters
$ctx = new RoutingContext('GET', '/users/42', 'api.example.com');
var_dump($ctx->getMethod());
var_dump($ctx->getPath());
var_dump($ctx->getDomain());

// Test 2: RoutingContext without domain
$ctx2 = new RoutingContext('POST', '/login');
var_dump($ctx2->getDomain());

// Test 3: routeUsing + dispatch (HTTP)
Router::flush();
Router::get('/users/{id}', fn($id) => $id)->whereNumber('id');
Router::routeUsing(
    ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/users/42'],
    function(array $server): RoutingContext {
        return new RoutingContext($server['REQUEST_METHOD'], $server['REQUEST_URI']);
    }
);
$r = Router::dispatch();
var_dump($r->matched());
var_dump($r->param('id'));

// Test 4: routeUsing with object input
Router::flush();
Router::post('/login', fn() => 'ok');
$input = new \stdClass();
$input->method = 'POST';
$input->path = '/login';
Router::routeUsing($input, function(object $req): RoutingContext {
    return new RoutingContext($req->method, $req->path);
});
$r = Router::dispatch();
var_dump($r->matched());

// Test 5: CLI route registration and matching
Router::flush();
Router::cli('cache:clear', fn() => 'cleared');
Router::cli('users:{id}:show', fn($id) => $id)->whereNumber('id');
$r = Router::match('CLI', 'users:42:show');
var_dump($r->matched());
var_dump($r->param('id'));

// Test 6: CLI route via routeUsing + dispatch
Router::flush();
Router::cli('app:migrate', fn() => 'migrated');
Router::routeUsing(
    ['app', 'app:migrate'],
    function(array $argv): RoutingContext {
        return new RoutingContext('CLI', $argv[1] ?? '');
    }
);
$r = Router::dispatch();
var_dump($r->matched());

// Test 7: CLI route with constraints via dispatch
Router::flush();
Router::cli('users:{id}:delete', fn($id) => $id)->whereNumber('id');
Router::routeUsing(
    'users:99:delete',
    function(string $cmd): RoutingContext {
        return new RoutingContext('CLI', $cmd);
    }
);
$r = Router::dispatch();
var_dump($r->matched());
var_dump($r->param('id'));

// Test 8: dispatch without routeUsing throws
Router::flush();
try {
    Router::dispatch();
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "No context: " . $e->getMessage() . "\n";
}

// Test 9: flush clears dispatch context
Router::flush();
Router::get('/test', fn() => 'ok');
Router::routeUsing(null, function($x): RoutingContext {
    return new RoutingContext('GET', '/test');
});
Router::flush();
try {
    Router::dispatch();
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "Cleared: ok\n";
}

// Test 10: routeUsing with domain routing
Router::flush();
Router::get('/dashboard', fn() => 'admin')->domain('{tenant}.example.com');
Router::routeUsing(
    ['method' => 'GET', 'path' => '/dashboard', 'domain' => 'acme.example.com'],
    function(array $req): RoutingContext {
        return new RoutingContext($req['method'], $req['path'], $req['domain']);
    }
);
$r = Router::dispatch();
var_dump($r->matched());
var_dump($r->param('tenant'));

echo "OK\n";
?>
--EXPECT--
string(3) "GET"
string(9) "/users/42"
string(15) "api.example.com"
NULL
bool(true)
string(2) "42"
bool(true)
bool(true)
string(2) "42"
bool(true)
bool(true)
string(2) "99"
No context: No routing context set. Call Router::routeUsing() or Router::resolver() before Router::dispatch()
Cleared: ok
bool(true)
string(4) "acme"
OK
