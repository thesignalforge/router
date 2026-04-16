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
$router = new Router();
$router->get('/users/{id}', fn($id) => $id)->whereNumber('id');
$router->routeUsing(
    ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/users/42'],
    function(array $server): RoutingContext {
        return new RoutingContext($server['REQUEST_METHOD'], $server['REQUEST_URI']);
    }
);
$r = $router->dispatch();
var_dump($r->matched());
var_dump($r->param('id'));

// Test 4: routeUsing with object input
$router = new Router();
$router->post('/login', fn() => 'ok');
$input = new \stdClass();
$input->method = 'POST';
$input->path = '/login';
$router->routeUsing($input, function(object $req): RoutingContext {
    return new RoutingContext($req->method, $req->path);
});
$r = $router->dispatch();
var_dump($r->matched());

// Test 5: CLI route registration and matching
$router = new Router();
$router->cli('cache:clear', fn() => 'cleared');
$router->cli('users:{id}:show', fn($id) => $id)->whereNumber('id');
$r = $router->match('CLI', 'users:42:show');
var_dump($r->matched());
var_dump($r->param('id'));

// Test 6: CLI route via routeUsing + dispatch
$router = new Router();
$router->cli('app:migrate', fn() => 'migrated');
$router->routeUsing(
    ['app', 'app:migrate'],
    function(array $argv): RoutingContext {
        return new RoutingContext('CLI', $argv[1] ?? '');
    }
);
$r = $router->dispatch();
var_dump($r->matched());

// Test 7: CLI route with constraints via dispatch
$router = new Router();
$router->cli('users:{id}:delete', fn($id) => $id)->whereNumber('id');
$router->routeUsing(
    'users:99:delete',
    function(string $cmd): RoutingContext {
        return new RoutingContext('CLI', $cmd);
    }
);
$r = $router->dispatch();
var_dump($r->matched());
var_dump($r->param('id'));

// Test 8: dispatch without routeUsing throws
$router = new Router();
try {
    $router->dispatch();
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "No context: " . $e->getMessage() . "\n";
}

// Test 9: flush clears dispatch context
$router = new Router();
$router->get('/test', fn() => 'ok');
$router->routeUsing(null, function($x): RoutingContext {
    return new RoutingContext('GET', '/test');
});
$router->flush();
try {
    $router->dispatch();
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "Cleared: ok\n";
}

// Test 10: routeUsing with domain routing
$router = new Router();
$router->get('/dashboard', fn() => 'admin')->domain('{tenant}.example.com');
$router->routeUsing(
    ['method' => 'GET', 'path' => '/dashboard', 'domain' => 'acme.example.com'],
    function(array $req): RoutingContext {
        return new RoutingContext($req['method'], $req['path'], $req['domain']);
    }
);
$r = $router->dispatch();
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
No context: No routing context set. Call $router->routeUsing() or $router->resolver() before $router->dispatch()
Cleared: ok
bool(true)
string(4) "acme"
OK
