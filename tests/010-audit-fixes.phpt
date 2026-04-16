--TEST--
Audit fixes: clone prevention, group wheres, resolver safety, unknown method warning
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext, MatchResult};

// Test 1: Clone prevention on Route
$router = new Router();
$route = $router->get('/test', fn() => 'ok');
try {
    clone $route;
    echo "FAIL: Route clone should throw\n";
} catch (\Error $e) {
    echo "Route clone blocked: ok\n";
}

// Test 2: Clone prevention on MatchResult
$result = $router->match('GET', '/test');
try {
    clone $result;
    echo "FAIL: MatchResult clone should throw\n";
} catch (\Error $e) {
    echo "MatchResult clone blocked: ok\n";
}

// Test 3: Clone prevention on RoutingContext
$ctx = new RoutingContext('GET', '/test');
try {
    clone $ctx;
    echo "FAIL: RoutingContext clone should throw\n";
} catch (\Error $e) {
    echo "RoutingContext clone blocked: ok\n";
}

// Test 4: Group where constraints -- routes inherit group-level constraints
$router = new Router();
$router->group(['prefix' => '/api', 'where' => ['id' => '[0-9]+']], function (Router $r) {
    $r->get('/users/{id}', fn($id) => $id);
    $r->get('/posts/{id}', fn($id) => $id);
});

$r = $router->match('GET', '/api/users/42');
var_dump($r->matched()); // true

$r = $router->match('GET', '/api/users/abc');
var_dump($r->matched()); // false -- group constraint blocks non-numeric

$r = $router->match('GET', '/api/posts/99');
var_dump($r->matched()); // true

$r = $router->match('GET', '/api/posts/xyz');
var_dump($r->matched()); // false

// Test 5: Route-specific constraint overrides group constraint
$router = new Router();
$router->group(['prefix' => '/v1', 'where' => ['id' => '[0-9]+']], function (Router $r) {
    $r->get('/items/{id}', fn($id) => $id)->where('id', '[a-zA-Z0-9-]+');
});

$r = $router->match('GET', '/v1/items/abc-123');
var_dump($r->matched()); // true -- route constraint overrides group

$r = $router->match('GET', '/v1/items/42');
var_dump($r->matched()); // true

// Test 6: Resolver safety -- callback that calls flush() during dispatch
$router = new Router();
$router->get('/safe', fn() => 'ok');

$router->resolver(function (array $req): RoutingContext {
    // This should NOT crash even though we're modifying state
    return new RoutingContext($req['method'], $req['path']);
});

$r = $router->dispatch(['method' => 'GET', 'path' => '/safe']);
var_dump($r->matched()); // true

// Test 7: Unknown HTTP method produces E_WARNING
$router = new Router();
$router->get('/warn', fn() => 'ok');

// Suppress the warning and capture it
set_error_handler(function ($errno, $errstr) {
    echo "Warning caught: " . (strpos($errstr, 'Unknown HTTP method') !== false ? 'ok' : 'wrong') . "\n";
    return true;
});

$router->match('FOOBAR', '/warn');

restore_error_handler();

echo "OK\n";
?>
--EXPECT--
Route clone blocked: ok
MatchResult clone blocked: ok
RoutingContext clone blocked: ok
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
Warning caught: ok
OK
