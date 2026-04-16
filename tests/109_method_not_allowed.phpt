--TEST--
Method mismatch returns 405-signaling MatchResult with Allow list (not 404)
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

$router = new Router();
$router->get('/foo', [FooController::class, 'show']);
$router->post('/foo', [FooController::class, 'create']);

// PUT /foo — path exists but method doesn't: expect 405 signal.
$result = $router->match('PUT', '/foo');

var_dump($result->matched());               // false
var_dump($result->isMethodNotAllowed());    // true
print_r($result->getAllowedMethods());

// Truly missing path → 404 (no 405 flag)
$result2 = $router->match('GET', '/nope');
var_dump($result2->matched());              // false
var_dump($result2->isMethodNotAllowed());   // false
var_dump($result2->getAllowedMethods());    // empty array

echo "OK\n";
?>
--EXPECT--
bool(false)
bool(true)
Array
(
    [0] => GET
    [1] => POST
)
bool(false)
bool(false)
array(0) {
}
OK
