--TEST--
Parameter constraints
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

$router = new Router();

// whereNumber constraint
$router->get('/users/{id}', function($id) { return $id; })->whereNumber('id');

// Should match numeric ID
$result = $router->match('GET', '/users/123');
var_dump($result->matched());
var_dump($result->param('id'));

// Should not match non-numeric ID (constraint fails at terminal)
$result = $router->match('GET', '/users/abc');
var_dump($result->matched());

// whereAlpha constraint
$router->get('/tags/{tag}', function($tag) { return $tag; })->whereAlpha('tag');

$result = $router->match('GET', '/tags/technology');
var_dump($result->matched());
var_dump($result->param('tag'));

// whereIn constraint
$router->get('/status/{status}', function($status) { return $status; })
    ->whereIn('status', ['active', 'pending', 'completed']);

$result = $router->match('GET', '/status/active');
var_dump($result->matched());

$result = $router->match('GET', '/status/invalid');
var_dump($result->matched());

// Custom regex constraint
$router->get('/products/{sku}', function($sku) { return $sku; })
    ->where('sku', '[A-Z]{2}-[0-9]{4}');

$result = $router->match('GET', '/products/AB-1234');
var_dump($result->matched());
var_dump($result->param('sku'));

$result = $router->match('GET', '/products/invalid');
var_dump($result->matched());

echo "OK\n";
?>
--EXPECT--
bool(true)
string(3) "123"
bool(false)
bool(true)
string(10) "technology"
bool(true)
bool(false)
bool(true)
string(7) "AB-1234"
bool(false)
OK
