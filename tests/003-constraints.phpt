--TEST--
Parameter constraints
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

Router::flush();

// whereNumber constraint
Router::get('/users/{id}', function($id) { return $id; })->whereNumber('id');

// Should match numeric ID
$result = Router::match('GET', '/users/123');
var_dump($result->matched());
var_dump($result->param('id'));

// Should not match non-numeric ID (constraint fails at terminal)
$result = Router::match('GET', '/users/abc');
var_dump($result->matched());

// whereAlpha constraint
Router::get('/tags/{tag}', function($tag) { return $tag; })->whereAlpha('tag');

$result = Router::match('GET', '/tags/technology');
var_dump($result->matched());
var_dump($result->param('tag'));

// whereIn constraint
Router::get('/status/{status}', function($status) { return $status; })
    ->whereIn('status', ['active', 'pending', 'completed']);

$result = Router::match('GET', '/status/active');
var_dump($result->matched());

$result = Router::match('GET', '/status/invalid');
var_dump($result->matched());

// Custom regex constraint
Router::get('/products/{sku}', function($sku) { return $sku; })
    ->where('sku', '[A-Z]{2}-[0-9]{4}');

$result = Router::match('GET', '/products/AB-1234');
var_dump($result->matched());
var_dump($result->param('sku'));

$result = Router::match('GET', '/products/invalid');
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
