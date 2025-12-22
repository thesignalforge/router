--TEST--
Basic route registration and matching
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

// Test 1: Simple GET route
Router::get('/hello', function() { return 'world'; });
$result = Router::match('GET', '/hello');
var_dump($result->matched());

// Test 2: Route with parameter
Router::get('/users/{id}', function($id) { return $id; })->whereNumber('id');
$result = Router::match('GET', '/users/42');
var_dump($result->matched());
var_dump($result->getParams());

// Test 3: Named route and URL generation
Router::get('/posts/{slug}', function($slug) { return $slug; })
    ->name('posts.show')
    ->whereAlpha('slug');
$url = Router::url('posts.show', ['slug' => 'hello']);
var_dump($url);

// Test 4: Route not found
$result = Router::match('GET', '/nonexistent');
var_dump($result->matched());
var_dump($result->getError());

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
array(1) {
  ["id"]=>
  string(2) "42"
}
string(12) "/posts/hello"
bool(false)
string(15) "Route not found"
OK
