--TEST--
Route groups with prefix and middleware
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

$router = new Router();

// Test group with prefix
$router->group(['prefix' => '/api/v1'], function(Router $r) {
    $r->get('/users', function() { return 'users'; })->name('api.users');
    $r->get('/posts', function() { return 'posts'; })->name('api.posts');
});

$result = $router->match('GET', '/api/v1/users');
var_dump($result->matched());
var_dump($result->getRouteName());

$result = $router->match('GET', '/api/v1/posts');
var_dump($result->matched());
var_dump($result->getRouteName());

// Test group with middleware
$router->group([
    'prefix' => '/admin',
    'middleware' => ['auth', 'admin']
], function(Router $r) {
    $r->get('/dashboard', function() { return 'dashboard'; });
});

$result = $router->match('GET', '/admin/dashboard');
var_dump($result->matched());
var_dump($result->getMiddleware());

echo "OK\n";
?>
--EXPECT--
bool(true)
string(9) "api.users"
bool(true)
string(9) "api.posts"
bool(true)
array(2) {
  [0]=>
  string(4) "auth"
  [1]=>
  string(5) "admin"
}
OK
