--TEST--
Route groups with prefix and middleware
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

Router::flush();

// Test group with prefix
Router::group(['prefix' => '/api/v1'], function() {
    Router::get('/users', function() { return 'users'; })->name('api.users');
    Router::get('/posts', function() { return 'posts'; })->name('api.posts');
});

$result = Router::match('GET', '/api/v1/users');
var_dump($result->matched());
var_dump($result->getRouteName());

$result = Router::match('GET', '/api/v1/posts');
var_dump($result->matched());
var_dump($result->getRouteName());

// Test group with middleware
Router::group([
    'prefix' => '/admin',
    'middleware' => ['auth', 'admin']
], function() {
    Router::get('/dashboard', function() { return 'dashboard'; });
});

$result = Router::match('GET', '/admin/dashboard');
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
