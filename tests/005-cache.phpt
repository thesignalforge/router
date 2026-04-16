--TEST--
Route caching - save and load from binary cache
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.cache_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--FILE--
<?php
use Signalforge\Routing\Router;

$cacheFile = sys_get_temp_dir() . '/sf_route_cache_test.bin';

// Clean up from previous runs
@unlink($cacheFile);

$router = new Router();

// Register routes
$router->get('/users', [UserController::class, 'index'])->name('users.index');
$router->get('/users/{id}', [UserController::class, 'show'])
    ->name('users.show')
    ->whereNumber('id');
$router->post('/users', [UserController::class, 'store'])
    ->middleware(['auth', 'validate']);
$router->get('/posts/{slug?}', [PostController::class, 'show'])
    ->name('posts.show')
    ->defaults('slug', 'latest');

$router->group(['prefix' => '/api', 'middleware' => ['api']], function(Router $r) {
    $r->get('/status', [ApiController::class, 'status'])->name('api.status');
});

// Save to cache
$saved = $router->cache($cacheFile);
var_dump($saved);
var_dump(file_exists($cacheFile));

// Check cache file is binary (starts with SFR1 authenticated magic)
$header = file_get_contents($cacheFile, false, null, 0, 4);
var_dump($header === 'SFR1');

// Create new router and load from cache
$router2 = new Router();

// Verify routes are not there yet
$result = $router2->match('GET', '/users');
var_dump($result->matched()); // Should be false

// Load from cache
$loaded = $router2->loadCache($cacheFile);
var_dump($loaded);

// Verify routes work after loading from cache
$result = $router2->match('GET', '/users');
var_dump($result->matched());
var_dump($result->getRouteName());

$result = $router2->match('GET', '/users/42');
var_dump($result->matched());
var_dump($result->getParams());
var_dump($result->getRouteName());

$result = $router2->match('POST', '/users');
var_dump($result->matched());
var_dump($result->getMiddleware());

$result = $router2->match('GET', '/posts');
var_dump($result->matched());
var_dump($result->getParams());

$result = $router2->match('GET', '/api/status');
var_dump($result->matched());
var_dump($result->getMiddleware());
var_dump($result->getRouteName());

// URL generation should work
$url = $router2->url('users.show', ['id' => 123]);
var_dump($url);

// Clean up
@unlink($cacheFile);

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
string(11) "users.index"
bool(true)
array(1) {
  ["id"]=>
  string(2) "42"
}
string(10) "users.show"
bool(true)
array(2) {
  [0]=>
  string(4) "auth"
  [1]=>
  string(8) "validate"
}
bool(true)
array(1) {
  ["slug"]=>
  string(6) "latest"
}
bool(true)
array(1) {
  [0]=>
  string(3) "api"
}
string(10) "api.status"
string(10) "/users/123"
OK
