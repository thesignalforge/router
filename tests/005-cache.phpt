--TEST--
Route caching - save and load from binary cache
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

$cacheFile = sys_get_temp_dir() . '/sf_route_cache_test.bin';

// Clean up from previous runs
@unlink($cacheFile);

// Register routes
Router::get('/users', [UserController::class, 'index'])->name('users.index');
Router::get('/users/{id}', [UserController::class, 'show'])
    ->name('users.show')
    ->whereNumber('id');
Router::post('/users', [UserController::class, 'store'])
    ->middleware(['auth', 'validate']);
Router::get('/posts/{slug?}', [PostController::class, 'show'])
    ->name('posts.show')
    ->defaults('slug', 'latest');

Router::group(['prefix' => '/api', 'middleware' => ['api']], function() {
    Router::get('/status', [ApiController::class, 'status'])->name('api.status');
});

// Save to cache
$saved = Router::cache($cacheFile);
var_dump($saved);
var_dump(file_exists($cacheFile));

// Check cache file is binary (starts with SFRC)
$header = file_get_contents($cacheFile, false, null, 0, 4);
var_dump($header === 'SFRC');

// Flush and reload from cache
Router::flush();

// Verify routes are gone
$result = Router::match('GET', '/users');
var_dump($result->matched()); // Should be false

// Load from cache
$loaded = Router::loadCache($cacheFile);
var_dump($loaded);

// Verify routes work after loading from cache
$result = Router::match('GET', '/users');
var_dump($result->matched());
var_dump($result->getRouteName());

$result = Router::match('GET', '/users/42');
var_dump($result->matched());
var_dump($result->getParams());
var_dump($result->getRouteName());

$result = Router::match('POST', '/users');
var_dump($result->matched());
var_dump($result->getMiddleware());

$result = Router::match('GET', '/posts');
var_dump($result->matched());
var_dump($result->getParams());

$result = Router::match('GET', '/api/status');
var_dump($result->matched());
var_dump($result->getMiddleware());
var_dump($result->getRouteName());

// URL generation should work
$url = Router::url('users.show', ['id' => 123]);
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
