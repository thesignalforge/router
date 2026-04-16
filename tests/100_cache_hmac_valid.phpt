--TEST--
Authenticated route cache: round-trip with valid HMAC key
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.cache_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--FILE--
<?php
use Signalforge\Routing\Router;

$cacheFile = sys_get_temp_dir() . '/sf_cache_hmac_valid.bin';
@unlink($cacheFile);

$router = new Router();
$router->get('/users', [UserController::class, 'index'])->name('users.index');
$router->get('/users/{id}', [UserController::class, 'show'])
    ->name('users.show')
    ->whereNumber('id');
$router->post('/articles', [ArticleController::class, 'store'])
    ->middleware(['auth']);

var_dump($router->cache($cacheFile));
var_dump(file_exists($cacheFile));

// Magic must be SFR1 (authenticated). Any old "SFRC" cache must be rejected.
$head = file_get_contents($cacheFile, false, null, 0, 4);
var_dump($head === 'SFR1');

// File must end with a 32-byte HMAC tag.
$size = filesize($cacheFile);
var_dump($size > 40); // header (8) + some payload + mac (32)

// Load into a fresh router and verify routes are present.
$r2 = new Router();
$r2_before = $r2->match('GET', '/users');
var_dump($r2_before->matched());

var_dump($r2->loadCache($cacheFile));

$m = $r2->match('GET', '/users');
var_dump($m->matched());
var_dump($m->getRouteName());

$m = $r2->match('GET', '/users/42');
var_dump($m->matched());
var_dump($m->getParams());
var_dump($m->getRouteName());

$m = $r2->match('POST', '/articles');
var_dump($m->matched());
var_dump($m->getMiddleware());

@unlink($cacheFile);
echo "OK\n";
?>
--EXPECT--
bool(true)
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
array(1) {
  [0]=>
  string(4) "auth"
}
OK
