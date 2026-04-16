--TEST--
Route caching throws when a route has a closure handler (no silent data loss)
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.cache_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--FILE--
<?php
use Signalforge\Routing\Router;
use Signalforge\Routing\RoutingException;

$cacheFile = sys_get_temp_dir() . '/sf_route_cache_closure_test.bin';
@unlink($cacheFile);

$router = new Router();

$router->get('/users', [UserController::class, 'index']);
// This one is a closure and cannot be serialized
$router->get('/legacy', function() { return 'hi'; });

try {
    $router->cache($cacheFile);
    echo "FAIL: cache() should have thrown\n";
} catch (RoutingException $e) {
    echo "THROWN\n";
    echo (str_contains($e->getMessage(), 'closure') ? 'has-closure-word' : 'missing-closure-word'), "\n";
    echo (str_contains($e->getMessage(), '/legacy') ? 'has-uri' : 'missing-uri'), "\n";
}

// Cache file should NOT have been written (or should be empty/absent)
var_dump(file_exists($cacheFile) && filesize($cacheFile) > 0);

@unlink($cacheFile);
echo "OK\n";
?>
--EXPECT--
THROWN
has-closure-word
has-uri
bool(false)
OK
