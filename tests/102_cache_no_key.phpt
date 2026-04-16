--TEST--
Route cache refuses to save or load when signalforge_routing.cache_key is unset
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.cache_key=
--FILE--
<?php
use Signalforge\Routing\Router;

$cacheFile = sys_get_temp_dir() . '/sf_cache_no_key.bin';
@unlink($cacheFile);

// Capture warnings about the missing key.
$warnings = [];
set_error_handler(function ($errno, $errstr) use (&$warnings) {
    if (strpos($errstr, 'cache_key') !== false || strpos($errstr, 'route cache') !== false) {
        $warnings[] = $errstr;
    }
    return true;
});

// Saving must fail.
$router = new Router();
$router->get('/x', fn() => null);
$saved = $router->cache($cacheFile);
var_dump($saved);
var_dump(file_exists($cacheFile));

// And even if someone drops a file in place, loading must fail.
file_put_contents($cacheFile, "SFR1\x00\x00\x00\x01garbage-garbage-garbage-garbage");

$r2 = new Router();
$loaded = $r2->loadCache($cacheFile);
var_dump($loaded);

restore_error_handler();

// At least one warning should reference the missing cache_key.
$hit = false;
foreach ($warnings as $w) {
    if (strpos($w, 'cache_key') !== false) { $hit = true; break; }
}
var_dump($hit);

@unlink($cacheFile);
echo "OK\n";
?>
--EXPECT--
bool(false)
bool(false)
bool(false)
bool(true)
OK
