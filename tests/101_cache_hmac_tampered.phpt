--TEST--
Authenticated route cache: tampered payload byte is rejected
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.cache_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--FILE--
<?php
use Signalforge\Routing\Router;

$cacheFile = sys_get_temp_dir() . '/sf_cache_hmac_tampered.bin';
@unlink($cacheFile);

$router = new Router();
$router->get('/users', [UserController::class, 'index'])->name('users.index');
$router->get('/users/{id}', [UserController::class, 'show'])
    ->name('users.show')
    ->whereNumber('id');
var_dump($router->cache($cacheFile));

// Corrupt one byte in the middle of the payload (after the 8-byte header,
// before the 32-byte trailing MAC). This simulates an attacker who can
// write the cache file trying to inject arbitrary handler bytes.
$size = filesize($cacheFile);
$content = file_get_contents($cacheFile);
$mid = (int) (($size - 32) / 2);
if ($mid < 8) { $mid = 8; }
$content[$mid] = chr(ord($content[$mid]) ^ 0xFF);
file_put_contents($cacheFile, $content);

// Load must fail. Capture the warning text to prove the right path ran.
set_error_handler(function ($errno, $errstr) {
    echo "warning: " .
        (strpos($errstr, 'HMAC mismatch') !== false ? 'HMAC mismatch ok' : $errstr) . "\n";
    return true;
});

$r2 = new Router();
$res = $r2->loadCache($cacheFile);
restore_error_handler();

var_dump($res);

// The router must still be empty — nothing from the tampered file should have
// leaked into the live trie.
$m = $r2->match('GET', '/users');
var_dump($m->matched());

@unlink($cacheFile);
echo "OK\n";
?>
--EXPECT--
bool(true)
warning: HMAC mismatch ok
bool(false)
bool(false)
OK
