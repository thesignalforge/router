--TEST--
Route cache rejects files with wrong/legacy magic bytes
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.cache_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--FILE--
<?php
use Signalforge\Routing\Router;

$cacheFile = sys_get_temp_dir() . '/sf_cache_wrong_magic.bin';

// Case 1: legacy unauthenticated "SFRC" cache — this is the whole point of
// the version bump. Any such file must be rejected even with a valid key.
file_put_contents($cacheFile, "SFRC\x01\x00\x00\x00"
    . str_repeat("\x00", 40) . str_repeat("X", 32));

set_error_handler(function ($errno, $errstr) {
    // Only print warnings that come from our extension.
    if (strpos($errstr, 'route cache') !== false) {
        // Distill to a stable token
        if (strpos($errstr, 'bad magic') !== false) echo "bad magic rejected\n";
        elseif (strpos($errstr, 'HMAC mismatch') !== false) echo "mac rejected\n";
        elseif (strpos($errstr, 'truncated') !== false) echo "truncated rejected\n";
        elseif (strpos($errstr, 'version') !== false) echo "version rejected\n";
    }
    return true;
});

$r = new Router();
var_dump($r->loadCache($cacheFile));

// Case 2: total garbage (long enough to pass the truncation check)
file_put_contents($cacheFile, "this is not a route cache at all"
    . str_repeat("X", 64));
var_dump((new Router())->loadCache($cacheFile));

// Case 3: short file (less than header + MAC)
file_put_contents($cacheFile, "SFR1");
var_dump((new Router())->loadCache($cacheFile));

// Case 4: correct magic, wrong version
file_put_contents($cacheFile, "SFR1\x00\x00\xFF\xFF" . str_repeat("\x00", 40));
var_dump((new Router())->loadCache($cacheFile));

restore_error_handler();
@unlink($cacheFile);
echo "OK\n";
?>
--EXPECT--
bad magic rejected
bool(false)
bad magic rejected
bool(false)
truncated rejected
bool(false)
version rejected
bool(false)
OK
