--TEST--
Route::domain() with invalid PCRE2 pattern throws instead of silently accepting
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;
use Signalforge\Routing\RoutingException;

$router = new Router();

// Register a route whose domain pattern contains an unclosed character class.
// The pattern builder preserves the `[` literal, yielding an invalid PCRE2
// expression — before the fix, pcre2_compile() returned NULL and the route
// silently never matched. Now it must throw.
try {
    $router->get('/x', [C::class, 'm'])->domain('{sub}.[invalid.example.com');
    echo "FAIL: expected exception\n";
} catch (RoutingException $e) {
    echo "THROWN\n";
    echo (str_contains($e->getMessage(), 'Invalid domain pattern') ? 'has-prefix' : 'missing-prefix'), "\n";
    echo (str_contains($e->getMessage(), 'PCRE2') ? 'has-pcre2' : 'missing-pcre2'), "\n";
}

echo "OK\n";
?>
--EXPECT--
THROWN
has-prefix
has-pcre2
OK
