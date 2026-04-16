--TEST--
SSRF: proxy_allow_private=1 permits private IPs but STILL blocks metadata
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.proxy_allow_private=1
signalforge_routing.proxy_allow_metadata_endpoint=0
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext, RoutingException};

// Silence HTTP wrapper warnings that fire once we let the request past the
// SSRF gate (nothing listens on 10.0.0.1 in the test env, but the test is
// about the SSRF gate, not the HTTP fetch).
set_error_handler(function ($errno, $errstr) {
    return true; // swallow everything
});

// Case 1: private IP 10.0.0.1 should be allowed through the SSRF gate.
// The proxy fetch will fail, but we must NOT see a "blocked address"
// RoutingException — that's what we're testing.
$router = new Router();
$router->get('/p', fn() => null)->proxy('http://10.0.0.1:9/');
$router->routeUsing(null, fn($p): RoutingContext => new RoutingContext('GET', '/p'));

$ssrf_thrown = false;
try {
    $router->dispatch();
} catch (RoutingException $e) {
    if (strpos($e->getMessage(), 'blocked address') !== false) {
        $ssrf_thrown = true;
    }
}
restore_error_handler();
echo ($ssrf_thrown ? "FAIL: private blocked despite allow_private\n"
                   : "private allowed\n");

// Case 2: metadata endpoint must STILL be blocked even with allow_private=1,
// because proxy_allow_metadata_endpoint is 0. This is the defense-in-depth
// check: sloppy "allow private" should never expose cloud creds.
set_error_handler(function ($errno, $errstr) { return true; });
$router = new Router();
$router->get('/p', fn() => null)->proxy('http://169.254.169.254/latest/meta-data/');
$router->routeUsing(null, fn($p): RoutingContext => new RoutingContext('GET', '/p'));
try {
    $router->dispatch();
    echo "FAIL: metadata allowed with allow_private=1\n";
} catch (RoutingException $e) {
    $m = $e->getMessage();
    echo ((strpos($m, 'blocked address') !== false
        && strpos($m, '169.254.169.254') !== false)
        ? "metadata still blocked\n"
        : "other: $m\n");
}
restore_error_handler();

echo "OK\n";
?>
--EXPECT--
private allowed
metadata still blocked
OK
