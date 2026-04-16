--TEST--
SSRF: proxy refuses to forward to cloud metadata endpoint 169.254.169.254
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.proxy_allow_private=0
signalforge_routing.proxy_allow_metadata_endpoint=0
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext, RoutingException};

// 169.254.169.254 is AWS/GCP/Azure/OpenStack metadata. Stealing creds from
// this address is the textbook SSRF payoff. Must be rejected unconditionally
// unless the operator opts in via proxy_allow_metadata_endpoint=1.
$router = new Router();
$router->get('/p', fn() => null)->proxy('http://169.254.169.254/latest/meta-data/');
$router->routeUsing(null, fn($p): RoutingContext => new RoutingContext('GET', '/p'));

try {
    $router->dispatch();
    echo "ERROR: metadata request was allowed\n";
} catch (RoutingException $e) {
    $msg = $e->getMessage();
    if (strpos($msg, 'blocked address') !== false &&
        strpos($msg, '169.254.169.254') !== false) {
        echo "metadata blocked ok\n";
    } else {
        echo "other: $msg\n";
    }
}

echo "OK\n";
?>
--EXPECT--
metadata blocked ok
OK
