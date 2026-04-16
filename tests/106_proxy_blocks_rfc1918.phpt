--TEST--
SSRF: proxy refuses to forward to RFC1918 private address ranges
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.proxy_allow_private=0
signalforge_routing.proxy_allow_metadata_endpoint=0
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext, RoutingException};

function expect_block(string $url, string $label): void
{
    $router = new Router();
    $router->get('/p', fn() => null)->proxy($url);
    $router->routeUsing(null, fn($p): RoutingContext => new RoutingContext('GET', '/p'));
    try {
        $router->dispatch();
        echo "$label: ERROR allowed\n";
    } catch (RoutingException $e) {
        echo (strpos($e->getMessage(), 'blocked address') !== false
            ? "$label: blocked"
            : "$label: other: " . $e->getMessage()) . "\n";
    }
}

expect_block('http://10.0.0.1/',       '10.0.0.0/8');
expect_block('http://10.255.255.255/', '10.255.255.255');
expect_block('http://172.16.0.1/',     '172.16.0.0/12 low');
expect_block('http://172.31.255.254/', '172.16.0.0/12 high');
expect_block('http://192.168.1.1/',    '192.168.0.0/16');
expect_block('http://169.254.42.1/',   '169.254.0.0/16 link-local');

echo "OK\n";
?>
--EXPECT--
10.0.0.0/8: blocked
10.255.255.255: blocked
172.16.0.0/12 low: blocked
172.16.0.0/12 high: blocked
192.168.0.0/16: blocked
169.254.0.0/16 link-local: blocked
OK
