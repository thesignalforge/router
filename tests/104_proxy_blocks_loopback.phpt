--TEST--
SSRF: proxy refuses to forward to loopback addresses (127.0.0.1, localhost)
--EXTENSIONS--
signalforge_routing
--INI--
signalforge_routing.proxy_allow_private=0
signalforge_routing.proxy_allow_metadata_endpoint=0
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext, RoutingException};

$ctx_builder = fn($p): RoutingContext => new RoutingContext('GET', '/p');

function expect_ssrf_block(string $upstream, string $label): void
{
    global $ctx_builder;
    $router = new Router();
    $router->get('/p', fn() => null)->proxy($upstream);
    $router->routeUsing(null, $ctx_builder);
    try {
        $router->dispatch();
        echo "$label: ERROR no exception\n";
    } catch (RoutingException $e) {
        $msg = $e->getMessage();
        if (strpos($msg, 'blocked address') !== false) {
            echo "$label: blocked\n";
        } else {
            echo "$label: other: $msg\n";
        }
    }
}

// 127.0.0.1 literal — must be rejected at the IPv4 blocklist
expect_ssrf_block('http://127.0.0.1/secrets', 'literal 127.0.0.1');

// localhost hostname — resolves to 127.0.0.1 / ::1
expect_ssrf_block('http://localhost/secrets', 'localhost');

// IPv6 ::1 literal
expect_ssrf_block('http://[::1]/secrets', '[::1]');

echo "OK\n";
?>
--EXPECT--
literal 127.0.0.1: blocked
localhost: blocked
[::1]: blocked
OK
