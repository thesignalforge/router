--TEST--
SSRF: proxy rejects dangerous URL schemes (file, gopher, dict, ftp, php, phar...)
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\{Router, RoutingContext, RoutingException};

function expect_scheme_block(string $url, string $label): void
{
    $router = new Router();
    try {
        // Rejection may happen at registration time (plain string scheme check)
        // or at dispatch time (after {param} substitution). Both paths must
        // surface a RoutingException mentioning the scheme.
        $router->get('/p', fn() => null)->proxy($url);
        $router->routeUsing(null, fn($p): RoutingContext => new RoutingContext('GET', '/p'));
        $router->dispatch();
        echo "$label: ERROR allowed\n";
        return;
    } catch (RoutingException $e) {
        $m = $e->getMessage();
        if (strpos($m, 'scheme') !== false ||
            strpos($m, 'not allowed') !== false ||
            strpos($m, 'must use http') !== false) {
            echo "$label: rejected\n";
        } else {
            echo "$label: other: $m\n";
        }
    }
}

expect_scheme_block('file:///etc/passwd',            'file');
expect_scheme_block('gopher://evil.example/x',       'gopher');
expect_scheme_block('dict://localhost:11211/stats',  'dict');
expect_scheme_block('ftp://example.com/secret',      'ftp');
expect_scheme_block('php://filter/resource=x',       'php');
expect_scheme_block('phar:///tmp/evil.phar/x',       'phar');
expect_scheme_block('data://text/plain,hi',          'data');
expect_scheme_block('tftp://example.com/',           'tftp');

echo "OK\n";
?>
--EXPECT--
file: rejected
gopher: rejected
dict: rejected
ftp: rejected
php: rejected
phar: rejected
data: rejected
tftp: rejected
OK
