--TEST--
Route proxy, ProxyRequest, ProxyResponse, onRequest, onResponse
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\{Router, Route, MatchResult, ProxyRequest, ProxyResponse};

// Test 1: proxy() returns Route for chaining and getProxyUrl() works
Router::flush();
$route = Router::get('/api/status', fn() => null)->proxy('https://api.example.com/status');
var_dump($route instanceof Route);
var_dump($route->getProxyUrl());

// Test 2: getProxyUrl() returns null when no proxy
Router::flush();
$route2 = Router::get('/home', fn() => null);
var_dump($route2->getProxyUrl());

// Test 3: onRequest/onResponse chain after proxy()
Router::flush();
$route3 = Router::get('/api/data', fn() => null)
    ->proxy('https://backend.internal/data')
    ->onRequest(function(ProxyRequest $req): ProxyRequest {
        return $req->withHeader('X-Custom', 'test');
    })
    ->onResponse(function(ProxyResponse $resp): ProxyResponse {
        return $resp->withHeader('X-Proxied', 'true');
    });
var_dump($route3 instanceof Route);
var_dump($route3->getProxyUrl());

// Test 4: onRequest without proxy() throws
Router::flush();
try {
    Router::get('/test', fn() => null)->onRequest(function($r) { return $r; });
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "onRequest needs proxy: " . $e->getMessage() . "\n";
}

// Test 5: onResponse without proxy() throws
Router::flush();
try {
    Router::get('/test', fn() => null)->onResponse(function($r) { return $r; });
    echo "ERROR: should have thrown\n";
} catch (\Signalforge\Routing\RoutingException $e) {
    echo "onResponse needs proxy: " . $e->getMessage() . "\n";
}

// Test 6: isProxy() returns false for non-proxy match
Router::flush();
Router::get('/users/{id}', fn($id) => $id)->whereNumber('id');
$result = Router::match('GET', '/users/42');
var_dump($result->isProxy());
var_dump($result->getProxyResponse());

// Test 7: Proxy URL parameter substitution in pattern
Router::flush();
Router::get('/api/users/{id}', fn($id) => null)
    ->whereNumber('id')
    ->proxy('https://api.example.com/users/{id}');
$result = Router::match('GET', '/api/users/42');
var_dump($result->matched());
// Note: proxy is only executed during dispatch(), not match()
var_dump($result->isProxy());

echo "OK\n";
?>
--EXPECT--
bool(true)
string(30) "https://api.example.com/status"
NULL
bool(true)
string(29) "https://backend.internal/data"
onRequest needs proxy: Call proxy() before onRequest()
onResponse needs proxy: Call proxy() before onResponse()
bool(false)
NULL
bool(true)
bool(false)
OK
