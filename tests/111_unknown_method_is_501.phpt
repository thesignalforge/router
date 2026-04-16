--TEST--
Unknown HTTP method does not silently match GET routes (501 signal)
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

$router = new Router();
$router->get('/foo', [FooController::class, 'show']);

// An attacker sends `METHOD: BANANA`. Before the fix, this would silently
// default to GET and hit the /foo route. After the fix, the match must fail
// with an 'Unknown HTTP method' error.
$result = @$router->match('BANANA', '/foo');

var_dump($result->matched());             // must be false
var_dump($result->getRoute());            // must be null (no GET match)
var_dump($result->getError());            // must mention unknown method

echo "OK\n";
?>
--EXPECTF--
bool(false)
NULL
string(19) "Unknown HTTP method"
OK
