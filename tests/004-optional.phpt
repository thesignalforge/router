--TEST--
Optional parameters and defaults
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

Router::flush();

// Optional parameter
Router::get('/posts/{slug?}', function($slug = null) {
    return $slug ?? 'all';
})->defaults('slug', 'latest');

// Match with parameter
$result = Router::match('GET', '/posts/hello-world');
var_dump($result->matched());
var_dump($result->param('slug'));

// Match without parameter (should use default)
$result = Router::match('GET', '/posts');
var_dump($result->matched());
var_dump($result->param('slug'));

// Multiple optional parameters
Router::get('/archive/{year?}/{month?}', function($year = null, $month = null) {
    return [$year, $month];
})->defaults('year', '2024')->defaults('month', '01');

$result = Router::match('GET', '/archive/2023/12');
var_dump($result->matched());
var_dump($result->getParams());

$result = Router::match('GET', '/archive');
var_dump($result->matched());
var_dump($result->getParams());

echo "OK\n";
?>
--EXPECT--
bool(true)
string(11) "hello-world"
bool(true)
string(6) "latest"
bool(true)
array(2) {
  ["year"]=>
  string(4) "2023"
  ["month"]=>
  string(2) "12"
}
bool(true)
array(2) {
  ["year"]=>
  string(4) "2024"
  ["month"]=>
  string(2) "01"
}
OK
