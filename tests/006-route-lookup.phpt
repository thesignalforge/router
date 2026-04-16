--TEST--
Router route() - get route by name
--EXTENSIONS--
signalforge_routing
--FILE--
<?php
use Signalforge\Routing\Router;

$router = new Router();

// Register named routes
$router->get('/users', [UserController::class, 'index'])->name('users.index');
$router->get('/users/{id}', [UserController::class, 'show'])
    ->name('users.show')
    ->whereNumber('id');
$router->post('/users', [UserController::class, 'store'])
    ->name('users.store')
    ->middleware(['auth', 'validate']);

// Test 1: Get route by name
$route = $router->route('users.index');
var_dump($route !== null);
var_dump($route->getUri());
var_dump($route->getMethods());
var_dump($route->getName());

// Test 2: Get route with parameter
$route = $router->route('users.show');
var_dump($route !== null);
var_dump($route->getUri());
var_dump($route->getMethods());

// Test 3: Get POST route with middleware
$route = $router->route('users.store');
var_dump($route !== null);
var_dump($route->getUri());
var_dump($route->getMethods());
var_dump($route->getMiddleware());

// Test 4: Non-existent route returns null
$route = $router->route('nonexistent');
var_dump($route);

// Test 5: has() consistency
var_dump($router->has('users.index'));
var_dump($router->has('nonexistent'));

echo "OK\n";
?>
--EXPECT--
bool(true)
string(6) "/users"
array(1) {
  [0]=>
  string(3) "GET"
}
string(11) "users.index"
bool(true)
string(11) "/users/{id}"
array(1) {
  [0]=>
  string(3) "GET"
}
bool(true)
string(6) "/users"
array(1) {
  [0]=>
  string(4) "POST"
}
array(2) {
  [0]=>
  string(4) "auth"
  [1]=>
  string(8) "validate"
}
NULL
bool(true)
bool(false)
OK
