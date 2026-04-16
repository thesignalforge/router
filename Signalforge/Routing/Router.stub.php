<?php
/**
 * Signalforge Routing Extension
 * Router.stub.php - IDE stub for Router class
 *
 * @package Signalforge\Routing
 */

namespace Signalforge\Routing;

/**
 * High-performance router using compressed radix trie.
 *
 * The Router class provides an instance-based interface for route registration
 * and matching. Each instance maintains its own radix trie optimized for O(k)
 * lookup where k is the URI path length.
 *
 * Usage:
 *   $router = new Router();
 *   $router->get('/users/{id}', [UserController::class, 'show']);
 *   $match = $router->match('GET', '/users/42');
 *
 * @final
 */
final class Router
{
    /**
     * Create a new Router instance with an empty route table.
     */
    public function __construct() {}

    /**
     * Register a GET route.
     *
     * @param string $uri The URI pattern (e.g., '/users/{id}')
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function get(string $uri, mixed $handler): Route {}

    /**
     * Register a POST route.
     *
     * @param string $uri The URI pattern
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function post(string $uri, mixed $handler): Route {}

    /**
     * Register a PUT route.
     *
     * @param string $uri The URI pattern
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function put(string $uri, mixed $handler): Route {}

    /**
     * Register a PATCH route.
     *
     * @param string $uri The URI pattern
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function patch(string $uri, mixed $handler): Route {}

    /**
     * Register a DELETE route.
     *
     * @param string $uri The URI pattern
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function delete(string $uri, mixed $handler): Route {}

    /**
     * Register an OPTIONS route.
     *
     * @param string $uri The URI pattern
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function options(string $uri, mixed $handler): Route {}

    /**
     * Register a route for any HTTP method.
     *
     * @param string $uri The URI pattern
     * @param callable $handler Any PHP callable: [Controller::class, 'method'], closure, function name, etc.
     * @return Route The created route for method chaining
     */
    public function any(string $uri, mixed $handler): Route {}

    /**
     * Match a request against registered routes.
     *
     * @param string $method HTTP method (GET, POST, etc.)
     * @param string $uri Request URI to match
     * @param string|null $domain Optional domain for subdomain routing
     * @return MatchResult The match result containing route and parameters
     */
    public function match(string $method, string $uri, ?string $domain = null): MatchResult {}

    /**
     * Define a route group with shared attributes.
     *
     * The callback receives the Router instance as its first argument,
     * allowing routes to be registered on the same router.
     *
     * Supported attributes:
     * - 'prefix': URI prefix for all routes in the group
     * - 'middleware': Array of middleware to apply
     * - 'as': Route name prefix
     * - 'domain': Domain constraint
     * - 'where': Array of parameter constraints
     *
     * @param array $attributes Group attributes
     * @param callable(Router): void $callback Callback receiving the Router instance
     * @return void
     */
    public function group(array $attributes, callable $callback): void {}

    /**
     * Register a fallback route for unmatched requests.
     *
     * @param mixed $handler Fallback handler
     * @return Route The fallback route
     */
    public function fallback(mixed $handler): Route {}

    /**
     * Generate URL for a named route.
     *
     * @param string $name Route name
     * @param array|null $params Route parameters
     * @return string|null Generated URL or null if route not found
     */
    public function url(string $name, ?array $params = null): ?string {}

    /**
     * Check if a named route exists.
     *
     * @param string $name Route name
     * @return bool True if route exists
     */
    public function has(string $name): bool {}

    /**
     * Get a route by its name.
     *
     * @param string $name Route name
     * @return Route|null The route object or null if not found
     */
    public function route(string $name): ?Route {}

    /**
     * Get all registered routes.
     *
     * @return Route[] Array of Route objects
     */
    public function getRoutes(): array {}

    /**
     * Clear all registered routes and reset the router state.
     *
     * @return void
     */
    public function flush(): void {}

    /**
     * Cache routes to a file.
     *
     * @param string $path File path for cache
     * @return bool True on success
     */
    public function cache(string $path): bool {}

    /**
     * Load routes from cache file, replacing the current route table.
     *
     * @param string $path Cache file path
     * @return bool True on success
     */
    public function loadCache(string $path): bool {}

    /**
     * Dump the internal trie structure (for debugging).
     *
     * @return void
     */
    public function dump(): void {}

    /**
     * Register a CLI command route.
     *
     * Uses colon-separated command names (e.g., 'cache:clear', 'users:{id}:delete').
     * Parameters and constraints work the same as HTTP routes.
     *
     * @param string $command Colon-separated command pattern
     * @param mixed $handler Any PHP callable
     * @return Route The created route for method chaining
     */
    public function cli(string $command, mixed $handler): Route {}

    /**
     * Bind input and resolver for dispatch.
     *
     * The resolver receives the input and must return a RoutingContext instance
     * containing the method, path, and optional domain to route against.
     *
     * @param mixed $input The request object, array, or any value to pass to the resolver
     * @param callable $resolver Callback that receives $input and returns RoutingContext
     * @return void
     */
    public function routeUsing(mixed $input, callable $resolver): void {}

    /**
     * Set a resolver callable for use with dispatch($input).
     *
     * The resolver receives the input passed to dispatch() and must return
     * a RoutingContext instance. Set it once at boot in worker runtimes
     * (RoadRunner, FrankenPHP), then call dispatch($input) per request.
     *
     * @param callable $resolver Callback that receives $input and returns RoutingContext
     * @return void
     */
    public function resolver(callable $resolver): void {}

    /**
     * Dispatch using the routing context.
     *
     * Without arguments: dispatches using the context set by routeUsing().
     * With $input: calls the resolver set by resolver() to extract
     * the routing context, then dispatches.
     *
     * @param mixed $input Optional input to pass to the stored resolver
     * @return MatchResult The match result
     * @throws RoutingException If no context or resolver is available
     */
    public function dispatch(mixed $input = null): MatchResult {}
}
