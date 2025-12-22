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
 * The Router class provides a static interface for route registration
 * and matching. All routes are stored in a global radix trie that is
 * optimized for O(k) lookup where k is the URI path length.
 *
 * @final
 */
final class Router
{
    /**
     * Register a GET route.
     *
     * @param string $uri The URI pattern (e.g., '/users/{id}')
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function get(string $uri, mixed $handler): Route {}

    /**
     * Register a POST route.
     *
     * @param string $uri The URI pattern
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function post(string $uri, mixed $handler): Route {}

    /**
     * Register a PUT route.
     *
     * @param string $uri The URI pattern
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function put(string $uri, mixed $handler): Route {}

    /**
     * Register a PATCH route.
     *
     * @param string $uri The URI pattern
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function patch(string $uri, mixed $handler): Route {}

    /**
     * Register a DELETE route.
     *
     * @param string $uri The URI pattern
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function delete(string $uri, mixed $handler): Route {}

    /**
     * Register an OPTIONS route.
     *
     * @param string $uri The URI pattern
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function options(string $uri, mixed $handler): Route {}

    /**
     * Register a route for any HTTP method.
     *
     * @param string $uri The URI pattern
     * @param mixed $handler Callable, closure, or 'Controller@method' string
     * @return Route The created route for method chaining
     */
    public static function any(string $uri, mixed $handler): Route {}

    /**
     * Match a request against registered routes.
     *
     * @param string $method HTTP method (GET, POST, etc.)
     * @param string $uri Request URI to match
     * @param string|null $domain Optional domain for subdomain routing
     * @return MatchResult The match result containing route and parameters
     */
    public static function match(string $method, string $uri, ?string $domain = null): MatchResult {}

    /**
     * Define a route group with shared attributes.
     *
     * Supported attributes:
     * - 'prefix': URI prefix for all routes in the group
     * - 'middleware': Array of middleware to apply
     * - 'namespace': Controller namespace
     * - 'as': Route name prefix
     * - 'domain': Domain constraint
     *
     * @param array $attributes Group attributes
     * @param callable $callback Callback containing route definitions
     * @return void
     */
    public static function group(array $attributes, callable $callback): void {}

    /**
     * Set a prefix for subsequent route registrations.
     *
     * @param string $prefix URI prefix
     * @return void
     */
    public static function prefix(string $prefix): void {}

    /**
     * Set middleware for subsequent route registrations.
     *
     * @param string|array $middleware Middleware name(s)
     * @return void
     */
    public static function middleware(string|array $middleware): void {}

    /**
     * Set domain constraint for subsequent route registrations.
     *
     * @param string $domain Domain pattern (supports {subdomain} parameters)
     * @return void
     */
    public static function domain(string $domain): void {}

    /**
     * Set namespace for subsequent route registrations.
     *
     * @param string $namespace Controller namespace
     * @return void
     */
    public static function namespace(string $namespace): void {}

    /**
     * Set name prefix for subsequent route registrations.
     *
     * @param string $name Route name prefix
     * @return void
     */
    public static function name(string $name): void {}

    /**
     * Register a fallback route for unmatched requests.
     *
     * @param mixed $handler Fallback handler
     * @return Route The fallback route
     */
    public static function fallback(mixed $handler): Route {}

    /**
     * Generate URL for a named route.
     *
     * @param string $name Route name
     * @param array|null $params Route parameters
     * @return string|null Generated URL or null if route not found
     */
    public static function url(string $name, ?array $params = null): ?string {}

    /**
     * Check if a named route exists.
     *
     * @param string $name Route name
     * @return bool True if route exists
     */
    public static function has(string $name): bool {}

    /**
     * Get all registered routes.
     *
     * @return Route[] Array of Route objects
     */
    public static function getRoutes(): array {}

    /**
     * Clear all registered routes.
     *
     * @return void
     */
    public static function flush(): void {}

    /**
     * Cache routes to a file.
     *
     * @param string $path File path for cache
     * @return bool True on success
     */
    public static function cache(string $path): bool {}

    /**
     * Load routes from cache file.
     *
     * @param string $path Cache file path
     * @return bool True on success
     */
    public static function loadCache(string $path): bool {}

    /**
     * Enable/disable strict trailing slash matching.
     *
     * @param bool $strict Whether to strictly match trailing slashes
     * @return void
     */
    public static function setStrictSlashes(bool $strict): void {}

    /**
     * Dump the internal trie structure (for debugging).
     *
     * @return void
     */
    public static function dump(): void {}

    /**
     * Get the router instance.
     *
     * @return Router
     */
    public static function getInstance(): Router {}
}
