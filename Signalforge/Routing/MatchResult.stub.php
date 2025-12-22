<?php
/**
 * Signalforge Routing Extension
 * MatchResult.stub.php - IDE stub for MatchResult class
 *
 * @package Signalforge\Routing
 */

namespace Signalforge\Routing;

/**
 * Result of a route matching operation.
 *
 * Returned by Router::match(), this immutable object contains all information
 * about the matched route, extracted parameters, and middleware stack.
 *
 * @final
 * @readonly
 */
final readonly class MatchResult
{
    /**
     * Private constructor - results are created by Router::match().
     */
    private function __construct() {}

    /**
     * Check if a route was matched.
     *
     * @return bool True if a route was matched
     */
    public function matched(): bool {}

    /**
     * Get the matched Route object.
     *
     * @return Route|null The matched route or null if no match
     */
    public function getRoute(): ?Route {}

    /**
     * Get the route handler.
     *
     * @return mixed The handler callable, or null if no match
     */
    public function getHandler(): mixed {}

    /**
     * Get all extracted route parameters.
     *
     * @return array Map of parameter name => value
     */
    public function getParams(): array {}

    /**
     * Get the middleware stack for the matched route.
     *
     * @return array Array of middleware names
     */
    public function getMiddleware(): array {}

    /**
     * Get the matched route's name.
     *
     * @return string|null Route name or null
     */
    public function getRouteName(): ?string {}

    /**
     * Get error message if matching failed.
     *
     * @return string|null Error message or null on success
     */
    public function getError(): ?string {}

    /**
     * Get a single parameter value.
     *
     * @param string $name Parameter name
     * @param mixed $default Default value if parameter not found
     * @return mixed Parameter value or default
     */
    public function param(string $name, mixed $default = null): mixed {}
}
