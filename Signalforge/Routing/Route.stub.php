<?php
/**
 * Signalforge Routing Extension
 * Route.stub.php - IDE stub for Route class
 *
 * @package Signalforge\Routing
 */

namespace Signalforge\Routing;

/**
 * Represents a registered route with its configuration.
 *
 * Route objects are returned by Router registration methods and support
 * method chaining for configuration. Routes cannot be instantiated directly.
 *
 * @final
 */
final class Route
{
    /**
     * Private constructor - routes are created by Router.
     */
    private function __construct() {}

    /**
     * Set the route name.
     *
     * @param string $name Unique route name for URL generation
     * @return $this
     */
    public function name(string $name): self {}

    /**
     * Add middleware to the route.
     *
     * @param string|array $middleware Middleware name(s)
     * @return $this
     */
    public function middleware(string|array $middleware): self {}

    /**
     * Add parameter constraint(s).
     *
     * Can be called with:
     * - A single parameter name and pattern
     * - An array of parameter => pattern pairs
     *
     * @param string|array $param Parameter name or array of constraints
     * @param string|null $pattern Regex pattern (when $param is string)
     * @return $this
     */
    public function where(string|array $param, ?string $pattern = null): self {}

    /**
     * Constrain parameter(s) to numeric values.
     *
     * @param string|array $params Parameter name(s)
     * @return $this
     */
    public function whereNumber(string|array $params): self {}

    /**
     * Constrain parameter(s) to alphabetic values.
     *
     * @param string|array $params Parameter name(s)
     * @return $this
     */
    public function whereAlpha(string|array $params): self {}

    /**
     * Constrain parameter(s) to alphanumeric values.
     *
     * @param string|array $params Parameter name(s)
     * @return $this
     */
    public function whereAlphaNumeric(string|array $params): self {}

    /**
     * Constrain parameter(s) to UUID format.
     *
     * @param string|array $params Parameter name(s)
     * @return $this
     */
    public function whereUuid(string|array $params): self {}

    /**
     * Constrain parameter(s) to ULID format.
     *
     * @param string|array $params Parameter name(s)
     * @return $this
     */
    public function whereUlid(string|array $params): self {}

    /**
     * Constrain parameter to a set of allowed values.
     *
     * @param string $param Parameter name
     * @param array $values Allowed values
     * @return $this
     */
    public function whereIn(string $param, array $values): self {}

    /**
     * Set default value for an optional parameter.
     *
     * @param string $param Parameter name
     * @param mixed $value Default value
     * @return $this
     */
    public function defaults(string $param, mixed $value): self {}

    /**
     * Set domain constraint for the route.
     *
     * @param string $domain Domain pattern (supports {subdomain} parameters)
     * @return $this
     */
    public function domain(string $domain): self {}

    /**
     * Remove middleware from the route.
     *
     * @param string|array $middleware Middleware to remove
     * @return $this
     */
    public function withoutMiddleware(string|array $middleware): self {}

    /**
     * Get the route name.
     *
     * @return string|null
     */
    public function getName(): ?string {}

    /**
     * Get the route URI pattern.
     *
     * @return string|null
     */
    public function getUri(): ?string {}

    /**
     * Get the HTTP methods for this route.
     *
     * @return array
     */
    public function getMethods(): array {}

    /**
     * Get the route handler.
     *
     * @return mixed
     */
    public function getHandler(): mixed {}

    /**
     * Get the route middleware stack.
     *
     * @return array
     */
    public function getMiddleware(): array {}

    /**
     * Get parameter constraints.
     *
     * @return array Map of parameter => pattern
     */
    public function getWheres(): array {}

    /**
     * Get default parameter values.
     *
     * @return array Map of parameter => default value
     */
    public function getDefaults(): array {}

    /**
     * Get the domain constraint.
     *
     * @return string|null
     */
    public function getDomain(): ?string {}
}
