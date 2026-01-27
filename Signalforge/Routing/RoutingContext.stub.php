<?php
/**
 * Signalforge Routing Extension
 * RoutingContext.stub.php - IDE stub for RoutingContext class
 *
 * @package Signalforge\Routing
 */

namespace Signalforge\Routing;

/**
 * Value object representing resolved routing context.
 *
 * Created by the resolver callback passed to Router::routeUsing().
 * Contains the HTTP method (or "CLI"), path, and optional domain
 * needed for the router to perform route matching.
 *
 * @final
 */
final class RoutingContext
{
    /**
     * Create a new routing context.
     *
     * @param string $method HTTP method or "CLI"
     * @param string $path Request path or CLI command
     * @param string|null $domain Optional domain for subdomain routing
     */
    public function __construct(string $method, string $path, ?string $domain = null) {}

    /**
     * Get the HTTP method or "CLI".
     *
     * @return string
     */
    public function getMethod(): string {}

    /**
     * Get the request path.
     *
     * @return string
     */
    public function getPath(): string {}

    /**
     * Get the domain, if set.
     *
     * @return string|null
     */
    public function getDomain(): ?string {}
}
