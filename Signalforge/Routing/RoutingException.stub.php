<?php
/**
 * Signalforge Routing Extension
 * RoutingException.stub.php - IDE stub for the RoutingException class
 *
 * @package Signalforge\Routing
 */

declare(strict_types=1);

namespace Signalforge\Routing;

/**
 * Thrown by the routing extension for runtime failures.
 *
 * Common causes: invalid route definition, name collision, unresolvable
 * named route in {@see Router::url()}, malformed cache file passed to
 * {@see Router::loadCache()}, or proxy/middleware misconfiguration.
 */
class RoutingException extends \RuntimeException
{
}
