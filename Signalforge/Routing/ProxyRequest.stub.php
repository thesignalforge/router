<?php
/**
 * Signalforge Routing Extension
 * ProxyRequest.stub.php - IDE stub for ProxyRequest class
 *
 * @package Signalforge\Routing
 */

namespace Signalforge\Routing;

/**
 * Immutable value object representing the outgoing proxy request.
 *
 * Created internally during proxy execution. Use with*() methods
 * in the onRequest callback to modify the request before it is sent.
 *
 * @final
 * @readonly
 */
final readonly class ProxyRequest
{
    /**
     * Private constructor - created internally by the router.
     */
    private function __construct() {}

    /**
     * Get the HTTP method.
     *
     * @return string
     */
    public function getMethod(): string {}

    /**
     * Get the upstream URL.
     *
     * @return string
     */
    public function getUrl(): string {}

    /**
     * Get all headers as an associative array.
     *
     * @return array<string, string> Map of lowercase header name => value
     */
    public function getHeaders(): array {}

    /**
     * Get a single header value by name (case-insensitive).
     *
     * @param string $name Header name
     * @return string|null Header value or null if not present
     */
    public function getHeader(string $name): ?string {}

    /**
     * Get the request body.
     *
     * @return string|null Request body or null
     */
    public function getBody(): ?string {}

    /**
     * Return a new instance with a different HTTP method.
     *
     * @param string $method HTTP method
     * @return self
     */
    public function withMethod(string $method): self {}

    /**
     * Return a new instance with a different URL.
     *
     * @param string $url Upstream URL
     * @return self
     */
    public function withUrl(string $url): self {}

    /**
     * Return a new instance with an added or replaced header.
     *
     * @param string $name Header name (stored lowercase)
     * @param string $value Header value
     * @return self
     */
    public function withHeader(string $name, string $value): self {}

    /**
     * Return a new instance with a different body.
     *
     * @param string $body Request body
     * @return self
     */
    public function withBody(string $body): self {}

    /**
     * Return a new instance with a header removed.
     *
     * @param string $name Header name to remove
     * @return self
     */
    public function withoutHeader(string $name): self {}
}
