<?php
/**
 * Signalforge Routing Extension
 * ProxyResponse.stub.php - IDE stub for ProxyResponse class
 *
 * @package Signalforge\Routing
 */

namespace Signalforge\Routing;

/**
 * Immutable value object representing the upstream proxy response.
 *
 * Created internally after the proxy HTTP request completes. Use with*() methods
 * in the onResponse callback to modify the response before it is sent to the browser.
 *
 * @final
 * @readonly
 */
final readonly class ProxyResponse
{
    /**
     * Private constructor - created internally by the router.
     */
    private function __construct() {}

    /**
     * Get the HTTP status code.
     *
     * @return int
     */
    public function getStatusCode(): int {}

    /**
     * Get all response headers as an associative array.
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
     * Get the response body.
     *
     * @return string
     */
    public function getBody(): string {}

    /**
     * Return a new instance with a different status code.
     *
     * @param int $code HTTP status code
     * @return self
     */
    public function withStatus(int $code): self {}

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
     * @param string $body Response body
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

    /**
     * Send the response to the browser.
     *
     * Sets HTTP status code, sends all headers via SAPI, and outputs the body.
     *
     * @return void
     */
    public function send(): void {}
}
