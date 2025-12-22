<?php
/**
 * Signalforge Routing Extension - Performance Benchmark
 *
 * Demonstrates the performance characteristics of the radix trie router.
 */

declare(strict_types=1);

use Signalforge\Routing\Router;

// Ensure extension is loaded
if (!extension_loaded('signalforge_routing')) {
    die("signalforge_routing extension not loaded\n");
}

/**
 * Simple timer utility
 */
class Timer
{
    private float $start;
    private float $end;

    public function start(): void
    {
        $this->start = hrtime(true);
    }

    public function stop(): void
    {
        $this->end = hrtime(true);
    }

    public function elapsed(): float
    {
        return ($this->end - $this->start) / 1e6; // Convert to milliseconds
    }

    public function perSecond(int $iterations): float
    {
        $seconds = ($this->end - $this->start) / 1e9;
        return $iterations / $seconds;
    }
}

/**
 * Generate realistic route patterns
 */
function generateRoutes(int $count): array
{
    $routes = [];
    $methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
    $resources = ['users', 'posts', 'comments', 'products', 'orders', 'categories', 'tags', 'files'];
    $actions = ['index', 'show', 'create', 'store', 'edit', 'update', 'destroy'];

    for ($i = 0; $i < $count; $i++) {
        $resource = $resources[array_rand($resources)];
        $method = $methods[array_rand($methods)];

        $patterns = [
            "/{$resource}",
            "/{$resource}/{id}",
            "/{$resource}/{id}/edit",
            "/{$resource}/{id}/{$actions[array_rand($actions)]}",
            "/api/v1/{$resource}",
            "/api/v1/{$resource}/{id}",
            "/admin/{$resource}",
            "/admin/{$resource}/{id}",
            "/api/v2/{$resource}/{resourceId}/nested",
            "/{$resource}/{parentId}/children/{childId}",
        ];

        $pattern = $patterns[array_rand($patterns)];
        $routes[] = [
            'method' => $method,
            'pattern' => $pattern . ($i > 0 ? "_{$i}" : ''), // Make unique
            'handler' => fn() => null,
        ];
    }

    return $routes;
}

/**
 * Generate test URIs that will match registered routes
 */
function generateMatchingUris(int $count): array
{
    $uris = [];
    $ids = range(1, 1000);

    $patterns = [
        '/users',
        '/users/42',
        '/users/42/edit',
        '/posts',
        '/posts/123',
        '/api/v1/users',
        '/api/v1/users/456',
        '/admin/products',
        '/admin/products/789',
        '/api/v2/orders/111/nested',
        '/categories/10/children/20',
    ];

    for ($i = 0; $i < $count; $i++) {
        $uris[] = $patterns[array_rand($patterns)];
    }

    return $uris;
}

/**
 * Run benchmarks
 */
function runBenchmarks(): void
{
    $timer = new Timer();

    echo "=== Signalforge Router Performance Benchmark ===\n\n";
    echo "PHP Version: " . PHP_VERSION . "\n";
    echo "Extension Version: " . phpversion('signalforge_routing') . "\n";
    echo str_repeat('-', 60) . "\n\n";

    // ========================================================================
    // Benchmark 1: Route Registration
    // ========================================================================
    echo "1. Route Registration Benchmark\n";

    foreach ([100, 500, 1000, 5000] as $routeCount) {
        Router::flush();
        $routes = generateRoutes($routeCount);

        $timer->start();
        foreach ($routes as $route) {
            match ($route['method']) {
                'GET' => Router::get($route['pattern'], $route['handler']),
                'POST' => Router::post($route['pattern'], $route['handler']),
                'PUT' => Router::put($route['pattern'], $route['handler']),
                'PATCH' => Router::patch($route['pattern'], $route['handler']),
                'DELETE' => Router::delete($route['pattern'], $route['handler']),
            };
        }
        $timer->stop();

        printf(
            "   %5d routes: %8.2f ms (%s routes/sec)\n",
            $routeCount,
            $timer->elapsed(),
            number_format($timer->perSecond($routeCount), 0)
        );
    }

    echo "\n";

    // ========================================================================
    // Benchmark 2: Route Matching (Static Routes)
    // ========================================================================
    echo "2. Static Route Matching Benchmark\n";

    Router::flush();

    // Register static routes
    for ($i = 0; $i < 1000; $i++) {
        Router::get("/static/route/{$i}", fn() => $i);
    }

    $iterations = 100000;
    $testUris = [];
    for ($i = 0; $i < $iterations; $i++) {
        $testUris[] = '/static/route/' . ($i % 1000);
    }

    $timer->start();
    foreach ($testUris as $uri) {
        Router::match('GET', $uri);
    }
    $timer->stop();

    printf(
        "   %d iterations: %8.2f ms (%s matches/sec)\n",
        $iterations,
        $timer->elapsed(),
        number_format($timer->perSecond($iterations), 0)
    );

    echo "\n";

    // ========================================================================
    // Benchmark 3: Route Matching (Dynamic Routes)
    // ========================================================================
    echo "3. Dynamic Route Matching Benchmark\n";

    Router::flush();

    // Register dynamic routes
    Router::get('/users/{id}', fn($id) => $id)->whereNumber('id');
    Router::get('/users/{id}/posts/{postId}', fn($id, $postId) => [$id, $postId])
        ->whereNumber(['id', 'postId']);
    Router::get('/categories/{slug}/products/{sku}', fn($slug, $sku) => [$slug, $sku])
        ->whereAlpha('slug')
        ->where('sku', '[A-Z0-9-]+');

    $dynamicUris = [
        '/users/42',
        '/users/123/posts/456',
        '/categories/electronics/products/SKU-001',
    ];

    $iterations = 100000;

    $timer->start();
    for ($i = 0; $i < $iterations; $i++) {
        $uri = $dynamicUris[$i % count($dynamicUris)];
        Router::match('GET', $uri);
    }
    $timer->stop();

    printf(
        "   %d iterations: %8.2f ms (%s matches/sec)\n",
        $iterations,
        $timer->elapsed(),
        number_format($timer->perSecond($iterations), 0)
    );

    echo "\n";

    // ========================================================================
    // Benchmark 4: Deep Nested Routes
    // ========================================================================
    echo "4. Deep Nested Route Matching Benchmark\n";

    Router::flush();

    // Create deeply nested routes
    $depths = [2, 4, 8, 16];

    foreach ($depths as $depth) {
        $pattern = '';
        $params = [];
        for ($i = 0; $i < $depth; $i++) {
            $pattern .= "/level{$i}/{param{$i}}";
            $params["param{$i}"] = 'value' . $i;
        }

        Router::get($pattern, fn() => null);
    }

    $iterations = 50000;

    $timer->start();
    for ($i = 0; $i < $iterations; $i++) {
        // Match the deepest route
        $uri = '';
        for ($j = 0; $j < 16; $j++) {
            $uri .= "/level{$j}/value{$j}";
        }
        Router::match('GET', $uri);
    }
    $timer->stop();

    printf(
        "   Depth 16, %d iterations: %8.2f ms (%s matches/sec)\n",
        $iterations,
        $timer->elapsed(),
        number_format($timer->perSecond($iterations), 0)
    );

    echo "\n";

    // ========================================================================
    // Benchmark 5: URL Generation
    // ========================================================================
    echo "5. URL Generation Benchmark\n";

    Router::flush();

    // Register named routes
    Router::get('/users/{id}', fn($id) => $id)
        ->name('users.show')
        ->whereNumber('id');

    Router::get('/posts/{slug}', fn($slug) => $slug)
        ->name('posts.show')
        ->whereAlpha('slug');

    Router::get('/articles/{year}/{month}/{slug}', fn($y, $m, $s) => [$y, $m, $s])
        ->name('articles.show')
        ->whereNumber(['year', 'month'])
        ->whereAlpha('slug');

    $iterations = 100000;

    $timer->start();
    for ($i = 0; $i < $iterations; $i++) {
        Router::url('users.show', ['id' => 42]);
        Router::url('posts.show', ['slug' => 'hello']);
        Router::url('articles.show', ['year' => 2024, 'month' => 1, 'slug' => 'test']);
    }
    $timer->stop();

    printf(
        "   %d iterations (3 URLs each): %8.2f ms (%s URLs/sec)\n",
        $iterations,
        $timer->elapsed(),
        number_format($timer->perSecond($iterations * 3), 0)
    );

    echo "\n";

    // ========================================================================
    // Benchmark 6: Memory Usage
    // ========================================================================
    echo "6. Memory Usage Analysis\n";

    foreach ([100, 1000, 5000, 10000] as $routeCount) {
        Router::flush();
        gc_collect_cycles();
        $memBefore = memory_get_usage(true);

        $routes = generateRoutes($routeCount);
        foreach ($routes as $route) {
            match ($route['method']) {
                'GET' => Router::get($route['pattern'], $route['handler']),
                'POST' => Router::post($route['pattern'], $route['handler']),
                'PUT' => Router::put($route['pattern'], $route['handler']),
                'PATCH' => Router::patch($route['pattern'], $route['handler']),
                'DELETE' => Router::delete($route['pattern'], $route['handler']),
            };
        }

        $memAfter = memory_get_usage(true);
        $memUsed = $memAfter - $memBefore;
        $perRoute = $memUsed / $routeCount;

        printf(
            "   %5d routes: %8s total, %6s per route\n",
            $routeCount,
            formatBytes($memUsed),
            formatBytes((int)$perRoute)
        );
    }

    echo "\n";

    // ========================================================================
    // Summary
    // ========================================================================
    echo str_repeat('=', 60) . "\n";
    echo "Benchmark Complete\n";
    echo str_repeat('=', 60) . "\n";
}

function formatBytes(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    $factor = 0;
    while ($bytes >= 1024 && $factor < count($units) - 1) {
        $bytes /= 1024;
        $factor++;
    }
    return sprintf("%.1f %s", $bytes, $units[$factor]);
}

// Run benchmarks
runBenchmarks();
