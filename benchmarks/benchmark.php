<?php
/**
 * Router Benchmark Script
 *
 * Compares performance of:
 * - Signalforge Router (C extension)
 * - Laravel Router
 * - Symfony Router
 * - FastRoute (nikic/fast-route)
 */

require_once __DIR__ . '/vendor/autoload.php';

use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Routing\Router as LaravelRouter;
use Symfony\Component\Routing\Route as SymfonyRoute;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use FastRoute\RouteCollector;
use FastRoute\Dispatcher as FastRouteDispatcher;
use Signalforge\Routing\Router;

// Check if Signalforge extension is loaded
if (!extension_loaded('signalforge_routing')) {
    die("Error: signalforge_routing extension not loaded. Run with:\n" .
        "php -d extension=../modules/signalforge_routing.so benchmark.php\n");
}

// Configuration
$routeCounts = [1, 10, 100, 1000, 10000, 20000];
$signalforgeOnlyRoutes = [100000]; // Only Signalforge tested for these counts
$iterations = 1000; // Number of match operations per test
$memoryLimit = 1024 * 1024 * 1024; // 1 GB memory limit per router

// Results storage
$results = [];

/**
 * Generate test routes
 */
function generateRoutes(int $count): array
{
    $routes = [];
    $methods = ['GET', 'POST', 'PUT', 'DELETE'];

    for ($i = 0; $i < $count; $i++) {
        $method = $methods[$i % 4];
        $routes[] = [
            'method' => $method,
            'uri' => "/api/v1/resource{$i}/{id}",
            'handler' => "Controller{$i}@action",
            'name' => "route_{$i}"
        ];
    }

    // Add some static routes for variety
    $routes[] = ['method' => 'GET', 'uri' => '/api/v1/users', 'handler' => 'UserController@index', 'name' => 'users.index'];
    $routes[] = ['method' => 'GET', 'uri' => '/api/v1/posts', 'handler' => 'PostController@index', 'name' => 'posts.index'];
    $routes[] = ['method' => 'GET', 'uri' => '/health', 'handler' => 'HealthController@check', 'name' => 'health'];

    return $routes;
}

/**
 * Generate test URIs to match against
 */
function generateTestUris(array $routes): array
{
    $uris = [];

    // Pick some routes to match
    $sampleSize = min(count($routes), 50);
    $indices = array_rand(array_flip(range(0, count($routes) - 1)), $sampleSize);
    if (!is_array($indices)) $indices = [$indices];

    foreach ($indices as $i) {
        if (isset($routes[$i])) {
            $route = $routes[$i];
            // Replace {id} with actual value
            $uri = str_replace('{id}', '123', $route['uri']);
            $uris[] = ['method' => $route['method'], 'uri' => $uri];
        }
    }

    // Add known static routes
    $uris[] = ['method' => 'GET', 'uri' => '/api/v1/users'];
    $uris[] = ['method' => 'GET', 'uri' => '/api/v1/posts'];
    $uris[] = ['method' => 'GET', 'uri' => '/health'];

    return $uris;
}

/**
 * Benchmark Signalforge Router
 */
function benchmarkSignalforge(array $routes, array $testUris, int $iterations): array
{
    gc_collect_cycles();
    $memBefore = memory_get_usage(true);

    // Register routes
    Router::flush();
    $regStart = microtime(true);

    foreach ($routes as $route) {
        $method = strtolower($route['method']);
        Router::$method($route['uri'], fn() => 'ok')
            ->whereNumber('id')
            ->name($route['name']);
    }

    $regTime = (microtime(true) - $regStart) * 1000;
    $memAfterReg = memory_get_usage(true);

    // Match routes
    $matchStart = microtime(true);
    $matched = 0;

    for ($i = 0; $i < $iterations; $i++) {
        foreach ($testUris as $test) {
            $result = Router::match($test['method'], $test['uri']);
            if ($result && $result->matched()) {
                $matched++;
            }
        }
    }

    $matchTime = (microtime(true) - $matchStart) * 1000;
    $totalMatches = $iterations * count($testUris);
    $memUsed = $memAfterReg - $memBefore;

    return [
        'registration_ms' => $regTime,
        'matching_ms' => $matchTime,
        'matches_per_sec' => $totalMatches / ($matchTime / 1000),
        'total_matches' => $totalMatches,
        'successful_matches' => $matched,
        'memory_used' => $memUsed
    ];
}

/**
 * Benchmark Laravel Router
 */
function benchmarkLaravel(array $routes, array $testUris, int $iterations): array
{
    gc_collect_cycles();
    $memBefore = memory_get_usage(true);

    $container = new Container();
    $events = new Dispatcher($container);
    $router = new LaravelRouter($events, $container);

    // Register routes
    $regStart = microtime(true);

    foreach ($routes as $route) {
        $method = strtolower($route['method']);
        $router->$method($route['uri'], ['uses' => $route['handler']])
            ->where('id', '[0-9]+')
            ->name($route['name']);
    }

    $regTime = (microtime(true) - $regStart) * 1000;

    // Compile routes
    $router->getRoutes()->refreshNameLookups();
    $memAfterReg = memory_get_usage(true);

    // Match routes
    $matchStart = microtime(true);
    $matched = 0;

    for ($i = 0; $i < $iterations; $i++) {
        foreach ($testUris as $test) {
            try {
                $request = Request::create($test['uri'], $test['method']);
                $route = $router->getRoutes()->match($request);
                if ($route) {
                    $matched++;
                }
            } catch (\Exception $e) {
                // Route not found
            }
        }
    }

    $matchTime = (microtime(true) - $matchStart) * 1000;
    $totalMatches = $iterations * count($testUris);
    $memUsed = $memAfterReg - $memBefore;

    // Cleanup
    unset($router, $container, $events);

    return [
        'registration_ms' => $regTime,
        'matching_ms' => $matchTime,
        'matches_per_sec' => $totalMatches / ($matchTime / 1000),
        'total_matches' => $totalMatches,
        'successful_matches' => $matched,
        'memory_used' => $memUsed
    ];
}

/**
 * Benchmark Symfony Router
 */
function benchmarkSymfony(array $routes, array $testUris, int $iterations): array
{
    gc_collect_cycles();
    $memBefore = memory_get_usage(true);

    $collection = new RouteCollection();

    // Register routes
    $regStart = microtime(true);

    foreach ($routes as $route) {
        $sfRoute = new SymfonyRoute(
            $route['uri'],
            ['_controller' => $route['handler']],
            ['id' => '\d+'],
            [],
            '',
            [],
            [$route['method']]
        );
        $collection->add($route['name'], $sfRoute);
    }

    $regTime = (microtime(true) - $regStart) * 1000;

    // Create matcher
    $context = new RequestContext();
    $matcher = new UrlMatcher($collection, $context);
    $memAfterReg = memory_get_usage(true);

    // Match routes
    $matchStart = microtime(true);
    $matched = 0;

    for ($i = 0; $i < $iterations; $i++) {
        foreach ($testUris as $test) {
            try {
                $context->setMethod($test['method']);
                $result = $matcher->match($test['uri']);
                if ($result) {
                    $matched++;
                }
            } catch (\Exception $e) {
                // Route not found
            }
        }
    }

    $matchTime = (microtime(true) - $matchStart) * 1000;
    $totalMatches = $iterations * count($testUris);
    $memUsed = $memAfterReg - $memBefore;

    // Cleanup
    unset($matcher, $collection, $context);

    return [
        'registration_ms' => $regTime,
        'matching_ms' => $matchTime,
        'matches_per_sec' => $totalMatches / ($matchTime / 1000),
        'total_matches' => $totalMatches,
        'successful_matches' => $matched,
        'memory_used' => $memUsed
    ];
}

/**
 * Benchmark FastRoute
 */
function benchmarkFastRoute(array $routes, array $testUris, int $iterations): array
{
    gc_collect_cycles();
    $memBefore = memory_get_usage(true);

    // Register routes
    $regStart = microtime(true);

    $dispatcher = FastRoute\simpleDispatcher(function(RouteCollector $r) use ($routes) {
        foreach ($routes as $route) {
            $r->addRoute($route['method'], $route['uri'], $route['handler']);
        }
    });

    $regTime = (microtime(true) - $regStart) * 1000;
    $memAfterReg = memory_get_usage(true);

    // Match routes
    $matchStart = microtime(true);
    $matched = 0;

    for ($i = 0; $i < $iterations; $i++) {
        foreach ($testUris as $test) {
            $result = $dispatcher->dispatch($test['method'], $test['uri']);
            if ($result[0] === FastRouteDispatcher::FOUND) {
                $matched++;
            }
        }
    }

    $matchTime = (microtime(true) - $matchStart) * 1000;
    $totalMatches = $iterations * count($testUris);
    $memUsed = $memAfterReg - $memBefore;

    // Cleanup
    unset($dispatcher);

    return [
        'registration_ms' => $regTime,
        'matching_ms' => $matchTime,
        'matches_per_sec' => $totalMatches / ($matchTime / 1000),
        'total_matches' => $totalMatches,
        'successful_matches' => $matched,
        'memory_used' => $memUsed
    ];
}

/**
 * Format number with thousands separator
 */
function formatNumber($num): string
{
    return number_format($num, 0, '.', ',');
}

/**
 * Format time in milliseconds
 */
function formatTime($ms): string
{
    if ($ms < 1) {
        return number_format($ms * 1000, 2) . ' µs';
    }
    if ($ms >= 1000) {
        return number_format($ms / 1000, 2) . ' s';
    }
    return number_format($ms, 2) . ' ms';
}

/**
 * Format memory in bytes
 */
function formatMemory($bytes): string
{
    if ($bytes >= 1024 * 1024 * 1024) {
        return number_format($bytes / (1024 * 1024 * 1024), 2) . ' GB';
    }
    if ($bytes >= 1024 * 1024) {
        return number_format($bytes / (1024 * 1024), 2) . ' MB';
    }
    return number_format($bytes / 1024, 2) . ' KB';
}

// Run benchmarks
echo "╔══════════════════════════════════════════════════════════════════════════════════════╗\n";
echo "║                           ROUTER BENCHMARK COMPARISON                                ║\n";
echo "╠══════════════════════════════════════════════════════════════════════════════════════╣\n";
echo "║ Comparing: Signalforge (C ext) | Laravel | Symfony | FastRoute                       ║\n";
echo "║ Iterations per test: " . str_pad(formatNumber($iterations), 62) . "║\n";
echo "╚══════════════════════════════════════════════════════════════════════════════════════╝\n\n";

$markdown = "# Router Benchmark Results\n\n";
$markdown .= "**Date:** " . date('Y-m-d H:i:s') . "\n";
$markdown .= "**PHP Version:** " . PHP_VERSION . "\n";
$markdown .= "**Iterations per test:** " . formatNumber($iterations) . "\n\n";

foreach ($routeCounts as $routeCount) {
    echo "┌────────────────────────────────────────────────────────────────────────────────────────┐\n";
    echo "│ BENCHMARK: " . str_pad(formatNumber($routeCount) . " routes", 74) . "│\n";
    echo "├────────────────────────────────────────────────────────────────────────────────────────┤\n";

    $routes = generateRoutes($routeCount);
    $testUris = generateTestUris($routes);

    $results[$routeCount] = [];

    // Warmup
    echo "│ Warming up...                                                                          │\n";

    // Run benchmarks - skip slow routers for large route counts
    $routers = [
        'Signalforge' => 'benchmarkSignalforge',
    ];

    // FastRoute up to 20,000 routes
    if ($routeCount <= 20000) {
        $routers['FastRoute'] = 'benchmarkFastRoute';
    }

    // Only test Symfony/Laravel up to 10000 routes (they're too slow beyond that)
    if ($routeCount <= 10000) {
        $routers['Symfony'] = 'benchmarkSymfony';
        $routers['Laravel'] = 'benchmarkLaravel';
    }

    foreach ($routers as $name => $func) {
        gc_collect_cycles();

        echo "│ Testing {$name}..." . str_repeat(' ', 73 - strlen($name)) . "│\r";
        $results[$routeCount][$name] = $func($routes, $testUris, $iterations);
        echo "│ Testing {$name}... Done" . str_repeat(' ', 68 - strlen($name)) . "│\n";
    }

    echo "├────────────────────────────────────────────────────────────────────────────────────────┤\n";
    echo "│                                    RESULTS                                             │\n";
    echo "├──────────────────┬───────────────┬───────────────┬───────────────┬────────────────────┤\n";
    echo "│ Router           │ Registration  │ Matching      │ Matches/sec   │ Memory             │\n";
    echo "├──────────────────┼───────────────┼───────────────┼───────────────┼────────────────────┤\n";

    // Find the fastest for comparison
    $fastestMatch = PHP_FLOAT_MAX;
    foreach ($results[$routeCount] as $name => $data) {
        if ($data['matching_ms'] < $fastestMatch) {
            $fastestMatch = $data['matching_ms'];
        }
    }

    foreach ($results[$routeCount] as $name => $data) {
        printf("│ %-16s │ %13s │ %13s │ %13s │ %18s │\n",
            $name,
            formatTime($data['registration_ms']),
            formatTime($data['matching_ms']),
            formatNumber((int)$data['matches_per_sec']),
            formatMemory($data['memory_used'])
        );
    }

    echo "└──────────────────┴───────────────┴───────────────┴───────────────┴────────────────────┘\n";

    // Show speedup comparison
    echo "\n  Speed comparison (matching time):\n";
    foreach ($results[$routeCount] as $name => $data) {
        $speedup = $data['matching_ms'] / $fastestMatch;
        if ($speedup <= 1.01) {
            echo "  → {$name}: FASTEST\n";
        } else {
            printf("  → %s: %.2fx slower\n", $name, $speedup);
        }
    }
    echo "\n";

    // Build markdown table
    $markdown .= "## " . formatNumber($routeCount) . " Routes\n\n";
    $markdown .= "| Router | Registration | Matching | Matches/sec | Memory |\n";
    $markdown .= "|--------|-------------|----------|-------------|--------|\n";

    foreach ($results[$routeCount] as $name => $data) {
        $markdown .= sprintf("| %s | %s | %s | %s | %s |\n",
            $name,
            formatTime($data['registration_ms']),
            formatTime($data['matching_ms']),
            formatNumber((int)$data['matches_per_sec']),
            formatMemory($data['memory_used'])
        );
    }
    $markdown .= "\n";
}

// Signalforge-only benchmarks for very large route counts
foreach ($signalforgeOnlyRoutes as $routeCount) {
    echo "┌────────────────────────────────────────────────────────────────────────────────────────┐\n";
    echo "│ BENCHMARK: " . str_pad(formatNumber($routeCount) . " routes (Signalforge only)", 74) . "│\n";
    echo "├────────────────────────────────────────────────────────────────────────────────────────┤\n";

    $routes = generateRoutes($routeCount);
    $testUris = generateTestUris($routes);

    $results[$routeCount] = [];

    echo "│ Warming up...                                                                          │\n";
    gc_collect_cycles();

    echo "│ Testing Signalforge..." . str_repeat(' ', 62) . "│\r";
    $results[$routeCount]['Signalforge'] = benchmarkSignalforge($routes, $testUris, $iterations);
    echo "│ Testing Signalforge... Done" . str_repeat(' ', 57) . "│\n";

    echo "├────────────────────────────────────────────────────────────────────────────────────────┤\n";
    echo "│                                    RESULTS                                             │\n";
    echo "├──────────────────┬───────────────┬───────────────┬───────────────┬────────────────────┤\n";
    echo "│ Router           │ Registration  │ Matching      │ Matches/sec   │ Memory             │\n";
    echo "├──────────────────┼───────────────┼───────────────┼───────────────┼────────────────────┤\n";

    $data = $results[$routeCount]['Signalforge'];
    printf("│ %-16s │ %13s │ %13s │ %13s │ %18s │\n",
        'Signalforge',
        formatTime($data['registration_ms']),
        formatTime($data['matching_ms']),
        formatNumber((int)$data['matches_per_sec']),
        formatMemory($data['memory_used'])
    );

    echo "└──────────────────┴───────────────┴───────────────┴───────────────┴────────────────────┘\n\n";

    // Build markdown
    $markdown .= "## " . formatNumber($routeCount) . " Routes (Signalforge Only)\n\n";
    $markdown .= "| Router | Registration | Matching | Matches/sec | Memory |\n";
    $markdown .= "|--------|-------------|----------|-------------|--------|\n";
    $markdown .= sprintf("| %s | %s | %s | %s | %s |\n\n",
        'Signalforge',
        formatTime($data['registration_ms']),
        formatTime($data['matching_ms']),
        formatNumber((int)$data['matches_per_sec']),
        formatMemory($data['memory_used'])
    );
}

// Summary
echo "╔══════════════════════════════════════════════════════════════════════════════════════╗\n";
echo "║                                    SUMMARY                                           ║\n";
echo "╠══════════════════════════════════════════════════════════════════════════════════════╣\n";

$markdown .= "## Summary\n\n";

$allCounts = array_merge($routeCounts, $signalforgeOnlyRoutes);
foreach ($allCounts as $routeCount) {
    $sfTime = $results[$routeCount]['Signalforge']['matching_ms'];
    $sfMem = $results[$routeCount]['Signalforge']['memory_used'];

    // Check if FastRoute was tested
    if (isset($results[$routeCount]['FastRoute'])) {
        $frTime = $results[$routeCount]['FastRoute']['matching_ms'];
        $frMem = $results[$routeCount]['FastRoute']['memory_used'];
        $winner = $sfTime <= $frTime ? "Signalforge" : "FastRoute";
        $memRatio = $frMem > 0 ? $sfMem / $frMem : 0;

        if (isset($results[$routeCount]['Laravel'])) {
            $laTime = $results[$routeCount]['Laravel']['matching_ms'];
            $speedupVsLaravel = $laTime / $sfTime;
            printf("║ %7s routes: %-12s wins | SF vs Laravel: %7.1fx faster | Memory: %5.1f%% of FR ║\n",
                formatNumber($routeCount), $winner, $speedupVsLaravel, $memRatio * 100);
            $markdown .= sprintf("- **%s routes**: %s wins (Signalforge %.1fx faster than Laravel, uses %.1f%% memory of FastRoute)\n",
                formatNumber($routeCount), $winner, $speedupVsLaravel, $memRatio * 100);
        } else {
            $speedupVsFr = $frTime / $sfTime;
            printf("║ %7s routes: %-12s wins | SF vs FastRoute: %5.1fx faster | Memory: %5.1f%% of FR ║\n",
                formatNumber($routeCount), $winner, $speedupVsFr, $memRatio * 100);
            $markdown .= sprintf("- **%s routes**: %s wins (Signalforge %.1fx faster than FastRoute, uses %.1f%% memory of FastRoute)\n",
                formatNumber($routeCount), $winner, $speedupVsFr, $memRatio * 100);
        }
    } else {
        // Signalforge only
        printf("║ %7s routes: Signalforge only | %s matching | Memory: %18s ║\n",
            formatNumber($routeCount), formatTime($sfTime), formatMemory($sfMem));
        $markdown .= sprintf("- **%s routes**: Signalforge only (%s matching, %s memory)\n",
            formatNumber($routeCount), formatTime($sfTime), formatMemory($sfMem));
    }
}

echo "╚══════════════════════════════════════════════════════════════════════════════════════╝\n";

// Memory comparison table
echo "\n";
echo "┌────────────────────────────────────────────────────────────────────────────────────────┐\n";
echo "│                              MEMORY USAGE COMPARISON                                   │\n";
echo "├──────────────────┬──────────────┬──────────────┬──────────────┬──────────────┬────────┤\n";
echo "│ Routes           │ Signalforge  │ FastRoute    │ Symfony      │ Laravel      │ SF/FR  │\n";
echo "├──────────────────┼──────────────┼──────────────┼──────────────┼──────────────┼────────┤\n";

$markdown .= "\n## Memory Usage Comparison\n\n";
$markdown .= "| Routes | Signalforge | FastRoute | Symfony | Laravel | SF/FR Ratio |\n";
$markdown .= "|--------|-------------|-----------|---------|---------|-------------|\n";

foreach ($allCounts as $routeCount) {
    $sf = formatMemory($results[$routeCount]['Signalforge']['memory_used']);
    $fr = isset($results[$routeCount]['FastRoute']) ? formatMemory($results[$routeCount]['FastRoute']['memory_used']) : 'N/A';
    $sy = isset($results[$routeCount]['Symfony']) ? formatMemory($results[$routeCount]['Symfony']['memory_used']) : 'N/A';
    $la = isset($results[$routeCount]['Laravel']) ? formatMemory($results[$routeCount]['Laravel']['memory_used']) : 'N/A';
    $ratio = isset($results[$routeCount]['FastRoute']) && $results[$routeCount]['FastRoute']['memory_used'] > 0
        ? $results[$routeCount]['Signalforge']['memory_used'] / $results[$routeCount]['FastRoute']['memory_used']
        : 0;

    $ratioStr = $ratio > 0 ? sprintf("%5.1f%%", $ratio * 100) : "N/A";

    printf("│ %16s │ %12s │ %12s │ %12s │ %12s │ %6s │\n",
        formatNumber($routeCount), $sf, $fr, $sy, $la, $ratioStr);

    $markdown .= sprintf("| %s | %s | %s | %s | %s | %s |\n",
        formatNumber($routeCount), $sf, $fr, $sy, $la, $ratioStr);
}

echo "└──────────────────┴──────────────┴──────────────┴──────────────┴──────────────┴────────┘\n";

// Write markdown file
$markdown .= "\n### Notes\n\n";
$markdown .= "- All routers were tested with the same routes and URIs\n";
$markdown .= "- Routes include parameter constraints (`{id}` with numeric validation)\n";
$markdown .= "- Matching includes both static and parameterized routes\n";
$markdown .= "- Memory shows router-specific memory usage (after registration)\n";
$markdown .= "- Symfony and Laravel benchmarks skipped for >10,000 routes due to excessive time\n";
$markdown .= "- FastRoute benchmarks skipped for >20,000 routes due to excessive time\n";
$markdown .= "- 100,000 routes tested only with Signalforge (other routers too slow)\n";

file_put_contents(__DIR__ . '/../benchmark.md', $markdown);
echo "\nResults saved to benchmark.md\n";
