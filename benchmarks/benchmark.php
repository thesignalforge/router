<?php
/**
 * Router Benchmark Script - Complex Multi-Parameter Routes
 *
 * Compares performance of routes with 1-10 path parameters (some optional):
 * - Signalforge Router (C extension)
 * - FastRoute (nikic/fast-route)
 * - Symfony Router
 * - Laravel Router
 *
 * Routes are distributed across 10 complexity tiers:
 *   Tier  1:  1 param   /t1rN/items/{id}
 *   Tier  2:  2 params  /t2rN/users/{userId}/posts/{postId}
 *   Tier  3:  3 params  /t3rN/users/{userId}/posts/{postId}/comments/{commentId?}        (optional)
 *   Tier  4:  4 params  /t4rN/orgs/{orgId}/teams/{teamId}/projects/{projectId}/tasks/{taskId}
 *   Tier  5:  5 params  /t5rN/orgs/{orgId}/teams/{teamId}/.../sub/{subtaskId?}            (optional)
 *   Tier  6:  6 params  /t6rN/r/{regionId}/z/{zoneId}/c/{clusterId}/.../v/{versionId}
 *   Tier  7:  7 params  /t7rN/a/{p1}/b/{p2}/.../g/{p7?}                                  (optional)
 *   Tier  8:  8 params  /t8rN/a/{p1}/b/{p2}/.../h/{p8}
 *   Tier  9:  9 params  /t9rN/a/{p1}/b/{p2}/.../i/{p9?}                                  (optional)
 *   Tier 10: 10 params  /t10rN/a/{p1}/b/{p2}/.../j/{p10}
 *
 * All parameters have numeric (\d+) constraints for fair comparison.
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
$routeCounts = [10, 50, 100, 500, 1000];
$iterations = 1000;

// Results storage
$results = [];

// ============================================================================
// Route Generation
// ============================================================================

/**
 * Build a route specification for a given complexity tier and index.
 *
 * @param int $tier  0-9 (maps to 1-10 parameters)
 * @param int $idx   Unique index within this tier
 * @return array     ['uri' => base URI, 'params' => [[name, optional], ...]]
 */
function buildTierRoute(int $tier, int $idx): array
{
    $prefix = "/t" . ($tier + 1) . "r{$idx}";

    switch ($tier) {
        case 0: // 1 param
            return [
                'uri' => "{$prefix}/items/{id}",
                'params' => [['id', false]],
            ];
        case 1: // 2 params
            return [
                'uri' => "{$prefix}/users/{userId}/posts/{postId}",
                'params' => [['userId', false], ['postId', false]],
            ];
        case 2: // 3 params, last optional
            return [
                'uri' => "{$prefix}/users/{userId}/posts/{postId}/comments/{commentId}",
                'params' => [['userId', false], ['postId', false], ['commentId', true]],
            ];
        case 3: // 4 params
            return [
                'uri' => "{$prefix}/orgs/{orgId}/teams/{teamId}/projects/{projectId}/tasks/{taskId}",
                'params' => [['orgId', false], ['teamId', false], ['projectId', false], ['taskId', false]],
            ];
        case 4: // 5 params, last optional
            return [
                'uri' => "{$prefix}/orgs/{orgId}/teams/{teamId}/projects/{projectId}/tasks/{taskId}/sub/{subtaskId}",
                'params' => [['orgId', false], ['teamId', false], ['projectId', false], ['taskId', false], ['subtaskId', true]],
            ];
        case 5: // 6 params
            return [
                'uri' => "{$prefix}/r/{regionId}/z/{zoneId}/c/{clusterId}/s/{serviceId}/e/{endpointId}/v/{versionId}",
                'params' => [['regionId', false], ['zoneId', false], ['clusterId', false], ['serviceId', false], ['endpointId', false], ['versionId', false]],
            ];
        case 6: // 7 params, last optional
            return [
                'uri' => "{$prefix}/a/{p1}/b/{p2}/c/{p3}/d/{p4}/e/{p5}/f/{p6}/g/{p7}",
                'params' => [['p1', false], ['p2', false], ['p3', false], ['p4', false], ['p5', false], ['p6', false], ['p7', true]],
            ];
        case 7: // 8 params
            return [
                'uri' => "{$prefix}/a/{p1}/b/{p2}/c/{p3}/d/{p4}/e/{p5}/f/{p6}/g/{p7}/h/{p8}",
                'params' => [['p1', false], ['p2', false], ['p3', false], ['p4', false], ['p5', false], ['p6', false], ['p7', false], ['p8', false]],
            ];
        case 8: // 9 params, last optional
            return [
                'uri' => "{$prefix}/a/{p1}/b/{p2}/c/{p3}/d/{p4}/e/{p5}/f/{p6}/g/{p7}/h/{p8}/i/{p9}",
                'params' => [['p1', false], ['p2', false], ['p3', false], ['p4', false], ['p5', false], ['p6', false], ['p7', false], ['p8', false], ['p9', true]],
            ];
        case 9: // 10 params
            return [
                'uri' => "{$prefix}/a/{p1}/b/{p2}/c/{p3}/d/{p4}/e/{p5}/f/{p6}/g/{p7}/h/{p8}/i/{p9}/j/{p10}",
                'params' => [['p1', false], ['p2', false], ['p3', false], ['p4', false], ['p5', false], ['p6', false], ['p7', false], ['p8', false], ['p9', false], ['p10', false]],
            ];
    }
    return [];
}

/**
 * Generate route specifications distributed across 10 complexity tiers.
 */
function generateRoutes(int $count): array
{
    $routes = [];
    $methods = ['GET', 'POST', 'PUT', 'DELETE'];

    for ($i = 0; $i < $count; $i++) {
        $tier = $i % 10;
        $tierIndex = intdiv($i, 10);
        $method = $methods[$i % 4];

        $spec = buildTierRoute($tier, $tierIndex);
        $routes[] = [
            'uri'    => $spec['uri'],
            'params' => $spec['params'],
            'method' => $method,
            'name'   => "route_{$i}",
            'tier'   => $tier + 1,
        ];
    }

    return $routes;
}

// ============================================================================
// URI Conversion Helpers
// ============================================================================

/**
 * Convert base URI to Signalforge/Laravel format (mark optional params with ?).
 */
function toOptionalUri(string $uri, array $params): string
{
    foreach ($params as [$name, $optional]) {
        if ($optional) {
            $uri = str_replace("{{$name}}", "{{$name}?}", $uri);
        }
    }
    return $uri;
}

/**
 * Convert base URI to FastRoute format ({param:\d+} constraints, [...] optional).
 */
function toFastRouteUri(string $uri, array $params): string
{
    $optionalName = null;

    foreach ($params as [$name, $optional]) {
        if ($optional) {
            $optionalName = $name;
            continue;
        }
        $uri = str_replace("{{$name}}", "{{$name}:\\d+}", $uri);
    }

    if ($optionalName === null) {
        return $uri;
    }

    // Split off the trailing optional segment (preceding static + param)
    $placeholder = "{{$optionalName}}";
    $paramPos = strpos($uri, $placeholder);
    $beforeParam = rtrim(substr($uri, 0, $paramPos), '/');
    $lastSlash = strrpos($beforeParam, '/');

    $required = substr($uri, 0, $lastSlash);
    $optionalPart = substr($uri, $lastSlash);
    $optionalPart = str_replace("{{$optionalName}}", "{{$optionalName}:\\d+}", $optionalPart);

    return $required . '[' . $optionalPart . ']';
}

/**
 * Build a concrete test URI by replacing all params with numeric values.
 */
function buildTestUri(string $uri, array $params): string
{
    foreach ($params as $i => [$name, $optional]) {
        $uri = str_replace("{{$name}}", (string)(100 + $i), $uri);
    }
    return $uri;
}

/**
 * Get Symfony requirements array (all params → \d+).
 */
function getSymfonyRequirements(array $params): array
{
    $reqs = [];
    foreach ($params as [$name, $optional]) {
        $reqs[$name] = '\\d+';
    }
    return $reqs;
}

/**
 * Get Symfony defaults array (optional params get empty-string default).
 */
function getSymfonyDefaults(array $params, string $handler): array
{
    $defaults = ['_controller' => $handler];
    foreach ($params as [$name, $optional]) {
        if ($optional) {
            $defaults[$name] = '';
        }
    }
    return $defaults;
}

/**
 * Generate deterministic test URIs from route specs (evenly sampled, up to 50).
 */
function generateTestUris(array $routes): array
{
    $uris = [];
    $sampleSize = min(count($routes), 50);
    $step = max(1, intdiv(count($routes), $sampleSize));

    for ($i = 0; $i < count($routes) && count($uris) < $sampleSize; $i += $step) {
        $route = $routes[$i];
        $uris[] = [
            'method' => $route['method'],
            'uri'    => buildTestUri($route['uri'], $route['params']),
        ];
    }

    return $uris;
}

// ============================================================================
// Benchmark Functions
// ============================================================================

/**
 * Benchmark Signalforge Router
 */
function benchmarkSignalforge(array $routes, array $testUris, int $iterations): array
{
    gc_collect_cycles();
    $memBefore = memory_get_usage(true);

    Router::flush();
    $regStart = microtime(true);

    foreach ($routes as $route) {
        $method = strtolower($route['method']);
        $sfUri = toOptionalUri($route['uri'], $route['params']);
        $paramNames = array_map(fn($p) => $p[0], $route['params']);

        Router::$method($sfUri, fn() => 'ok')
            ->whereNumber($paramNames)
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

    return [
        'registration_ms'    => $regTime,
        'matching_ms'        => $matchTime,
        'matches_per_sec'    => $totalMatches / ($matchTime / 1000),
        'total_matches'      => $totalMatches,
        'successful_matches' => $matched,
        'memory_used'        => $memAfterReg - $memBefore,
    ];
}

/**
 * Benchmark FastRoute
 */
function benchmarkFastRoute(array $routes, array $testUris, int $iterations): array
{
    gc_collect_cycles();
    $memBefore = memory_get_usage(true);

    $regStart = microtime(true);

    $dispatcher = FastRoute\simpleDispatcher(function (RouteCollector $r) use ($routes) {
        foreach ($routes as $route) {
            $frUri = toFastRouteUri($route['uri'], $route['params']);
            $r->addRoute($route['method'], $frUri, $route['name']);
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

    unset($dispatcher);

    return [
        'registration_ms'    => $regTime,
        'matching_ms'        => $matchTime,
        'matches_per_sec'    => $totalMatches / ($matchTime / 1000),
        'total_matches'      => $totalMatches,
        'successful_matches' => $matched,
        'memory_used'        => $memAfterReg - $memBefore,
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
    $regStart = microtime(true);

    foreach ($routes as $route) {
        $sfRoute = new SymfonyRoute(
            $route['uri'],
            getSymfonyDefaults($route['params'], $route['name']),
            getSymfonyRequirements($route['params']),
            [],
            '',
            [],
            [$route['method']]
        );
        $collection->add($route['name'], $sfRoute);
    }

    $regTime = (microtime(true) - $regStart) * 1000;

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

    unset($matcher, $collection, $context);

    return [
        'registration_ms'    => $regTime,
        'matching_ms'        => $matchTime,
        'matches_per_sec'    => $totalMatches / ($matchTime / 1000),
        'total_matches'      => $totalMatches,
        'successful_matches' => $matched,
        'memory_used'        => $memAfterReg - $memBefore,
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

    $regStart = microtime(true);

    foreach ($routes as $route) {
        $method = strtolower($route['method']);
        $laUri = toOptionalUri($route['uri'], $route['params']);

        $constraints = [];
        foreach ($route['params'] as [$name, $optional]) {
            $constraints[$name] = '[0-9]+';
        }

        $router->$method($laUri, ['uses' => 'Controller@action'])
            ->where($constraints)
            ->name($route['name']);
    }

    $regTime = (microtime(true) - $regStart) * 1000;
    $router->getRoutes()->refreshNameLookups();
    $memAfterReg = memory_get_usage(true);

    // Match routes
    $matchStart = microtime(true);
    $matched = 0;

    for ($i = 0; $i < $iterations; $i++) {
        foreach ($testUris as $test) {
            try {
                $request = Request::create($test['uri'], $test['method']);
                $matchedRoute = $router->getRoutes()->match($request);
                if ($matchedRoute) {
                    $matched++;
                }
            } catch (\Exception $e) {
                // Route not found
            }
        }
    }

    $matchTime = (microtime(true) - $matchStart) * 1000;
    $totalMatches = $iterations * count($testUris);

    unset($router, $container, $events);

    return [
        'registration_ms'    => $regTime,
        'matching_ms'        => $matchTime,
        'matches_per_sec'    => $totalMatches / ($matchTime / 1000),
        'total_matches'      => $totalMatches,
        'successful_matches' => $matched,
        'memory_used'        => $memAfterReg - $memBefore,
    ];
}

// ============================================================================
// Formatting Helpers
// ============================================================================

function formatNumber($num): string
{
    return number_format($num, 0, '.', ',');
}

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

// ============================================================================
// Run Benchmarks
// ============================================================================

echo "╔══════════════════════════════════════════════════════════════════════════════════════════════╗\n";
echo "║                      ROUTER BENCHMARK - COMPLEX MULTI-PARAMETER ROUTES                     ║\n";
echo "╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n";
echo "║ Comparing: Signalforge (C ext) | FastRoute | Symfony | Laravel                             ║\n";
echo "║ Route complexity: 1-10 path parameters per route (tiers 3,5,7,9 have optional last param)  ║\n";
echo "║ All parameters have numeric (\\d+) constraints                                              ║\n";
echo "║ Iterations per test: " . str_pad(formatNumber($iterations), 68) . "║\n";
echo "╚══════════════════════════════════════════════════════════════════════════════════════════════╝\n\n";

$markdown = "# Router Benchmark Results — Complex Multi-Parameter Routes\n\n";
$markdown .= "**Date:** " . date('Y-m-d H:i:s') . "\n";
$markdown .= "**PHP Version:** " . PHP_VERSION . "\n";
$markdown .= "**Iterations per test:** " . formatNumber($iterations) . "\n\n";
$markdown .= "## Route Complexity\n\n";
$markdown .= "Routes are distributed across 10 tiers with increasing parameter count:\n\n";
$markdown .= "| Tier | Params | Optional | Example Pattern |\n";
$markdown .= "|------|--------|----------|-----------------|\n";
$markdown .= "| 1 | 1 | No | `/t1rN/items/{id}` |\n";
$markdown .= "| 2 | 2 | No | `/t2rN/users/{userId}/posts/{postId}` |\n";
$markdown .= "| 3 | 3 | Yes | `/t3rN/users/{userId}/posts/{postId}/comments/{commentId?}` |\n";
$markdown .= "| 4 | 4 | No | `/t4rN/orgs/{orgId}/teams/{teamId}/projects/{projectId}/tasks/{taskId}` |\n";
$markdown .= "| 5 | 5 | Yes | `/t5rN/.../tasks/{taskId}/sub/{subtaskId?}` |\n";
$markdown .= "| 6 | 6 | No | `/t6rN/r/{regionId}/z/{zoneId}/.../v/{versionId}` |\n";
$markdown .= "| 7 | 7 | Yes | `/t7rN/a/{p1}/b/{p2}/.../g/{p7?}` |\n";
$markdown .= "| 8 | 8 | No | `/t8rN/a/{p1}/b/{p2}/.../h/{p8}` |\n";
$markdown .= "| 9 | 9 | Yes | `/t9rN/a/{p1}/b/{p2}/.../i/{p9?}` |\n";
$markdown .= "| 10 | 10 | No | `/t10rN/a/{p1}/b/{p2}/.../j/{p10}` |\n\n";
$markdown .= "All parameters have `\\d+` (numeric) constraints. Test URIs match with all parameters filled in.\n\n";

$routers = [
    'Signalforge' => 'benchmarkSignalforge',
    'FastRoute'   => 'benchmarkFastRoute',
    'Symfony'     => 'benchmarkSymfony',
    'Laravel'     => 'benchmarkLaravel',
];

foreach ($routeCounts as $routeCount) {
    echo "┌──────────────────────────────────────────────────────────────────────────────────────────────┐\n";
    echo "│ BENCHMARK: " . str_pad(formatNumber($routeCount) . " routes (distributed across 1-10 param tiers)", 80) . "│\n";
    echo "├──────────────────────────────────────────────────────────────────────────────────────────────┤\n";

    $routes = generateRoutes($routeCount);
    $testUris = generateTestUris($routes);

    $tierCounts = array_count_values(array_column($routes, 'tier'));
    $tierSummary = [];
    for ($t = 1; $t <= 10; $t++) {
        if (isset($tierCounts[$t])) {
            $tierSummary[] = "T{$t}:" . $tierCounts[$t];
        }
    }
    echo "│ Tier distribution: " . str_pad(implode(' ', $tierSummary), 72) . "│\n";
    echo "│ Test URIs: " . str_pad(count($testUris) . " unique URIs × {$iterations} iterations = " . formatNumber(count($testUris) * $iterations) . " matches", 80) . "│\n";
    echo "├──────────────────────────────────────────────────────────────────────────────────────────────┤\n";

    $results[$routeCount] = [];

    foreach ($routers as $name => $func) {
        gc_collect_cycles();

        $label = "│ Testing {$name}...";
        echo str_pad($label, 93) . "│\r";

        $results[$routeCount][$name] = $func($routes, $testUris, $iterations);

        $data = $results[$routeCount][$name];
        $label = "│ Testing {$name}... Done";
        $matchInfo = "({$data['successful_matches']}/{$data['total_matches']} matched)";
        echo str_pad($label, 50) . str_pad($matchInfo, 43) . "│\n";
    }

    echo "├──────────────────────────────────────────────────────────────────────────────────────────────┤\n";
    echo "│                                          RESULTS                                            │\n";
    echo "├──────────────────┬───────────────┬───────────────┬───────────────┬──────────┬───────────────┤\n";
    echo "│ Router           │ Registration  │ Matching      │ Matches/sec   │ Memory   │ Hit Rate      │\n";
    echo "├──────────────────┼───────────────┼───────────────┼───────────────┼──────────┼───────────────┤\n";

    // Find fastest for comparison
    $fastestMatch = PHP_FLOAT_MAX;
    foreach ($results[$routeCount] as $name => $data) {
        if ($data['matching_ms'] < $fastestMatch) {
            $fastestMatch = $data['matching_ms'];
        }
    }

    foreach ($results[$routeCount] as $name => $data) {
        $hitRate = $data['total_matches'] > 0
            ? number_format($data['successful_matches'] / $data['total_matches'] * 100, 1) . '%'
            : 'N/A';

        printf("│ %-16s │ %13s │ %13s │ %13s │ %8s │ %13s │\n",
            $name,
            formatTime($data['registration_ms']),
            formatTime($data['matching_ms']),
            formatNumber((int)$data['matches_per_sec']),
            formatMemory($data['memory_used']),
            $hitRate
        );
    }

    echo "└──────────────────┴───────────────┴───────────────┴───────────────┴──────────┴───────────────┘\n";

    // Speed comparison
    echo "\n  Speed comparison (matching time):\n";
    foreach ($results[$routeCount] as $name => $data) {
        $speedup = $data['matching_ms'] / $fastestMatch;
        if ($speedup <= 1.01) {
            echo "  → {$name}: FASTEST\n";
        } else {
            printf("  → %s: %.1fx slower\n", $name, $speedup);
        }
    }
    echo "\n";

    // Build markdown table
    $markdown .= "## " . formatNumber($routeCount) . " Routes\n\n";
    $markdown .= "| Router | Registration | Matching | Matches/sec | Memory | Hit Rate |\n";
    $markdown .= "|--------|-------------|----------|-------------|--------|----------|\n";

    foreach ($results[$routeCount] as $name => $data) {
        $hitRate = $data['total_matches'] > 0
            ? number_format($data['successful_matches'] / $data['total_matches'] * 100, 1) . '%'
            : 'N/A';

        $markdown .= sprintf("| %s | %s | %s | %s | %s | %s |\n",
            $name,
            formatTime($data['registration_ms']),
            formatTime($data['matching_ms']),
            formatNumber((int)$data['matches_per_sec']),
            formatMemory($data['memory_used']),
            $hitRate
        );
    }
    $markdown .= "\n";
}

// ============================================================================
// Summary
// ============================================================================

echo "╔══════════════════════════════════════════════════════════════════════════════════════════════╗\n";
echo "║                                        SUMMARY                                             ║\n";
echo "╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n";

$markdown .= "## Summary\n\n";

foreach ($routeCounts as $routeCount) {
    $sfTime = $results[$routeCount]['Signalforge']['matching_ms'];

    // Find slowest comparison router
    $slowestName = null;
    $slowestTime = 0;
    foreach (['Laravel', 'Symfony', 'FastRoute'] as $comp) {
        if (isset($results[$routeCount][$comp]) && $results[$routeCount][$comp]['matching_ms'] > $slowestTime) {
            $slowestTime = $results[$routeCount][$comp]['matching_ms'];
            $slowestName = $comp;
        }
    }

    if ($slowestName && $sfTime > 0) {
        $speedup = $slowestTime / $sfTime;
        printf("║ %7s routes: Signalforge %.1fx faster than %-12s │ SF: %13s │ %s: %13s ║\n",
            formatNumber($routeCount),
            $speedup,
            $slowestName,
            formatTime($sfTime),
            str_pad($slowestName, 10),
            formatTime($slowestTime)
        );
        $markdown .= sprintf("- **%s routes**: Signalforge %.1fx faster than %s (%s vs %s)\n",
            formatNumber($routeCount),
            $speedup,
            $slowestName,
            formatTime($sfTime),
            formatTime($slowestTime)
        );
    }
}

echo "╚══════════════════════════════════════════════════════════════════════════════════════════════╝\n";

// Memory comparison
echo "\n";
echo "┌──────────────────────────────────────────────────────────────────────────────────────────────┐\n";
echo "│                                  MEMORY USAGE COMPARISON                                    │\n";
echo "├──────────────────┬──────────────┬──────────────┬──────────────┬──────────────┬──────────────┤\n";
echo "│ Routes           │ Signalforge  │ FastRoute    │ Symfony      │ Laravel      │ SF/FR Ratio  │\n";
echo "├──────────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────┤\n";

$markdown .= "\n## Memory Usage Comparison\n\n";
$markdown .= "| Routes | Signalforge | FastRoute | Symfony | Laravel | SF/FR Ratio |\n";
$markdown .= "|--------|-------------|-----------|---------|---------|-------------|\n";

foreach ($routeCounts as $routeCount) {
    $sf = formatMemory($results[$routeCount]['Signalforge']['memory_used']);
    $fr = isset($results[$routeCount]['FastRoute']) ? formatMemory($results[$routeCount]['FastRoute']['memory_used']) : 'N/A';
    $sy = isset($results[$routeCount]['Symfony']) ? formatMemory($results[$routeCount]['Symfony']['memory_used']) : 'N/A';
    $la = isset($results[$routeCount]['Laravel']) ? formatMemory($results[$routeCount]['Laravel']['memory_used']) : 'N/A';

    $frMem = $results[$routeCount]['FastRoute']['memory_used'] ?? 0;
    $sfMem = $results[$routeCount]['Signalforge']['memory_used'];
    $ratio = $frMem > 0 ? $sfMem / $frMem : 0;
    $ratioStr = $ratio > 0 ? sprintf("%5.1f%%", $ratio * 100) : "N/A";

    printf("│ %16s │ %12s │ %12s │ %12s │ %12s │ %12s │\n",
        formatNumber($routeCount), $sf, $fr, $sy, $la, $ratioStr);

    $markdown .= sprintf("| %s | %s | %s | %s | %s | %s |\n",
        formatNumber($routeCount), $sf, $fr, $sy, $la, $ratioStr);
}

echo "└──────────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘\n";

// Write markdown file
$markdown .= "\n### Notes\n\n";
$markdown .= "- All routers tested with identical route patterns and matching URIs\n";
$markdown .= "- Routes distributed evenly across 10 complexity tiers (1-10 path parameters)\n";
$markdown .= "- Tiers 3, 5, 7, 9 include an optional trailing parameter\n";
$markdown .= "- All parameters have numeric (`\\d+`) constraints\n";
$markdown .= "- Test URIs always include all parameters (including optional) for fair matching comparison\n";
$markdown .= "- Memory shows router-specific memory delta after route registration\n";
$markdown .= "- Hit Rate shows percentage of successful matches out of total attempts\n";

file_put_contents(__DIR__ . '/../benchmark.md', $markdown);
echo "\nResults saved to benchmark.md\n";
