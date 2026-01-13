<?php
/**
 * Signalforge Routing Extension - Basic Usage Examples
 *
 * This file demonstrates the complete feature set of the Signalforge router.
 */

declare(strict_types=1);

use Signalforge\Routing\Router;
use Signalforge\Routing\Route;
use Signalforge\Routing\MatchResult;

// ============================================================================
// 1. Basic Route Registration
// ============================================================================

// Simple GET route with closure
Router::get('/hello', function () {
    return 'Hello, World!';
});

// Route with required parameter
Router::get('/users/{id}', function (int $id) {
    return "User ID: {$id}";
})->whereNumber('id');

// Route with optional parameter
Router::get('/posts/{slug?}', function (?string $slug = null) {
    return $slug ? "Post: {$slug}" : "All posts";
});

// Route with multiple parameters
Router::get('/users/{userId}/posts/{postId}', function (int $userId, int $postId) {
    return "User {$userId}, Post {$postId}";
})->whereNumber(['userId', 'postId']);

// Named route for URL generation
Router::get('/articles/{slug}', [ArticleController::class, 'show'])
    ->name('articles.show')
    ->whereAlpha('slug');

// ============================================================================
// 2. HTTP Methods
// ============================================================================

Router::post('/users', [UserController::class, 'store']);
Router::put('/users/{id}', [UserController::class, 'update']);
Router::patch('/users/{id}', [UserController::class, 'patch']);
Router::delete('/users/{id}', [UserController::class, 'destroy']);
Router::options('/api/resource', fn() => ['GET', 'POST', 'PUT', 'DELETE']);

// Match any HTTP method
Router::any('/webhook', [WebhookController::class, 'handle']);

// ============================================================================
// 3. Parameter Constraints
// ============================================================================

// Custom regex constraint
Router::get('/products/{sku}', [ProductController::class, 'show'])
    ->where('sku', '[A-Z]{2}-[0-9]{4}');

// Multiple constraints
Router::get('/catalog/{category}/{item}', [CatalogController::class, 'show'])
    ->where([
        'category' => '[a-z-]+',
        'item' => '[a-z0-9-]+'
    ]);

// Predefined constraint helpers
Router::get('/orders/{id}', [OrderController::class, 'show'])
    ->whereNumber('id');

Router::get('/tags/{tag}', [TagController::class, 'show'])
    ->whereAlpha('tag');

Router::get('/search/{query}', [SearchController::class, 'search'])
    ->whereAlphaNumeric('query');

Router::get('/resources/{uuid}', [ResourceController::class, 'show'])
    ->whereUuid('uuid');

Router::get('/events/{ulid}', [EventController::class, 'show'])
    ->whereUlid('ulid');

// Constrain to specific values
Router::get('/status/{status}', [StatusController::class, 'show'])
    ->whereIn('status', ['pending', 'active', 'completed', 'cancelled']);

// ============================================================================
// 4. Default Parameter Values
// ============================================================================

Router::get('/search/{query?}', [SearchController::class, 'index'])
    ->defaults('query', 'all');

Router::get('/pagination/{page?}/{perPage?}', [PaginationController::class, 'index'])
    ->defaults('page', 1)
    ->defaults('perPage', 25);

// ============================================================================
// 5. Middleware
// ============================================================================

// Single middleware
Router::get('/dashboard', [DashboardController::class, 'index'])
    ->middleware('auth');

// Multiple middleware
Router::get('/admin', [AdminController::class, 'index'])
    ->middleware(['auth', 'admin', 'log']);

// Middleware with parameters (when supported by your middleware resolver)
Router::get('/api/users', [Api\UserController::class, 'index'])
    ->middleware('throttle:60,1');

// Remove middleware
Router::get('/public-stats', [StatsController::class, 'public'])
    ->middleware(['auth', 'log'])
    ->withoutMiddleware('auth');

// ============================================================================
// 6. Route Groups
// ============================================================================

// Basic group with prefix
Router::group(['prefix' => '/api/v1'], function () {
    Router::get('/users', [Api\V1\UserController::class, 'index']);
    Router::get('/posts', [Api\V1\PostController::class, 'index']);
    Router::get('/comments', [Api\V1\CommentController::class, 'index']);
});

// Group with middleware
Router::group([
    'prefix' => '/admin',
    'middleware' => ['auth', 'admin']
], function () {
    Router::get('/dashboard', [Admin\DashboardController::class, 'index']);
    Router::get('/users', [Admin\UserController::class, 'index']);
    Router::post('/users', [Admin\UserController::class, 'store']);
});

// Group with name prefix
Router::group([
    'prefix' => '/blog',
    'as' => 'blog.'
], function () {
    Router::get('/', [BlogController::class, 'index'])->name('index');
    Router::get('/{slug}', [BlogController::class, 'show'])->name('show');
    Router::get('/{slug}/comments', [BlogController::class, 'comments'])->name('comments');
});

// Nested groups
Router::group(['prefix' => '/api'], function () {
    Router::group(['prefix' => '/v1', 'middleware' => ['api.v1']], function () {
        Router::get('/users', [Api\V1\UserController::class, 'index']);
    });

    Router::group(['prefix' => '/v2', 'middleware' => ['api.v2']], function () {
        Router::get('/users', [Api\V2\UserController::class, 'index']);
    });
});

// ============================================================================
// 7. Domain/Subdomain Routing
// ============================================================================

// Static domain constraint
Router::get('/dashboard', [DashboardController::class, 'index'])
    ->domain('admin.example.com');

// Dynamic subdomain
Router::get('/profile', [TenantController::class, 'profile'])
    ->domain('{tenant}.example.com');

// Domain in group
Router::group([
    'domain' => '{account}.myapp.com',
    'prefix' => '/api'
], function () {
    Router::get('/settings', [Account\SettingsController::class, 'index']);
    Router::get('/users', [Account\UserController::class, 'index']);
});

// ============================================================================
// 8. Wildcard Routes
// ============================================================================

// Catch-all wildcard (captures remaining path)
Router::get('/docs/{path*}', [DocsController::class, 'show']);

// Alternative syntax
Router::get('/files/{filepath...}', [FileController::class, 'serve']);

// ============================================================================
// 9. Fallback Route
// ============================================================================

Router::fallback(function () {
    return response()->json(['error' => 'Not Found'], 404);
});

// ============================================================================
// 10. Route Matching
// ============================================================================

// Match a request
$result = Router::match('GET', '/users/42');

if ($result->matched()) {
    $handler = $result->getHandler();
    $params = $result->getParams();
    $middleware = $result->getMiddleware();
    $routeName = $result->getRouteName();

    echo "Route matched: {$routeName}\n";
    echo "Parameters: " . json_encode($params) . "\n";
    echo "Middleware: " . json_encode($middleware) . "\n";

    // Get individual parameter
    $userId = $result->param('id');
    $page = $result->param('page', 1); // With default

    // Execute handler (in a real application, you'd use a container/dispatcher)
    if (is_callable($handler)) {
        $response = $handler(...array_values($params));
    }
} else {
    echo "No route matched: " . $result->getError() . "\n";
}

// Match with domain
$result = Router::match('GET', '/profile', 'tenant1.example.com');

// ============================================================================
// 11. URL Generation
// ============================================================================

// Generate URL for named route
$url = Router::url('articles.show', ['slug' => 'hello-world']);
echo "URL: {$url}\n"; // /articles/hello-world

// Check if route exists
if (Router::has('articles.show')) {
    echo "Route exists\n";
}

// ============================================================================
// 12. Route Introspection
// ============================================================================

// Get all registered routes
$routes = Router::getRoutes();

foreach ($routes as $route) {
    echo sprintf(
        "%s %s -> %s [%s]\n",
        implode('|', $route->getMethods()),
        $route->getUri(),
        $route->getName() ?? '(unnamed)',
        implode(', ', $route->getMiddleware())
    );
}

// ============================================================================
// 13. Route Caching
// ============================================================================

// Cache routes to file (for production)
$cachePath = '/tmp/routes.cache';

// Save cache
Router::cache($cachePath);

// In production, load from cache
if (file_exists($cachePath)) {
    Router::loadCache($cachePath);
}

// ============================================================================
// 14. Trailing Slash Handling
// ============================================================================

// Enable strict trailing slash matching
Router::setStrictSlashes(true);

// With strict mode:
// /users  will NOT match /users/
// /users/ will NOT match /users

// Disable for lenient matching (default)
Router::setStrictSlashes(false);

// ============================================================================
// 15. Debugging
// ============================================================================

// Dump trie structure (development only)
if (getenv('APP_DEBUG')) {
    Router::dump();
}

// ============================================================================
// Example: Full Application Bootstrap
// ============================================================================

function bootstrapRouter(): void
{
    // API routes
    Router::group([
        'prefix' => '/api',
        'middleware' => ['api', 'throttle:60,1']
    ], function () {
        // Public API
        Router::get('/status', [Api\StatusController::class, 'index']);

        // Authenticated API
        Router::group(['middleware' => ['auth:sanctum']], function () {
            Router::get('/user', [Api\UserController::class, 'current']);
            Router::get('/users', [Api\UserController::class, 'index']);
            Router::post('/users', [Api\UserController::class, 'store']);
            Router::get('/users/{id}', [Api\UserController::class, 'show'])
                ->whereNumber('id')
                ->name('api.users.show');
            Router::put('/users/{id}', [Api\UserController::class, 'update'])
                ->whereNumber('id');
            Router::delete('/users/{id}', [Api\UserController::class, 'destroy'])
                ->whereNumber('id');
        });
    });

    // Web routes
    Router::group(['middleware' => ['web']], function () {
        Router::get('/', [HomeController::class, 'index'])->name('home');
        Router::get('/about', [PageController::class, 'about'])->name('about');
        Router::get('/contact', [PageController::class, 'contact'])->name('contact');
        Router::post('/contact', [PageController::class, 'submitContact']);

        // Auth routes
        Router::group(['middleware' => ['guest']], function () {
            Router::get('/login', [Auth\LoginController::class, 'showForm'])->name('login');
            Router::post('/login', [Auth\LoginController::class, 'login']);
            Router::get('/register', [Auth\RegisterController::class, 'showForm'])->name('register');
            Router::post('/register', [Auth\RegisterController::class, 'register']);
        });

        // Authenticated routes
        Router::group(['middleware' => ['auth']], function () {
            Router::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
            Router::post('/logout', [Auth\LoginController::class, 'logout'])->name('logout');

            // User settings
            Router::get('/settings', [SettingsController::class, 'index'])->name('settings');
            Router::put('/settings', [SettingsController::class, 'update']);
        });
    });

    // Fallback
    Router::fallback(function () {
        return view('errors.404');
    });
}

// Bootstrap and handle request
bootstrapRouter();

// Simulated request handling
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';

$result = Router::match($method, $uri, $host);

if ($result->matched()) {
    // Dispatch to controller/handler
    // This is where your framework's dispatcher would take over
    echo "Matched route: " . ($result->getRouteName() ?? 'unnamed') . "\n";
    echo "Handler: " . print_r($result->getHandler(), true) . "\n";
    echo "Params: " . json_encode($result->getParams()) . "\n";
} else {
    http_response_code(404);
    echo "404 Not Found\n";
}
