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
Router::get('/articles/{slug}', 'ArticleController@show')
    ->name('articles.show')
    ->whereAlpha('slug');

// ============================================================================
// 2. HTTP Methods
// ============================================================================

Router::post('/users', 'UserController@store');
Router::put('/users/{id}', 'UserController@update');
Router::patch('/users/{id}', 'UserController@patch');
Router::delete('/users/{id}', 'UserController@destroy');
Router::options('/api/resource', fn() => ['GET', 'POST', 'PUT', 'DELETE']);

// Match any HTTP method
Router::any('/webhook', 'WebhookController@handle');

// ============================================================================
// 3. Parameter Constraints
// ============================================================================

// Custom regex constraint
Router::get('/products/{sku}', 'ProductController@show')
    ->where('sku', '[A-Z]{2}-[0-9]{4}');

// Multiple constraints
Router::get('/catalog/{category}/{item}', 'CatalogController@show')
    ->where([
        'category' => '[a-z-]+',
        'item' => '[a-z0-9-]+'
    ]);

// Predefined constraint helpers
Router::get('/orders/{id}', 'OrderController@show')
    ->whereNumber('id');

Router::get('/tags/{tag}', 'TagController@show')
    ->whereAlpha('tag');

Router::get('/search/{query}', 'SearchController@search')
    ->whereAlphaNumeric('query');

Router::get('/resources/{uuid}', 'ResourceController@show')
    ->whereUuid('uuid');

Router::get('/events/{ulid}', 'EventController@show')
    ->whereUlid('ulid');

// Constrain to specific values
Router::get('/status/{status}', 'StatusController@show')
    ->whereIn('status', ['pending', 'active', 'completed', 'cancelled']);

// ============================================================================
// 4. Default Parameter Values
// ============================================================================

Router::get('/search/{query?}', 'SearchController@index')
    ->defaults('query', 'all');

Router::get('/pagination/{page?}/{perPage?}', 'PaginationController@index')
    ->defaults('page', 1)
    ->defaults('perPage', 25);

// ============================================================================
// 5. Middleware
// ============================================================================

// Single middleware
Router::get('/dashboard', 'DashboardController@index')
    ->middleware('auth');

// Multiple middleware
Router::get('/admin', 'AdminController@index')
    ->middleware(['auth', 'admin', 'log']);

// Middleware with parameters (when supported by your middleware resolver)
Router::get('/api/users', 'Api\UserController@index')
    ->middleware('throttle:60,1');

// Remove middleware
Router::get('/public-stats', 'StatsController@public')
    ->middleware(['auth', 'log'])
    ->withoutMiddleware('auth');

// ============================================================================
// 6. Route Groups
// ============================================================================

// Basic group with prefix
Router::group(['prefix' => '/api/v1'], function () {
    Router::get('/users', 'Api\V1\UserController@index');
    Router::get('/posts', 'Api\V1\PostController@index');
    Router::get('/comments', 'Api\V1\CommentController@index');
});

// Group with middleware
Router::group([
    'prefix' => '/admin',
    'middleware' => ['auth', 'admin']
], function () {
    Router::get('/dashboard', 'Admin\DashboardController@index');
    Router::get('/users', 'Admin\UserController@index');
    Router::post('/users', 'Admin\UserController@store');
});

// Group with namespace
Router::group([
    'prefix' => '/api/v2',
    'namespace' => 'App\Http\Controllers\Api\V2'
], function () {
    Router::get('/users', 'UserController@index');
    Router::get('/products', 'ProductController@index');
});

// Group with name prefix
Router::group([
    'prefix' => '/blog',
    'as' => 'blog.'
], function () {
    Router::get('/', 'BlogController@index')->name('index');
    Router::get('/{slug}', 'BlogController@show')->name('show');
    Router::get('/{slug}/comments', 'BlogController@comments')->name('comments');
});

// Nested groups
Router::group(['prefix' => '/api'], function () {
    Router::group(['prefix' => '/v1', 'middleware' => ['api.v1']], function () {
        Router::get('/users', 'Api\V1\UserController@index');
    });

    Router::group(['prefix' => '/v2', 'middleware' => ['api.v2']], function () {
        Router::get('/users', 'Api\V2\UserController@index');
    });
});

// ============================================================================
// 7. Domain/Subdomain Routing
// ============================================================================

// Static domain constraint
Router::get('/dashboard', 'DashboardController@index')
    ->domain('admin.example.com');

// Dynamic subdomain
Router::get('/profile', 'TenantController@profile')
    ->domain('{tenant}.example.com');

// Domain in group
Router::group([
    'domain' => '{account}.myapp.com',
    'prefix' => '/api'
], function () {
    Router::get('/settings', 'Account\SettingsController@index');
    Router::get('/users', 'Account\UserController@index');
});

// ============================================================================
// 8. Wildcard Routes
// ============================================================================

// Catch-all wildcard (captures remaining path)
Router::get('/docs/{path*}', 'DocsController@show');

// Alternative syntax
Router::get('/files/{filepath...}', 'FileController@serve');

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
        Router::get('/status', 'Api\StatusController@index');

        // Authenticated API
        Router::group(['middleware' => ['auth:sanctum']], function () {
            Router::get('/user', 'Api\UserController@current');
            Router::get('/users', 'Api\UserController@index');
            Router::post('/users', 'Api\UserController@store');
            Router::get('/users/{id}', 'Api\UserController@show')
                ->whereNumber('id')
                ->name('api.users.show');
            Router::put('/users/{id}', 'Api\UserController@update')
                ->whereNumber('id');
            Router::delete('/users/{id}', 'Api\UserController@destroy')
                ->whereNumber('id');
        });
    });

    // Web routes
    Router::group(['middleware' => ['web']], function () {
        Router::get('/', 'HomeController@index')->name('home');
        Router::get('/about', 'PageController@about')->name('about');
        Router::get('/contact', 'PageController@contact')->name('contact');
        Router::post('/contact', 'PageController@submitContact');

        // Auth routes
        Router::group(['middleware' => ['guest']], function () {
            Router::get('/login', 'Auth\LoginController@showForm')->name('login');
            Router::post('/login', 'Auth\LoginController@login');
            Router::get('/register', 'Auth\RegisterController@showForm')->name('register');
            Router::post('/register', 'Auth\RegisterController@register');
        });

        // Authenticated routes
        Router::group(['middleware' => ['auth']], function () {
            Router::get('/dashboard', 'DashboardController@index')->name('dashboard');
            Router::post('/logout', 'Auth\LoginController@logout')->name('logout');

            // User settings
            Router::get('/settings', 'SettingsController@index')->name('settings');
            Router::put('/settings', 'SettingsController@update');
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
