# Signalforge Routing

Finally, a PHP router that doesn't suck at scale.

I got tired of watching Laravel's router choke on large route tables. The problem? It's regex all the way down. Every request iterates through your entire route collection, compiling and matching patterns until something sticks. With 500+ routes, you start feeling it. With 5000+, it's painful.

So I wrote this. It's a native PHP extension that uses a radix trie instead of regex iteration. Match time is O(k) where k is the path length - completely independent of how many routes you have.

## What's Different

- **Trie-based matching** - routes are stored in a compressed prefix tree, not an array
- **No regex during traversal** - constraints are only checked at terminal nodes
- **Separate trees per HTTP method** - GET requests never touch POST routes
- **Written in C** - because PHP userland has limits

The API mirrors Laravel's router, so you can mostly drop it in without rewriting everything.

## Requirements

- PHP 8.3+
- Linux (tested on x86_64, other archs might work)
- PCRE2 (`apt install libpcre2-dev`)
- PHP dev headers (`apt install php-dev`)

## Building

```bash
phpize
./configure --enable-signalforge-routing
make
make test
sudo make install
```

Then add `extension=signalforge_routing.so` to your php.ini.

## Usage

```php
use Signalforge\Routing\Router;

Router::get('/users/{id}', function ($id) {
    return "User: {$id}";
})->whereNumber('id')->name('users.show');

Router::group(['prefix' => '/api', 'middleware' => ['auth']], function () {
    Router::get('/profile', 'ProfileController@show');
});

// match a request
$result = Router::match('GET', '/users/42');

if ($result->matched()) {
    $handler = $result->getHandler();
    $params = $result->getParams();  // ['id' => '42']
}
```

## How It Works

The trie looks something like this:

```
Root
├── api/
│   └── v1/
│       └── users/
│           └── {id} → handler
├── users/
│   ├── {id}/
│   │   └── posts/
│   │       └── {postId} → handler
│   └── → handler (list)
└── docs/
    └── {path*} → handler (wildcard)
```

When a request comes in for `/api/v1/users/42`:
1. Walk down: `api` → `v1` → `users` → param node
2. Store "42" as the `id` parameter
3. Hit terminal node, check constraints (`[0-9]+`)
4. Return match with handler + params

No iteration. No regex compilation per-route. Just pointer traversal.

## API

Everything you'd expect from Laravel's router:

```php
// methods
Router::get($uri, $handler)
Router::post($uri, $handler)
Router::put($uri, $handler)
Router::patch($uri, $handler)
Router::delete($uri, $handler)
Router::any($uri, $handler)

// groups
Router::group(['prefix' => '/api', 'middleware' => ['auth']], fn() => ...);

// constraints
$route->where('id', '[0-9]+')
$route->whereNumber('id')
$route->whereAlpha('slug')
$route->whereIn('status', ['active', 'pending'])

// optionals and defaults
Router::get('/posts/{page?}', $handler)->defaults('page', 1);

// named routes
Router::get('/users/{id}', $handler)->name('users.show');
$url = Router::url('users.show', ['id' => 42]);  // /users/42

// fallback
Router::fallback(fn() => abort(404));
```

Check `examples/basic_usage.php` for more.

## Performance

Rough numbers on my machine (10k routes registered):

| | Signalforge | Laravel |
|---|---|---|
| Static match | ~0.5μs | ~45μs |
| Dynamic match | ~1.2μs | ~120μs |
| Memory/route | ~800 bytes | ~4KB |

The gap widens as route count increases. Laravel's O(n) vs our O(k).

## Thread Safety

Works with ZTS builds. Each request gets isolated state, and the trie is read-only during request handling. Mutex protection where needed.

## Known Limitations

- Routes should be registered at bootstrap, not runtime
- Linux x86_64 is the primary target
- Needs PCRE2 for constraint matching
- Route caching is basic (works but could be better)

## TODO

Stuff I want to add eventually:
- Shared memory caching (APCu/SHM)
- SIMD for segment matching
- Better serialization format
- More constraint types built-in

## Structure

```
signalforge_routing.c/h   - extension glue, PHP class implementations
routing_trie.c/h          - the actual trie and matching logic
config.m4                 - build config
Signalforge/Routing/*.stub.php - IDE stubs
examples/                 - usage examples
tests/                    - phpt tests
```

## License

MIT

---

Built by signalforger. Not affiliated with Laravel.
