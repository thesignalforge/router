# Router Benchmark Results — Complex Multi-Parameter Routes

**Date:** 2026-01-26 23:35:04
**PHP Version:** 8.4.17
**Iterations per test:** 1,000

## Route Complexity

Routes are distributed across 10 tiers with increasing parameter count:

| Tier | Params | Optional | Example Pattern |
|------|--------|----------|-----------------|
| 1 | 1 | No | `/t1rN/items/{id}` |
| 2 | 2 | No | `/t2rN/users/{userId}/posts/{postId}` |
| 3 | 3 | Yes | `/t3rN/users/{userId}/posts/{postId}/comments/{commentId?}` |
| 4 | 4 | No | `/t4rN/orgs/{orgId}/teams/{teamId}/projects/{projectId}/tasks/{taskId}` |
| 5 | 5 | Yes | `/t5rN/.../tasks/{taskId}/sub/{subtaskId?}` |
| 6 | 6 | No | `/t6rN/r/{regionId}/z/{zoneId}/.../v/{versionId}` |
| 7 | 7 | Yes | `/t7rN/a/{p1}/b/{p2}/.../g/{p7?}` |
| 8 | 8 | No | `/t8rN/a/{p1}/b/{p2}/.../h/{p8}` |
| 9 | 9 | Yes | `/t9rN/a/{p1}/b/{p2}/.../i/{p9?}` |
| 10 | 10 | No | `/t10rN/a/{p1}/b/{p2}/.../j/{p10}` |

All parameters have `\d+` (numeric) constraints. Test URIs match with all parameters filled in.

## 10 Routes

| Router | Registration | Matching | Matches/sec | Memory | Hit Rate |
|--------|-------------|----------|-------------|--------|----------|
| Signalforge | 33.86 µs | 3.18 ms | 3,148,404 | 0.00 KB | 100.0% |
| FastRoute | 704.05 µs | 6.34 ms | 1,577,280 | 0.00 KB | 100.0% |
| Symfony | 224.11 µs | 24.98 ms | 400,273 | 0.00 KB | 100.0% |
| Laravel | 2.22 ms | 99.44 ms | 100,567 | 2.00 MB | 100.0% |

## 50 Routes

| Router | Registration | Matching | Matches/sec | Memory | Hit Rate |
|--------|-------------|----------|-------------|--------|----------|
| Signalforge | 164.03 µs | 16.45 ms | 3,039,703 | 0.00 KB | 100.0% |
| FastRoute | 442.03 µs | 36.24 ms | 1,379,805 | 0.00 KB | 100.0% |
| Symfony | 121.12 µs | 241.42 ms | 207,105 | 0.00 KB | 100.0% |
| Laravel | 288.96 µs | 607.92 ms | 82,247 | 0.00 KB | 100.0% |

## 100 Routes

| Router | Registration | Matching | Matches/sec | Memory | Hit Rate |
|--------|-------------|----------|-------------|--------|----------|
| Signalforge | 226.02 µs | 15.39 ms | 3,248,225 | 0.00 KB | 100.0% |
| FastRoute | 694.04 µs | 44.21 ms | 1,130,838 | 0.00 KB | 100.0% |
| Symfony | 207.90 µs | 388.04 ms | 128,851 | 0.00 KB | 100.0% |
| Laravel | 504.97 µs | 765.96 ms | 65,277 | 0.00 KB | 100.0% |

## 500 Routes

| Router | Registration | Matching | Matches/sec | Memory | Hit Rate |
|--------|-------------|----------|-------------|--------|----------|
| Signalforge | 1.47 ms | 8.02 ms | 6,237,625 | 2.00 MB | 100.0% |
| FastRoute | 3.38 ms | 98.04 ms | 509,995 | 2.00 MB | 100.0% |
| Symfony | 997.07 µs | 1.55 s | 32,186 | 0.00 KB | 100.0% |
| Laravel | 2.19 ms | 1.88 s | 26,570 | 0.00 KB | 100.0% |

## 1,000 Routes

| Router | Registration | Matching | Matches/sec | Memory | Hit Rate |
|--------|-------------|----------|-------------|--------|----------|
| Signalforge | 2.42 ms | 7.81 ms | 6,402,931 | 0.00 KB | 100.0% |
| FastRoute | 6.29 ms | 174.45 ms | 286,620 | 2.00 MB | 100.0% |
| Symfony | 2.14 ms | 2.95 s | 16,961 | 0.00 KB | 100.0% |
| Laravel | 4.24 ms | 3.31 s | 15,101 | 0.00 KB | 100.0% |

## Summary

- **10 routes**: Signalforge 31.3x faster than Laravel (3.18 ms vs 99.44 ms)
- **50 routes**: Signalforge 37.0x faster than Laravel (16.45 ms vs 607.92 ms)
- **100 routes**: Signalforge 49.8x faster than Laravel (15.39 ms vs 765.96 ms)
- **500 routes**: Signalforge 234.8x faster than Laravel (8.02 ms vs 1.88 s)
- **1,000 routes**: Signalforge 424.0x faster than Laravel (7.81 ms vs 3.31 s)

## Memory Usage Comparison

| Routes | Signalforge | FastRoute | Symfony | Laravel | SF/FR Ratio |
|--------|-------------|-----------|---------|---------|-------------|
| 10 | 0.00 KB | 0.00 KB | 0.00 KB | 2.00 MB | N/A |
| 50 | 0.00 KB | 0.00 KB | 0.00 KB | 0.00 KB | N/A |
| 100 | 0.00 KB | 0.00 KB | 0.00 KB | 0.00 KB | N/A |
| 500 | 2.00 MB | 2.00 MB | 0.00 KB | 0.00 KB | 100.0% |
| 1,000 | 0.00 KB | 2.00 MB | 0.00 KB | 0.00 KB | N/A |

### Notes

- All routers tested with identical route patterns and matching URIs
- Routes distributed evenly across 10 complexity tiers (1-10 path parameters)
- Tiers 3, 5, 7, 9 include an optional trailing parameter
- All parameters have numeric (`\d+`) constraints
- Test URIs always include all parameters (including optional) for fair matching comparison
- Memory shows router-specific memory delta after route registration
- Hit Rate shows percentage of successful matches out of total attempts
