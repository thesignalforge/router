# Router Benchmark Results

**Date:** 2026-01-13 21:27:17
**PHP Version:** 8.4.16
**Iterations per test:** 1,000

## 1 Routes

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 31.95 µs | 1.02 ms | 6,856,638 | 0.00 KB |
| FastRoute | 648.98 µs | 1.03 ms | 6,769,685 | 0.00 KB |
| Symfony | 235.08 µs | 13.40 ms | 522,199 | 0.00 KB |
| Laravel | 2.09 ms | 62.57 ms | 111,873 | 2.00 MB |

## 10 Routes

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 20.98 µs | 2.84 ms | 5,631,828 | 0.00 KB |
| FastRoute | 97.04 µs | 4.52 ms | 3,536,699 | 0.00 KB |
| Symfony | 26.94 µs | 41.13 ms | 389,048 | 0.00 KB |
| Laravel | 91.79 µs | 148.56 ms | 107,702 | 0.00 KB |

## 100 Routes

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 107.05 µs | 8.56 ms | 6,190,078 | 0.00 KB |
| FastRoute | 385.05 µs | 28.85 ms | 1,836,901 | 0.00 KB |
| Symfony | 137.09 µs | 451.79 ms | 117,311 | 0.00 KB |
| Laravel | 489.95 µs | 820.58 ms | 64,588 | 0.00 KB |

## 1,000 Routes

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 919.82 µs | 9.32 ms | 5,687,264 | 2.00 MB |
| FastRoute | 4.06 ms | 113.70 ms | 466,147 | 0.00 KB |
| Symfony | 1.21 ms | 3.80 s | 13,951 | 0.00 KB |
| Laravel | 3.65 ms | 4.04 s | 13,131 | 0.00 KB |

## 10,000 Routes

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 9.07 ms | 9.47 ms | 5,597,192 | 10.00 MB |
| FastRoute | 31.84 ms | 1.48 s | 35,741 | 10.00 MB |
| Symfony | 13.40 ms | 35.93 s | 1,475 | 4.00 MB |
| Laravel | 38.98 ms | 164.30 s | 322 | 6.00 MB |

## 20,000 Routes

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 17.53 ms | 8.90 ms | 5,956,381 | 8.00 MB |
| FastRoute | 110.38 ms | 3.92 s | 13,528 | 10.00 MB |

## 100,000 Routes (Signalforge Only)

| Router | Registration | Matching | Matches/sec | Memory |
|--------|-------------|----------|-------------|--------|
| Signalforge | 102.01 ms | 8.69 ms | 6,096,706 | 117.00 MB |

## Summary

- **1 routes**: Signalforge wins (Signalforge 61.3x faster than Laravel, uses 0.0% memory of FastRoute)
- **10 routes**: Signalforge wins (Signalforge 52.3x faster than Laravel, uses 0.0% memory of FastRoute)
- **100 routes**: Signalforge wins (Signalforge 95.8x faster than Laravel, uses 0.0% memory of FastRoute)
- **1,000 routes**: Signalforge wins (Signalforge 433.1x faster than Laravel, uses 0.0% memory of FastRoute)
- **10,000 routes**: Signalforge wins (Signalforge 17350.9x faster than Laravel, uses 100.0% memory of FastRoute)
- **20,000 routes**: Signalforge wins (Signalforge 440.3x faster than FastRoute, uses 80.0% memory of FastRoute)
- **100,000 routes**: Signalforge only (8.69 ms matching, 117.00 MB memory)

## Memory Usage Comparison

| Routes | Signalforge | FastRoute | Symfony | Laravel | SF/FR Ratio |
|--------|-------------|-----------|---------|---------|-------------|
| 1 | 0.00 KB | 0.00 KB | 0.00 KB | 2.00 MB | N/A |
| 10 | 0.00 KB | 0.00 KB | 0.00 KB | 0.00 KB | N/A |
| 100 | 0.00 KB | 0.00 KB | 0.00 KB | 0.00 KB | N/A |
| 1,000 | 2.00 MB | 0.00 KB | 0.00 KB | 0.00 KB | N/A |
| 10,000 | 10.00 MB | 10.00 MB | 4.00 MB | 6.00 MB | 100.0% |
| 20,000 | 8.00 MB | 10.00 MB | N/A | N/A |  80.0% |
| 100,000 | 117.00 MB | N/A | N/A | N/A | N/A |

### Notes

- All routers were tested with the same routes and URIs
- Routes include parameter constraints (`{id}` with numeric validation)
- Matching includes both static and parameterized routes
- Memory shows router-specific memory usage (after registration)
- Symfony and Laravel benchmarks skipped for >10,000 routes due to excessive time
- FastRoute benchmarks skipped for >20,000 routes due to excessive time
- 100,000 routes tested only with Signalforge (other routers too slow)
