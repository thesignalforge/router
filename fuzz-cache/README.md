# Signalforge router cache deserializer fuzzer

libFuzzer + ASan + UBSan harness for the SFRC binary cache format
consumed by `sf_router_unserialize()` in `../routing_trie.c`.

## Running locally

```bash
make
make run        # 5-minute run
make run-long   # 1-hour run
```

## What is fuzzed

`cache_deserializer_extracted.c` is a byte-level replica of the
production deserializer: same `sf_buf_read_u8/u16/u32/string` helpers,
same flag-byte walk, same recursion structure and depth limit. It
constructs stripped-down `sf_fuzz_node` / `sf_fuzz_route` structs
(omitting pthread locks, PCRE2 handles, and zend_objects) so ASan
watches every allocation via plain malloc.

## Why not fuzz sf_router_unserialize directly?

The production function builds real `sf_router` / `sf_trie_node` /
`sf_route` instances. Those pull in:

- libsodium (for the SFR1 HMAC verification layer, which we
  deliberately bypass to reach the deserializer)
- PCRE2 (`sf_constraint_set_pattern` compiles the regex on load)
- pthread `rwlock_t` (`sf_router_create` initialises it)
- zend objects + handlers (backrefs to the PHP Router class)

Linking all of that into a fuzz harness would slow exec/sec 10-100x
and require libphp-embed. The extracted byte-parser hits the bugs
we actually care about in a cache format (OOB reads, integer
wraparound, UAF on error paths, stack overflow through the tree
walk) at ~2000-40000 exec/sec.

## Seed corpus

12 hand-written seeds covering:

- Minimal valid 16-byte header with no tries
- Single-route happy path (`/hello` + method=GET)
- Empty input, just-magic, bad magic, bad version
- Truncated string (u16 length claims more than remains)
- Deeply nested static children (150 levels - past `SF_MAX_DESERIALIZE_DEPTH=128`)
- All three param children set on one node
- Overflow-count middleware (`mw_count=5000` exceeds `SF_MAX_MIDDLEWARE_COUNT=1024`)
- Handler type=2 (`[class, method]`)

## Findings on first run

- **Orphaned child on duplicate static-child keys.** When the static
  children loop encounters two siblings with the same segment name,
  the production `zend_hash_add(node->static_children, key, &zv)`
  returns `NULL` (real PHP's `zend_hash_add` does not replace). The
  caller does NOT check the return value, so the second child pointer
  is orphaned. Production installs a `sf_ht_trie_node_dtor` destructor
  on `static_children`, so the first child is freed when the root
  node is destroyed - but the orphan (the one that failed to insert)
  is never in the hash table, and never tracked elsewhere. It leaks.
  The production tag (1.0-rc) is exposed only via authenticated SFR1
  cache files, so an attacker needs the HMAC key; still, fix the
  caller to check the `zend_hash_add` return value and free the child
  on failure. Regression seed: `corpus/seed_020_duplicate_static`
  once added.

## Limitations

- We bypass libsodium's HMAC authentication. In production the SFR1
  gate rejects tampered payloads before they reach the deserializer.
  This fuzzer targets the layer behind the gate, for defense in depth.
- Handler zval reconstruction (`handler_type=1` / `2`) is stubbed to
  release the read strings - we don't build array/ZVAL_STR. To fuzz
  those paths we'd need a zval-capable shim or libphp-embed.
- PCRE2 compilation for `{param:constraint}` patterns is not exercised.

## Current state (last run on this codebase)

- 3570 executions before hitting the duplicate-key leak
- 354 edge-coverage points
- 7 leak allocations (761 bytes) - root cause above
