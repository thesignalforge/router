# Signalforge router URI parser fuzzer

libFuzzer + ASan + UBSan harness for `sf_parse_uri()` from
`../routing_trie.c`.

## Running locally

```bash
make
make run        # 5-minute run
make run-long   # 1-hour run
```

## What is fuzzed

`sf_parse_uri(bytes, len)` tokenises a URI template into a linked list
of `sf_uri_segment` structs. The harness:

1. Copies the fuzzer bytes into a fresh malloc'd buffer (so ASan
   catches reads past end-of-input).
2. Calls `sf_parse_uri(buf, size)`.
3. Walks the segment list, touching every `zend_string` pointer,
   mirroring what the trie-insertion code does next.
4. Calls `sf_uri_segments_destroy()` to catch leak paths.

## Source layout

The production `sf_parse_uri()` lives in `../routing_trie.c`, which
is a 3600-line TU that pulls in libsodium, PCRE2, pthread rwlocks, and
PHP streams. Compiling all of that to fuzz a 90-line byte scanner is
overkill, so `uri_parser_extracted.c` contains a verbatim copy of the
URI parser and its destroy helper. **Keep the copy in sync when
upstream changes** - the banner in that file calls this out.

## Seed corpus

15 hand-picked seeds covering:

- `/`, `/users`, `/users/{id}`, `/users/{id?}`
- Wildcards: `/files/{path*}`, `/files/{path...}`
- Deep nesting: `/api/v1/users/{id}/posts/{post_id}/comments`
- Degenerate: empty, `{` alone, `/{}`, `/{?}`, `/{*}`, `/{...}`, `///`
- Malformed: `/users/{id/name}` (slash inside param)

## Current state (last run on this codebase)

- 8.0M executions in 3 minutes
- 44,461 exec/s
- 0 crashes, 0 leaks, 0 UBSan violations

## Potential extensions

- Fuzz `sf_method_from_string()` for HTTP method parsing
- Extend to the full `sf_trie_match()` matcher by building a small
  pre-populated trie and fuzzing the match input
