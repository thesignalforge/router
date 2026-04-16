/*
 * libFuzzer harness for the Signalforge router cache deserializer.
 *
 * Target: a byte-level replica of sf_router_unserialize() - see
 * cache_deserializer_extracted.c for why we fuzz an extracted copy
 * instead of the full routing_trie.c function.
 *
 * Input: raw bytes. The real format expects a 16-byte header starting
 * with "SFRC" magic, but we feed anything - the deserializer must
 * reject malformed input cleanly, not crash.
 *
 * What we want to catch:
 *   - OOB reads from sf_buf_read_* when a length prefix claims more
 *     bytes than remain in the buffer
 *   - Integer wraparound in 'pos + len > buf.len' if pos approaches
 *     SIZE_MAX (unlikely given the 256MB cap, but worth checking)
 *   - UAF if a deserialize error path frees a struct but later code
 *     still holds a pointer
 *   - Stack overflow through deep recursion (guard: SF_MAX_DESERIALIZE_DEPTH)
 *   - Memory leaks on error paths (ASan reports at process exit)
 *
 * Note: because we skipped libsodium authentication, this harness
 * exercises the deserializer as if an attacker HAD valid credentials
 * (or as if the MAC had been bypassed). The production code refuses
 * unauthenticated payloads - that's good - but we want the inner layer
 * to be safe anyway, defense in depth.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern int fuzz_router_unserialize(const char *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 256 * 1024) return 0;

    char *buf = (char *)malloc(size ? size : 1);
    if (!buf) return 0;
    if (size) memcpy(buf, data, size);

    (void)fuzz_router_unserialize(buf, size);

    free(buf);
    return 0;
}
