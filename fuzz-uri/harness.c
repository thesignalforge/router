/*
 * libFuzzer harness for the Signalforge router URI parser.
 *
 * Target: sf_parse_uri() from routing_trie.c, compiled here as an
 * extracted TU (see uri_parser_extracted.c for the why).
 *
 * Input shape: raw URI bytes, starting with or without a leading slash.
 * The parser tokenizes into segments: static, {param}, {param?},
 * {wildcard*} / {wildcard...}.
 *
 * What we're trying to catch:
 *   - OOB reads when '{' appears without '}' at odd positions
 *   - Underflow on the "ends in '...' so subtract 3" branch
 *     (param_len > 3 check - is it correct for exactly len 3?)
 *   - Memory leaks on error paths
 *   - Very long URIs hitting the SF_MAX_URI_LENGTH guard (8 KiB)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../../fuzz-support/php_stubs.h"

typedef enum {
    SF_NODE_STATIC         = 0,
    SF_NODE_PARAM          = 1,
    SF_NODE_PARAM_OPTIONAL = 2,
    SF_NODE_WILDCARD       = 3,
    SF_NODE_ROOT           = 4
} sf_node_type;

typedef struct _sf_uri_segment {
    zend_string *value;
    sf_node_type type;
    zend_string *param_name;
    zend_bool is_optional;
    struct _sf_uri_segment *next;
} sf_uri_segment;

extern sf_uri_segment *sf_parse_uri(const char *uri, size_t len);
extern void sf_uri_segments_destroy(sf_uri_segment *head);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* 10 KiB ceiling - SF_MAX_URI_LENGTH is 8 KiB so we want to cover
     * inputs just above the limit as well as under it. */
    if (size > 10 * 1024) return 0;

    /* URIs are passed as (ptr, len) so no \0 is required, but copy into
     * a fresh buffer so ASan flags any read past end. */
    char *input = (char *)malloc(size ? size : 1);
    if (!input) return 0;
    if (size) memcpy(input, data, size);

    sf_uri_segment *segs = sf_parse_uri(input, size);

    /* Walk the list to exercise every zend_string pointer, which also
     * mirrors what the trie insertion path does. */
    size_t count = 0;
    for (sf_uri_segment *s = segs; s; s = s->next) {
        if (s->value) {
            volatile size_t tmp = ZSTR_LEN(s->value);
            (void)tmp;
        }
        if (s->param_name) {
            volatile size_t tmp = ZSTR_LEN(s->param_name);
            (void)tmp;
        }
        if (++count > 100000) break;   /* pathological guard */
    }

    sf_uri_segments_destroy(segs);
    free(input);
    return 0;
}
