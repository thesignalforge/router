/*
 * URI parser extracted from routing_trie.c for standalone fuzzing.
 *
 * Why extract?
 * ------------
 * routing_trie.c is 3600+ lines and links libsodium, PCRE2, PHP streams,
 * and pthread rwlocks. The URI parser itself is pure-C and touches none
 * of that. Pulling in the whole TU would 10x our build cost and mean
 * stubbing PCRE and libsodium for a byte scanner that doesn't care.
 *
 * This file is a verbatim copy of sf_parse_uri() and
 * sf_uri_segments_destroy() from routing_trie.c @ 2026-04-13. Keep in
 * sync when the upstream implementation changes - the fuzz harness is
 * only useful if it exercises the same code the production extension
 * runs.
 *
 * The node-type constants are small enough to duplicate rather than
 * cross-include.
 */

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

#define SF_MAX_URI_LENGTH 8192

sf_uri_segment *sf_parse_uri(const char *uri, size_t len);
void sf_uri_segments_destroy(sf_uri_segment *head);

/* ---- Begin verbatim copy from routing_trie.c ---- */

sf_uri_segment *sf_parse_uri(const char *uri, size_t len)
{
    sf_uri_segment *head = NULL;
    sf_uri_segment *tail = NULL;
    const char *ptr = uri;
    const char *end = uri + len;

    /* Validate URI length to prevent excessive memory allocation */
    if (len > SF_MAX_URI_LENGTH) {
        php_error_docref(NULL, E_WARNING,
            "Signalforge\\Routing: URI exceeds maximum length of %d bytes", SF_MAX_URI_LENGTH);
        return NULL;
    }

    /* Skip leading slash */
    if (ptr < end && *ptr == '/') {
        ptr++;
    }

    while (ptr < end) {
        const char *seg_start = ptr;
        sf_uri_segment *segment = ecalloc(1, sizeof(sf_uri_segment));

        /* Check for parameter segment */
        if (*ptr == '{') {
            ptr++; /* Skip '{' */
            const char *param_start = ptr;

            /* Find closing brace */
            while (ptr < end && *ptr != '}' && *ptr != '/') {
                ptr++;
            }

            if (ptr >= end || *ptr != '}') {
                php_error_docref(NULL, E_WARNING,
                    "Signalforge\\Routing: Unclosed parameter in URI at position %zu",
                    (size_t)(param_start - uri));
                efree(segment);
                sf_uri_segments_destroy(head);
                return NULL;
            }

            size_t param_len = ptr - param_start;
            ptr++; /* Skip '}' */

            /* Check for optional marker '?' or wildcard '*' / '...' */
            if (param_len > 0 && param_start[param_len - 1] == '?') {
                segment->type = SF_NODE_PARAM_OPTIONAL;
                segment->is_optional = 1;
                param_len--;
            } else if (param_len > 0 && param_start[param_len - 1] == '*') {
                segment->type = SF_NODE_WILDCARD;
                param_len--;
            } else if (param_len > 3 &&
                       param_start[param_len - 3] == '.' &&
                       param_start[param_len - 2] == '.' &&
                       param_start[param_len - 1] == '.') {
                segment->type = SF_NODE_WILDCARD;
                param_len -= 3;
            } else {
                segment->type = SF_NODE_PARAM;
            }

            segment->param_name = zend_string_init(param_start, param_len, 0);
            segment->value = zend_string_init(seg_start, ptr - seg_start, 0);
        } else {
            /* Static segment - find next '/' or end */
            while (ptr < end && *ptr != '/') {
                ptr++;
            }

            segment->value = zend_string_init(seg_start, ptr - seg_start, 0);
        }

        /* Skip trailing slash */
        if (ptr < end && *ptr == '/') {
            ptr++;
        }

        /* Append to list */
        if (!head) {
            head = segment;
            tail = segment;
        } else {
            tail->next = segment;
            tail = segment;
        }
    }

    return head;
}

void sf_uri_segments_destroy(sf_uri_segment *head)
{
    sf_uri_segment *current = head;
    while (current) {
        sf_uri_segment *next = current->next;
        if (current->value) {
            zend_string_release(current->value);
        }
        if (current->param_name) {
            zend_string_release(current->param_name);
        }
        efree(current);
        current = next;
    }
}
