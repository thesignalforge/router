CC      := clang
CFLAGS  := -fsanitize=fuzzer,address,undefined \
           -fno-sanitize-recover=all \
           -fno-omit-frame-pointer \
           -g -O1 -Wall

SRCS    := harness.c cache_deserializer_extracted.c
LDFLAGS := -L/tmp -L/usr/lib/x86_64-linux-gnu
RUN_ARGS := corpus/ -print_final_stats=1 -artifact_prefix=artifacts/

harness: $(SRCS)
	@mkdir -p artifacts
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

run: harness
	./harness $(RUN_ARGS) -max_total_time=300

run-long: harness
	./harness $(RUN_ARGS) -max_total_time=3600

clean:
	rm -f harness
	rm -rf artifacts

.PHONY: run run-long clean
