CC = gcc
PREFIX ?= /usr
INCLUDEDIR := $(CURDIR)/build/include
CFLAGS = -O3 -w -std=c11 -Wall -Wextra -DTIMEKEEPING -DTVHASHOPTIMIZED -DOHBF -I$(INCLUDEDIR)
# For benchmarks, disable TVHASHOPTIMIZED to use safer code paths
BENCH_CFLAGS = $(filter-out -DTVHASHOPTIMIZED,$(CFLAGS))
LDFLAGS = -lssl -lcrypto -ltomcrypt -lm -lxxhash

# Use source files instead of prebuilt .o; create a local include dir so root privileges aren't required.
HORS_SRC = hors_example.c src/hors.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
BFTVMHORS_SRC = bftvmhors_example.c src/ohbf.c src/crypto/hash/wyhash/wyhash.c src/bf.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/bftvmhors.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c

HORS_BENCH_SRC = test/hors_time_bench.c src/hors.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
BFTVMHORS_BENCH_SRC = test/bftvmhors_time_bench.c src/ohbf.c src/crypto/hash/wyhash/wyhash.c src/bf.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/bftvmhors.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
TEST_SRC = hash_test.c src/crypto/hash/cityhash/city.o src/crypto/hash/wyhash/wyhash.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c

## Libxxhaash needs to be installed
install:
	if [ ! -d $(PREFIX)/include/bftvmhors/ ]; then \
		mkdir -p $(PREFIX)/include/bftvmhors/; \
	fi
	cp src/*.h $(PREFIX)/include/bftvmhors/
	cp src/utils/*.h $(PREFIX)/include/bftvmhors/

# Prepare local include mirror (no sudo needed)
.PHONY: headers
headers:
	@mkdir -p $(INCLUDEDIR)/bftvmhors
	@cp -u src/*.h $(INCLUDEDIR)/bftvmhors/
	@cp -u src/utils/*.h $(INCLUDEDIR)/bftvmhors/

BFTVMHORS: headers
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(BFTVMHORS_SRC) $(CFLAGS) -o target/bftvmhors $(LDFLAGS)
	cp ./config_sample target/config_bftvmhors


HORS: headers
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(HORS_SRC) $(CFLAGS) -o target/hors $(LDFLAGS)
	cp ./config_sample target/config_hors

.PHONY: HORS_BENCH BFTVMHORS_BENCH
HORS_BENCH: headers
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(HORS_BENCH_SRC) $(BENCH_CFLAGS) -o target/hors_bench $(LDFLAGS)
	cp ./config_sample target/config_hors

BFTVMHORS_BENCH: headers
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(BFTVMHORS_BENCH_SRC) $(BENCH_CFLAGS) -o target/bftvmhors_bench $(LDFLAGS)
	cp ./config_sample target/config_bftvmhors

clean:
	rm -rf ./target ./test
