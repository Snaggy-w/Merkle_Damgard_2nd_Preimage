CC=clang
BLOCKSIZE=32
CFLAGS=-O3 -march=native -DBLOCKSIZE=$(BLOCKSIZE)
LDLIBS=-lm

default:
	@echo "Usage: make [test_speck|test_hash|test_attack] BLOCKSIZE=[32|48|64]"

all: test_speck test_hash test_attack

test_speck: test_speck.c utils.c

test_hash: test_hash.c utils.c hash.c

test_attack: test_attack.c utils.c hash.c attack.c

clean:
	rm test_speck
