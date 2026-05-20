CC=clang
BLOCKSIZE=32
CFLAGS=-O3 -march=native -DBLOCKSIZE=$(BLOCKSIZE) -pg
LDLIBS=-lm

default:
	@echo "Usage: make [test_speck|test_hash|test_attack] BLOCKSIZE=[32|48|64]"
	# recursively call make all when calling make alone from the command line
	@$(MAKE) all

all: test_speck test_hash test_attack

test_speck: test_speck.c utils.c

test_hash: test_hash.c utils.c hash.c

test_attack: test_attack.c utils.c hash.c attack.c

# writing inline bash in Makee is actually epic ngl...
clean:
	@for file in test_speck test_hash test_attack; do \
		if [ -f $$file ]; then \
			rm $$file; \
			echo "removed $$file"; \
		else \
			echo "$$file not found, skipping..."; \
		fi \
	done

