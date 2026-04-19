# Challenge binaries for ghx smoke testing.
#
# `make build` produces symboled binaries; `make strip` strips them; `make
# install` copies the stripped binaries to /tmp/ for the agent to load.
#
# Flags: -O2 to give the decompiler something non-trivial; -fno-inline so
# function boundaries survive (the agent can exercise function-level ops);
# -g so pre-strip builds carry source debug info for reference.

CC      := gcc
CFLAGS  := -O2 -fno-inline -g -Wall -Wextra -std=c11
LDFLAGS :=

BINS := inventory vm32 authd

.PHONY: all build strip install clean

all: install

build: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

strip: build
	@for bin in $(BINS); do \
		cp -f $$bin $$bin.with-symbols; \
		strip --strip-all $$bin; \
		echo "stripped $$bin ($$(stat -c%s $$bin) bytes)"; \
	done

install: strip
	@for bin in $(BINS); do \
		install -m 0755 $$bin /tmp/$$bin; \
		echo "installed /tmp/$$bin"; \
	done

clean:
	rm -f $(BINS) *.with-symbols
