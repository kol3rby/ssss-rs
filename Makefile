# Thin wrapper around Cargo, mirroring the original ssss Makefile's targets.
# Cargo (see Cargo.toml) is the real build system; it builds the ssss-split and
# ssss-combine binaries into target/release/. Documentation is generated from
# ssss.manpage.xml, the single source of truth, just like the original build.

CARGO ?= cargo

all: compile doc

compile:
	$(CARGO) build --release

test:
	$(CARGO) test

# Man page + HTML are generated artifacts (gitignored). Mirrors the original's
# `doc:` target, including the graceful fallback when the tools are absent.
doc: ssss.1 ssss.1.html

ssss.1: ssss.manpage.xml
	if [ `which xmltoman` ]; then xmltoman ssss.manpage.xml > ssss.1; else echo "WARNING: xmltoman not found, skipping generation of man page."; fi
	if [ -e ssss.1 ]; then cp ssss.1 ssss-split.1; cp ssss.1 ssss-combine.1; fi

ssss.1.html: ssss.manpage.xml
	if [ `which xmlmantohtml` ]; then xmlmantohtml ssss.manpage.xml > ssss.1.html; else echo "WARNING: xmlmantohtml not found, skipping generation of HTML documentation."; fi

clean:
	$(CARGO) clean
	rm -f ssss.1 ssss-split.1 ssss-combine.1 ssss.1.html

.PHONY: all compile test doc clean
