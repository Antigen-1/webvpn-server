.PHONY: test docs build

test:
	mkdir -p .tmp
	TMPDIR="$(CURDIR)/.tmp" raco test -x tests/

docs:
	raco scribble --htmls --dest doc scribblings/webvpn-server.scrbl

build:
	racket build.rkt
