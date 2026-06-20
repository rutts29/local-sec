GO ?= go
GOCACHE ?= /private/tmp/local-sec-gocache

.PHONY: test build release verify-release clean

test:
	env -u GOROOT GOCACHE=$(GOCACHE) $(GO) test -count=1 ./...

build:
	mkdir -p dist
	env -u GOROOT GOCACHE=$(GOCACHE) $(GO) build -trimpath -o dist/lsec ./cmd/lsec

release:
	env -u GOROOT GOCACHE=$(GOCACHE) sh ./scripts/build-release.sh

verify-release:
	sh ./scripts/verify-release-artifacts.sh

clean:
	rm -rf dist
