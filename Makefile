VERSION ?=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_SYMBOL := github.com/fahedouch/vens/cmd/vens/version.Version

GO ?= go
GO_LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"

.PHONY: all
all: binaries

.PHONY: binaries
binaries: _output/bin/vens

.PHONY: _output/bin/vens
_output/bin/vens:
	$(GO_BUILD) -o $@ ./cmd/vens