# Cheburbox Makefile.
#
# cheburbox links sing-box-extended as a Go library and validates generated
# configs in-process via box.New(). The binary therefore needs the same
# protocol build tags as a sing-box runtime, otherwise box.New() rejects
# configs that use tagged protocols. The original failure was:
#   "WireGuard is not included in this build, rebuild with -tags with_wireguard"
#
# TAGS below is the protocol/transport subset of the fork's canonical set at
#   https://github.com/shtorm-7/sing-box-extended  (release/DEFAULT_BUILD_TAGS_OTHERS)
# The following tags from that file are INTENTIONALLY EXCLUDED — do not add
# them back without reading this comment:
#
#   with_admin_panel   //go:embed dist needs the fork's pre-built SPA
#                      (npm run build + admin_panel_pack); fails for downstream
#                      consumers. Runtime web UI, irrelevant to box.New().
#   with_manager       manager service + manager_api swagger UI; runtime-only,
#                      not a protocol type registered with box.New().
#   with_ccm           connection-cache service; not a protocol type.
#   with_ocm           outbound-cache service; not a protocol type.
#   badlinkname        //go:linkname against crypto/tls.(*Conn).handlePostHandshakeMessage,
#                      which moved in Go 1.26; kTLS runtime optimization with no
#                      effect on config validation. Fails to link on the toolchain
#                      cheburbox requires (go 1.26.4).
#   tfogo_checklinkname0  companion linkname-relaxation tag for trusttunnel;
#                      trusttunnel builds via its stub path without it.
#
# For full runtime parity, override on the command line (requires the fork's
# SPA build and a Go version compatible with badlinkname):
#   make build TAGS="$(cat ../sing-box-extended/release/DEFAULT_BUILD_TAGS_OTHERS)"
TAGS        ?= with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_masque,with_mtproxy,with_openvpn,with_trusttunnel,with_sudoku,with_snell

# Pure-Go static build: no libc dependency, matches the distroless runtime image.
CGO_ENABLED ?= 0
GOTOOLCHAIN ?= local
LDFLAGS     := -s -w
BINARY      := build/cheburbox
PKG         := ./cmd/cheburbox
IMAGE       ?= cheburbox

.PHONY: all build install run test test-race vet check clean docker print-tags

all: build

# Build the cheburbox binary into ./build/.
build:
	mkdir -p build
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -trimpath -tags '$(TAGS)' -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

# Install to $GOBIN (or $GOPATH/bin), with the same tags as `build`.
install:
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go install -trimpath -tags '$(TAGS)' -ldflags '$(LDFLAGS)' $(PKG)

# Build and run the freshly built binary.
run: build
	./$(BINARY)

# Full test suite with the same tags as the build, so the in-process box.New()
# validation path is exercised. Without these tags, AmneziaWG and Hysteria2
# tests skip with "is not included in this build".
test:
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go test -tags '$(TAGS)' ./...

# Race detector (forces CGO_ENABLED=1).
test-race:
	CGO_ENABLED=1 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go test -race -tags '$(TAGS)' ./...

vet:
	CGO_ENABLED=$(CGO_ENABLED) GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go vet -tags '$(TAGS)' ./...

# golangci-lint; --fix first per AGENTS.md, then report remaining issues.
check:
	golangci-lint run --fix
	golangci-lint run

# Build the container image, passing TAGS through so the image validates the
# same protocols as a local build (the Dockerfile default matches this TAGS).
docker:
	docker build --build-arg TAGS='$(TAGS)' -t $(IMAGE) .

clean:
	rm -rf build

# Echo the resolved tag set — handy for debugging build-vs-runtime mismatch
# and for passing to a bare `go` invocation: go test -tags "$$(make print-tags)".
print-tags:
	@echo '$(TAGS)'
