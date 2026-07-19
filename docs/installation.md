# Installation

> Get from zero to a working `cheburbox` binary in a couple of minutes.

## Table of Contents

- [Requirements](#requirements)
- [Build from source](#build-from-source)
- [Container image (Docker)](#container-image-docker)
- [Install sing-box](#install-sing-box)
- [Verify the install](#verify-the-install)
- [Next steps](#next-steps)

---

## Requirements

`cheburbox` is a single-binary Go CLI. The only hard requirement is a Go toolchain new enough to build it.

| Component | Version | Notes |
| --- | --- | --- |
| Go toolchain | `1.26.4` or newer | Declared in `go.mod` (`go 1.26.4`). Older toolchains will refuse to build. |
| sing-box binary | not required | sing-box is linked as a Go library; you do **not** need a separate binary on `PATH`. See [Install sing-box](#install-sing-box) below for details. |

### Operating systems

The project is pure Go and uses no platform-specific syscalls outside what the upstream sing-box library already supports. In practice this means any OS that has a working Go 1.26.4 toolchain should work for building. The research data does not enumerate per-OS support tiers — if you hit a build-time issue on a less common platform, that is a sing-box library question, not a cheburbox one.

> **Note:** The project's documented commands assume a POSIX-like shell (Linux, macOS, WSL). Windows users may need to translate path separators in examples.

---

## Build from source

The supported install path. Clone and build with `make`:

### 1. Clone the repository

```shell
$ git clone https://github.com/Arsolitt/cheburbox.git
$ cd cheburbox
```

### 2. Build the binary

```shell
$ make build
```

The binary lands at `build/cheburbox`. To install it on your `PATH` (`$GOBIN` / `$GOPATH/bin`) instead:

```shell
$ make install
$ cheburbox --help
```

> **Why `make`, not `go build`?** `make build` passes the sing-box protocol build tags (`with_wireguard`, `with_utls`, `with_quic`, … — see the `Makefile` header for the full set) that `cheburbox validate` needs to validate WireGuard / AmneziaWG / Hysteria2 configs in-process. A bare `go build ./cmd/cheburbox/` without those tags builds, but silently fails validation for tagged protocols with `"is not included in this build"`.
>
> `go install github.com/Arsolitt/cheburbox/cmd/cheburbox@latest` does not work at all: the `go.mod` carries `replace` directives (redirecting `sing-box` to the [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) fork) that Go rejects for `go install pkg@version`.

> **Note:** The `build/` directory is gitignored — it's the project's local sandbox for binaries and scratch `cheburbox.json` fixtures used in manual testing.

### 3. (Optional) run the tests

```shell
$ make test
```

`make test` uses the same tags as the build, so the in-process `box.New` validation path (AmneziaWG, Hysteria2, …) is exercised rather than skipped.

If you plan to send a patch upstream, also run the linter:

```shell
$ golangci-lint run --fix
```

---

## Container image (Docker)

cheburbox ships as a multi-stage Docker image: the binary is compiled with `CGO_ENABLED=0` (static, no libc dependency) and runs on a distroless `nonroot` base (uid 65532, no shell). The image is a one-shot CLI — you run it with mounted volumes, it does not stay running.

The examples below use `ghcr.io/arsolitt/cheburbox` (GitHub Container Registry). The image name works with any registry — only the prefix changes.

### Build locally

```shell
$ docker build --tag ghcr.io/arsolitt/cheburbox:latest .
```

### Build with version metadata

Stamp the OCI labels (`version`, `revision`, `created`) from git:

```shell
$ docker build \
    --build-arg VERSION="$(git describe --tags --always --dirty)" \
    --build-arg REVISION="$(git rev-parse --short HEAD)" \
    --build-arg CREATED="$(date --utc --iso-8601=seconds)" \
    --tag ghcr.io/arsolitt/cheburbox:latest .
```

### Verify the image

```shell
$ docker run --rm ghcr.io/arsolitt/cheburbox:latest --help
```

### Multi-arch build and push

Build for `linux/amd64` and `linux/arm64` and push in a single step. If you have never used buildx, create a builder once first: `docker buildx create --use`.

```shell
$ docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --build-arg VERSION="$(git describe --tags --always --dirty)" \
    --build-arg REVISION="$(git rev-parse --short HEAD)" \
    --build-arg CREATED="$(date --utc --iso-8601=seconds)" \
    --tag ghcr.io/arsolitt/cheburbox:latest \
    --push .
```

### Push to a registry

Tag a versioned image alongside `:latest`, then log in and push both tags:

```shell
$ docker tag ghcr.io/arsolitt/cheburbox:latest ghcr.io/arsolitt/cheburbox:v0.1.0
$ docker login ghcr.io
$ docker push ghcr.io/arsolitt/cheburbox:latest
$ docker push ghcr.io/arsolitt/cheburbox:v0.1.0
```

### Pin base images by digest (reproducible builds)

The Dockerfile exposes the base images as `ARG`s so they can be pinned to a SHA256 digest for reproducible builds. Resolve the current digest with `docker manifest inspect`:

```shell
$ docker manifest inspect golang:1.26-bookworm --verbose | grep digest | head -1
$ docker manifest inspect gcr.io/distroless/static-debian12:nonroot --verbose | grep digest | head -1
```

Then build with the pinned digests:

```shell
$ docker build \
    --build-arg GO_IMAGE=golang:1.26-bookworm@sha256:<builder-digest> \
    --build-arg RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:<runtime-digest> \
    --tag ghcr.io/arsolitt/cheburbox:latest .
```

### Run the container

Generate configs from the current project directory by mounting it at `/work`:

```shell
$ docker run --rm --volume "$PWD:/work" --workdir /work ghcr.io/arsolitt/cheburbox:latest generate
```

The distroless `nonroot` image runs as uid 65532. To make generated files owned by your own uid instead, override with `--user`:

```shell
$ docker run --rm --user "$(id -u):$(id -g)" --volume "$PWD:/work" --workdir /work ghcr.io/arsolitt/cheburbox:latest generate
```

> **Note:** The image's `ENTRYPOINT` is the `cheburbox` binary itself, so subcommands (`generate`, `validate`, `links`, `rule-set`) go directly after the image name — no `cheburbox` prefix needed.

---

## Install sing-box

**You don't need to.**

`cheburbox` does not shell out to a separate `sing-box` binary at any point. The `cheburbox validate` command performs its sing-box correctness check **in-process**, by linking the [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) fork (module path `github.com/sagernet/sing-box`, redirected via `replace` in `go.mod`) and instantiating a sing-box runtime against your config in memory.

What this means in practice:

- No `sing-box` binary on `PATH`. No version-mismatch headaches between cheburbox's expectations and a system-installed sing-box.
- The sing-box-extended version is pinned by cheburbox's `go.mod` and updated together with cheburbox releases.
- A source build (`make build` / `make install`) gives you everything `cheburbox validate` needs.

If you want to actually serve traffic on your servers, deploy the generated `config.json` to a **sing-box-extended** runtime — the same fork cheburbox builds and validates against. Configs that stick to standard sing-box features also run on upstream sing-box, but fork-specific features (e.g. **AmneziaWG**) require sing-box-extended at runtime. cheburbox's job ends at producing a validated `config.json`; installing and running sing-box-extended on your servers is up to you. See <https://github.com/shtorm-7/sing-box-extended> for the fork.

> **Tip:** See the [validate](./validate.md) page for what cheburbox's in-process check actually verifies — and what it doesn't.

---

## Verify the install

Confirm the binary is on `PATH` and prints help:

```shell
$ cheburbox --help
```

You should see the top-level command summary listing the available subcommands (`generate`, `validate`, `links`, etc.).

That's the only check you need. There is no `sing-box version` step — see [Install sing-box](#install-sing-box) above for why.

---

## Next steps

- [Quick start](./quick-start.md) — write your first `cheburbox.json` and generate a config.
- [Configuration](./configuration.md) — full schema reference for `cheburbox.json`.
- [Validate](./validate.md) — what `cheburbox validate` checks and how to read its output.
