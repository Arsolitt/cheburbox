# Configuration

> Complete reference for the `cheburbox.json` schema. Every field, type, and constraint here is taken directly from the source — author any valid configuration from this page alone.

> **Note:** Generated configs target [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) — the fork cheburbox builds and validates against. The schema uses standard sing-box format; fork-specific features (e.g. **AmneziaWG**) are flagged where they appear. See [Architecture](./architecture.md).

## Table of contents

- [File location](#file-location)
- [Top-level structure](#top-level-structure)
- [Servers](#servers)
- [Inbounds](#inbounds)
  - [VLESS / Reality](#vless--reality)
  - [Multiplex](#multiplex)
  - [Hysteria2](#hysteria2)
  - [TUN](#tun)
  - [AmneziaWG](#amneziawg)
- [Outbounds](#outbounds)
  - [AmneziaWG (cross-server)](#amneziawg-cross-server)
- [Route](#route)
- [DNS](#dns)
- [Persistence](#persistence)
- [Cross-server references](#cross-server-references)
- [Field reference tables](#field-reference-tables)

## File location

A cheburbox project is a directory whose **direct child directories** each contain one of:

- `cheburbox.json` — plain JSON config, or
- `.cheburbox.jsonnet` — Jsonnet source compiled at load time.

`cheburbox` discovers servers by scanning only the **direct children** of the project root. Nested files at depth >1 are not picked up, and a `cheburbox.json` at the root itself is ignored — it must live inside a child directory.

Each child directory becomes a **server**, and the directory name is its identifier (used as the default cross-server `user`, see [cross-server references](#cross-server-references)).

```text
my-project/
├── server-a/
│   └── cheburbox.json
└── server-b/
    └── .cheburbox.jsonnet
```

The CLI selects the project root with `--project <path>`. When both `cheburbox.json` and `.cheburbox.jsonnet` exist in a server directory, **`.cheburbox.jsonnet` takes precedence**. Jsonnet imports are resolved via the `--jsonnet-path` flag (default `lib`), evaluated relative to the project root.

## Top-level structure

Each server's config has the following top-level shape:

```json
{
  "version": 1,
  "endpoint": "vpn.example.com",
  "log": { "level": "info" },
  "dns": { "servers": [ ... ] },
  "inbounds": [ ... ],
  "outbounds": [ ... ],
  "route": { ... },
  "experimental": { "cache_file": { "enabled": true } }
}
```

| Field          | Type              | Required                       | Notes                                                                                         |
| -------------- | ----------------- | ------------------------------ | --------------------------------------------------------------------------------------------- |
| `version`      | `int`             | Yes                            | Must equal `1`. Missing or zero is rejected with `missing or zero version field`.             |
| `endpoint`     | `string`          | Yes if `inbounds` is non-empty | Public IP/hostname. Used as the default address by other servers' outbounds referencing this server. |
| `log`          | `json.RawMessage` | No                             | Passed through to sing-box `log` options unchanged.                                           |
| `dns`          | `DNS`             | Yes                            | Must contain at least one server (`len(dns.servers) > 0`).                                    |
| `inbounds`     | `[]Inbound`       | No                             | Listening services this server exposes.                                                       |
| `outbounds`    | `[]Outbound`      | No                             | Upstream destinations / cross-server clients.                                                 |
| `route`        | `*Route`          | No                             | Routing rules. If omitted, the generated route forces `auto_detect_interface=true`.           |
| `experimental` | `*Experimental`   | No                             | Container for experimental sing-box options (currently only `cache_file`).                    |

### Validation rules at load time

- `version != 1` → `unsupported version N (want 1)` (after the missing-field check).
- `dns.servers` empty → `dns section is required: at least one dns server must be defined`.
- `inbounds` non-empty without `endpoint` → `endpoint is required when inbounds are defined`.
- `listen_port` outside `[0, 65535]` → rejected. `0` is allowed (used by TUN).

Outbound-only servers (no `inbounds`) do **not** need `endpoint`.

## Servers

A "server" in cheburbox is one child directory of the project root containing a config file. It has no dedicated wrapper struct — the `Config` object **is** the server. The directory name carries semantic meaning:

- It is the identifier other servers use in `outbound.server` to reference this one.
- It is the **default `user`** when another server's outbound references this server without specifying `user`.

`config.Discover(projectRoot)` returns the list of child directory names that contain a config file. `config.LoadServerWithJsonnet(dir, jpath)` loads one server's config, choosing Jsonnet over JSON when both exist.

## Inbounds

An inbound is a service this server listens on. Four types are supported, identified by the `type` field:

| `type`      | Purpose                                                          |
| ----------- | ---------------------------------------------------------------- |
| `vless`     | VLESS proxy with TLS or Reality.                                 |
| `hysteria2` | Hysteria2 (QUIC) with optional obfs and masquerade.              |
| `tun`       | OS-level TUN device (typically used on client servers).          |
| `amneziawg` | AmneziaWG (WireGuard + Amnezia 2.0 obfuscation) server endpoint. |

Common inbound fields:

```json
{
  "type": "vless",
  "tag": "vless-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    { "name": "alice", "flow": "xtls-rprx-vision" }
  ],
  "tls": { ... }
}
```

> [!IMPORTANT]
> `users` is an **array of objects**, each with `name` and optional `flow`. Older design-doc examples showed a string array (`["alice"]`) — that form is **not** what the implementation accepts. Always use the object form.

Per-user `flow` is honored when set. When new VLESS user credentials are generated, `flow` defaults to `xtls-rprx-vision`.

### VLESS / Reality

A VLESS inbound carries TLS configuration through the `tls` field. For Reality, populate `tls.reality`:

```json
{
  "type": "vless",
  "tag": "vless-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    { "name": "alice", "flow": "xtls-rprx-vision" }
  ],
  "tls": {
    "server_name": "example.com",
    "reality": {
      "handshake": {
        "server": "www.cloudflare.com",
        "server_port": 443
      },
      "short_id": ["abcdef0123456789"]
    }
  }
}
```

`RealityConfig`:

| Field       | Type                | Required | Notes                                                            |
| ----------- | ------------------- | -------- | ---------------------------------------------------------------- |
| `handshake` | `*RealityHandshake` | Yes      | Real upstream the Reality handshake mimics.                      |
| `short_id`  | `[]string`          | No       | If absent, one 8-byte hex `short_id` is auto-generated.          |

`RealityHandshake.server` and `server_port` are both required when `reality` is set.

The Reality x25519 keypair and `short_id` are **not** in the cheburbox schema. They are generated on first run and persisted in the resulting `config.json`; subsequent runs re-extract them so existing clients keep working. See [Persistence](#persistence).

### Multiplex

A VLESS inbound (server side) or a cross-server VLESS outbound (client side) can enable
sing-box [multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex/) (mux), which bundles several logical streams over a single TCP connection. Cheburbox models both sides:

- **Inbound `multiplex`** — the server accepts whichever mux protocol the client selects, so only `enabled`, `padding`, and `brutal` apply.
- **Outbound `multiplex`** (cross-server VLESS only) — the client selects the `protocol` and the connection/stream limits.

Hysteria2 and TUN ignore `multiplex` (sing-box does not apply mux to them).

VLESS inbound with multiplex:

```json
{
  "type": "vless",
  "tag": "vless-in",
  "listen_port": 443,
  "users": [{"name": "alice"}],
  "tls": {"server_name": "example.com"},
  "multiplex": {"enabled": true, "padding": true}
}
```

Cross-server VLESS outbound with multiplex:

```json
{
  "type": "vless",
  "tag": "to-a",
  "server": "srv-a",
  "inbound": "vless-in",
  "multiplex": {
    "enabled": true,
    "protocol": "smux",
    "max_connections": 4,
    "min_streams": 1,
    "padding": true
  }
}
```

`InboundMultiplex`:

| Field     | Type            | Required | Notes                                         |
| --------- | --------------- | -------- | --------------------------------------------- |
| `enabled` | `bool`          | No       | Turns on server-side mux.                     |
| `padding` | `bool`          | No       | Enables mux padding against traffic analysis. |
| `brutal`  | `*BrutalConfig` | No       | TCP Brutal congestion control. See below.     |

`OutboundMultiplex`:

| Field             | Type            | Required | Notes                                                                                |
| ----------------- | --------------- | -------- | ----------------------------------------------------------------------------------- |
| `enabled`         | `bool`          | No       | Turns on client-side mux.                                                           |
| `protocol`        | `string`        | No       | `h2mux` (default), `smux`, or `yamux`. Other values are rejected at generation time. |
| `max_connections` | `int`           | No       | Max TCP connections the mux pool opens.                                             |
| `min_streams`     | `int`           | No       | Min streams before opening a new connection.                                        |
| `max_streams`     | `int`           | No       | Max streams per connection before a new one opens.                                  |
| `padding`         | `bool`          | No       | Enables mux padding.                                                                |
| `brutal`          | `*BrutalConfig` | No       | TCP Brutal congestion control. See below.                                           |

`BrutalConfig`:

| Field       | Type   | Required | Notes                                                   |
| ----------- | ------ | -------- | ------------------------------------------------------- |
| `enabled`   | `bool` | No       | Enables TCP Brutal CC (requires a Brutal-capable build). |
| `up_mbps`   | `int`  | No       | Upload bandwidth in Mbps.                               |
| `down_mbps` | `int`  | No       | Download bandwidth in Mbps.                             |

For the full field reference, see [Field reference tables](#field-reference-tables).

### Hysteria2

```json
{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": 8443,
  "up_mbps": 100,
  "down_mbps": 500,
  "users": [
    { "name": "alice" }
  ],
  "tls": {
    "server_name": "hy2.example.com"
  },
  "obfs": {
    "type": "salamander",
    "password": ""
  },
  "masquerade": {
    "type": "proxy",
    "url": "https://example.com",
    "rewrite_host": true
  }
}
```

| Field         | Type                | Notes                                                                                       |
| ------------- | ------------------- | ------------------------------------------------------------------------------------------- |
| `up_mbps`     | `int`               | Bandwidth limit (Hysteria2-specific).                                                       |
| `down_mbps`   | `int`               | Bandwidth limit (Hysteria2-specific).                                                       |
| `obfs`        | `*ObfsConfig`       | Salamander obfuscation. If `password` is empty, one is generated and persisted.             |
| `masquerade`  | `*MasqueradeConfig` | HTTP masquerade configuration (`type: "proxy"`).                                            |

`ObfsConfig`:

| Field      | Type     | Allowed values | Notes                                       |
| ---------- | -------- | -------------- | ------------------------------------------- |
| `type`     | `string` | `salamander`   |                                             |
| `password` | `string` | any            | Auto-generated and persisted if left empty. |

`MasqueradeConfig`:

| Field          | Type     | Allowed values | Notes |
| -------------- | -------- | -------------- | ----- |
| `type`         | `string` | `proxy`        |       |
| `url`          | `string` | any            |       |
| `rewrite_host` | `bool`   | any            |       |

Hysteria2 inbounds use a self-signed certificate at `<server>/certs/<server_name>.crt`. The certificate is generated automatically and **two Hysteria2 inbounds on one server cannot share a `tls.server_name`** — they would collide on cert filenames, and validation will reject this.

`tls.alpn` is supported here as a passthrough field. See the field reference tables below.

### TUN

The TUN inbound type exposes OS-level networking. Its fields are largely sing-box-native and are passed through:

| Field                        | Type       | Notes                                  |
| ---------------------------- | ---------- | -------------------------------------- |
| `interface_name`             | `string`   |                                        |
| `address`                    | `[]string` | Parsed as `netip.Prefix`.              |
| `mtu`                        | `int`      |                                        |
| `auto_route`                 | `bool`     |                                        |
| `auto_redirect`              | `bool`     |                                        |
| `strict_route`               | `bool`     |                                        |
| `endpoint_independent_nat`   | `bool`     |                                        |
| `stack`                      | `string`   |                                        |
| `exclude_interface`          | `[]string` |                                        |
| `route_exclude_address`      | `[]string` | Parsed as `netip.Prefix`.              |
| `iproute2_table_index`       | `int`      |                                        |
| `iproute2_rule_index`        | `int`      |                                        |

TUN inbounds usually run with `listen_port: 0` (allowed by validation).

### AmneziaWG

AmneziaWG is WireGuard hardened with the Amnezia 2.0 obfuscation layer — X25519 plus generated Junk/Handshake magic-byte parameters (Jc/Jmin/Jmax/S1-S4/H1-H4) that defeat WireGuard protocol fingerprinting. Cheburbox maps an `amneziawg` inbound onto a **native sing-box `wireguard` endpoint** emitted under the top-level `endpoints[]` array, **not** under `inbounds[]`. The endpoint carries an `amnezia` sub-block; the server holds the persisted X25519 private key and the shared AmneziaWG parameters, and each declared user becomes a peer with its own generated keypair.

sing-box 1.13 (the extended fork base) promoted WireGuard from an inbound/outbound to an `endpoint`, and the fork adds the `amnezia` block for AmneziaWG 2.0 obfuscation. Cheburbox builds the underlying endpoint and persists all key material so peers remain stable across regenerations (see [Persistence](#persistence)).

```json
{
  "type": "amneziawg",
  "tag": "awg-in",
  "listen_port": 51820,
  "address": ["10.7.0.1/24"],
  "mtu": 1280,
  "amnezia": { "preset": "mobile-aggressive", "protocol": "dns", "mtu": 1280 }
}
```

| Field         | Type             | Required | Notes                                                                                          |
| ------------- | ---------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `tag`         | `string`         | Yes      | Inbound identifier; referenced by cross-server outbounds.                                      |
| `listen_port` | `int`            | Yes      | UDP port the WireGuard endpoint binds.                                                         |
| `address`     | `[]string`       | Yes      | Exactly one CIDR — the tunnel subnet for this server (e.g. `["10.7.0.1/24"]`).                 |
| `mtu`         | `int`            | No       | WireGuard interface MTU. Defaults to `1280`.                                                    |
| `amnezia`     | `*AmneziaConfig` | No       | User-facing obfuscation preferences (`protocol`, `preset`, `mtu`); raw Jc/S1/H1 params are generated.    |
| `users`       | `[]InboundUser`  | No       | Client peers. Each `{name}` becomes a peer with its own keypair; cross-server outbounds provision additional peers. |

Each declared user is provisioned as a WireGuard peer on the server endpoint. The server's `amnezia` block carries the shared obfuscation parameters (Jc/Jmin/Jmax/S1-S4/H1-H4); the client-only I1-I5 parameters are generated on each client endpoint — see [AmneziaWG (cross-server)](#amneziawg-cross-server).

### AmneziaConfig

User-facing AmneziaWG preferences. Only `protocol`, `preset`, and `mtu` are set in `cheburbox.json`; the raw obfuscation parameters (Jc/Jmin/Jmax/S1-S4/H1-H4 on the server, plus client-only I1-I5) are produced by the bundled `amnezigo` library and persisted in `config.json` so they stay stable across runs.

| Field      | Type     | Default   | Notes                                                                                       |
| ---------- | -------- | --------- | ------------------------------------------------------------------------------------------- |
| `protocol` | `string` | `quic`    | I1-I5 transport-fingerprint template. One of `quic`, `dns`, `dtls`, `stun`, `sip`, `rtp`, `random`. `random` picks one of the six templates per client. |
| `preset`   | `string` | _(empty)_ | Named bundle of shared params (Jc/Jmin/Jmax/S1-S4/H1-H4) tuned for a network profile. Empty → fully random params per server (the default). One of the preset names below. |
| `mtu`      | `int`    | `1280`    | Transport MTU. Overrides the inbound-level `mtu` when set.                                  |

#### Protocols

The `protocol` field selects which real-world protocol AmneziaWG's I1-I5 client packets mimic in size and byte-pattern. Each client generates its own I1-I5 from the template; the server carries no I1-I5.

| Value    | Mimics                                  | When to choose                                                                 |
| -------- | --------------------------------------- | ------------------------------------------------------------------------------ |
| `quic`   | QUIC initial packets (RFC 9000).        | Default. Blends with HTTP/3 and QUIC-bearing services.                        |
| `dns`    | DNS-over-UDP query/response.            | Networks where DNS is whitelisted; small-packet profiles.                     |
| `dtls`   | DTLS 1.2 records (RFC 6347).            | VPN-adjacent camouflage; pairs well with `low-overhead`.                      |
| `stun`   | STUN binding requests (RFC 5389).       | WebRTC/voice infrastructure where STUN is ubiquitous.                         |
| `sip`    | SIP signalling (RFC 3261, ASCII).       | VoIP gateways; distinct text byte-length distribution.                        |
| `rtp`    | RTP media packets (RFC 3550).           | DPI that whitelists voice/video; per-packet timestamp semantics.              |
| `random` | Random selection from the six templates | Fleet diversity — every client gets a different fingerprint.                  |

#### Presets

The `preset` field fixes the shared server-side parameters to a curated bundle. When omitted, cheburbox generates a fully random valid bundle for each server (recommended for most deployments — it maximises per-server uniqueness). Use a preset when you want a specific throughput/stealth trade-off or need reproducible parameter shapes.

Padded handshake sizes (S1+148, S2+92, S3+64, S4+32) and junk ranges are pre-validated by amnezigo to be collision-free and pass `ValidatePacketSizes`.

| Preset              | MTU  | Profile                                                                                            | Best for                                                                 |
| ------------------- | ---- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `lan-conservative`  | 1280 | Small S values, narrow junk range, low overhead.                                                   | Corporate LANs with minimal DPI.                                        |
| `home-balanced`     | 1280 | Moderate S values and junk range.                                                                  | Home internet; the closest equivalent to the random default.            |
| `mobile-aggressive` | 1280 | Large S values, wide junk range, high junk count. Maximum entropy.                                 | Carrier networks with heavy DPI (MTS, Beeline, etc.).                   |
| `stealth-paranoid`  | 1280 | Maximum steady-state masking; large S4 pads every transport packet. ~3% per-packet overhead.       | Hostile DPI — national firewalls, deep statistical inspection.          |
| `standard-1420`     | 1420 | Same masking as `home-balanced` at WireGuard's classic MTU 1420, with more I-packet headroom.       | Links that tolerate 1420 MTU (note: S4+MTU exceeds IPv6 Ethernet by 16 B). |
| `low-overhead`      | 1280 | Minimal overhead; S4 at the AWG floor, low junk count.                                             | Satellite, metered, slow cellular. Trades masking for throughput.       |
| `test-minimal`      | 1280 | Smallest valid parameter set. **Not for production.**                                              | CI and integration tests only.                                          |

> The client (`amneziawg` outbound) inherits shared params from its target server — never set `preset` or `protocol` on an outbound, only on the inbound.

## Outbounds

An outbound is a destination this server can route traffic to. Six types are supported:

| `type`      | Purpose                                                                        |
| ----------- | ------------------------------------------------------------------------------ |
| `direct`    | Direct connection (no proxy).                                                  |
| `vless`     | VLESS client targeting another server's VLESS inbound.                         |
| `hysteria2` | Hysteria2 client targeting another server's Hysteria2 inbound.                 |
| `amneziawg` | AmneziaWG client targeting another server's amneziawg inbound.                 |
| `urltest`   | Group: pick the fastest member by latency probe.                               |
| `selector`  | Group: manually select one of several members.                                 |

For `vless`, `hysteria2`, and `amneziawg`, cheburbox builds a cross-server reference using the `server` and `inbound` fields:

```json
{
  "type": "vless",
  "tag": "to-server-a",
  "server": "server-a",
  "inbound": "vless-in"
}
```

`server` is the target server's directory name; `inbound` is the target inbound's `tag` on that server.

| Field                         | Type       | Used by              | Notes                                                                                         |
| ----------------------------- | ---------- | -------------------- | --------------------------------------------------------------------------------------------- |
| `tag`                         | `string`   | all                  | Required.                                                                                     |
| `server`                      | `string`   | vless / hysteria2 / amneziawg | Target server directory name.                                                                 |
| `inbound`                     | `string`   | vless / hysteria2 / amneziawg | Target inbound `tag` on the target server.                                                    |
| `user`                        | `string`   | vless / hysteria2 / amneziawg | Defaults to **this** server's directory name when omitted.                                    |
| `flow`                        | `string`   | vless                | Honored when set; the generated cross-server outbound otherwise mirrors the target user's flow. |
| `endpoint`                    | `string`   | vless / hysteria2    | Overrides the target server's `endpoint` field.                                               |
| `domain_resolver`             | `string`   | vless / hysteria2    | DNS server tag used to resolve the outbound's hostname.                                       |
| `multiplex`                    | `*OutboundMultiplex` | vless                | Sing-box [multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex/) (mux). See [Multiplex](#multiplex). |
| `outbounds`                   | `[]string` | urltest / selector   | Member outbound tags. **Intra-server only** — cross-server tags are not supported in groups.  |
| `url`                         | `string`   | urltest              | Probe URL.                                                                                    |
| `interval`                    | `string`   | urltest              | Go duration (e.g. `3m`).                                                                      |
| `tolerance`                   | `uint16`   | urltest              |                                                                                               |
| `idle_timeout`                | `string`   | urltest              | Go duration.                                                                                  |
| `interrupt_exist_connections` | `bool`     | urltest              |                                                                                               |

Generated VLESS cross-server outbounds use UTLS fingerprint `firefox` (share links use `chrome` — see [`./links.md`](./links.md)). For Hysteria2, when persistent state holds an obfs password, the generated outbound's obfs `type` is hardcoded to `salamander`.

### AmneziaWG (cross-server)

An `amneziawg` outbound is a client WireGuard endpoint that tunnels traffic to another server's `amneziawg` inbound. Like VLESS and Hysteria2, it uses the `server` + `inbound` cross-server reference model: cheburbox auto-registers a peer on the target server's endpoint and reuses persisted credentials. The client **owns** its X25519 keypair (persisted in its own `config.json`), derives its public key, and registers that public key as a peer on the target server's endpoint.

The client inherits the server's shared AmneziaWG parameters (Jc/Jmin/Jmax/S1-S4/H1-H4) and generates its own client-only I1-I5. Its single peer points at the server — server public key, server `endpoint` address:port, and `allowed_ips: ["0.0.0.0/0", "::/0"]`.

```json
{
  "type": "amneziawg",
  "tag": "awg-out",
  "server": "awg-server",
  "inbound": "awg-in",
  "address": ["10.7.0.2/32"],
  "mtu": 1280
}
```

| Field     | Type       | Required | Notes                                                                                                              |
| --------- | ---------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `tag`     | `string`   | Yes      | Outbound identifier.                                                                                               |
| `server`  | `string`   | Yes      | Target server directory name (the `amneziawg` server).                                                             |
| `inbound` | `string`   | Yes      | Target server's `amneziawg` inbound `tag`.                                                                         |
| `user`    | `string`   | No       | Peer name on the target. Defaults to **this** server's directory name (see [cross-server references](#cross-server-references)). |
| `address` | `[]string` | Yes      | Exactly one CIDR — this client's tunnel IP within the server's subnet (e.g. `["10.7.0.2/32"]`).                   |
| `mtu`     | `int`      | No       | WireGuard interface MTU. Defaults to `1280`.                                                                       |

The client endpoint registers its public key on the target server's peer list — cross-server provisioning that mirrors the VLESS user-provisioning flow. See [Persistence](#persistence) for key stability.

## Route

```json
{
  "route": {
    "final": "out-direct",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-local",
    "rules": [ { "ip_is_private": true, "outbound": "out-direct" } ],
    "rule_sets": [ { "tag": "geosite-cn", "type": "remote", "format": "binary", "url": "..." } ],
    "custom_rule_sets": ["my-blocklist"]
  }
}
```

| Field                     | Type              | Notes                                                                                                            |
| ------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| `final`                   | `string`          | Default outbound tag when no rule matches.                                                                       |
| `auto_detect_interface`   | `bool`            |                                                                                                                  |
| `default_domain_resolver` | `string`          |                                                                                                                  |
| `rules`                   | `json.RawMessage` | Passed through verbatim to sing-box (cheburbox does not validate rule content).                                  |
| `rule_sets`               | `json.RawMessage` | Remote and other rule-set declarations passed through. See [`./rule-set.md`](./rule-set.md).                     |
| `custom_rule_sets`        | `[]string`        | Names of local JSON rule-set files in the server directory. Each is compiled to `rule-set/<name>.srs` and registered as type `local`. |

If `route` is omitted entirely, the generated route forces `auto_detect_interface=true`. When `route` is present, your value is preserved as-is — no override.

## DNS

`DNS` is required and must contain at least one server.

```json
{
  "dns": {
    "servers": [
      { "type": "udp", "tag": "dns-google", "server": "8.8.8.8", "server_port": 53, "detour": "out-direct" },
      { "type": "local", "tag": "dns-local" }
    ],
    "final": "dns-google",
    "strategy": "prefer_ipv4",
    "cache_capacity": 1024,
    "rules": []
  }
}
```

`DNS`:

| Field            | Type              | Notes                                                                                                                                                  |
| ---------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `servers`        | `[]DNSServer`     | Required, must be non-empty.                                                                                                                           |
| `final`          | `*string`         | Default DNS server tag if no rule matches.                                                                                                             |
| `strategy`       | `*string`         | One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`, `as_is`, or `""`.                                                                       |
| `cache_capacity` | `*uint32`         |                                                                                                                                                        |
| `rules`          | `json.RawMessage` | Passed through to sing-box DNS rules (cheburbox does not validate content).                                                                            |

`DNSServer`:

| Field         | Type     | Required                              | Notes                                                                          |
| ------------- | -------- | ------------------------------------- | ------------------------------------------------------------------------------ |
| `type`        | `string` | Yes                                   | One of `local`, `udp`, `tcp`, `tls`, `quic`, `https`, `http3`, `dhcp`, `fakeip`. |
| `tag`         | `string` | Yes                                   |                                                                                |
| `server`      | `string` | De facto for `udp`/`tcp`/`tls`/`quic`/`https`/`http3` | DNS server hostname/IP. Required by sing-box at runtime, not enforced by cheburbox. |
| `server_port` | `int`    | No                                    |                                                                                |
| `detour`      | `string` | No                                    | Outbound tag used to reach this DNS server.                                    |

## Persistence

Cheburbox persists generated secrets to each server's `config.json` and re-extracts them on every subsequent run. Specifically:

- VLESS user UUIDs and flows.
- Hysteria2 user passwords.
- Reality x25519 **private** keys and `short_id` values.
- Hysteria2 obfs passwords.
- AmneziaWG server X25519 private key, shared amnezia parameters (Jc/Jmin/Jmax/S1-S4/H1-H4), and each client peer's X25519 private key — all stored in the generated `config.json` `endpoints[]` and reused across runs.

The Reality **public** key is not stored; it is derived from the private key on demand. Missing `<server>/config.json` is not an error — it just means the server has never been generated, and fresh credentials will be created.

Practical consequence: **changing your `cheburbox.json` will not rotate UUIDs, passwords, or keys.** To force regeneration, run `cheburbox generate --full-reset`. See [`./generate.md`](./generate.md) for flag behavior and [`./architecture.md`](./architecture.md) for the persistence mechanism.

## Cross-server references

When server B's outbound has `type: vless`, `hysteria2`, or `amneziawg` with a `server` field, cheburbox treats it as a directed reference from B to that server. The reference does three things:

1. **Defines a dependency edge** in the project DAG, so the target is generated first (see [`./generate.md`](./generate.md)).
2. **Auto-provisions a user** on the target inbound. The `user` field of the outbound names that user; if `user` is omitted, it defaults to **the source server's directory name**.
3. **Reuses the target's persisted credentials** when generating the outbound — no manual UUID/password copying.

Example: server `client-1` proxies to `server-a`'s VLESS inbound:

```json
{
  "version": 1,
  "dns": { "servers": [ { "type": "local", "tag": "dns-local" } ] },
  "outbounds": [
    {
      "type": "vless",
      "tag": "to-a",
      "server": "server-a",
      "inbound": "vless-in"
    }
  ]
}
```

A user named `client-1` (the source directory name) is auto-added to `server-a`'s `vless-in` inbound. Specify `user: "alice"` to attach to an existing user explicitly.

Self-references (a server's outbound pointing to itself) and cycles are rejected at validation time. `urltest` and `selector` group `outbounds` may only reference tags on the **same** server — cross-server members are not supported in groups.

AmneziaWG cross-server outbounds participate in the same DAG/topological-generation model: the target `amneziawg` server is generated first, after which the client endpoint's public key is registered as a peer on it. The provisioning difference is that an `amneziawg` reference registers a **WireGuard peer** (the client's public key) rather than a named user.

## Field reference tables

### `Config` (top-level)

| Field          | Type              | Required           | Description                                                                          |
| -------------- | ----------------- | ------------------ | ------------------------------------------------------------------------------------ |
| `version`      | `int`             | Yes                | Schema version. Must equal `1`.                                                      |
| `endpoint`     | `string`          | If inbounds exist  | Public IP/hostname. Used as default address for cross-server outbounds.              |
| `log`          | `json.RawMessage` | No                 | Sing-box log options passthrough.                                                    |
| `dns`          | `DNS`             | Yes                | Must contain at least one server.                                                    |
| `inbounds`     | `[]Inbound`       | No                 | Inbound services exposed by this server.                                             |
| `outbounds`    | `[]Outbound`      | No                 | Outbound destinations and groups.                                                    |
| `route`        | `*Route`          | No                 | Routing rules; if omitted, `auto_detect_interface=true` is forced in generated config. |
| `experimental` | `*Experimental`   | No                 | Container for experimental sing-box options.                                         |

### `Experimental`

| Field        | Type                | Required | Description                                              |
| ------------ | ------------------- | -------- | -------------------------------------------------------- |
| `cache_file` | `*CacheFileConfig`  | No       | Sing-box cache-file options. Emitted only when enabled.  |

### `CacheFileConfig`

| Field     | Type    | Required | Description                                                                                  |
| --------- | ------- | -------- | -------------------------------------------------------------------------------------------- |
| `enabled` | `*bool` | No       | Pointer semantics: `experimental.cache_file` is emitted only when non-nil **and** `*enabled == true`. |

### `DNS`

| Field            | Type              | Required | Description                                                                                       |
| ---------------- | ----------------- | -------- | ------------------------------------------------------------------------------------------------- |
| `servers`        | `[]DNSServer`     | Yes      | At least one server required.                                                                     |
| `final`          | `*string`         | No       | Default DNS server tag.                                                                           |
| `strategy`       | `*string`         | No       | `prefer_ipv4` / `prefer_ipv6` / `ipv4_only` / `ipv6_only` / `as_is` / `""`.                       |
| `cache_capacity` | `*uint32`         | No       |                                                                                                   |
| `rules`          | `json.RawMessage` | No       | Sing-box DNS rules passthrough.                                                                   |

### `DNSServer`

| Field         | Type     | Required                                  | Description                                                                                |
| ------------- | -------- | ----------------------------------------- | ------------------------------------------------------------------------------------------ |
| `type`        | `string` | Yes                                       | One of `local`, `udp`, `tcp`, `tls`, `quic`, `https`, `http3`, `dhcp`, `fakeip`.           |
| `tag`         | `string` | Yes                                       |                                                                                            |
| `server`      | `string` | De facto for `udp`/`tcp`/`tls`/`quic`/`https`/`http3` | sing-box requires this at runtime; cheburbox does not enforce it.                           |
| `server_port` | `int`    | No                                        |                                                                                            |
| `detour`      | `string` | No                                        | Outbound tag for resolving DNS queries.                                                    |

### `InboundUser`

| Field  | Type     | Required | Description                                                                                          |
| ------ | -------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `name` | `string` | Yes      | User identifier (used for cross-server `user` lookups and share-link fragments).                     |
| `flow` | `string` | No       | VLESS only. Defaults to `xtls-rprx-vision` when new credentials are generated and no flow is set.    |

### `Inbound`

| Field                        | Type                | Used by              | Description                                                                                    |
| ---------------------------- | ------------------- | -------------------- | ---------------------------------------------------------------------------------------------- |
| `type`                       | `string`            | all                  | One of `vless`, `hysteria2`, `tun`, `amneziawg`.                                               |
| `tag`                        | `string`            | all (Required)       | Inbound identifier.                                                                            |
| `listen`                     | `string`            | all                  | Listen address (`::`, `0.0.0.0`, …).                                                            |
| `listen_port`                | `int`               | all                  | `0..65535`. `0` is allowed (TUN).                                                              |
| `users`                      | `[]InboundUser`     | vless / hysteria2 / amneziawg | Object array. Per-user `flow` honored (VLESS). For `amneziawg`, each user is a client peer.     |
| `tls`                        | `*InboundTLS`       | vless / hysteria2    | TLS / Reality config.                                                                          |
| `multiplex`                   | `*InboundMultiplex` | vless                | Server-side [multiplex](#multiplex) (mux) config.                                             |
| `obfs`                       | `*ObfsConfig`       | hysteria2            |                                                                                                |
| `masquerade`                 | `*MasqueradeConfig` | hysteria2            |                                                                                                |
| `amnezia`                    | `*AmneziaConfig`    | amneziawg            | User-facing obfuscation preferences (`protocol`, `mtu`); raw params generated by `amnezigo`.   |
| `up_mbps`                    | `int`               | hysteria2            |                                                                                                |
| `down_mbps`                  | `int`               | hysteria2            |                                                                                                |
| `interface_name`             | `string`            | tun                  |                                                                                                |
| `address`                    | `[]string`          | tun / amneziawg      | Parsed as `netip.Prefix`. For `amneziawg`, exactly one CIDR (tunnel subnet).                    |
| `mtu`                        | `int`               | tun / amneziawg      |                                                                                                |
| `auto_route`                 | `bool`              | tun                  |                                                                                                |
| `auto_redirect`              | `bool`              | tun                  |                                                                                                |
| `strict_route`               | `bool`              | tun                  |                                                                                                |
| `endpoint_independent_nat`   | `bool`              | tun                  |                                                                                                |
| `stack`                      | `string`            | tun                  |                                                                                                |
| `exclude_interface`          | `[]string`          | tun                  |                                                                                                |
| `route_exclude_address`      | `[]string`          | tun                  | Parsed as `netip.Prefix`.                                                                      |
| `iproute2_table_index`       | `int`               | tun                  |                                                                                                |
| `iproute2_rule_index`        | `int`               | tun                  |                                                                                                |

### `InboundTLS`

| Field         | Type             | Required | Description                                                                                                |
| ------------- | ---------------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| `server_name` | `string`         | No       | TLS SNI. For Hysteria2, also drives the cert filename `certs/<server_name>.crt`.                           |
| `alpn`        | `[]string`       | No       |                                                                                                            |
| `reality`     | `*RealityConfig` | No       | Set to enable Reality.                                                                                     |

### `InboundMultiplex`

| Field     | Type            | Required | Description                                         |
| --------- | --------------- | -------- | --------------------------------------------------- |
| `enabled` | `bool`          | No       | Turns on server-side mux.                           |
| `padding` | `bool`          | No       | Enables mux padding against traffic analysis.       |
| `brutal`  | `*BrutalConfig` | No       | TCP Brutal congestion control.                      |

### `OutboundMultiplex`

| Field             | Type            | Required | Description                                                                                |
| ----------------- | --------------- | -------- | ----------------------------------------------------------------------------------------- |
| `enabled`         | `bool`          | No       | Turns on client-side mux.                                                                 |
| `protocol`        | `string`        | No       | `h2mux` (default), `smux`, or `yamux`. Other values are rejected at generation time.       |
| `max_connections` | `int`           | No       | Max TCP connections the mux pool opens.                                                   |
| `min_streams`     | `int`           | No       | Min streams before opening a new connection.                                              |
| `max_streams`     | `int`           | No       | Max streams per connection before a new one opens.                                        |
| `padding`         | `bool`          | No       | Enables mux padding.                                                                      |
| `brutal`          | `*BrutalConfig` | No       | TCP Brutal congestion control.                                                            |

### `BrutalConfig`

| Field       | Type   | Required | Description                                                   |
| ----------- | ------ | -------- | ------------------------------------------------------------ |
| `enabled`   | `bool` | No       | Enables TCP Brutal CC (requires a Brutal-capable build).      |
| `up_mbps`   | `int`  | No       | Upload bandwidth in Mbps.                                    |
| `down_mbps` | `int`  | No       | Download bandwidth in Mbps.                                  |

### `RealityConfig`

| Field       | Type                | Required | Description                                                            |
| ----------- | ------------------- | -------- | ---------------------------------------------------------------------- |
| `handshake` | `*RealityHandshake` | Yes      | Real upstream the Reality handshake mimics.                            |
| `short_id`  | `[]string`          | No       | If absent, one 8-byte hex `short_id` is auto-generated and persisted.  |

### `RealityHandshake`

| Field         | Type     | Required | Description                       |
| ------------- | -------- | -------- | --------------------------------- |
| `server`      | `string` | Yes      | Hostname of the camouflage target. |
| `server_port` | `int`    | Yes      | Port of the camouflage target.    |

### `ObfsConfig` (Hysteria2 only)

| Field      | Type     | Allowed values | Description                                                |
| ---------- | -------- | -------------- | ---------------------------------------------------------- |
| `type`     | `string` | `salamander`   |                                                            |
| `password` | `string` | any            | Auto-generated and persisted if empty.                     |

### `MasqueradeConfig` (Hysteria2 only)

| Field          | Type     | Allowed values | Description |
| -------------- | -------- | -------------- | ----------- |
| `type`         | `string` | `proxy`        |             |
| `url`          | `string` | any            |             |
| `rewrite_host` | `bool`   | any            |             |

### `AmneziaConfig` (AmneziaWG only)

Only `protocol`, `preset`, and `mtu` are user-facing. The actual obfuscation parameters (Jc/Jmin/Jmax/S1-S4/H1-H4 server-side, plus I1-I5 client-side) are generated by the `amnezigo` library and persisted in `config.json` so they remain stable across runs — users never specify the raw params.

| Field      | Type     | Required | Allowed values                                     | Description                                               |
| ---------- | -------- | -------- | -------------------------------------------------- | --------------------------------------------------------- |
| `protocol` | `string` | No       | `quic`, `dns`, `dtls`, `stun`, `sip`, `rtp`, `random` | Transport the obfuscation magic bytes mimic. Default `quic`. |
| `preset`   | `string` | No       | One of the preset names below                      | Named bundle of shared server-side params. Empty → fully random (default). See [Presets](#presets). |
| `mtu`      | `int`    | No       |                                                    | Obfuscation-layer MTU. Default `1280`.                    |

### `Outbound`

| Field                         | Type       | Used by              | Description                                                                                     |
| ----------------------------- | ---------- | -------------------- | ----------------------------------------------------------------------------------------------- |
| `type`                        | `string`   | all                  | One of `direct`, `vless`, `hysteria2`, `amneziawg`, `urltest`, `selector`.                      |
| `tag`                         | `string`   | all (Required)       |                                                                                                 |
| `server`                      | `string`   | vless / hysteria2 / amneziawg | Target server directory name.                                                            |
| `inbound`                     | `string`   | vless / hysteria2 / amneziawg | Target inbound `tag` on the target server.                                               |
| `user`                        | `string`   | vless / hysteria2 / amneziawg | Defaults to source server's directory name when omitted.                                 |
| `flow`                        | `string`   | vless                |                                                                                                 |
| `endpoint`                    | `string`   | vless / hysteria2    | Overrides the target server's `endpoint`.                                                       |
| `domain_resolver`             | `string`   | vless / hysteria2    | DNS server tag for resolving the outbound hostname.                                             |
| `address`                     | `[]string` | amneziawg            | Exactly one CIDR: this client's tunnel IP within the target server's subnet.                   |
| `mtu`                         | `int`      | amneziawg            | WireGuard interface MTU. Default `1280`.                                                        |
| `outbounds`                   | `[]string` | urltest / selector   | Intra-server tags only.                                                                         |
| `url`                         | `string`   | urltest              | Probe URL.                                                                                      |
| `interval`                    | `string`   | urltest              | Go duration (e.g. `3m`).                                                                        |
| `tolerance`                   | `uint16`   | urltest              |                                                                                                 |
| `idle_timeout`                | `string`   | urltest              | Go duration.                                                                                    |
| `interrupt_exist_connections` | `bool`     | urltest              |                                                                                                 |

### `Route`

| Field                     | Type              | Required | Description                                                                                                                          |
| ------------------------- | ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `final`                   | `string`          | No       | Default outbound tag if no rule matches.                                                                                             |
| `auto_detect_interface`   | `bool`            | No       |                                                                                                                                      |
| `default_domain_resolver` | `string`          | No       |                                                                                                                                      |
| `rules`                   | `json.RawMessage` | No       | Sing-box rule passthrough.                                                                                                           |
| `rule_sets`               | `json.RawMessage` | No       | Remote and other rule-set declarations passed through.                                                                               |
| `custom_rule_sets`        | `[]string`        | No       | Local JSON rule-set source names. Compiled to `rule-set/<name>.srs` and emitted with `type: local`. See [`./rule-set.md`](./rule-set.md). |

---

## Cross-references

- [`./generate.md`](./generate.md) — DAG, topological order, `--full-reset` / `--orphan` flags, persistence mechanics.
- [`./validate.md`](./validate.md) — what the validator checks (cycle detection, server-name collisions, intra-server group rules, sing-box phase 2).
- [`./links.md`](./links.md) — share-link generation built from inbound config and persisted credentials.
- [`./architecture.md`](./architecture.md) — two layers of types (cheburbox config vs sing-box options), persistence implementation.
