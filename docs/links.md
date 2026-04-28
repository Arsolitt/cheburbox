# Links

> Generate share URIs (or sing-box outbound JSON) for client apps to import — derived directly from each server's persisted `config.json`.

## Table of Contents

- [What links does](#what-links-does)
- [Usage](#usage)
- [Flags](#flags)
- [Supported protocols](#supported-protocols)
- [Output formats](#output-formats)
  - [URI format](#uri-format)
  - [JSON format](#json-format)
- [VLESS share links](#vless-share-links)
- [Hysteria2 share links](#hysteria2-share-links)
- [Filtering](#filtering)
- [Pin SHA-256](#pin-sha-256)

## What links does

`cheburbox links` walks each server in your project, reads the credentials persisted in the previously generated `<server>/config.json`, and emits one client-importable record per `(server, inbound, user)` triple.

Two output shapes are supported:

- **URI** — share-link strings such as `vless://...` or `hysteria2://...` that most VPN client apps accept directly.
- **JSON** — sing-box `outbound` objects you can paste into a client-side config.

The command does **not** read `cheburbox.json` for credentials — it relies on the values that `cheburbox generate` already materialised on disk. This means it will only show links for users, UUIDs, passwords, and Reality keys that have actually been provisioned.

> **Note:** Run `cheburbox generate` (see [./generate.md](./generate.md)) at least once before `cheburbox links`. An empty project — or a project where no `config.json` files have been written yet — produces empty output without an error.

## Usage

```shell
cheburbox links [flags]
```

Inherited persistent flags from the root command:

- `--project <path>` — project root (defaults to the current working directory)
- `--jpath <dir>` — Jsonnet library search path (default `lib`)

## Flags

| Flag | Type | Default | Purpose |
| --- | --- | --- | --- |
| `--server` | string | `""` | Restrict output to a single server directory by name. |
| `--user` | string | `""` | Restrict output to a single user (matches `users[].name`). |
| `--inbound` | string | `""` | Restrict output to a single inbound by tag. |
| `--format` | string | `"uri"` | Output format. Accepted values: `uri`, `json`. |

`--format` is validated up-front: any value other than `uri` or `json` exits with `invalid format: must be "uri" or "json"`.

`--server` is also validated: passing a name that does not match any discovered server directory returns `server <name> not found in project`. The `--user` and `--inbound` filters are non-strict — an unmatched value simply yields no output.

## Supported protocols

Only two inbound types contribute to the output:

- **VLESS** — including Reality TLS, plain TLS, and no-TLS variants.
- **Hysteria2** — with optional Salamander obfuscation, ALPN, and certificate pinning.

Any other inbound type (for example `tun`) is silently skipped.

## Output formats

### URI format

`--format uri` (the default) prints one share-link string per matching `(server, inbound, user)` triple, one per line. Each link's URI fragment uses the pattern `<server>-<inbound-tag>-<user>` so it shows up as a recognisable label inside client apps.

### JSON format

`--format json` prints sing-box `outbound` JSON objects, pretty-printed with two-space indentation. Multiple matches produce multiple back-to-back JSON objects (one per result), each separated by a newline. The `tag` field of each object follows the same `<server>-<inbound-tag>-<user>` pattern as the URI fragment.

## VLESS share links

VLESS URIs are assembled from persisted credentials plus the inbound's TLS configuration. The `type` is always `tcp`, the UTLS fingerprint is always `chrome`, and the security mode is selected at build time:

| Mode | Trigger | Query parameters added |
| --- | --- | --- |
| `reality` | inbound has Reality TLS configured | `security=reality`, `sni`, `fp=chrome`, `pbk`, `sid` (if present) |
| `tls` | inbound has plain TLS with a non-empty `server_name` | `security=tls`, `sni` |
| `none` | neither of the above | `security=none` |

Notes on field sources:

- `pbk` (Reality public key) is **derived fresh** from the persisted Reality private key on every run. It is not stored on disk.
- `sid` is the **first** entry of the persisted Reality `short_id` list (subsequent IDs are not included). If the list is empty, `sid` is omitted entirely.
- The Reality `sni` parameter comes from the inbound's `tls.reality.handshake.server`, **not** `tls.server_name`.
- `flow` is included only when non-empty. With Cheburbox defaults this is typically `xtls-rprx-vision`.

Example URI (Reality with all parameters):

```text
vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=pubkey123&sid=abcd1234&flow=xtls-rprx-vision#srv1-vless-in-alice
```

The corresponding JSON output mirrors these fields:

```json
{
  "type": "vless",
  "tag": "srv1-vless-in-alice",
  "server": "1.2.3.4",
  "server_port": 443,
  "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "www.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "pubkey123",
      "short_id": "abcd1234"
    }
  }
}
```

> **Note:** This `chrome` fingerprint is specific to share links. Cheburbox-generated **cross-server** VLESS outbounds (the ones written into `config.json` itself) use `firefox`. The two are independent constants.

## Hysteria2 share links

Hysteria2 URIs put the password in the userinfo position of the URL. Optional features are added as query parameters; missing fields are omitted silently.

Fields included:

| Field | Source | URI parameter |
| --- | --- | --- |
| password | persisted user password | userinfo (before `@`) |
| `sni` | inbound `tls.server_name` | `sni=` |
| `alpn` | inbound `tls.alpn` (joined with `,`) | `alpn=` (commas URL-encoded as `%2C`) |
| `obfs` type | persisted obfuscation type (e.g. `salamander`) | `obfs=` |
| `obfs` password | persisted obfuscation password | `obfs-password=` |
| `pinSHA256` | computed from the server's TLS certificate | `pinSHA256=` |
| listen port | inbound `listen_port` | host port |

Example URI (full, with obfuscation, ALPN list, and pin):

```text
hysteria2://secret123@example.com:443?alpn=h3%2Ch2&obfs=salamander&obfs-password=obfs-pass&pinSHA256=sha256%2FAAA...&sni=example.com#server1-hy2-alice
```

The corresponding JSON output:

```json
{
  "type": "hysteria2",
  "tag": "server1-hy2-alice",
  "server": "example.com",
  "server_port": 443,
  "password": "secret123",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "alpn": ["h3"],
    "certificate_public_key_sha256": [/* raw 32 bytes */]
  },
  "obfs": {
    "type": "salamander",
    "password": "obfs-pass"
  }
}
```

> **Note:** The Hysteria2 JSON outbound emitted by `cheburbox links` **always** sets `tls.enabled: true` and `tls.alpn: ["h3"]`, regardless of the inbound's actual TLS or ALPN configuration. This is intentional: client-side Hysteria2 outbounds need a TLS block, and `h3` is the default Hysteria2 transport. The URI form, in contrast, faithfully echoes the inbound's full ALPN list.

## Filtering

The three discriminating filters compose with logical AND. Use them to narrow output to a specific subset.

Show every link for every user on every server:

```shell
cheburbox links
```

Restrict to a single server:

```shell
cheburbox links --server srv1
```

Combine server, inbound, and user filters to target one specific link:

```shell
cheburbox links --server srv1 --inbound vless-in --user alice
```

Switch the format to JSON, scoped to a single user across all of their inbounds and servers:

```shell
cheburbox links --user alice --format json
```

Reminder: an unknown `--server` errors out, but unknown `--user` or `--inbound` filters return no rows silently.

## Pin SHA-256

For Hysteria2 inbounds, the `pinSHA256` field is computed from `<server-dir>/certs/<server-name>.crt` using `generate.ComputePinSHA256`, which was exported in commit `6fbea30` specifically so the `links` package could share the same implementation as the generation pipeline. The result has the form `sha256/<base64-rawurl>`. The same byte payload also appears in the JSON outbound's `tls.certificate_public_key_sha256` array (decoded back to its raw 32-byte form).

If the certificate file is missing, the URI simply omits the `pinSHA256` parameter — no error is raised.

For more on certificate generation, persistence, and the pin-SHA-256 format internals, see [./architecture.md](./architecture.md). For inbound configuration that drives this output, see [./configuration.md](./configuration.md).
