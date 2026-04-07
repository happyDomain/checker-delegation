# checker-delegation

DNS delegation checker for [happyDomain](https://www.happydomain.org/).

Audits the delegation of a zone: NS consistency between parent and child,
glue correctness, DS / DNSKEY hand-off, TCP reachability, SOA serial drift,
and authoritativeness of each delegated server. Applies to services of type
`abstract.Delegation`.

## Usage

### Standalone HTTP server

```bash
# Build and run
make
./checker-delegation -listen :8080
```

The server exposes:

- `GET /health`, health check
- `POST /collect`, collect delegation observations (happyDomain external checker protocol)

### Docker

```bash
make docker
docker run -p 8080:8080 happydomain/checker-delegation
```

### happyDomain plugin

```bash
make plugin
# produces checker-delegation.so, loadable by happyDomain as a Go plugin
```

The plugin exposes a `NewCheckerPlugin` symbol returning the checker
definition and observation provider, which happyDomain registers in its
global registries at load time.

### Versioning

The binary, plugin, and Docker image embed a version string overridable
at build time:

```bash
make CHECKER_VERSION=1.2.3
make plugin CHECKER_VERSION=1.2.3
make docker CHECKER_VERSION=1.2.3
```

### happyDomain remote endpoint

Set the `endpoint` admin option for the delegation checker to the URL of
the running checker-delegation server (e.g.,
`http://checker-delegation:8080`). happyDomain will delegate observation
collection to this endpoint.

### Deployment

The `/collect` endpoint has no built-in authentication and will issue
DNS queries to whatever name servers (and glue addresses) the parent
zone advertises for the target. It is meant to run on a trusted network,
reachable only by the happyDomain instance that drives it. Restrict
access via a reverse proxy with authentication, a network ACL, or by
binding the listener to a private interface; do not expose it directly
to the public internet.

## Options

| Option              | Type | Default | Description                                                                                       |
|---------------------|------|---------|---------------------------------------------------------------------------------------------------|
| `requireDS`         | bool | `false` | When enabled, missing DS records at the parent are treated as critical (otherwise informational). |
| `requireTCP`        | bool | `true`  | When enabled, name servers that fail to answer over TCP are reported as critical (otherwise warning). |
| `minNameServers`    | uint | `2`     | Below this count, the delegation is reported as a warning (RFC 1034 recommends at least 2).       |
| `allowGlueMismatch` | bool | `false` | When disabled, glue/address mismatches between parent and child are reported as critical.         |

## Protocol

### POST /collect

Request:
```json
{
  "key": "delegation",
  "target": {"userId": "...", "domainId": "..."},
  "options": {
    "domain_name": "example.com.",
    "subdomain": "www",
    "service": { "_svctype": "abstract.Delegation", "Service": { "ns": [...], "ds": [...] } }
  }
}
```

Response:
```json
{
  "data": {
    "delegated_fqdn": "www.example.com.",
    "parent_zone": "example.com.",
    "parent_ns": ["a.iana-servers.net.", "b.iana-servers.net."],
    "advertised_ns": ["ns1.example.net.", "ns2.example.net."],
    "advertised_glue": {},
    "parent_ds": [],
    "child_serials": {"ns1.example.net.:53": 2026042401},
    "findings": [
      {
        "code": "delegation_ns_mismatch",
        "severity": "crit",
        "message": "NS RRset at parent does not match declared service: missing=[ns3.example.net] extra=[]",
        "server": "a.iana-servers.net.:53"
      }
    ]
  }
}
```

Findings carry a stable `code` (e.g. `delegation_lame`,
`delegation_missing_glue`, `delegation_ds_mismatch`,
`delegation_soa_serial_drift`, `delegation_dnskey_no_match`, …) so that
downstream rules can match on them deterministically.

## License

This project is licensed under the **MIT License** (see `LICENSE`), in
line with the rest of the happyDomain checker ecosystem.

The third-party Apache-2.0 attributions for `checker-sdk-go` are recorded
in `NOTICE` and must accompany any binary or source redistribution of this
project.
