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

## Rules

Each rule emits findings with a stable `code` so downstream consumers
can match on them deterministically.

| Rule                                     | Finding code                         | What it checks                                                                        |
|------------------------------------------|--------------------------------------|---------------------------------------------------------------------------------------|
| `delegation_min_name_servers`            | `delegation_too_few_ns`              | The zone declares at least `minNameServers` NS records (RFC 1034 recommends ≥ 2).     |
| `delegation_parent_discovered`           | `delegation_no_parent_ns`            | The parent zone and its authoritative name servers can be discovered.                 |
| `delegation_parent_ns_query`             | `delegation_parent_query_failed`     | Each parent name server answers the NS query for the delegated zone.                  |
| `delegation_parent_tcp`                  | `delegation_parent_tcp_failed`       | Each parent name server is reachable over TCP (RFC 7766).                             |
| `delegation_ns_matches_declared`         | `delegation_ns_mismatch`             | The NS RRset at the parent matches the NS set declared by the service.                |
| `delegation_in_bailiwick_glue`           | `delegation_missing_glue`            | In-bailiwick name servers have glue (A/AAAA) records at the parent.                   |
| `delegation_unnecessary_glue`            | `delegation_unnecessary_glue`        | Out-of-bailiwick name servers do not carry unnecessary glue at the parent.            |
| `delegation_ds_query`                    | `delegation_ds_query_failed`         | The DS RRset can be queried from the parent name servers.                             |
| `delegation_ds_matches_declared`         | `delegation_ds_mismatch`             | The DS RRset at the parent matches the DS set declared by the service.                |
| `delegation_ds_present_at_parent`        | `delegation_ds_missing`              | DS records are present at the parent when DNSSEC is expected (gated by `requireDS`).  |
| `delegation_ds_rrsig_validity`           | `delegation_ds_rrsig_invalid`        | The DS RRset is covered by a valid RRSIG at the parent.                               |
| `delegation_ns_resolvable`               | `delegation_ns_unresolvable`         | Each declared name server name resolves to at least one address.                      |
| `delegation_child_reachable`             | `delegation_unreachable`             | Each child name server answers DNS queries on its advertised addresses.               |
| `delegation_child_authoritative`         | `delegation_lame`                    | Each child name server is authoritative for the delegated zone (no lame delegation).  |
| `delegation_child_soa_serial_drift`      | `delegation_soa_serial_drift`        | The SOA serial is consistent across all child name servers.                           |
| `delegation_child_tcp`                   | `delegation_tcp_failed`              | Each child name server answers over TCP (gated by `requireTCP`).                      |
| `delegation_child_ns_matches_parent`     | `delegation_ns_drift`                | The NS RRset returned by each child matches the NS RRset at the parent.               |
| `delegation_child_glue_matches_parent`   | `delegation_glue_mismatch`           | Glue addresses at the child match those at the parent (gated by `allowGlueMismatch`). |
| `delegation_dnskey_query`                | `delegation_dnskey_query_failed`     | The DNSKEY RRset can be queried from each child name server.                          |
| `delegation_dnskey_matches_ds`           | `delegation_dnskey_no_match`         | At least one DNSKEY at the child matches a DS digest published at the parent.         |
| `delegation_ns_has_authoritative_answer` | `delegation_no_authoritative_answer` | Each child name server sets the AA flag in its answers for the zone.                  |

## License

This project is licensed under the **MIT License** (see `LICENSE`), in
line with the rest of the happyDomain checker ecosystem.
