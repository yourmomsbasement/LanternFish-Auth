# Optional hardening controls

Every feature below is opt-in. Existing service clients keep IP-based access
and unrestricted Jellyfin API routing unless you configure stricter options.
Existing application records keep their original owner-list semantics. New
applications created in the dashboard start disabled with an empty explicit
owner selection, so they cannot accidentally open to everyone.

## 1. Service mTLS identities and credential lifecycle

Keep the isolated subnet, source-IP allow-list and firewall rules from
[MEDIA-STACK.md](MEDIA-STACK.md), then enable mTLS in `gate.env`:

```sh
LANTERNFISH_SERVICE_AUTH=mtls
LANTERNFISH_SERVICE_TLS_CERT=/etc/lanternfish/service-server.pem
LANTERNFISH_SERVICE_TLS_KEY=/etc/lanternfish/service-server-key.pem
LANTERNFISH_SERVICE_CLIENT_CA=/etc/lanternfish/service-client-ca.pem
LANTERNFISH_SERVICE_CLIENTS_FILE=/etc/lanternfish/service-clients.json
```

Remove `LANTERNFISH_SERVICE_CLIENTS` when using the JSON file; setting both
is an error. The service listener becomes **HTTPS with TLS 1.3 and mandatory
verified client certificates**. Its server certificate must cover the literal
listener IP. Point Seerr, or its sidecar proxy, at `https://10.20.0.2:8096` and
configure verification of your private server CA. Never disable verification.
Standard HTTP/HTTPS port omission in the Host header is accepted only for
the same configured literal address at port 80/443 respectively.
Apps lacking client-certificate support need a local sidecar; the Gate does
not change those applications or distribute their private keys.

Use a separate client key/certificate for each service, issued by your private
CA with client-auth usage and exactly one URI SAN identifying that service.
The default URI is `spiffe://lanternfish/service/NAME`; `certificate_uri` can
select another valid SPIFFE URI. A certificate must match both the named
service's URI and its configured source IP. The configured trust file accepts
CA certificates, not arbitrary leaf certificates.

Example `service-clients.json`:

```json
[
  {
    "name": "seerr",
    "ip": "10.20.0.4",
    "certificate_uri": "spiffe://lanternfish/service/seerr",
    "disabled": false,
    "revoked_serials": [],
    "max_concurrent": 2,
    "requests_per_minute": 120,
    "max_body_bytes": 1048576,
    "permissions": [
      {"methods": ["POST"], "path": "/Users/AuthenticateByName"},
      {"methods": ["GET"], "path_prefix": "/Users"},
      {"methods": ["GET"], "path_prefix": "/Items"},
      {"methods": ["GET"], "path": "/Library/VirtualFolders"},
      {"methods": ["GET"], "path_prefix": "/System/Info"}
    ]
  }
]
```

These API permissions illustrate the format; they are not a verified complete
Seerr integration profile. Test the endpoints your installed version uses.
Omitting `permissions` (or setting it to `null`) retains unrestricted legacy routing. Setting it to `[]`
explicitly denies all requests. Jellyfin credentials and its own authorization
still apply in every mode.

Your existing CA/PKI tooling issues and renews client/server certificates.
Renewed client certificates can retain the same URI and need no Gate policy
change. Server certificate/key file renewals are reloaded automatically, with
a 30-second check interval. The Gate is not a certificate issuer or scheduler.
Client CA changes, policy-file changes and revocation settings require a Gate
restart. Use overlapping trust during a CA migration, then remove the old CA.

To disable a service, set `disabled: true` and restart. To revoke one certificate,
add its hexadecimal serial to `revoked_serials` and restart. Expired certificates
are denied, including on established connections. Store private keys in private
files and directories; give backends separate app API keys where supported and
rotate those through the application's supported administration interface.

## 2. Per-service Jellyfin permissions

Each permission rule specifies explicit uppercase HTTP methods and either an
exact `path` or a segment-delimited `path_prefix`, never both. `/Items` as a
prefix matches `/Items/123`, but not `/ItemsOther`. Query parameters do not
grant additional permission. Canonical paths are required; dot-segment,
encoded-separator and double-encoding bypass forms are denied under a policy.
There are at most 64 rules per service. Gate endpoints and CONNECT/TRACE or
protocol upgrades remain unavailable regardless of the rules.

Permissions apply before forwarding/signing. A denied request returns 403 and
is audited without including its path, query, body or credentials. Policies
limit service API reachability; Jellyfin still controls which user's data an
API key or login may access. Avoid a broad `/` prefix unless unrestricted
access is deliberately intended.

## 3. Explicit application access modes

The Network tab offers **Everyone**, **Selected owners**, and **Admins only**.
The optional application JSON parameter is `access_mode`:

| Value | Meaning |
| --- | --- |
| omitted / `""` | legacy: empty `owners` means everyone |
| `everyone` | every otherwise-authorized owner/device |
| `selected` | only IDs in `owners`; an empty list denies everyone |
| `admins` | only an existing, active owner with the admin role |

Changing access modes closes that app's active streams. Owner disablement
also closes the owner's streams. Existing policy checks still apply. Choose
Everyone for family Seerr access, and either Admins only or Selected owners
with your specific admin ID for the optional administrative hostnames.

## 4. Firewall verification and timed rollback

`deploy/proxmox/guarded-firewall.sh` is an optional companion to a reviewed
firewall script generated by the dashboard. Copy both to the Proxmox host and
run as root. Preflight does not execute the supplied script or change files:

```sh
bash guarded-firewall.sh --verify-only lanternfish-firewall.sh
bash guarded-firewall.sh --rollback-after 600 lanternfish-firewall.sh
```

Preflight requires valid shell syntax, declared numeric guest IDs, an enabled
and running firewall, existing compilable firewall configuration, and enabled
firewall NICs on each declared guest. It checks prerequisites and structure;
it cannot prove arbitrary executable script semantics or network connectivity.
The generated script is operator-reviewed executable code, not an untrusted
upload. This companion targets the existing `pve-firewall` deployment.

Guarded application backs up only the declared numeric guest `.fw` files in
`/etc/pve/firewall`, arms a transient systemd rollback timer first, then runs
a captured copy with an execution timeout shorter than the rollback interval.
It bounds prerequisite/compilation commands, retires interrupted pre-apply
preparations under the lock, and rolls back immediately if application/compilation
fails. Existing `cluster.fw` and unrelated guest files are never restored or
rewritten by the wrapper. New guest files are removed on rollback; original
files are restored. The delay must be 30–604800 seconds. `systemd-run`,
`systemctl`, `flock`, and `timeout` are required for this mode.

Success does **not** confirm the change. The wrapper prints the exact
`--confirm STATE` and `--rollback STATE` commands for that transaction.
After testing management access, permitted backend connections and forbidden
connections from the relevant guests, explicitly confirm. Otherwise the timer
restores the captured files. Confirmation and timer execution coordinate under
a lock; only one unconfirmed transaction may be pending.

The timer survives losing the SSH shell, **not a Proxmox host reboot**.
After an unexpected reboot, inspect the pending state under
`/var/lib/lanternfish-firewall` and explicitly roll back or confirm it before
another guarded apply. No automatic job is enabled by installing the helper.
Do not run another administrator's firewall changes during a pending transaction.

See the [Proxmox firewall source/documentation](https://github.com/proxmox/pve-firewall/blob/master/debian/README)
for compilation and rule syntax. Actual enforcement still needs deployment
checks; mock tests do not substitute for testing your hypervisor and guests.

## 5. Additional LAN isolation

Optional Firewall tab fields also map to plan JSON:

```json
{
  "blocked_networks": ["2001:db8:1234::/48"],
  "block_link_local": true
}
```

Replace the documentation IPv6 prefix with your actual LAN prefix. There are
at most 32 distinct extra network prefixes; values are normalized/deduplicated.
`block_link_local` adds `169.254.0.0/16`, `fe80::/10`, `224.0.0.0/4`, and
`ff00::/8`, covering link-local/metadata and multicast destinations. Both
options default off/empty and apply only to guests with **Keep it off my LAN**
on. Explicit guest, internal-service and NAS/DNS allowances precede these
blocks. Enable discovery/multicast blocking only if the apps do not need it.

## 6. Encrypted backups and isolated recovery checks

`deploy/systemd/lanternfish-recovery.py` is an optional Linux operator helper
using Python's standard library and the external **age** executable. Keep the
age private decryption identity separately from the Gate and backup storage.
The backup recipient is its public encryption identity. No plaintext fallback
exists; missing age is an error.

Run against a stopped or otherwise stable Gate snapshot. The helper reads
files sequentially; it does not stop the service, snapshot storage, or schedule
jobs on its own. Example parameters:

```sh
python3 lanternfish-recovery.py backup \
  --data /var/lib/lanternfish/gate.json \
  --master-key /etc/lanternfish/keys/master_key \
  --recipient AGE_PUBLIC_RECIPIENT \
  --output /secure-backups/gate-2026-10-16.age

python3 lanternfish-recovery.py verify /secure-backups/gate-2026-10-16.age \
  --identity /offline/age-identity.txt --max-age 168

python3 lanternfish-recovery.py restore /secure-backups/gate-2026-10-16.age \
  --identity /offline/age-identity.txt --destination /private/recovery-test
```

Optional parameters: repeat `--recipient` for multiple encryption recipients;
`--include-audit PATH`; `--max-bytes` (default 256 MiB, including decrypted tar
framing); `--timeout` (default 120 seconds for the age process and its children);
`--age-binary`; and `--max-age HOURS` on verify/restore. Nonfinite ages and
future manifest timestamps are rejected. Output must be a new file (0600),
and restore requires a new directory (0700, restored files 0600) under a
caller-owned parent that is not group/world-writable. Directory-relative file
operations prevent path replacements from redirecting restore writes.

The archive includes Gate data, its base64 master-key file, an optional audit
log and an integrity manifest. The tool never writes a plaintext temporary
archive or prints secrets. It refuses traversal, links, duplicate/unexpected
entries, oversized data, bad digests, decryption failures and nonzero trailing
data. Restore validates the whole archive before writing anything and never
replaces live files.

Verification proves archive integrity and file formats, **not** that every
Gate secret can be unsealed or that the restored application works. Perform
an isolated recovery drill with the Gate too. For an existing signing key,
running `lanternfish-gate upstream-key` against the **restored** data/master-key
paths exercises signing-key unsealing without starting a listener; compare
its public key to your recorded original. Keep all environment paths directed
at the recovery copy and test the application separately before a live restore.
This helper does not cover Windows DPAPI master-key blobs.

## 7. Service limits and alerts

Set these optional `gate.env` parameters and restart:

| Parameter | Default | Effect |
| --- | --- | --- |
| `LANTERNFISH_SERVICE_MAX_CONCURRENT` | `0` | per-service concurrent-request cap; 0 unlimited |
| `LANTERNFISH_SERVICE_REQUESTS_PER_MINUTE` | `0` | per-service fixed one-minute request window; 0 unlimited |
| `LANTERNFISH_SERVICE_MAX_BODY_BYTES` | `0` | maximum request body, including unknown-length bodies; 0 unlimited |
| `LANTERNFISH_SERVICE_TIMEOUT` | `2m` | request deadline; configurable from 1s to 10m |
| `LANTERNFISH_SERVICE_ALERT_FAILURES` | `0` | HTTP failure count needed for an alert; 0 off |
| `LANTERNFISH_SERVICE_ALERT_WINDOW` | `5m` | failure-count window, up to 24h |
| `LANTERNFISH_SERVICE_CERT_WARN_BEFORE` | `0` | active client-certificate expiry warning horizon; 0 off |
| `LANTERNFISH_SERVICE_ALERT_CONFIG_DRIFT` | `false` | alert when checked firewall plan/configuration differs |

Client JSON `max_concurrent`, `requests_per_minute`, and `max_body_bytes`
override the corresponding globals when nonzero. Limits return 429 (rate or
concurrency) and 413 (oversized body) before forwarding; optional body limits
buffer at most that body cap in memory. Choose small API-appropriate limits,
then test library scans so a normal initial sync is not throttled unexpectedly.

Alerts require the existing `LANTERNFISH_ALERT_WEBHOOK`; enabling alerts
without one is an error. Expiry warnings require mTLS and fire on successful
service requests, at most once per service per day. Your CA tooling must
monitor idle certificates. HTTP failure alerts fire at most once per window;
repeated rate-limit failures can therefore alert on traffic spikes. These
are configured thresholds, not statistical anomaly detection, and TLS
handshake failures before HTTP are not counted by the service handler.

Drift alerts fire when the plan is checked/saved/generated and are suppressed
for an hour after delivery is requested. They compare Gate configuration and
the plan, **not the running Proxmox rules**. Use hypervisor monitoring and the
verification workflow to detect live enforcement drift. No scheduled monitor
or notification destination is created automatically. Size limits bound input bytes,
not total process memory; parsing and concurrent requests add overhead.
