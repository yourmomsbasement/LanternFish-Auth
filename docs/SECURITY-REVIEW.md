# Security reviews, October 2026

Scope: the Gate (`internal/gate`, `cmd/lanternfish-gate`), its web client, the
Jellyfin plugin, and the deploy files. Fixed issues are marked `SECURITY:` in
the code.

## Fixed

| # | Severity | Component | Issue | Fix |
|---|---|---|---|---|
| 1 | Medium | Gate | **Revocation did not end open connections.** Authentication runs once per request, so a WebSocket or media stream opened before a revocation kept running. A stolen or lost device stayed connected. | Proxied requests are tracked per device. Revoking a device cancels them, which closes upgraded connections and streams. A re-check after tracking closes the race with a revocation that lands mid-request. |
| 2 | Medium | Gate | **One client could block all sign-ins.** `/v1/challenge` needs no authentication and shared one table of 10,000 slots. A single client could fill it in seconds, and then every device got `503` for as long as it kept doing that. | At most 32 outstanding challenges per source (an IPv4 address or an IPv6 /64). Over the limit the Gate returns `429` with `Retry-After`. |
| 3 | Medium | Web client | **Open redirect on the sign-in page.** `login.js` checked `next` as a string, but URL parsing removes tabs and newlines, so `?next=/%09/evil.example` became `//evil.example`. That made a convincing phishing link on the real Gate domain. | `next` is resolved with `new URL()` and must stay same-origin. |
| 4 | Low | Gate | **The identity headers sent to Jellyfin could be stripped.** The Gate set `X-Lanternfish-Device` and `X-Lanternfish-Auth` on the incoming request. A client could name them in its `Connection` header, and ReverseProxy then removed them as hop-by-hop headers. The plugin rejected such requests, so it was not a bypass. | The headers are set on the outgoing request in `Rewrite`, after hop-by-hop headers are removed. |
| 5 | Low | Plugin | **The health-check exemption was too wide.** Any unsigned `GET` from loopback whose path *ended* in `/health` (for example `/Artists/health`) skipped the signature check. | The exemption covers exactly `/health`. |
| 6 | Low | Gate | **Alert mention injection.** Device names come from whoever enrolls. A name such as `@everyone` pinged the whole Discord server. | Webhook posts set `allowed_mentions: {"parse": []}`. |
| 7 | Low | Gate | **Log injection.** The proxy error log printed the client-controlled path raw. A path with an encoded newline could forge log lines. | The path is logged with `%q`. |
| 8 | Info | Docker | **Admin API exposure through Docker.** The admin API's default allow list includes `172.16.0.0/12`. Docker's userland proxy can make outside clients appear to come from the bridge gateway, which is in that range. An admin key is still required. | `docker-compose.yml` now says to set `LANTERNFISH_ADMIN_ALLOW` to the Builder's address. |

## Follow-up review: resource limits and state integrity

A second review (of `368827d`) found eight more issues. None was an
authentication bypass. All are fixed, each with a regression test.

| # | Priority | Component | Issue | Fix |
|---|---|---|---|---|
| F1 | Medium | Gate | Small JSON bodies had no read deadline, so an unauthenticated client could hold a handler open by stalling its body. | Bodies to the Gate's own endpoints must arrive within 10 s (`BodyReadTimeout`). Media requests are not affected. |
| F2 | Medium | Gate | The failure limiter keyed IPv6 by full address, so a /64 gave unlimited budgets. Its table had no real cap, and once past 10,000 entries every failure scanned the whole table. | Keyed by source like challenges (IPv4 address or IPv6 /64). Capped at 10,000 sources, and swept at most once a minute. |
| F3 | Medium | Gate | Every session renewal rewrote and synced the whole data file under the lock that every proxied request's device lookup waits on. | Last sign-in times are kept in memory and saved only when the stored one is over 15 minutes old. Readers no longer wait on disk I/O (see F5). |
| F4 | Medium | Gate, web client | Sessions per device were unlimited, and each new one scanned all sessions. | At most 16 sessions per device; a new one replaces the oldest. Expired sessions are swept once a minute. The web client runs one renewal at a time. |
| F5 | Medium | Gate | A failed save left memory changed but the disk not. A failed revocation returned 500 with the device revoked in memory, its streams still open, and the device active on disk. | Store updates are transactional: they work on a copy and publish it only after it is saved. A revocation that can't be saved fails closed: the device is locked out and its connections are closed until restart, the device list flags `revocation_unsaved`, and revoking again saves it. |
| F6 | Medium | Gate | `serve` took over any existing lock file, and on exit removed it even when another process held it, so two Gates could overwrite each other's data. | An OS-held exclusive lock (flock / unshared handle) for the whole process lifetime. It is released on crash, and no process can take over or remove another's lock. |
| F7 | Low | Plugin | The nonce limit only triggered cleanup. At the limit, every request scanned the whole cache, and `Count` took every lock. | A real cap. When the cache is full of live nonces, requests get `503` rather than live nonces being evicted. Cleanup runs one at a time, at most once a second while full. The count is kept separately. |
| F8 | Low | Plugin | Renewal injection buffered the whole response before checking the 4 MiB limit. | Buffers up to 4 MiB, then streams the rest through unchanged. |

Not done: a global request budget for unauthenticated endpoints. A single
flood could use it up and lock every device out, which would make it a
lockout tool rather than a defence. Many separate sources stay out of scope,
as SECURITY.md says.

## v0.2.0 review: policies, streams and the release toolchain

A review of v0.2.0 found one release-toolchain issue and six problems with
how policy changes reach live sessions and open connections. None was an
unauthenticated bypass. All are fixed, each with a regression test (tests
R2–R6 were checked to fail with their fix taken out).

| # | Priority | Issue | Fix |
|---|---|---|---|
| R1 | High | Release binaries were built with Go 1.24.13, an unsupported Go release with known TLS 1.3 and HTTP/2 denial-of-service bugs (GO-2026-4870, GO-2026-6617). | `go.mod` pins Go 1.27.2, and the Dockerfile follows it (CI checks they match). The release fails unless each binary reports that compiler, and runs govulncheck on every binary; CI runs it on the source. |
| R2 | Medium | A change that took access away (owner disabled, revocation, network removed, policy restricted) could miss a request authorized just before it but registered as a stream just after, letting that request through. | An access epoch: changes bump it after saving and before closing streams; a request reads it before authorizing and after registering, and is authorized again if it moved. |
| R3 | Medium | When a new policy shortened the session lifetime, a session already expired under it got one more request through. | The session is removed and the request refused as soon as the recomputed expiry has passed. Re-authorizing a session that was removed concurrently also fails. |
| R4 | Medium | Switching to strict expiry, or shortening a strict lifetime, didn't put a deadline on connections already open. | Streams record their credential's issue time and end; a recheck sets the strict deadline from them under the current lifetime. |
| R5 | Medium | A stream opened while IP binding was off kept no network, so after binding was turned back on, removing that network's approval didn't close it. | Rechecks store each stream's current network. Removing an approval also re-judges the device's streams under the policy. |
| R6 | Medium | A date cutoff or blackout more than eight days away gave continuity-mode connections no deadline. | Exact cutoffs and blackouts are found however far away. For a weekly schedule with no change in the horizon (only possible around a clock change), the horizon itself becomes the deadline. |
| R7 | Low | Each schedule boundary lookup scanned up to 11,520 minutes, checking every blackout each time, while holding the stream lock. | Blackouts are merged so each check is a binary search. 24/7 schedules skip the minute scan. Results are cached per policy, and streams are evaluated outside the lock. Benchmark: 16.4 ms → 139 ns with 256 blackouts. |

The review also noted design boundaries, which are unchanged:
continuity mode lets an open connection outlive its token by design; a new
network is approved by device-key proof (not TOTP or WebAuthn, which aren't
implemented and are rejected in policies); IP binding uses the TCP peer
address; and the dashboard shares an origin with Jellyfin.

## v0.2.2 review: the updater

A review of v0.2.2 found that R1–R7 still reproduced there, because their
fixes merged after that tag (in yourmomsbasement/LanternFish-Auth#12). It
also found three updater problems, fixed here with regression tests that
fail when their fix is taken out:

| # | Priority | Issue | Fix |
|---|---|---|---|
| U1 | Medium | Updates from the dashboard, the timer and the command line could overlap. Each compared against the version compiled into its own process, so a delayed update could install an older release over a newer one, without allowing downgrades. | One OS lock (`/var/lib/lanternfish-update/install.lock`, root-only) covers the whole installation. Under it, the downgrade check asks the installed binary its version. Each attempt stages its binary under its own name. |
| U2 | Medium | A rollback restores the whole data file, so a revocation, a used ticket or a policy change made while the new version was being health-checked was undone. | The updater marks the new version as on probation (`/var/lib/lanternfish-update/probation`). Until it is confirmed, the Gate refuses every change to its data with `503 update_in_progress`, and the store refuses writes as a backstop. Signing in and proxying keep working. A stale marker (over 10 minutes old) is ignored. |
| U3 | Medium | Rollback ignored a failure to stop the new Gate, then overwrote its binary and data and reported `rolled_back`. | Stopping is confirmed by taking the Gate's own data file lock, which a running Gate holds. If that fails, nothing is overwritten and the status is `needs_manual_recovery`. A rollback is reported only once the restored version reports the right version and passes the health check. A failed restart after an early error is reported too. |

These fixes protect updates run by a fixed updater. The updater is the
installed binary, so the update *to* the first fixed release still runs
v0.2.2's updater. Run that one update by hand, with the timer and the
dashboard trigger paused so nothing overlaps it (as root on the Gate):

```sh
systemctl stop lanternfish-gate-update-auto.timer lanternfish-gate-update.path
lanternfish-gate update apply
systemctl start lanternfish-gate-update-auto.timer lanternfish-gate-update.path
```

Not changed: the maintainer's signing script checks the archives against the
manifest from the same GitHub release. That shows they are consistent, not
that they came from the intended commit. If the release were tampered with
before signing, the signature would vouch for it. Check that the release's
workflow run built the expected commit before signing.

## Adaptive authentication review (main at 8b9a5bb)

A review of the factor, step-up, location, MAC and override features found
five problems. It also carried two items forward from the previous review
(N1, N2). None was an unauthenticated account takeover. All are fixed. Each
regression test was checked to fail on the unfixed code, or with its fix
taken out.

| # | Severity | Issue | Fix |
|---|---|---|---|
| A1 | High | A passkey that passed the strict registration check was stored as `verified`, but the library accepts `fmt: none` (and self attestation) there without consulting the FIDO metadata. A software authenticator could satisfy `require_trusted`. | `verified` needs a certificate-chain attestation type, a non-zero AAGUID and a metadata entry the Gate confirms itself. Anything else is `not_provided` or `unverified`, and `require_trusted` refuses it. At startup, stored credentials wrongly marked `verified` are reclassified, and the network and country approvals a passkey granted those owners' devices are withdrawn. Tests use a real certificate-chain attestation fixture anchored in test metadata. |
| A2 | Medium | A registration that had passed the setup-grant check could still save a passkey after the grant was revoked (a new setup link, owner disabled). | The body is read first (bounded in size and time). The credential is checked and saved under the grant table's lock, which revocation also takes, and only for an active owner. The lock is never held across client I/O. |
| A3 | Medium | With IP binding off, unknown-location approvals and sessions were bound to an empty network, so verifying at one unplaceable address approved all of them. | Unknown locations bind to their own source (the network key, or the exact address when IP binding is off). That covers approvals, sessions, certificate grants and verification completion. Legacy approvals without a source no longer count. |
| A4 | Medium | When a temporary override expired, connections it had authorized kept running. | An override's end is a hard end, like a schedule closing. Sessions, grants and stream deadlines are bounded by it, in both stream modes. |
| A5 | Low | A step-up could produce a session without the MAC report its policy requires. | A missing or invalid required report is refused before a step-up starts. The verification carries the report's status, and session issuance (every path) checks the evidence. |
| N1 | Medium | Lowering the approval lifetime, remembered networks or session cap didn't touch existing approvals and sessions. | Publishing applies the new limits to existing state: approvals are shortened or dropped, sessions and grants on dropped networks end, and the oldest sessions beyond the cap end. Streams are then re-judged. |
| N2 | Low | The updater's backup read at most 256 MiB, so a larger data file would have been backed up truncated without warning. | Over the limit the update stops with an error, before anything is changed. |

## Review of main at 8355814 (2026-10-17)

One high, six medium and eleven low findings, plus two informational notes.
All are fixed except where noted. The Gate's regression tests started from
the reviewer's probes and were checked to fail on the unfixed code (or with
the fix taken out).

| # | Severity | Issue | Fix |
|---|---|---|---|
| H1 | High | The dashboard shared Jellyfin's origin. A script running in Jellyfin's web client (a malicious plugin or theme, or a stored XSS) in an administrator's browser could fetch `GET /_lanternfish/admin/session` for the CSRF token and drive the admin API with the session cookie. CSRF tokens only stop other origins. | `LANTERNFISH_ADMIN_LISTEN` (`:9443` in the example `gate.env` and compose file) serves the dashboard on its own port, which is a separate origin. That listener serves only `/_lanternfish/admin…` and never proxies. In this mode the main listener no longer serves the dashboard and refuses dashboard cookies altogether, since browsers send cookies regardless of port. Admin keys still work on the main listener. The firewall generator opens the admin port to the admin PC only. Without the setting, the Gate logs a warning at startup and the dashboard shows one. |
| M1 | Medium | The plugin's replay cache was a single global quota, so one device sending fast enough got every device `503`. | Each signed device ID gets a share (10,000 live nonces by default). A device over its share gets `429`; the others keep working. |
| M2 | Medium | A `tickets`-only key (the Builder's) could mint a ticket for an admin-role owner, whose devices pass "admins only" app rules, and place it in any profile. | Tickets and email invitations for an admin owner need the `owners` scope. Choosing a profile needs `policy-write`, as assigning one later does. |
| M3 | Medium | The hand-written `201.fw`/`202.fw` lacked the generator's `ipfilter` and IPSET, so a compromised guest could send as `10.20.0.2` and pass for the Gate. | `202.fw` carries `ipfilter: 1` and its own IPSET, and the guides say every guest on `vmbr1` needs the same (the generator adds them). |
| M4 | Medium | `deploy/certs` (where compose reads the TLS key) wasn't in `.gitignore` or `.dockerignore`. | Both ignore it, and `.dockerignore` ignores `*.pem` and `*.key` too. |
| M5 | Medium | `verify.sh` sent the admin key over TLS with verification off. | The key is sent only to a server presenting exactly the certificate installed in the Gate's container, checked on each connection. The script asks for the key (hidden) instead of taking it on the command line. |
| M6 | Medium | Go 1.27.2 has GO-2026-6809 (crypto/x509), which is reachable from the FIDO metadata path. | Go 1.27.3. |
| L1 | Low | A challenge's source wasn't checked when it was answered, and `client` isn't signed. Someone who read one browser sign-in could replay it from elsewhere as a native client and get a bearer token. | A challenge is answered only from the source it was issued to (an IPv4 address or IPv6 /64). One requested by the Gate's own page (`Sec-Fetch-Site: same-origin`) can't be exchanged for a native token. |
| L2 | Low | `GET admin/v2/admin-keys` answered any key. | It needs the `owners` scope. |
| L3 | Low | `GET admin/v2/subjects` returned the whole record: the sealed TOTP secret, passkey credentials and recovery-code hashes. | It returns a view: identity, role, status, and whether TOTP and passkeys are set up. |
| L4 | Low | A plugin settings save built a fresh replay cache (a replay window) and never disposed of the old verifier's keys. | One cache for the plugin's life. The replaced verifier is disposed a minute later. |
| L5 | Low | The plugin logged the decoded path, so `%0A` could forge log lines. | It logs the raw target, still percent-encoded, quoted and truncated. |
| L6 | Low | The updater's webhook didn't suppress mentions. | `allowed_mentions: {"parse": []}`, as the Gate's alerts already did. |
| L7 | Low | Dashboard sign-out had no CSRF or origin check. | It needs a same-origin JSON request. |
| L8 | Low | The plugin's `/health` exemption compared the decoded path (`/he%61lth`), and trusted a loopback address that a forwarded-headers middleware could have set. | It compares the raw target exactly, and is off whenever `X-Forwarded-For`, `X-Original-For` or `Forwarded` is present. |
| L9 | Low | Renewal-script injection keyed on the unsigned `X-Lanternfish-Auth` header. | Exactly one value, `cookie`, is required. The Gate always replaces the header. It controls only whether a script tag is added, never access, so it stays unsigned (see residual risks). |
| L10 | Low | Actions, images and the Playwright install were pinned to mutable tags. | Actions are pinned to commit SHAs. The Go, distroless and Jellyfin images are pinned by digest (Jellyfin to 12.2, which the plugin targets). Playwright installs with `npm ci` from a committed lockfile (`scripts/browser-test`). |
| L11 | Low | The docs piped `curl … \| bash` into a root shell and put admin keys on the command line. | Download, read, then run. The admin key is read hidden into a variable and passed to curl through `-H @<(printf …)`, so it stays out of history and `ps`. |
| I1 | Info | The plugin warned only once when unconfigured. | The warning repeats every ten minutes. |
| I2 | Info | Nothing tells the Gate that the plugin is missing. | Not changed in this round. `verify.sh` checks that Jellyfin refuses unsigned requests; rerun it after every Jellyfin update. |

## Reviewed, no change needed

* **Credential handling:** tickets, admin keys and session tokens are 256-bit
  random values. The Gate stores only their SHA-256 hashes. Lookups by hash
  are not timing-sensitive.
* **Crypto:** AES-256-GCM sealing binds each value to its purpose as
  associated data. ECDSA P-256 is used with context strings for each purpose.
  HMAC tags are compared with `hmac.Equal`. Challenges are single-use and
  bound to their device. The plugin's nonce cache stores only nonces from
  genuine requests.
* **mTLS:** a client certificate is accepted only if its CN names an active
  device and its public key matches the stored SPKI. Revocation therefore does
  not depend on certificate expiry.
* **Enrollment:** the ticket is checked and consumed atomically under the
  store lock, and duplicate public keys are rejected.
* **Proxying:** `lf_session` and `X-Lanternfish-Session` are stripped before
  forwarding. Incoming `X-Forwarded-*` headers are replaced. Paths under
  `/_lanternfish/` are never forwarded.
* **Web pages:** a strict CSP, `frame-ancestors 'none'`, `nosniff` and HSTS.
  The session cookie is `Secure`, `HttpOnly` and `SameSite=Lax`.
* **Deployment:** the data, key and audit files are written `0600`. The
  systemd unit is hardened. The container runs as a nonroot distroless image.

## Accepted residual risks

* **The request body is not signed** between the Gate and Jellyfin
  (documented in PROTOCOL.md). An attacker who can tamper with traffic on the
  internal link can already do worse. Keep that link on an internal-only
  bridge.
* **XSS in Jellyfin's web client** runs on the Gate's origin. It could ask
  the browser to sign with the non-extractable device key while the page is
  open, but it cannot export the key.
* **Per-IP limits are a speed bump** against distributed sources, as
  SECURITY.md says.
* **`X-Lanternfish-Auth` is not signed.** It decides only whether the plugin
  adds the renewal script to the web client page, never access (L9).
* **Without `LANTERNFISH_ADMIN_LISTEN`** the dashboard shares Jellyfin's
  origin (H1). This is kept for existing installs, and both the Gate and the
  dashboard warn about it.
