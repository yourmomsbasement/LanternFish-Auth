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
* **GitHub Actions are pinned to tags, not commit SHAs.** Pinning to SHAs
  would harden the release pipeline against a compromised action.
