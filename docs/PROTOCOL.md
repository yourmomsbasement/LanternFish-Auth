# Lanternfish Gate protocol (v1 and v2)

Lanternfish Gate is an authenticating reverse proxy that sits in front of
Jellyfin. Every request has to come from an **enrolled device**. A device
proves itself by showing that it holds a key generated on the device itself,
never by replaying a stored secret.

The Gate is a second lock. Jellyfin's own login stays in place behind it.

## Goals

* **Clients never send a reusable secret.** Each device signs a fresh,
  single-use challenge, so a captured signature is useless once its challenge
  has been spent.
* **The Gate stores only public keys** for every platform except Roku. If the
  Gate's data file leaks, it does not give anyone usable credentials.
* **Built packages are not credentials.** The Builder bakes in only the server
  URL, a pin of the server key, and a one-time enrollment ticket that expires
  within hours and is burned on first use.
* **Short-lived sessions** cover the cases where a key cannot sign every
  request (a `<video>` element, Roku's video player). A session lasts
  15 minutes and is renewed by a fresh signature.
* **Revocation is immediate.** Revoking a device kills its sessions and its
  client certificate on the next request.

## Credentials by platform

| Platform | `kind` | Key storage | How each request is authenticated |
|---|---|---|---|
| Android TV, Fire TV | `ecdsa-p256` | Android Keystore (hardware-backed, non-exportable) | mTLS client certificate issued by the Gate at enrollment; can also use sessions |
| Browser, webOS, Tizen | `ecdsa-p256` | WebCrypto `CryptoKey` with `extractable: false`, kept in IndexedDB | Session obtained by signing a challenge |
| Roku | `hmac-sha256` | `roRegistry` (no secure storage available) | Session obtained by HMAC over a challenge |

Roku is the weak link. Roku apps cannot use custom client certificates or a
hardware keystore, so the Gate has to keep a copy of each Roku's secret. That
secret is sealed (AES-256-GCM) under the **master key**, which is kept
outside the data file.

ECDSA uses NIST P-256 with SHA-256. It is the one curve that both Android
Keystore and WebCrypto support everywhere. The Gate accepts signatures in
either encoding: raw `r‖s` (64 bytes, what WebCrypto produces) or ASN.1 DER
(what Android's `Signature` produces).

## Encodings

* All binary fields are base64. Standard or URL-safe alphabets are accepted,
  with or without padding. The Gate always responds with standard padded
  base64.
* Public keys are DER-encoded `SubjectPublicKeyInfo` (WebCrypto
  `exportKey("spki")`, Android `PublicKey.getEncoded()`).
* Timestamps are RFC 3339.
* Errors are returned as `{"error": "<message>"}` with a 4xx/5xx status.

## Signed messages

Each signed message starts with its own context string, so a signature made
for one purpose can never be accepted for another. Messages are UTF-8, and
`\n` is a single line feed (0x0A).

```
enroll proof:   "lanternfish-gate/v1/enroll\n" + ticket
session proof:  "lanternfish-gate/v1/session\n" + device_id + "\n" + challenge
```

For `ecdsa-p256` the proof is ECDSA-P256-SHA256 over the message bytes. For
`hmac-sha256` it is HMAC-SHA256(secret, message).

## Lifecycle

### 1. Ticket (Builder → Gate, admin API)

The Builder authenticates with its own admin API key (see *Admin API* below)
and asks for a ticket for one platform:

```
POST /_lanternfish/admin/v1/tickets
Authorization: Bearer lfa_…
{"platform": "android", "label": "Living room Shield", "ttl_seconds": 21600}

201 {"id": "tkt_…", "ticket": "lft_…", "platform": "android",
     "label": "Living room Shield", "expires_at": "…"}
```

* `platform` is one of `android`, `firetv`, `webos`, `tizen`, `web`, `roku`.
  The platform decides the credential `kind`.
* `ttl_seconds` defaults to 6 hours and is capped at 24 hours.
* The Gate stores only a SHA-256 hash of the ticket.

The Builder bakes into the package the server URL, the server-key pin and the
ticket. Nothing else.

### 2. Enrollment (device → Gate, first launch)

A browser can be sent a link `https://host/_lanternfish/#ticket=lft_…` (the
dashboard shows it as a QR code). The ticket is in the fragment, which
browsers never send to a server; the sign-in page reads it, removes it from
the address bar and offers to enroll.

**ECDSA devices** generate a P-256 key pair in their best available secure
storage. They then sign the enroll message with the new key:

```
POST /_lanternfish/v1/enroll
{"ticket": "lft_…", "public_key": "<spki b64>", "proof": "<sig b64>",
 "name": "optional display name"}

201 {"device_id": "dev_…", "kind": "ecdsa-p256",
     "certificate": "-----BEGIN CERTIFICATE-----…",
     "ca_certificate": "-----BEGIN CERTIFICATE-----…"}
```

**Roku** sends only the ticket. The Gate generates a 256-bit secret, seals it
with the master key, and returns it once:

```
POST /_lanternfish/v1/enroll
{"ticket": "lft_…"}

201 {"device_id": "dev_…", "kind": "hmac-sha256", "secret": "<b64>"}
```

The ticket is burned on success. A failed proof leaves the ticket intact, but
the failure counts toward the caller's rate limit. Every enrollment is
written to the audit log and sent to the alert webhook.

`certificate` is an X.509 client certificate for the device's own public key,
with `CN=<device_id>`, issued by the Gate's private device CA. Android uses it
as the client certificate for mTLS. Other ECDSA platforms can ignore it.

### 3. Session (device → Gate)

```
POST /_lanternfish/v1/challenge
{"device_id": "dev_…"}
200 {"challenge": "<b64, 32 random bytes>", "expires_at": "…"}   // valid 60 s

POST /_lanternfish/v1/session
{"device_id": "dev_…", "challenge": "<as received>", "signature": "<b64>"}
200 {"session_token": "lfs_…", "expires_at": "…"}                // lifetime set by the access policy
403 {"error": "access_denied", "reason": "outside_schedule"}       // signature fine, policy says no
Set-Cookie: lf_session=lfs_…; Path=/; Secure; HttpOnly; SameSite=Lax
```

* A challenge is bound to the `device_id` it was issued for. It is deleted the
  first time anyone tries to use it, whether that attempt succeeds or fails.
* The Gate issues challenges for unknown device IDs as well, so this endpoint
  cannot be used to find out which devices exist.
* Each source (an IPv4 address, or an IPv6 /64) may hold at most 32
  outstanding challenges. Past that the Gate answers `429` with `Retry-After`.
* Clients renew by repeating the exchange before `expires_at`. Renewing at
  about two-thirds of the lifetime works well. Run one renewal at a time.
* A device holds at most 16 sessions. A new session replaces the device's
  oldest, so a client that renews too often only invalidates its own old
  tokens.
* `POST /_lanternfish/v1/logout` ends the current session.
* The signed challenge is a fresh proof of the device key, and the device's
  access policy is applied to it (see *Access policy*). A correct signature
  the policy refuses gets `403 access_denied` with a `reason`, and doesn't
  count against the address's failure limit. `503 temporarily_unavailable`
  means the Gate couldn't record a network approval; try again.

### 4. Proxied requests

Every path outside `/_lanternfish/` is forwarded to Jellyfin once the request
is authenticated in one of these ways:

1. A **verified client certificate** from the device CA whose `CN` names an
   active `ecdsa-p256` device and whose public key matches the one on file.
2. A **session token** in the `X-Lanternfish-Session` header, or in the
   `lf_session` cookie.

Before forwarding, the Gate removes `lf_session` and `X-Lanternfish-Session`
from the request. It replaces any incoming `X-Lanternfish-Device` header with
the authenticated device ID, and any incoming `X-Lanternfish-Auth` with how
the request authenticated: `certificate`, `cookie` (a browser) or `header`
(an app sending `X-Lanternfish-Session`).

Authentication and the access policy are checked on every request. A client
certificate on its own no longer authorizes anything: the policy is applied
to it as to a session, and the result is remembered for at most one session
lifetime (and dropped whenever a policy is published). A request that
presents one device's certificate and another device's session token gets
`403 credential_mismatch`.

Revoking a device, disabling its owner, withdrawing a network approval, a
schedule closing, or publishing a policy that blocks the device also closes
the requests it still has open, such as WebSockets and media streams. Whether
an open stream outlives the session that started it is the policy's
`stream_expiry_mode`.

The Gate then **signs** the forwarded request (see *Signed requests to
Jellyfin* below), so Jellyfin can refuse anything that did not come through
the Gate.

Unauthenticated requests receive `401 {"error": "lanternfish_auth_required"}`,
with a `reason` when there is one (`network_changed`: the session is bound to
another network; sign in again from this one). Requests the policy refuses
receive `403 {"error": "access_denied", "reason": "…"}`. The exception is a
browser page navigation (a `GET` whose `Accept` includes `text/html`). That
is redirected to the Gate's sign-in page at
`/_lanternfish/?next=<path>[&reason=…]`, which signs in again and shows the
reason if access is still refused.

Reasons: `outside_schedule`, `owner_disabled`, `network_changed`,
`credential_mismatch`, `device_revoked`, `could_not_save_network_approval`.

### Session renewal in the web client

A browser's session lasts 15 minutes. A page load after that signs in again
silently. The Jellyfin web app, though, is a single page whose background
requests would start failing with `401` until a reload. To prevent that, the
web client's `index.html` loads
`<script src="/_lanternfish/gate-client.js" data-autorenew></script>`, which
renews the session at about two-thirds of its lifetime, and again whenever
the tab becomes visible after it was due.

The script is added only for `GET` requests to `…/web/` or
`…/web/index.html` from browsers that authenticated with a cookie
(`X-Lanternfish-Auth: cookie`). Apps never get it, because it would send them
to the browser sign-in page. It is added in exactly one place:

1. **The Jellyfin plugin**, when its *Keep browser sessions alive* setting is
   on (the default). It marks the response with `X-Lanternfish-Renewal`.
2. **Otherwise, the Gate**, as the page passes through. Set
   `LANTERNFISH_INJECT_RENEWAL=false` to stop that too.

The Gate removes the marker before the response reaches the browser. To be
able to edit the page, whichever side adds the script asks Jellyfin for it
uncompressed and unconditionally (no `If-None-Match`), and drops `ETag` and
`Last-Modified` from the edited page.

### 5. Revocation

```
POST /_lanternfish/admin/v1/devices/{id}/revoke
```

Revocation is permanent. It drops the device's sessions immediately, and its
client certificate is refused from the next request on, because the Gate
looks up every certificate in its device list rather than trusting the
certificate's validity period.

If the revocation can't be saved (for example, the disk is full), the Gate
answers `500` but still locks the device out and closes its connections
until the Gate restarts. The device list shows `"revocation_unsaved": true`.
Fix the problem and revoke again to make it permanent.

## Access policy

Every device is governed by one policy: its profile's, or the global policy.
A policy is a typed document (schema version 2), validated as a whole before
it can be published. Every publish creates a new immutable version, recorded
with who published it and why.

```json
{
  "schema_version": 2,
  "session":  {"ttl_seconds": 300, "max_per_device": 16, "stream_expiry_mode": "continuity"},
  "ip":       {"enabled": true, "match": "prefix", "ipv4_prefix_len": 32, "ipv6_prefix_len": 64,
               "on_change": "key_proof", "approval_ttl_seconds": 86400, "remembered_networks": 1},
  "schedule": {"enabled": true, "timezone": "America/Chicago",
               "weekly_windows": [{"days": ["fri", "sat"], "start": "18:00", "end": "01:00"}],
               "valid_from": null, "valid_until": null,
               "blackout_intervals": [{"start": "2026-12-24T00:00:00Z", "end": "2026-12-26T00:00:00Z", "reason": "holiday"}]}
}
```

**Session.** `ttl_seconds` (60–86400) is a session's hard lifetime; clients
renew before it ends. `stream_expiry_mode`:

* `continuity` (default): a connection that is already open, such as a
  playing stream or a WebSocket, may outlive its session. The next new
  request needs a valid session.
* `strict`: open connections close when their session expires.

Either way, revocation, a disabled owner, a schedule closing, or a published
policy that blocks the device closes them at once.

Open connections are re-judged under the policy that is current, not the one
they opened under. Switching to `strict`, or shortening `ttl_seconds`, gives
them a deadline of their session's issue time plus the new lifetime, and
closes them straight away if that has passed. Turning IP binding on binds
them to their network, so withdrawing that network's approval closes them.
A session that a shorter `ttl_seconds` has already expired is refused on its
next request.

**IP binding.** When enabled, sessions are bound to the network they were
issued on: the client address (`exact`), or the IPv4/IPv6 prefix around it
(`prefix`; /32 and /64 recommended, as IPv6 addresses rotate within a /64).
A session used from another network gets `401 network_changed`. A device may
only sign in from networks it is approved for:

* Enrolling approves the network the ticket was used from.
* `on_change: "key_proof"`: a signed challenge (or client certificate) from a
  new network approves it. This stops stolen session tokens, not a stolen
  device key.
* `on_change: "deny"`: only enrollment approves networks.
* `on_change: "additional_verification"`: the device's owner approves the new
  network with the factors in `verification.new_network_required_all`
  (authenticator code and/or passkey). See [Additional
  verification](#additional-verification-v2).

Approvals last `approval_ttl_seconds` (1 hour to 30 days). A device keeps at
most `remembered_networks` (1–10). When a new approval pushes one out, the
device's sessions and streams on that network end. Lowering either setting,
or `max_per_device`, applies to existing approvals and sessions as soon as
the policy is published. The address is the TCP
peer the Gate sees. `X-Forwarded-For` is never trusted. Behind a TCP-level
proxy every client shares the proxy's address, so IP binding means nothing
there.

Changing `match` or the prefix lengths changes what networks are called, so
existing approvals stop matching. Under `key_proof` devices re-approve on
their next sign-in; under `deny` they need re-enrolling. The preview warns
about this.

**Schedule.** Access is allowed inside `weekly_windows`, in `timezone` (an
IANA name; `Local` is refused). Times are `HH:MM`, half-open `[start, end)`.
An end at or before the start runs past midnight; `24:00` is the end of the
day. Times are judged by the wall clock in that zone:

* A local time skipped when clocks go forward never happens, so it grants
  nothing.
* A local time repeated when they go back happens twice, and both count.

`valid_from`/`valid_until` bound access to `[from, until)`, and
`blackout_intervals` deny access inside them, overriding the windows. The
Gate's clock decides, never the client's. A session never outlives the
schedule window it was issued in.

**Verification and factors.**

```json
"verification": {"new_network_required_all": ["totp"], "enrollment_required_all": [],
                 "pending_ttl_seconds": 300, "max_failed_code_attempts": 5},
"totp":     {"enabled": true, "allowed_step_drift": 1, "recovery_codes": true},
"webauthn": {"enabled": false, "attestation": "collect_if_available",
             "user_verification": "required", "allow_backup_eligible": true}
```

`*_required_all` lists factors that are *all* needed (`["webauthn", "totp"]`
means a passkey and an authenticator code). Every listed factor must be
enabled, and a policy that asks for verification must list at least one. A
publish names owners in scope who haven't set those factors up (they can't
pass verification until they do). `enrollment_required_all` makes enrolling
a device wait for its owner's approval; v1 enrollment is then refused.

* TOTP is RFC 6238 (SHA-1, 6 digits, 30 seconds). `allowed_step_drift` is 0
  or 1. A code is accepted once: a step at or before the last accepted one
  is refused. Recovery codes (10, each single use, stored as hashes) let an
  owner who lost the app set up a new one; their use is alerted.
* Passkeys need `LANTERNFISH_WEBAUTHN_RP_ID` and `_ORIGINS`. `attestation`:
  `none` (don't ask), `collect_if_available` (record what's offered), or
  `require_trusted` (only models the FIDO metadata service vouches for; needs
  `LANTERNFISH_WEBAUTHN_MDS`). "Vouches for" means certificate-chain
  attestation (`basic_full`, `attca` or `anonca`) anchored in the metadata for
  a model it lists. No attestation and self attestation never count, even
  where the library accepts them. `allow_backup_eligible: false` refuses synced
  passkeys. A passkey shows that the owner approved; it doesn't identify the
  computer.

**Location.**

```json
"geo": {"mode": "enforce", "country_allowlist": ["US", "CA"], "country_denylist": [],
        "unknown_action": "deny", "new_country_action": "additional_verification",
        "exempt_networks": ["192.168.0.0/16"]}
```

Countries come from a local MaxMind-format database (`LANTERNFISH_GEOIP_DB`,
e.g. GeoLite2-Country), never an online service. `observe` records the
country in the audit log; `enforce` applies the lists (the deny list wins) and
the actions (`deny`, `additional_verification` or `observe`):

* `unknown_action`: private, unlisted and stale-database addresses are
  *unknown*, never assumed to be home. An unknown approval is tied to the
  network it was made on, or, with IP binding off, to the exact address. So
  are sessions issued there: verifying at one unknown address approves no
  other.
* `new_country_action`: a country the device hasn't been approved in (30
  days). A device's first country is recorded without asking.
* `exempt_networks` skip country rules (your LAN, a VPN you run).

Sessions are checked per request: one used from another country is refused.
VPNs and mobile carriers often show the wrong country, so treat this as a
signal, not proof.

**MAC reports.**

```json
"mac": {"collect": true, "require_report": false, "on_change": "additional_verification",
        "max_observation_age_seconds": 600}
```

Only native apps can report a MAC address; browsers can't. A report is signed
with the device key along with the session challenge (see [v2
session](#v2-session)), and stored only as an HMAC tag keyed from the master
key. `on_change` when a reported address changes: `observe`,
`additional_verification`, or `reenroll` (the device is suspended until an
administrator resets or unsuspends it). `require_report` can only be set on a
profile or device policy, never globally, and never applies to browsers. It
applies to every way of getting a session: a step-up doesn't stand in for the
report. A
report shows that the app reported an address; a modified client can lie.

**Precedence.** A device's own policy (an *override*, set by an
administrator with a reason and optional end time) comes first, then its
profile's, then the global policy. Revocation, a disabled owner and a
suspended device are always checked first, and country deny lists and
schedules are checked before any step-up, so verification never overrides a
hard rule. An override's end time is a hard end like a schedule closing: sessions
and connections it authorized end then, in either stream mode, and the next
request is judged under the policy that applies after it.

**Upgrading.** A data file from before policies gets a default owner
(`sub_default`) for its devices and tickets, and a global policy equal to the
old behaviour: sessions of `LANTERNFISH_SESSION_TTL`, no IP binding, no
schedule. Nothing changes until you publish a policy. After that,
`LANTERNFISH_SESSION_TTL` has no effect.

**Policy changes** take effect immediately. Sessions issued under an older
version are re-checked on their next request, and can only get shorter.
Open streams are re-checked when the policy is published.

## Additional verification (v2)

v1 clients keep working unchanged: where a policy asks for verification,
`/v1/session` answers `403 additional_verification_required` and they can't
continue. v2 clients can.

<a id="v2-session"></a>**Session.** `POST /_lanternfish/v2/session` takes the
v1 body plus `client` (`"browser"`: the session is only set as the HttpOnly
cookie; `"native"`, the default: also returned as `session_token`) and an
optional `mac_report`:

```json
{"device_id": "dev_…", "challenge": "…", "signature": "…", "client": "native",
 "mac_report": {"interface_kind": "wifi", "mac": "3c:22:fb:01:02:03", "randomized": false,
                "collected_at": 1792000000, "signature": "…"}}
```

`interface_kind` is `wifi`, `ethernet`, `cellular` or `other`. The report's
signature is over `"lanternfish-gate/v2/mac\n" + device_id + "\n" + challenge
+ "\n" + digest`, where `digest` is the hex SHA-256 of `interface_kind`, the
lower-case colon form of `mac`, `yes`/`no`/`unknown`, and `collected_at` in
decimal, each preceded by its length as a 4-byte big-endian integer.
All-zero, all-ones and `02:00:00:00:00:00` addresses are refused. Replies add
`expires_in_seconds`.

When verification is needed the reply is:

```json
403 {"error": "additional_verification_required", "verification_id": "lfv_…",
     "required_all": ["totp"], "reason": "network_changed", "expires_in_seconds": 300}
```

`verification_id` is a short-lived handle, not a session: it authorizes
nothing upstream. Reasons: `network_changed`, `new_country`,
`location_unknown`, `mac_changed`, `new_device`. A device has at most 3
pending verifications.

**Steps.** All under `/_lanternfish/v2/verification/{id}`, JSON, same-site
only:

| Method & path | Purpose |
|---|---|
| `GET` | Status: `required_all`, `done`, device, network, country, key fingerprint, `expires_in_seconds`, `attempts_left` |
| `POST …/totp` | `{code}`; `401 code_not_accepted` with `attempts_left` |
| `POST …/webauthn/options` then `…/webauthn/finish` | A passkey assertion for this verification only (each challenge is used once) |
| `POST …/recovery` | `{code}`: a recovery code. Returns a `setup_grant` for `/_lanternfish/setup` to set up a new authenticator; it doesn't complete the verification |
| `POST …/pairing` | Returns `pairing_code` (`XXXX-XXXX`, single use, 10 minutes) for approving on a phone at `/_lanternfish/pair` |
| `POST …/complete` | A fresh signed challenge (`{device_id, challenge, signature, client}`) once every factor is done → the session reply |

Wrong codes count against the verification (`max_failed_code_attempts`, then
it ends) and the owner (10 per 15 minutes across all their verifications).
`complete` requires the same device, the same network (and country) the
verification started on, and the same policy version; otherwise it answers
`409 verification_restart` with a reason, and the client starts again.
Completing approves the network (and country) as *verified*. Revoking the
device, disabling the owner or a new policy version cancels pending
verifications.

On a TV, the app shows the pairing code and `https://host/_lanternfish/pair`;
the owner enters the code on their phone, sees the device name, network,
country and key fingerprint, and passes the factors there. The TV polls the
status and completes when it's done. The code only finds the verification;
every factor is still required.

**Enrollment.** `POST /_lanternfish/v2/enrollment/begin` takes the v1 enroll
body. Without `enrollment_required_all` it enrolls at once (`201 {"status":
"enrolled", "device": …}`). Otherwise it reserves the ticket and answers `202
{"status": "verification_required", "verification_id": …, "required_all":
…}`. Another attempt with that ticket gets `409` until the reservation ends.
After the owner approves, `POST
/_lanternfish/v2/enrollment/{id}/finish` with `{ticket, proof}` (the same key)
enrolls the device and approves its network. Repeating `finish` returns the
same device, so a lost reply can be fetched again.

Tickets can be bound to a key: `key_fingerprint` (from the device's public
key, as shown by the app) on ticket creation makes any other key's enrollment
fail.

**Factor setup.** Owners set up factors with a setup link from an
administrator (`/_lanternfish/setup#grant=…`, 30 minutes, one live link per
owner; the grant is in the URL fragment and never reaches a server log).
Endpoints under `/_lanternfish/v2/factors/`: `setup/info`, `totp/setup` (secret
and `otpauth://` URI), `totp/confirm` (`{grant, code}` → 10 recovery codes,
shown once), `recovery-codes` (new set, old ones stop working),
`passkey/options` and `passkey/finish` (grant in `X-Lanternfish-Grant`),
`done`. Replacing an existing authenticator needs a link issued with
`replace_totp` or a recovery-code grant.

## Signed requests to Jellyfin

Network isolation is the first lock on the Gate→Jellyfin link. The
Lanternfish Jellyfin plugin (`jellyfin-plugin/`) is the second: it refuses
every request that does not carry a valid Gate signature, so a misconfigured
port or a forgotten Docker `ports:` line doesn't open Jellyfin to the network.

On first start, the Gate creates an ECDSA P-256 **upstream signing key**,
sealed under the master key. `lanternfish-gate upstream-key` prints its public
half (base64 SPKI), which goes into the plugin's settings. Jellyfin holds only
that public key, so a Jellyfin backup or compromise can't be used to forge
Gate traffic.

Every forwarded request carries:

| Header | Value |
|---|---|
| `X-Lanternfish-Gate-Timestamp` | Unix seconds |
| `X-Lanternfish-Gate-Nonce` | 32 random bytes, base64url |
| `X-Lanternfish-Device` | authenticated device ID |
| `X-Lanternfish-Gate-Signature` | base64 raw `r‖s` ECDSA-P256-SHA256 over the message below |

```
"lanternfish-gate/v1/upstream\n" + METHOD + "\n" + target + "\n" + timestamp + "\n" + nonce + "\n" + device_id
```

`target` is the request target exactly as sent on the wire: the escaped path
plus `?query`. The plugin reads it from ASP.NET Core's `RawTarget`.

The plugin accepts a request only when:

* the signature verifies against one of its configured keys (listing more
  than one key allows rotation);
* the timestamp is within ±30 seconds (configurable) of Jellyfin's clock, so
  keep both machines on NTP;
* the nonce has not been seen before. Nonces are remembered until their
  timestamp falls out of the window. The cache holds up to 200,000 nonces;
  when it is full of unexpired ones the plugin answers `503` rather than
  forget a nonce early.

The request body is not signed, because streaming uploads can't be buffered.
The signature binds the method, target, device and time, and the nonce makes
each request single-use.

Exceptions and failure modes:

* Unsigned `GET`/`HEAD` requests to exactly `/health` from loopback are
  allowed by default, for Docker health checks. This can be turned off.
* **No key configured: the plugin does not enforce.** It logs a warning, so
  installing the plugin can't lock you out before the key is pasted in.
* **Unparseable key: the plugin refuses everything** (`503`). A typo must not
  open the server.
* Rejections get `403` and are logged at most once every 30 seconds, with a
  running count.

## Admin API

Admin endpoints answer only from the networks in `LANTERNFISH_ADMIN_ALLOW`
(default: loopback and private ranges). From anywhere else they return `404`,
as if they didn't exist, and such probes don't count toward the rate limit.
Inside those networks, they also require `Authorization: Bearer lfa_…`. Admin keys are
created offline with `lanternfish-gate admin-key create`, and the Gate stores
only their hashes. Give the Builder its own key. Never give it your Jellyfin
admin password.

| Method & path | Purpose |
|---|---|
| `POST /_lanternfish/admin/v1/tickets` | Create an enrollment ticket |
| `GET /_lanternfish/admin/v1/tickets` | List pending tickets (no ticket values) |
| `DELETE /_lanternfish/admin/v1/tickets/{id}` | Cancel a pending ticket |
| `GET /_lanternfish/admin/v1/devices` | List devices |
| `POST /_lanternfish/admin/v1/devices/{id}/revoke` | Revoke a device |

Tickets also take `subject_id` (the owner; default `sub_default`),
`profile_id` (the device's policy profile; default: the global policy) and
`key_fingerprint` (bind the ticket to one device key).

**Scopes.** Admin keys can be limited with `admin-key create -scopes`:
`tickets`, `devices`, `policy-read`, `policy-write`, `owners`,
`factor-recovery`, `audit`, `updates`. A key without scopes (older keys
included) has all of them. A request outside the key's scopes gets `403
scope_required`.

**Re-verification.** Link an admin key to an owner with the `admin` role
(`admin-key link ID SUBJECT`, or the dashboard's Security tab). Once that owner
has an authenticator app, dashboard changes in the sensitive scopes
(`policy-write`, `owners`, `factor-recovery`, `updates`) answer `403
recent_verification_required` unless the dashboard session passed `POST
/_lanternfish/admin/verify {code}` in the last 5 minutes. Bearer-key requests
(the Builder, scripts) aren't affected; protect those keys with scopes.

**Break-glass.** If the admin owner loses their authenticator and recovery
codes, stop the Gate and run `lanternfish-gate factor reset SUBJECT` on the
host. It removes that owner's authenticator, recovery codes and passkeys and
is audited.

The admin dashboard at `/_lanternfish/admin/` uses the same API. `POST
/_lanternfish/admin/session` with `{"key": "lfa_…"}` (JSON content type,
same-origin) sets a `__Secure-lf_admin` cookie (HttpOnly, SameSite=Strict,
path `/_lanternfish/admin`, bound to the client address, 15 minutes idle,
8 hours at most) and returns a `csrf` token. Requests authenticated by that
cookie are refused if the browser marks them cross-site, and changes
(anything but `GET`) must carry the token in `X-Lanternfish-CSRF`. Revoking
the admin key ends its dashboard sessions. `GET /_lanternfish/admin/session`
returns the current session; `POST /_lanternfish/admin/logout` ends it.

Admin API v2 (same guard):

| Method & path | Purpose |
|---|---|
| `GET /_lanternfish/admin/v2/policy` | Current global and profile policies |
| `GET /_lanternfish/admin/v2/policy/recommended` | The recommended starting policy |
| `GET /_lanternfish/admin/v2/policy/history?scope=` | Published versions, newest first |
| `POST /_lanternfish/admin/v2/policy/preview` | `{scope, policy}` → validity, problems, upcoming schedule changes, devices affected |
| `PUT /_lanternfish/admin/v2/policy` | `{scope, expected_version, reason, policy}`; `409` if `expected_version` isn't current, `422` with `problems` if invalid |
| `GET`/`POST /_lanternfish/admin/v2/profiles` | List; create `{name, policy?}` (defaults to a copy of the global policy) |
| `DELETE /_lanternfish/admin/v2/profiles/{id}` | Delete; its devices fall back to the global policy |
| `GET`/`POST /_lanternfish/admin/v2/subjects` | List; create `{name, role}` |
| `POST /_lanternfish/admin/v2/subjects/{id}/disable` / `enable` | Disabling ends its devices' sessions and streams |
| `GET /_lanternfish/admin/v2/devices/{id}` | Device detail: owner, profile, policy version, approved networks, live sessions |
| `PUT /_lanternfish/admin/v2/devices/{id}/profile` | `{profile_id}` (`""` for global) |
| `DELETE /_lanternfish/admin/v2/devices/{id}/networks/{nid}` | Withdraw a network approval; its sessions and streams end |
| `GET /_lanternfish/admin/v2/audit?q=&limit=` | Recent audit entries, newest first (`q` filters by text) |
| `POST /_lanternfish/admin/v2/qr` | `{text}` → QR code modules, for showing an enrollment link |
| `GET /_lanternfish/admin/v2/update?refresh=1` | Running version, newest verified release, recent releases and their signature status, the updater's last result |
| `POST /_lanternfish/admin/v2/update` | `{version}`: ask the updater to install the newest verified release (`202`); see [RELEASES.md](RELEASES.md) |
| `GET /_lanternfish/admin/v2/status` | What this Gate supports: passkeys (RP ID, origins, metadata), GeoIP database health |
| `GET /_lanternfish/admin/v2/admin-keys` | Admin keys with scopes and linked owners (no secrets) |
| `GET /_lanternfish/admin/v2/subjects/{id}/factors` | An owner's authenticator app, passkeys and recovery codes left |
| `POST /_lanternfish/admin/v2/subjects/{id}/setup-link` | `{replace_totp?}` → `{path, expires_at}`; cancels the owner's previous link |
| `DELETE /_lanternfish/admin/v2/subjects/{id}/factors/totp` | Remove the authenticator app and recovery codes |
| `DELETE /_lanternfish/admin/v2/subjects/{id}/factors/passkeys/{n}` | Remove a passkey |
| `PUT`/`DELETE /_lanternfish/admin/v2/devices/{id}/override` | `{policy, reason, expires_at?}`: the device's own policy |
| `POST /_lanternfish/admin/v2/devices/{id}/reset-enrollment` | Revoke the device and return a replacement ticket |
| `POST /_lanternfish/admin/v2/devices/{id}/unsuspend` | Lift a suspension (after a MAC change under `reenroll`) |
| `POST /_lanternfish/admin/verify` / `link` | Dashboard re-verification `{code}`; link the key to an admin owner `{subject_id}` |

## Abuse controls

* Every failed ticket, signature or admin key counts against the client's
  source: its IPv4 address, or the IPv6 /64 it is in. After 10 failures in
  10 minutes, that source gets `429` from all Gate endpoints until the window
  passes. The Gate tracks up to 10,000 sources at a time.
* Request bodies to the Gate's own endpoints must arrive within 10 seconds.
* Every enrollment, ticket, revocation and failure is appended to the audit
  log (JSON lines).
* Enrollments and revocations are posted to `LANTERNFISH_ALERT_WEBHOOK`, using
  a Discord-compatible `{"content": "…"}` body.

## Transport

* The Gate terminates TLS itself, with TLS 1.3 only. It needs to, because it
  has to see the client certificates. It sends
  `Strict-Transport-Security: max-age=31536000` on every response.
* The server certificate is reloaded from disk when it changes, so
  Let's Encrypt renewals need no restart.
* **Pinning.** Clients should pin a key that survives renewal: the SPKI of
  your own CA, or at least two keys (the current one and a pre-generated
  backup). Pinning only the leaf certificate's key bricks every TV at the
  first renewal that rotates the key.
* **Jellyfin must not be reachable except through the Gate.** Bind it to
  `127.0.0.1` or to a Docker network with no published ports. A gate that can
  be routed around protects nothing. See `deploy/docker-compose.yml`. The
  Jellyfin plugin backs this up by refusing unsigned requests.

## Secrets at rest

| Secret | Where it lives |
|---|---|
| Master key (32 bytes) | `LANTERNFISH_MASTER_KEY`, `LANTERNFISH_MASTER_KEY_FILE` (Docker secret), or `LANTERNFISH_MASTER_KEY_DPAPI_FILE` (Windows DPAPI). Never the data file. |
| Device CA private key | Data file, sealed with the master key |
| Upstream signing key | Data file, sealed with the master key (Jellyfin holds only the public half) |
| Roku secrets | Data file, sealed with the master key, with the device ID as associated data |
| Tickets, admin keys | Data file, SHA-256 hashes only |
| Device public keys | Data file, in plain form (not secret) |

The data file also holds a sealed check value, so the Gate refuses to start
with the wrong master key rather than quietly failing later.
