# Lanternfish Gate protocol (v1)

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
200 {"session_token": "lfs_…", "expires_at": "…"}                // valid 15 min
Set-Cookie: lf_session=lfs_…; Path=/; Secure; HttpOnly; SameSite=Lax
```

* A challenge is bound to the `device_id` it was issued for. It is deleted the
  first time anyone tries to use it, whether that attempt succeeds or fails.
* The Gate issues challenges for unknown device IDs as well, so this endpoint
  cannot be used to find out which devices exist.
* Clients renew by repeating the exchange before `expires_at`. Renewing at
  about two-thirds of the lifetime works well.
* `POST /_lanternfish/v1/logout` ends the current session.

### 4. Proxied requests

Every path outside `/_lanternfish/` is forwarded to Jellyfin once the request
is authenticated in one of these ways:

1. A **verified client certificate** from the device CA whose `CN` names an
   active `ecdsa-p256` device and whose public key matches the one on file.
2. A **session token** in the `X-Lanternfish-Session` header, or in the
   `lf_session` cookie.

Before forwarding, the Gate removes `lf_session` and `X-Lanternfish-Session`
from the request, and replaces any incoming `X-Lanternfish-Device` header with
the authenticated device ID.

The Gate then **signs** the forwarded request (see *Signed requests to
Jellyfin* below), so Jellyfin can refuse anything that did not come through
the Gate.

Unauthenticated requests receive `401 {"error": "lanternfish_auth_required"}`.
The exception is a browser page navigation (a `GET` whose `Accept` includes
`text/html`). That is redirected to the Gate's sign-in page at
`/_lanternfish/?next=<path>`.

### 5. Revocation

```
POST /_lanternfish/admin/v1/devices/{id}/revoke
```

Revocation is permanent. It drops the device's sessions immediately, and its
client certificate is refused from the next request on, because the Gate
looks up every certificate in its device list rather than trusting the
certificate's validity period.

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
  timestamp falls out of the window.

The request body is not signed, because streaming uploads can't be buffered.
The signature binds the method, target, device and time, and the nonce makes
each request single-use.

Exceptions and failure modes:

* Unsigned `GET`/`HEAD` requests to `/health` from loopback are allowed by
  default, for Docker health checks. This can be turned off.
* **No key configured: the plugin does not enforce.** It logs a warning, so
  installing the plugin can't lock you out before the key is pasted in.
* **Unparseable key: the plugin refuses everything** (`503`). A typo must not
  open the server.
* Rejections get `403` and are logged at most once every 30 seconds, with a
  running count.

## Admin API

All admin endpoints require `Authorization: Bearer lfa_…`. Admin keys are
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

## Abuse controls

* Every failed ticket, signature or admin key counts against the client IP.
  After 10 failures in 10 minutes, that IP gets `429` from all Gate endpoints
  until the window passes.
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
