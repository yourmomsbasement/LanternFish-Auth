# LanternFish-Auth

**Lanternfish Gate** is an authenticating reverse proxy for Jellyfin. Only
enrolled devices get through, and no client ever sends a reusable secret.
Each device proves that it holds a private key that was generated on the
device and never leaves it.

* **Android TV / Fire TV:** the key lives in Android Keystore. The device
  authenticates with an mTLS client certificate that the Gate issues for that
  key.
* **Browsers, webOS, Tizen:** the key is a non-extractable WebCrypto key. The
  device signs a single-use challenge to get a 15-minute session.
* **Roku:** an HMAC secret, sealed on the Gate under a master key that is
  kept outside the data file.
* **Builds are not credentials.** A package carries only the server URL, a key
  pin and a one-time enrollment ticket that expires within hours.
* **A Jellyfin plugin** ([jellyfin-plugin/](jellyfin-plugin/)) that refuses
  any request the Gate didn't sign, so Jellyfin stays shut even if its port
  is accidentally exposed.
* Admin API for Lanternfish Builder, with its own revocable key, one-call
  revocation, an audit log, rate limiting and enrollment alerts (Discord
  webhook).

The Gate is a second lock. Keep Jellyfin's own login.

The full protocol, for client implementers, is in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Running it

**On Proxmox:** follow [deploy/proxmox/README.md](deploy/proxmox/README.md).
It covers two LXC containers, an internal-only bridge for Jellyfin, the
firewall rules, a systemd service and certbot.

### Docker (Linux)

See [deploy/docker-compose.yml](deploy/docker-compose.yml). Jellyfin publishes
no ports there, so the Gate is the only way in.

```sh
cd deploy
mkdir -p secrets certs
docker compose build
docker run --rm lanternfish-gate gen-master-key > secrets/master_key
# put fullchain.pem and privkey.pem in ./certs
docker compose run --rm gate admin-key create -name builder   # shown once
docker compose up -d
```

### Bare binary (Linux or Windows)

```sh
go build -o lanternfish-gate ./cmd/lanternfish-gate

lanternfish-gate gen-master-key > master_key          # Linux: chmod 600 it
# Windows: protect the key with DPAPI for the account that runs the Gate
lanternfish-gate gen-master-key -dpapi master_key.dpapi

export LANTERNFISH_MASTER_KEY_FILE=master_key          # or LANTERNFISH_MASTER_KEY_DPAPI_FILE
export LANTERNFISH_TLS_CERT=fullchain.pem LANTERNFISH_TLS_KEY=privkey.pem
export LANTERNFISH_UPSTREAM=http://127.0.0.1:8096      # Jellyfin bound to localhost

lanternfish-gate admin-key create -name builder
lanternfish-gate serve
```

Run `lanternfish-gate help` for every setting. The Gate terminates TLS itself
(TLS 1.3 only) because it has to see client certificates. It reloads the
server certificate when the file changes, so renewals need no restart. If you
already run a reverse proxy on port 443, forward raw TCP (TLS passthrough) to
the Gate rather than terminating TLS in front of it.

### Locking Jellyfin to the Gate

Install the Lanternfish Gate plugin in Jellyfin (see
[jellyfin-plugin/README.md](jellyfin-plugin/README.md)), then paste the
Gate's key into its settings:

```sh
lanternfish-gate upstream-key        # also printed in the Gate's log at startup
```

From then on, Jellyfin answers `403` to anything that didn't come through the
Gate, including requests made straight to port 8096.

### Enrolling a browser

```sh
curl -X POST https://your.host/_lanternfish/admin/v1/tickets \
  -H "Authorization: Bearer lfa_…" \
  -d '{"platform":"web","label":"Office laptop"}'
```

Open `https://your.host/` in the browser, paste the `ticket` when asked, and
you're in. The browser keeps a non-extractable key and signs in again on its
own after that. For long-running pages, the Jellyfin web client should include
`<script src="/_lanternfish/gate-client.js" data-autorenew></script>` so the
session renews before it expires.

## Hardening checklist

* Jellyfin must not be reachable except through the Gate. Bind it to
  `127.0.0.1` or a Docker network with no published ports, and install the
  Jellyfin plugin as a second lock.
* Keep the master key out of the data file and out of backups of it.
* Set `LANTERNFISH_ALERT_WEBHOOK` so every enrollment and revocation pings you.
* Pin your own CA, or two keys, in the clients. Never pin only the leaf
  certificate, or a renewal will brick your TVs.
* Give Lanternfish Builder its own admin key, never your Jellyfin admin
  password.
* The admin API only answers from private networks by default. Narrow
  `LANTERNFISH_ADMIN_ALLOW` to the PC that runs Builder.

## Development

```sh
go test -race ./...                                       # Gate
dotnet test jellyfin-plugin/Jellyfin.Plugin.LanternfishGate.sln   # plugin
```

The Gate uses only the Go standard library. Both test suites check
`testdata/upstream-vector.json`, a request signed by the Gate, so the two
sides can't drift apart.
