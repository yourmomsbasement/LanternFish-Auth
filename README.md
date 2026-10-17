# LanternFish-Auth

**Lanternfish Gate** is an authenticating reverse proxy for Jellyfin. Only
enrolled devices get through, and no client ever sends a reusable secret.
Each device proves that it holds a private key that was generated on the
device and never leaves it.

* **Android TV / Fire TV:** the key lives in Android Keystore. The device
  authenticates with an mTLS client certificate that the Gate issues for that
  key.
* **Browsers, webOS, Tizen:** the key is a non-extractable WebCrypto key. The
  device signs a single-use challenge to get a short-lived session.
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

For family Seerr access, private admin tools, backend Jellyfin integration and
narrow NAS firewall rules, see [the media stack guide](docs/MEDIA-STACK.md).
Additional opt-in controls are described in [optional hardening](docs/OPTIONAL-HARDENING.md).

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
own after that. While the Jellyfin web app is open, its Gate session (15
minutes by default, or whatever the access policy sets) renews in the
background. The renewal script is added to the web client by
the Jellyfin plugin, or by the Gate when the plugin doesn't (see
[Session renewal](docs/PROTOCOL.md#session-renewal-in-the-web-client)).

### Admin dashboard

From a computer on an admin network (`LANTERNFISH_ADMIN_ALLOW`), open
`https://your.host/_lanternfish/admin/` and paste an admin key. From there you
can create enrollment tickets (with a QR code a phone can scan to enroll),
see and revoke devices (or reset their enrollment), remove their approved
networks, give one device its own policy, edit and publish access policies
with a weekly preview, manage profiles, owners and their sign-in factors, and
read the audit log. From anywhere else the page answers `404`.

The key is exchanged for a session cookie that scripts can't read, bound to
your address, ending after 15 minutes idle or 8 hours. Every change also
needs a per-session token, so other sites open in the same browser can't act
through it.

### Access policy

Out of the box the Gate behaves as before: 15-minute sessions, from any
network, at any time. To switch to the recommended policy (5-minute sessions
bound to the network they were issued on, with a new network approved by a
fresh key signature), fetch it, look at what it would do, and publish it:

```sh
H='Authorization: Bearer lfa_…'; A=https://your.host/_lanternfish/admin/v2
curl -s -H "$H" $A/policy/recommended > rec.json
curl -s -H "$H" $A/policy | jq .global.version          # current version, e.g. 1
jq '{policy: .policy}' rec.json | curl -s -H "$H" -X POST $A/policy/preview -d @-
jq '{expected_version: 1, reason: "recommended policy", policy: .policy}' rec.json \
  | curl -s -H "$H" -X PUT $A/policy -d @-
```

Schedules, blackouts, per-device profiles and owners are described in
[Access policy](docs/PROTOCOL.md#access-policy).

### Approving new networks, devices and countries

A policy can ask the device's owner to approve a sign-in instead of just
allowing or refusing it, for example from a network the device hasn't used,
when adding a device, or from a new country:

1. **Give owners a factor.** On the dashboard's Owners tab, open *Sign-in
   factors* and create a setup link (show the QR code in person, or send the
   link privately). The owner adds an authenticator app (and gets 10
   recovery codes) and/or a passkey. Passkeys need
   `LANTERNFISH_WEBAUTHN_RP_ID` and `LANTERNFISH_WEBAUTHN_ORIGINS` (see
   [gate.env.example](deploy/systemd/gate.env.example)).
2. **Ask for it in the policy.** Under *Network binding*, set *New network* to
   *ask the owner to verify*, and tick the factors under *Additional
   verification*. The preview lists owners who haven't set them up yet.
3. **Signing in.** A browser shows a page asking for the code or passkey. A
   TV shows a short code to approve from a phone at
   `https://your.host/_lanternfish/pair`.

Country rules need a local GeoLite2-Country database: create a free MaxMind
account, install `geoipupdate`, and set `LANTERNFISH_GEOIP_DB`. Locations
from VPNs and mobile networks are often wrong, so start with *record only*.
Native apps can also report the device's MAC address (signed with the
device key); requiring that belongs on a profile for TVs, never globally.

**Protect the dashboard too.** Create an owner with the *admin* role, give it
an authenticator app, and link your admin key to it on the Security tab.
Changes to policy, owners' factors and updates then need a code from that
app (at most every 5 minutes). Give the Builder a key limited to what it needs:
`lanternfish-gate admin-key create -name builder -scopes tickets,devices`.
If you lose the authenticator and its recovery codes, stop the Gate and run
`lanternfish-gate factor reset SUBJECT_ID` on the host.

Old apps (protocol v1) keep working wherever no approval is needed. Details:
[Additional verification](docs/PROTOCOL.md#additional-verification-v2).

### Network settings and more applications

The dashboard's **Network** tab changes, without editing `gate.env` or
restarting:

* **Jellyfin's address**, with a *Test* button that checks the Gate can reach it.
* **The sign-in host**: Jellyfin's public name, where browsers enroll.
* **The admin networks** the dashboard and admin API answer from. Your own
  address must stay in the list. If you lock yourself out anyway, stop the
  Gate and run `lanternfish-gate settings reset -admin-only` on the host.

It also lists the listen address and the TLS certificate's names and expiry,
which stay in `gate.env`.

**Putting another web application behind the Gate** (Sonarr, Radarr,
Jellyseerr, Home Assistant…):

1. Give it its own hostname, e.g. `sonarr.example.com`, pointing at the Gate
   like Jellyfin's. Apps get hostnames, not sub-paths: most break under a path.
2. Add the hostname to the Gate's certificate (see
   [the Proxmox guide](deploy/proxmox/README.md#adding-more-applications)).
3. Let the Gate reach the application, and nothing else reach it: the
   dashboard's **Firewall** tab writes the Proxmox rules for you (below).
4. On the Network tab, *Add application*: its name, hostname, and the
   address the Gate reaches it at (`http://10.20.0.5:8989`). Optionally limit
   it to some owners. Save.

Devices, owners, policies, schedules and approvals are the same as Jellyfin's.
The first time a browser opens the application it is sent to the sign-in host,
signs in there as usual, and comes back *linked*. That gives it its own key for
the application, shown on the Devices tab, which stops working when its device
is revoked. Keep the application's own login on: the Gate decides who may
reach it, not who they are inside it. Phone apps that talk to these
applications with their own API keys (LunaSea, nzb360…) can't sign in to the
Gate.

### Proxmox firewall rules

The **Firewall** tab describes your Proxmox layout and turns it into a script
for the Proxmox host. It starts from the Network tab's addresses:

* the Gate's container ID, LAN interface and internal address, and who may
  SSH to it;
* each container or VM behind it: ID, address, ports, whether the Gate reaches
  it, which other guests it talks to (Sonarr → qBittorrent), and whether to
  keep it off your LAN.

The script writes `/etc/pve/firewall/<ID>.fw` for each guest and keeps a backup
of any file it replaces. Each guest is limited to its own address, so a
compromised guest can't pose as the Gate. Run it with `DRY_RUN=1` first to see
the files. It checks, but never changes, the datacenter firewall switch and
each NIC's `firewall=1`, because flipping those could lock you out. The tab
also warns when an address the Gate uses isn't covered.

### Updates

Releases are signed with the maintainer's offline key, whose public half is
built into every Gate, so anyone running one gets verified updates without
setting anything up: from the dashboard's Updates tab, or nightly if you
turn that on.
A failed update rolls itself back. Setup and the release routine are in
[docs/RELEASES.md](docs/RELEASES.md).

## Hardening checklist

* Jellyfin must not be reachable except through the Gate. Bind it to
  `127.0.0.1` or a Docker network with no published ports, and install the
  Jellyfin plugin as a second lock.
* Keep the master key out of the data file and out of backups of it.
* Set `LANTERNFISH_ALERT_WEBHOOK` so every enrollment and revocation pings you.
* Pin your own CA, or two keys, in the clients. Never pin only the leaf
  certificate, or a renewal will brick your TVs.
* Give Lanternfish Builder its own admin key, limited with `-scopes`, never
  your Jellyfin admin password.
* Link your own admin key to an admin owner with an authenticator app, so
  dashboard changes that weaken access need a code.
* The admin API only answers from private networks by default. Narrow
  `LANTERNFISH_ADMIN_ALLOW` to the PC that runs Builder.

## Installing the Jellyfin plugin from Jellyfin

Once you can reach Jellyfin's dashboard through the Gate, add this repository
under **Dashboard → Plugins → Repositories**:

```
https://github.com/yourmomsbasement/LanternFish-Auth/releases/latest/download/manifest.json
```

Jellyfin then installs and updates the plugin itself. The first install is
manual; see [jellyfin-plugin/README.md](jellyfin-plugin/README.md).

## Releases

Push a tag like `v0.2.0` (or `v0.2.0-rc1` for a pre-release), or publish a
release with a `v*` tag on GitHub, and the
[release workflow](.github/workflows/release.yml) does the rest. It runs CI,
builds the Gate for Linux (amd64, arm64) and Windows, builds the plugin and
its repository manifest, and publishes everything with `SHA256SUMS` and the
release manifest. Then sign it from your admin PC with
`scripts/sign-releases.sh sign`, which checks every file and uploads the
signature ([docs/RELEASES.md](docs/RELEASES.md)).

## Development

```sh
go test -race ./...                                       # Gate
dotnet test jellyfin-plugin/Jellyfin.Plugin.LanternfishGate.sln   # plugin
```

The Gate uses only the Go standard library. Both test suites check
`testdata/upstream-vector.json`, a request signed by the Gate, so the two
sides can't drift apart.

## Security and license

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

Licensed under the [GNU General Public License v3.0](LICENSE). The Jellyfin
plugin builds against Jellyfin's GPL-3.0 libraries.

Email invitations can be submitted through an internal Postfix relay. Tickets
and invitations can optionally authorize a recipient to create a Jellyfin
account with administrator-selected libraries and permissions. See
[Email enrollment and Jellyfin accounts](docs/email-enrollment.md) for setup,
security boundaries, failure handling and API details.

Policies can require fresh authenticator or passkey verification after a
configurable interval, independently of session renewal. See
[Periodic reauthentication](docs/reauthentication.md).

Jellyfin web query state is invalidated selectively across Gate/frontend upgrades,
while enrollment keys and login data are preserved. See
[Jellyfin query cache compatibility](docs/jellyfin-query-cache.md).
