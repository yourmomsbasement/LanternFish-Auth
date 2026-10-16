# Family requests and private administration

Use the Network tab for public hostname routes and the Firewall tab for
backend connections. Plans are saved configuration: **Generate script**,
review it with `DRY_RUN=1`, then apply it on Proxmox. Saving a plan does not
change the running firewall. The Gate remains the only public entry point.

For opt-in mTLS, API permissions, explicit owner access modes, rollback, extra
LAN blocks, encrypted recovery and resource alerts, see
[optional hardening](OPTIONAL-HARDENING.md).

## Public applications

| App | Hostname | Owners allowed | Backend port |
| --- | --- | --- | --- |
| Jellyfin | your existing sign-in hostname | every enrolled owner | 8096 |
| Seerr / Jellyseerr | `requests.cindertrace.com` | every enrolled owner | 5055 |
| Radarr | optional `radarr.cindertrace.com` | select your admin owner only | 7878 |
| Sonarr | optional `sonarr.cindertrace.com` | select your admin owner only | 8989 |
| Prowlarr | optional `prowlarr.cindertrace.com` | select your admin owner only | 9696 |
| Bazarr | optional `bazarr.cindertrace.com` | select your admin owner only | 6767 |
| qBittorrent / SABnzbd | none by default | backend access only | configured Web UI/API port, often 8080 |

Add Seerr as an application on the Network tab, with its private upstream
address, **Enabled**, **Send the public hostname**, and browser renewal on.
Choose **Everyone** for its access mode, subject to the usual device and owner
policies. Existing records without an explicit mode retain their old behavior. Leave Lanternfish identity headers off for
Seerr and the admin tools; those headers are intended for the Jellyfin plugin.
Set the Jellyfin sign-in hostname, DNS records and certificate coverage for
each public app hostname.

For each optional admin hostname, choose **Admins only**, or **Selected owners**
and tick only your admin owner. An empty selected list denies everyone.
Legacy records without a mode still interpret an empty owner list as everyone. Jellyfin and Seerr retain their own
user accounts and logins.

Alternatively, give the admin tools no Network-tab application or public DNS
entry. Reach them over your VPN and add only the VPN client address/range to
that guest's **Also allow from** field. Leave **The Gate reaches it** off for
VPN-only tools. LunaSea/nzb360 use app API keys and do not support the Gate's
device sign-in protocol, so use this direct VPN route for them. Scope VPN
rules to the intended admin devices rather than a whole shared VPN if possible.

## Directed backend connections

Set **Talks to** on the app in the left column. Each tick permits connections
to the destination guest's listed TCP ports. It permits replies, but does
not permit the destination to initiate connections back. Prowlarr therefore
needs separate ticks in both directions with Radarr/Sonarr.

| From | To |
| --- | --- |
| Seerr | Radarr, Sonarr |
| Radarr, Sonarr | Prowlarr, configured download client |
| Prowlarr | Radarr, Sonarr |
| Bazarr | Radarr, Sonarr |
| Prowlarr | optional FlareSolverr on TCP 8191 |

Give each guest only the ports its peers need. Keep **Keep it off my LAN**
on. Internet metadata/indexer access remains available; private destinations
need a specific guest, service, or external-target allowance. If DNS uses a
private resolver, add that resolver's exact IP and TCP/UDP 53 as external
targets too. No guest needs a direct **Talks to Jellyfin** rule: the plugin
will reject unsigned requests.

## Seerr's internal Jellyfin connection

This optional route is disabled by default. It is separate from public TLS
and exposes only a proxy to Jellyfin, with no Gate sign-in/admin API. To enable
it, set these deployment variables in `gate.env` and restart the Gate:

```sh
LANTERNFISH_SERVICE_NETWORK=10.20.0.0/24
LANTERNFISH_SERVICE_LISTEN=10.20.0.2:8096
LANTERNFISH_SERVICE_CLIENTS=seerr=10.20.0.4
```

These are examples: use the Gate's actual address on an isolated backend
bridge and Seerr's static address. The listener must be a literal private IP
and port within the explicitly configured subnet; wildcards, public addresses,
loopback, broad public networks and hostnames are rejected. Each client must
have a unique lowercase name and a distinct private IP on that same subnet.
There must be 1–32 clients. To disable it, remove all three variables and restart.

In the Firewall tab, set the same internal network/address, **Internal service
port** `8096`, and the Gate's actual **Internal interface**, usually `net1`,
separate from its LAN NIC. Tick **Internal Jellyfin service access** only on
Seerr. Keep **The Gate reaches it** enabled on Jellyfin for port 8096 and on
Seerr for port 5055. Generate, review and apply the rules. The generator adds
Seerr → Gate TCP 8096 before Seerr's private-network drops, and an inbound rule
on the Gate's internal NIC from Seerr's exact IP. It warns when the plan and
`gate.env` disagree. It never silently adds authorized peers.

Point Seerr's Jellyfin server URL at **`http://10.20.0.2:8096`**, including the
literal address and port. Use normal Jellyfin credentials. Do not point it
at Jellyfin directly or at the public sign-in URL. Requests retain Jellyfin
Authorization/API keys and bodies, receive a fresh Gate signature with the
identity `service:seerr`, and are forwarded to the current Jellyfin upstream.
Jellyfin's plugin stays strict, and Jellyfin's own authentication still applies.
There is no device/owner policy on this service route: the named backend is
trusted to call Jellyfin's API with its own credentials.

Authorization uses the actual TCP peer, never `Forwarded`, `X-Forwarded-For`
or the Host header. The Host must additionally match the configured literal
listener address/port (standard HTTP/HTTPS port omission is supported). Gate credentials/cookies and supplied Lanternfish headers are stripped.
Requests to Gate endpoints, CONNECT/TRACE and protocol upgrades are rejected.
Calls are bounded to two minutes; this listener is for backend API integration,
not long-running playback or WebSocket clients. Audit events record service,
peer address and HTTP status, excluding URLs, queries, bodies and credentials.
They use the existing rotating audit log; size it for library scan traffic.

**Source IP trust requires network enforcement.** Put this listener on the
isolated backend bridge, never a general LAN/VPN interface, and do not publish,
NAT, or forward its port publicly. Its HTTP traffic carries Jellyfin credentials,
so this bridge must be trusted and isolated from untrusted listeners. Include
all guests on that bridge in an enforced firewall plan, with static unique
addresses, their correct NICs and source-address filtering. Enable the
Proxmox datacenter firewall and `firewall=1` on every guest NIC, and verify the
actual running rules. An unfiltered guest on the same bridge can spoof a
trusted IP; an allow-list in the Gate alone cannot prevent that. See
[Proxmox's IP filter documentation](https://pve.proxmox.com/pve-docs/chapter-pve-firewall.html#pve_firewall_ip_sets).

Radarr/Sonarr's optional Jellyfin notification integration can use its own
named service client and firewall tick if needed. Prefer Jellyfin library
monitoring when that suffices; do not authorize every backend by default.

## Narrow NAS access

On each guest that mounts media, add an **External target**: the NAS's exact
static IP, TCP/UDP protocol and specific destination ports. Examples:

- SMB: TCP 445.
- NFSv4: TCP 2049.
- NFSv3: configure fixed ports for the required NAS RPC services, then allow
  only those ports/protocols; TCP 2049 alone is insufficient.

There are at most 16 targets per guest and 16 ports per target. No CIDR,
wildcard, hostname, unspecified/multicast address or shell text is accepted.
Rules allow outbound connections before private-network drops; they create
no new inbound service opening and grant no reverse-initiated connection.
Mount permissions and NAS export restrictions remain separate controls.
**Keep it off my LAN** blocks RFC1918, CGNAT and ULA ranges; LANs using public
IPv6 prefixes also need explicit deployment firewall rules for those prefixes.

## Application authentication

For Radarr, Sonarr, Prowlarr and related tools, leave Authentication on
**Forms**, with authentication **Enabled**. Never choose **Disabled for local
addresses**: all proxied traffic comes from the Gate's internal address.
The Gate limits reachability; application logins remain an additional control.
