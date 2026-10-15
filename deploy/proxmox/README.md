# Lanternfish on Proxmox

This guide sets up two unprivileged LXC containers: the Gate, and Jellyfin
behind it on a network your LAN can't reach.

```
 Internet ──► Router (forward WAN 443 → 192.168.1.20:443, nothing else)
                 │
   LAN 192.168.1.0/24  (vmbr0)
                 │
   ┌─────────────┴──────────────┐          Windows PC: Lanternfish Builder
   │ CT 201  lanternfish-gate   │◄──────── (admin API, LAN only)
   │ eth0 192.168.1.20  (LAN)   │
   │ eth1 10.20.0.2     (int)   │
   └─────────────┬──────────────┘
                 │  only path in
   INTERNAL 10.20.0.0/24  (vmbr1, no physical port; host NATs outbound)
                 │
   ┌─────────────┴──────────────┐
   │ CT 202  jellyfin 12.2      │  + Lanternfish plugin (refuses unsigned requests)
   │ eth0 10.20.0.3:8096        │  + /dev/dri for hardware transcoding
   └────────────────────────────┘
```

Four locks stand between the internet and Jellyfin, plus Jellyfin's own login:

1. The router forwards only to the Gate.
2. Jellyfin has no address on your LAN.
3. The Proxmox firewall lets only the Gate in.
4. The plugin refuses anything the Gate didn't sign.

The addresses below are examples. Replace `192.168.1.x`, `192.168.1.1` (your
router), `192.168.1.10` (your admin PC) and `jellyfin.example.com`
throughout.

## 0. Build the two artifacts

Do this on any machine with Go and the .NET 10 SDK, from this repository:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o lanternfish-gate ./cmd/lanternfish-gate
dotnet publish jellyfin-plugin/Jellyfin.Plugin.LanternfishGate -c Release -o plugin-out
```

Copy `lanternfish-gate`, `plugin-out/`, and this repository's `deploy/`
folder to the Proxmox host, for example into `/root/lanternfish/`.

## 1. Host: internal bridge

Append [`vmbr1.interfaces`](vmbr1.interfaces) to `/etc/network/interfaces`,
then run `ifreload -a`. Check that `ip -br addr show vmbr1` shows
`10.20.0.1/24`.

## 2. Host: key folder and template

```sh
# The Gate's master key lives on the host, bind-mounted into the container.
# Bind mounts are never included in vzdump backups, so backups of the Gate
# never contain the key.
mkdir -p /srv/lanternfish-keys
chown 100000:100000 /srv/lanternfish-keys    # root inside an unprivileged CT
chmod 700 /srv/lanternfish-keys

pveam update
pveam available --section system | grep debian    # pick the newest debian-13 (or 12) standard image
pveam download local debian-13-standard_<version>_amd64.tar.zst
```

## 3. CT 202: Jellyfin

```sh
pct create 202 local:vztmpl/debian-13-standard_<version>_amd64.tar.zst \
  --hostname jellyfin --unprivileged 1 --features nesting=1 \
  --cores 4 --memory 6144 --swap 512 --rootfs local-lvm:32 \
  --net0 name=eth0,bridge=vmbr1,ip=10.20.0.3/24,gw=10.20.0.1,firewall=1 \
  --nameserver 1.1.1.1 \
  --mp0 /tank/media,mp=/media,ro=1 \
  --onboot 1 --startup order=1
pct start 202
```

* `--mp0` is your media: a host directory, ZFS dataset or mounted NFS share,
  passed in **read-only**. In an unprivileged container, files must be
  readable by "other" (or by uid 100000+), or Jellyfin can't see them.
* `--nameserver` is a public resolver, because Jellyfin's firewall blocks
  your LAN, router DNS included (step 7).

**Hardware transcoding (Intel or AMD iGPU).** Find the `render` group's ID
inside the container, then pass the device through:

```sh
pct exec 202 -- getent group render          # e.g. render:x:993:
pct set 202 --dev0 /dev/dri/renderD128,gid=993
pct reboot 202
```

For an NVIDIA card, use a VM with PCI passthrough instead of this container.

**Install Jellyfin 12.2 or newer** (the plugin targets 12.2):

```sh
pct enter 202
apt update && apt install -y curl
curl -fsSL https://repo.jellyfin.org/install-debuntu.sh | bash
usermod -aG render jellyfin && systemctl restart jellyfin
exit
```

**Install the plugin.** It doesn't enforce anything until a key is set (step 5):

```sh
pct exec 202 -- mkdir -p /var/lib/jellyfin/plugins/LanternfishGate_1.0.0.0
pct push 202 /root/lanternfish/plugin-out/Jellyfin.Plugin.LanternfishGate.dll \
  /var/lib/jellyfin/plugins/LanternfishGate_1.0.0.0/Jellyfin.Plugin.LanternfishGate.dll
pct push 202 /root/lanternfish/plugin-out/meta.json \
  /var/lib/jellyfin/plugins/LanternfishGate_1.0.0.0/meta.json
pct exec 202 -- chown -R jellyfin:jellyfin /var/lib/jellyfin/plugins/LanternfishGate_1.0.0.0
```

## 4. CT 201: Gate

```sh
pct create 201 local:vztmpl/debian-13-standard_<version>_amd64.tar.zst \
  --hostname lanternfish-gate --unprivileged 1 --features nesting=1 \
  --cores 1 --memory 512 --swap 0 --rootfs local-lvm:4 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.1.20/24,gw=192.168.1.1,firewall=1 \
  --net1 name=eth1,bridge=vmbr1,ip=10.20.0.2/24,firewall=1 \
  --mp0 /srv/lanternfish-keys,mp=/etc/lanternfish/keys \
  --onboot 1 --startup order=2
pct start 201

pct exec 201 -- mkdir -p /root/lanternfish
pct push 201 /root/lanternfish/lanternfish-gate /root/lanternfish/lanternfish-gate
for f in lanternfish-gate.service gate.env.example lanternfish-gatectl certbot-deploy-hook.sh install-gate.sh; do
  pct push 201 /root/lanternfish/deploy/systemd/$f /root/lanternfish/$f
done
pct exec 201 -- sh /root/lanternfish/install-gate.sh /root/lanternfish/lanternfish-gate
```

The installer generates the master key. **Copy it into your password manager
now**: `cat /srv/lanternfish-keys/master_key` on the host. Without it, a
restored Gate can't open its own data.

Then edit `/etc/lanternfish/gate.env` inside CT 201 (`pct enter 201`):

* `LANTERNFISH_ADMIN_ALLOW`: narrow it to the PC that runs Builder, for
  example `192.168.1.10`.
* `LANTERNFISH_ALERT_WEBHOOK`: your Discord webhook.

## 5. TLS certificate (inside CT 201)

Use a DNS challenge, so no port 80 is needed. Cloudflare is shown here; certbot
has plugins for most DNS providers.

```sh
apt install -y certbot python3-certbot-dns-cloudflare
install -d -m 700 /root/.secrets
printf 'dns_cloudflare_api_token = <token with Zone:DNS:Edit>\n' > /root/.secrets/cloudflare.ini
chmod 600 /root/.secrets/cloudflare.ini

certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d jellyfin.example.com --key-type ecdsa --reuse-key \
  --deploy-hook /usr/local/lib/lanternfish/certbot-deploy-hook.sh
```

`--reuse-key` keeps the same key across renewals, so the pin baked into your
TV apps stays valid. The deploy hook copies each renewal into
`/etc/lanternfish/tls`, and the Gate picks it up without a restart.

**Pins for Lanternfish Builder.** Pin the current key and a spare one that you
keep offline. If the current key is ever lost or rotated, switch the
certificate to the spare and the TVs keep working.

```sh
# Current key's pin:
openssl pkey -in /etc/lanternfish/tls/privkey.pem -pubout -outform der | openssl dgst -sha256 -binary | base64
# Spare key: generate it, store it OFF this machine, record its pin:
openssl ecparam -genkey -name prime256v1 -noout -out spare-key.pem
openssl pkey -in spare-key.pem -pubout -outform der | openssl dgst -sha256 -binary | base64
```

## 6. Keys, plugin, start

Run these from the host. Jellyfin's dashboard isn't reachable yet, so the
plugin's key goes straight into its settings file.

```sh
pct exec 201 -- lanternfish-gatectl admin-key create -name builder   # shown once: store it for Builder
KEY=$(pct exec 201 -- lanternfish-gatectl upstream-key | tail -1)

pct exec 202 -- mkdir -p /var/lib/jellyfin/plugins/configurations
pct exec 202 -- sh -c "cat > /var/lib/jellyfin/plugins/configurations/Jellyfin.Plugin.LanternfishGate.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<PluginConfiguration>
  <GatePublicKeys>$KEY</GatePublicKeys>
  <MaxClockSkewSeconds>30</MaxClockSkewSeconds>
  <AllowLoopbackHealthCheck>true</AllowLoopbackHealthCheck>
</PluginConfiguration>
EOF
pct exec 202 -- chown -R jellyfin:jellyfin /var/lib/jellyfin/plugins/configurations
pct exec 202 -- systemctl restart jellyfin

pct exec 201 -- systemctl start lanternfish-gate
pct exec 201 -- journalctl -u lanternfish-gate -n 20
```

From now on Jellyfin answers `403` to anything the Gate didn't sign.

## 7. Firewall

1. **Enable the firewall at the datacenter level** (Datacenter → Firewall →
   Options → Firewall: Yes). Before you do, check that Datacenter →
   Firewall still lets you reach the web UI (port 8006) and SSH from your LAN.
   Keep a console open in case it doesn't.
2. Copy [`201.fw`](201.fw) to `/etc/pve/firewall/201.fw` and
   [`202.fw`](202.fw) to `/etc/pve/firewall/202.fw`. Edit the admin PC
   address in `201.fw`.
3. Both containers' NICs were created with `firewall=1`. Confirm under each
   CT → Network.

## 8. Router and DNS

* **Port forward:** WAN TCP 443 → `192.168.1.20:443`. Nothing else, and
  nothing at all to Jellyfin.
* **Turn off UPnP** on the router.
* **Local DNS** (router, Pi-hole or AdGuard): point `jellyfin.example.com`
  at `192.168.1.20`. Home clients then reach the Gate directly instead of
  looping out through the router.
* **Public DNS:** point `jellyfin.example.com` at your WAN IP. Use DDNS if it
  changes.
* **Port 443 already taken** by another reverse proxy? Give it a TCP/SNI
  passthrough for `jellyfin.example.com` to `192.168.1.20:443`, and don't
  let it decrypt the traffic. Note that a passthrough proxy makes every
  visitor appear to come from the proxy's address. In that case, set
  `LANTERNFISH_ADMIN_ALLOW` to your Builder PC's address only.

## 9. Jellyfin settings

Do this through the Gate, once a browser is enrolled. Create a `web` ticket
from the LAN (see the main README), open `https://jellyfin.example.com`, and
paste it in.

* **Dashboard → Networking → Known proxies:** `10.20.0.2`. Jellyfin then sees
  real client addresses in its logs.
* **LAN networks:** `192.168.1.0/24`. Home clients get treated as local, for
  bitrate limits.
* Don't install DLNA or other discovery plugins. Every client, even one at
  home, comes through the Gate.

## 10. Check it

| From | Command | Expect |
|---|---|---|
| LAN PC | `curl -m 5 http://10.20.0.3:8096/health` | timeout (no route) |
| Proxmox host | `curl -m 5 http://10.20.0.3:8096/health` | timeout (firewall) |
| CT 202 | `pct exec 202 -- curl -s localhost:8096/health` | `Healthy` |
| CT 202 | `pct exec 202 -- curl -s -o /dev/null -w '%{http_code}' localhost:8096/System/Info/Public` | `403` (plugin) |
| CT 202 | `pct exec 202 -- curl -m 5 http://192.168.1.1` | timeout (Jellyfin can't reach LAN) |
| Phone on mobile data | `https://jellyfin.example.com/System/Info/Public` | `{"error":"lanternfish_auth_required"}` |
| Phone on mobile data | `https://jellyfin.example.com/_lanternfish/admin/v1/devices` | `404` |
| Admin PC | `curl -H "Authorization: Bearer lfa_…" https://jellyfin.example.com/_lanternfish/admin/v1/devices` | device list |

## Backups and updates

* **vzdump backups** of CT 201 contain the device list but not the master
  key, which lives on the host in `/srv/lanternfish-keys`. Restoring needs the
  copy in your password manager. CT 202 backs up as normal.
* **Updating the Gate:** build a new binary, push it, re-run
  `install-gate.sh` (it leaves your settings and keys alone), then
  `systemctl restart lanternfish-gate`.
* **Updating the plugin:** push the new DLL over the old one, then
  `systemctl restart jellyfin`.
* **Clocks:** the containers share the host's clock, so the Gate and Jellyfin
  always agree. Keep NTP (chrony) running on the Proxmox host.
