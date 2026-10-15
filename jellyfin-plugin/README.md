# Lanternfish Gate plugin for Jellyfin

This plugin makes Jellyfin refuse every request that Lanternfish Gate didn't
forward and sign. If Jellyfin's port is exposed by mistake, through a
forgotten Docker `ports:` line, a firewall change or a router's UPnP, direct
requests still get `403 Forbidden`.

It is a second lock. Keep Jellyfin off the network as well; see
`deploy/docker-compose.yml`.

## How it works

The Gate signs each forwarded request with its own ECDSA P-256 key. It signs
the method, the exact request target, a timestamp, a single-use nonce and the
device ID. The plugin runs ahead of all of Jellyfin's own middleware. It
checks the signature against the Gate's **public** key, rejects timestamps
more than 30 seconds off, and rejects any nonce it has already seen. Jellyfin
never holds anything that could be used to forge Gate traffic. The full
format is in [docs/PROTOCOL.md](../docs/PROTOCOL.md#signed-requests-to-jellyfin).

## Build

Requires the .NET 10 SDK. Built against Jellyfin 12.2 (`targetAbi` 12.2.0.0).

```sh
dotnet publish Jellyfin.Plugin.LanternfishGate -c Release -o out
```

## Install

**First install (manual).** Download `jellyfin-plugin-lanternfish-gate_<version>.zip`
from the latest release, or build it yourself (above). Unzip it into a new
folder in Jellyfin's plugins directory named `LanternfishGate_<version>`:

* Docker: `/config/plugins/LanternfishGate_<version>/`
* Linux packages: `/var/lib/jellyfin/plugins/LanternfishGate_<version>/`
* Windows: `%ProgramData%\Jellyfin\Server\plugins\LanternfishGate_<version>\`

Then restart Jellyfin. Until a key is configured the plugin **does not
enforce**; it only logs a warning. That way, installing it can't lock you
out.

**Updates (from Jellyfin).** Add this under **Dashboard → Plugins →
Repositories**:

```
https://github.com/yourmomsbasement/LanternFish-Auth/releases/latest/download/manifest.json
```

New releases then show up as plugin updates. If you switch an existing manual
install to the repository, delete the manual `LanternfishGate_<version>`
folder after the repository copy is installed, so only one copy remains.

**Set the key.** Run `lanternfish-gate upstream-key`; the key is also printed
in the Gate's log at startup. Through the Gate, open **Dashboard → Plugins →
Lanternfish Gate**, paste the key and save. Enforcement starts immediately.

You can also write the settings file before the first start:
`plugins/configurations/Jellyfin.Plugin.LanternfishGate.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<PluginConfiguration>
  <GatePublicKeys>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…</GatePublicKeys>
  <MaxClockSkewSeconds>30</MaxClockSkewSeconds>
  <AllowLoopbackHealthCheck>true</AllowLoopbackHealthCheck>
</PluginConfiguration>
```

## Settings

| Setting | Default | Meaning |
|---|---|---|
| Gate public keys | empty | One base64 key per line. Empty means not enforcing. When rotating, add the new key before removing the old one. |
| Allowed clock difference | 30 s | Keep the Gate and Jellyfin on NTP. |
| Allow unsigned health checks from this machine | on | Lets `GET /health` (that exact path) from loopback through, for the Docker health check. |
| Keep browser sessions alive in the web client | on | Adds the Gate's renewal script to the web client for browsers, so their 15-minute Gate session renews in the background. When off, the Gate adds the script itself. |

An unparseable key makes the plugin **refuse every request** (`503`) rather
than quietly letting traffic through. If that locks you out, fix the XML file
above, or remove the plugin folder, and restart Jellyfin.

## Locked out?

Either delete `plugins/LanternfishGate_<version>/`, or clear `GatePublicKeys` in
the XML file, then restart Jellyfin.
