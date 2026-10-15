# Security policy

Lanternfish Gate guards a media server that's reachable from the internet, so
security reports are very welcome.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:
**Security → Report a vulnerability** on this repository. You'll get an
answer within a week. Please allow time for a fix before you publish
details.

Useful things to include: the affected component (Gate, Jellyfin plugin,
deploy scripts), the version (`lanternfish-gate version`), and steps or a
proof of concept.

## In scope

* Getting through the Gate without an enrolled device's key: forged or
  replayed signatures, sessions, client certificates or tickets.
* Reaching Jellyfin around the Gate when the plugin is configured, for
  example a request it should reject but doesn't.
* Reading or recovering secrets from the Gate's data file without the master
  key.
* Reaching the admin API from outside `LANTERNFISH_ADMIN_ALLOW`.
* Weaknesses in the shipped deployment (systemd unit, Proxmox firewall
  files, install scripts).

## Out of scope

* Deployments that ignore the documented setup, for example Jellyfin's port
  published directly with the plugin unconfigured.
* Attacks that need an admin key, the master key, or root on the Gate's host.
* Rate-limit evasion by distributed sources; the per-IP limiter is a speed
  bump, not a guarantee.

## Supported versions

Only the latest release gets fixes.
