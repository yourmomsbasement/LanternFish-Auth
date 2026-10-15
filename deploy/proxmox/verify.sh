#!/bin/bash
# Checks a Lanternfish deployment on Proxmox end to end. Run on the Proxmox
# host as root:
#
#   ADMIN_KEY=lfa_… GATE=200 JF=201 GATE_IP=192.168.1.20 bash verify.sh
#
# GATE / JF   container IDs of the Gate and Jellyfin (defaults 201 / 202)
# GATE_IP     the Gate's LAN address
# JF_IP       Jellyfin's internal address (default 10.20.0.3)
# ADMIN_KEY   an admin key; enables the round trip through the Gate. The host
#             must be inside LANTERNFISH_ADMIN_ALLOW. Without it, that part
#             is skipped.
#
# The round trip enrolls a temporary Roku-type device, uses it, then revokes
# it. It costs two deliberate failed attempts against this host's rate limit
# (10 per 10 minutes), so don't run it more than a few times in a row.
#
# Exit status: 0 if nothing failed, 1 otherwise.

# "check && pass … || fail …" is safe here: pass only prints, so it can't fail.
# shellcheck disable=SC2015

set -u
GATE=${GATE:-201}
JF=${JF:-202}
JF_IP=${JF_IP:-10.20.0.3}
GATE_IP=${GATE_IP:-}
ADMIN_KEY=${ADMIN_KEY:-}

fails=0
warns=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
warn() { printf '  WARN  %s\n' "$1"; warns=$((warns + 1)); }
section() { printf '\n%s\n' "$1"; }
in_gate() { pct exec "$GATE" -- "$@"; }
in_jf() { pct exec "$JF" -- "$@"; }

if [ -z "$GATE_IP" ]; then
  GATE_IP=$(pct config "$GATE" | sed -n 's/^net0:.*ip=\([0-9.]*\).*/\1/p')
fi

section "Services"
gate_version=$(in_gate /usr/local/bin/lanternfish-gate version 2>/dev/null | grep -m1 -E '^[0-9]')
[ "$(in_gate systemctl is-active lanternfish-gate 2>/dev/null)" = active ] &&
  pass "Gate is running${gate_version:+ (version $gate_version)}" ||
  fail "Gate is not running: pct exec $GATE -- journalctl -u lanternfish-gate -n 30"
[ "$(in_jf systemctl is-active jellyfin 2>/dev/null)" = active ] &&
  pass "Jellyfin is running" ||
  fail "Jellyfin is not running: pct exec $JF -- journalctl -u jellyfin -n 30"
log=$(in_jf sh -c 'ls -t /var/log/jellyfin/log_*.log 2>/dev/null | head -1')
if [ -n "$log" ] && in_jf grep -q 'Loaded plugin: "\{0,1\}Lanternfish Gate' "$log"; then
  jf_version=$(in_jf grep -o 'Jellyfin version: "\{0,1\}[0-9.]*' "$log" | tail -1 | grep -o '[0-9][0-9.]*')
  pass "Jellyfin${jf_version:+ $jf_version} loaded the Lanternfish plugin"
else
  fail "Lanternfish plugin not loaded in Jellyfin's current log ($log)"
fi

section "Jellyfin only accepts the Gate"
code=$(in_jf curl -s -o /dev/null -w '%{http_code}' localhost:8096/System/Info/Public)
[ "$code" = 403 ] && pass "Unsigned request inside Jellyfin's container: 403" ||
  fail "Unsigned request inside Jellyfin's container got $code, expected 403 (plugin not enforcing: key missing or plugin disabled)"
code=$(in_jf curl -s -o /dev/null -w '%{http_code}' \
  -H 'X-Lanternfish-Gate-Timestamp: 1' -H 'X-Lanternfish-Gate-Nonce: x' \
  -H 'X-Lanternfish-Device: dev_x' -H 'X-Lanternfish-Gate-Signature: AAAA' \
  localhost:8096/System/Info/Public)
[ "$code" = 403 ] && pass "Forged signature headers: 403" || fail "Forged signature headers got $code, expected 403"
body=$(in_jf curl -s localhost:8096/health)
[ "$body" = Healthy ] && pass "Health check from Jellyfin's own container: Healthy" ||
  warn "Health check returned '$body' (fine if you turned that setting off)"
code=$(in_gate curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$JF_IP:8096/System/Info/Public")
[ "$code" = 403 ] && pass "Unsigned request from the Gate's container: 403 (trust comes from the signature, not the address)" ||
  fail "Unsigned request from the Gate's container got $code, expected 403"

section "Network"
code=$(curl -s -m 4 -o /dev/null -w '%{http_code}' "http://$JF_IP:8096/System/Info/Public")
case "$code" in
  000) pass "Proxmox host can't reach Jellyfin (firewall)" ;;
  403) warn "Proxmox host reaches Jellyfin (refused by the plugin). Enable the Proxmox firewall for CT $JF to block it at the network too" ;;
  *) fail "Proxmox host reached Jellyfin with HTTP $code" ;;
esac
gw=$(ip route 2>/dev/null | sed -n 's/^default via \([0-9.]*\).*/\1/p' | head -1)
if [ -n "$gw" ]; then
  if in_jf timeout 4 bash -c "exec 3<>/dev/tcp/$gw/80" 2>/dev/null; then
    warn "Jellyfin can reach your LAN ($gw). Apply the firewall file for CT $JF so a compromised Jellyfin can't"
  else
    pass "Jellyfin can't reach your LAN ($gw)"
  fi
fi
in_jf timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null &&
  pass "Jellyfin has outbound internet (metadata, updates)" ||
  warn "Jellyfin has no outbound internet. Check the MASQUERADE rule on vmbr1"
iptables -t nat -S POSTROUTING 2>/dev/null | grep -q 'MASQUERADE' &&
  pass "NAT rule for the internal bridge is present" ||
  warn "No MASQUERADE rule on the host. Jellyfin can't reach the internet"
grep -q 'MASQUERADE' /etc/network/interfaces 2>/dev/null &&
  pass "NAT rule is saved in /etc/network/interfaces (survives reboot)" ||
  warn "NAT rule isn't in /etc/network/interfaces, so it will be lost on reboot"

section "Gate: TLS and keys"
if echo | openssl s_client -connect "$GATE_IP:443" -tls1_2 >/dev/null 2>&1; then
  fail "Gate accepted TLS 1.2 (expected TLS 1.3 only)"
else
  pass "Gate refuses TLS 1.2"
fi
cert=$(echo | openssl s_client -connect "$GATE_IP:443" -tls1_3 2>/dev/null | openssl x509 2>/dev/null)
if [ -n "$cert" ]; then
  subject=$(echo "$cert" | openssl x509 -noout -subject | sed 's/^subject=//')
  issuer=$(echo "$cert" | openssl x509 -noout -issuer | sed 's/^issuer=//')
  end=$(echo "$cert" | openssl x509 -noout -enddate | cut -d= -f2)
  days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
  pass "TLS 1.3 works; certificate $subject, $days days left"
  [ "$subject" = "$issuer" ] && warn "Certificate is self-signed (the temporary one). Replace it with certbot before building TV apps"
  [ "$days" -lt 14 ] && warn "Certificate expires in $days days. Check: pct exec $GATE -- certbot renew --dry-run"
else
  fail "No TLS 1.3 connection to $GATE_IP:443"
fi
[ -n "$(in_gate findmnt -n /etc/lanternfish/keys 2>/dev/null)" ] &&
  pass "Master key is on the host mount (not in the Gate's backups)" ||
  warn "/etc/lanternfish/keys is not a mount. The master key will be included in backups of CT $GATE"

section "Round trip through the Gate"
if [ -z "$ADMIN_KEY" ]; then
  warn "Skipped. Set ADMIN_KEY=lfa_… to enroll, use and revoke a temporary device"
else
  out=$(GATE_URL="https://$GATE_IP" ADMIN_KEY="$ADMIN_KEY" python3 - <<'PY'
import base64, hashlib, hmac, json, os, ssl, time, urllib.request, urllib.error

base, admin = os.environ["GATE_URL"], os.environ["ADMIN_KEY"]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def call(method, path, body=None, headers=None):
    h = {"Content-Type": "application/json", "Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(base + path, method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)

def say(ok, msg):
    print(("PASS " if ok else "FAIL ") + msg)
    return ok

st, body, hdrs = call("GET", "/System/Info/Public")
say(st == 401 and "lanternfish_auth_required" in body, f"No credentials: {st} {body.strip()[:60]}")
say("max-age" in hdrs.get("Strict-Transport-Security", ""), "HSTS header present")

auth = {"Authorization": "Bearer " + admin}
st, body, _ = call("GET", "/_lanternfish/admin/v1/devices", headers=auth)
if not say(st == 200, f"Admin API from this host: {st}"):
    print("FAIL   (404: this host isn't in LANTERNFISH_ADMIN_ALLOW; 401: wrong admin key)")
    raise SystemExit
st, body, _ = call("POST", "/_lanternfish/admin/v1/tickets",
                   {"platform": "roku", "label": "verify.sh " + time.strftime("%Y-%m-%d %H:%M"), "ttl_seconds": 300}, auth)
ticket = json.loads(body)["ticket"]
st, body, _ = call("POST", "/_lanternfish/v1/enroll", {"ticket": ticket})
if not say(st == 201, f"Enrolled a temporary device: {st}"):
    raise SystemExit
dev = json.loads(body); device, secret = dev["device_id"], base64.b64decode(dev["secret"])
st, _, _ = call("POST", "/_lanternfish/v1/enroll", {"ticket": ticket})
say(st == 401, f"Same ticket a second time: {st} (expected 401)")

st, body, _ = call("POST", "/_lanternfish/v1/challenge", {"device_id": device})
challenge = json.loads(body)["challenge"]
sig = base64.b64encode(hmac.new(secret, f"lanternfish-gate/v1/session\n{device}\n{challenge}".encode(), hashlib.sha256).digest()).decode()
st, body, _ = call("POST", "/_lanternfish/v1/session", {"device_id": device, "challenge": challenge, "signature": sig})
say(st == 200, f"Signed in with a signed challenge: {st}")
token = json.loads(body).get("session_token", "")
st, _, _ = call("POST", "/_lanternfish/v1/session", {"device_id": device, "challenge": challenge, "signature": sig})
say(st == 401, f"Replaying the same signature: {st} (expected 401)")

st, body, _ = call("GET", "/System/Info/Public", headers={"X-Lanternfish-Session": token})
ok = st == 200 and '"Version"' in body
say(ok, f"Reached Jellyfin through the Gate: {st}" + (f" (Jellyfin {json.loads(body).get('Version')})" if ok else f" {body[:80]}"))

st, _, _ = call("POST", f"/_lanternfish/admin/v1/devices/{device}/revoke", headers=auth)
say(st == 204, f"Revoked the temporary device: {st}")
st, _, _ = call("GET", "/System/Info/Public", headers={"X-Lanternfish-Session": token})
say(st == 401, f"Its session after revocation: {st} (expected 401)")
PY
)
  while IFS= read -r line; do
    case "$line" in
      PASS\ *) pass "${line#PASS }" ;;
      FAIL\ *) fail "${line#FAIL }" ;;
      *) [ -n "$line" ] && printf '        %s\n' "$line" ;;
    esac
  done <<<"$out"
fi

section "Check by hand from outside your network (phone on mobile data)"
printf '        https://<your domain>/System/Info/Public               -> {"error":"lanternfish_auth_required"}\n'
printf '        https://<your domain>/_lanternfish/admin/v1/devices    -> 404 (admin API hidden from the internet)\n'
printf '        http://<your WAN IP>:8096                              -> no connection\n'

printf '\n%d failed, %d warnings\n' "$fails" "$warns"
[ "$fails" -eq 0 ]
