#!/bin/bash
# Tests for guarded-firewall.sh. Run it from anywhere:
#
#   bash deploy/proxmox/guarded-firewall_test.sh
#
# Everything happens in a temporary directory: the host commands (id,
# pve-firewall, systemd-run, systemctl, pct, qm) are stubs on PATH, and the
# wrapper is pointed at a temporary FW_DIR and STATE_ROOT with
# LANTERNFISH_FIREWALL_TEST=1. Nothing here touches /etc/pve, systemd or the
# real firewall, and no host administration command is ever run for real.
#
# The stub bodies below are single-quoted on purpose: they expand when the
# stub runs, not here.
# Subshell environment changes below are intentionally isolated per test.
# shellcheck disable=SC2016,SC2030,SC2031

set -uo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
wrapper=$here/guarded-firewall.sh

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

bin=$tmp/bin
fw=$tmp/fw
state=$tmp/state
log=$tmp/calls
mkdir -p -- "$bin" "$fw"
: >"$log"

fails=0
ok() { printf '  ok      %s\n' "$1"; }
bad() {
  printf '  FAILED  %s\n' "$1"
  fails=$((fails + 1))
}
is() { # is WHAT GOT WANT
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi
}
has() { # has WHAT NEEDLE FILE
  if grep -qF -- "$2" "$3"; then ok "$1"; else bad "$1 ('$2' not in $3)"; fi
}
hasnt() { # hasnt WHAT NEEDLE FILE
  if grep -qF -- "$2" "$3"; then bad "$1 ('$2' found in $3)"; else ok "$1"; fi
}
exists() {
  if [ -e "$2" ]; then ok "$1"; else bad "$1 ($2 is missing)"; fi
}
absent() {
  if [ -e "$2" ]; then bad "$1 ($2 exists)"; else ok "$1"; fi
}
refused() { # refused WHAT: the last run must have exited non-zero
  if [ "$rc" = 0 ]; then bad "$1 (it exited 0)"; else ok "$1 (exit $rc)"; fi
}

# ---- stubs ----------------------------------------------------------------

mock() { # mock NAME BODY
  {
    printf '#!/bin/bash\n'
    printf '%s\n' "$2"
  } >"$bin/$1"
  chmod 755 -- "$bin/$1"
}
mock id 'echo 0'
mock pve-firewall 'echo running'
mock pct 'echo "net0: name=eth0,bridge=vmbr1,firewall=1"'
mock qm 'case "$2" in 204) echo "net0: virtio=AA:BB,bridge=vmbr1,firewall=1" ;; *) exit 2 ;; esac'
mock systemd-run 'printf "systemd-run %s\n" "$*" >>"$CALLS"'
mock systemctl 'printf "systemctl %s\n" "$*" >>"$CALLS"'

run() { # run ARGS...
  (
    export LANTERNFISH_FIREWALL_TEST=1 FW_DIR="$fw" STATE_ROOT="$state" CALLS="$log"
    export PATH="$bin:$PATH"
    bash "$wrapper" "$@"
  ) >"$tmp/out" 2>"$tmp/err"
  rc=$?
}

# ---- the host and the generated script ------------------------------------

reset_fw() {
  rm -rf -- "$fw" "$state"
  mkdir -p -- "$fw"
  printf '[OPTIONS]\nenable: 1\n' >"$fw/cluster.fw"
  printf 'old-jellyfin\n' >"$fw/201.fw"
  printf 'unrelated\n' >"$fw/299.fw"
  : >"$log"
}
reset_fw

write_generated() { # write_generated FILE [TAIL]
  cat >"$1" <<'GEN'
#!/bin/bash
# Stand-in for the script the Gate renders.
set -euo pipefail
FW_DIR=${FW_DIR:-/etc/pve/firewall}
write_fw() {
  local kind=$1 id=$2
  cat > "$FW_DIR/$id.fw"
}
write_fw ct 200 'the Gate' <<'LANTERNFISH_FW'
[OPTIONS]
enable: 1
LANTERNFISH_FW
write_fw ct 201 'Jellyfin' <<'LANTERNFISH_FW'
[OPTIONS]
enable: 1
policy_in: DROP
LANTERNFISH_FW
write_fw ct 203 'Sonarr' <<'LANTERNFISH_FW'
[OPTIONS]
enable: 1
LANTERNFISH_FW
GEN
  [ $# -ge 2 ] && printf '%s\n' "$2" >>"$1"
  chmod 755 -- "$1"
}
write_generated "$tmp/generated.sh"
write_generated "$tmp/generated-fail.sh" 'exit 2'

printf '\nNo mutation without permission\n'
run --verify-only "$tmp/generated.sh"
is "--verify-only exits 0" "$rc" 0
is "the existing 201.fw is untouched" "$(cat "$fw/201.fw")" "old-jellyfin"
absent "no new 203.fw was written" "$fw/203.fw"
absent "no new 200.fw was written" "$fw/200.fw"
absent "no state directory was made" "$state"
if [ -s "$log" ]; then
  bad "verify-only ran a host command that could change something"
else
  ok "verify-only scheduled or ran nothing"
fi
has "the preflight reports what it would write" "guest file(s) to write" "$tmp/out"
has "the preflight says it is only structural" "structural check only" "$tmp/out"

printf '\nRollback timer is armed before the script runs\n'
run --rollback-after 60 "$tmp/generated.sh"
is "--rollback-after exits 0" "$rc" 0
has "the Gate's file was written" "enable: 1" "$fw/200.fw"
has "201.fw was replaced" "policy_in: DROP" "$fw/201.fw"
exists "203.fw was created" "$fw/203.fw"
sdir=$(find "$state" -mindepth 1 -maxdepth 1 -type d | head -1)
is "one state directory" "$(find "$state" -mindepth 1 -maxdepth 1 -type d | wc -l)" 1
is "the state directory is private" "$(stat -c '%a' -- "$sdir")" "700"
is "the old file is backed up" "$(cat -- "$sdir/original/201.fw")" "old-jellyfin"
is "only the script's numeric guests are captured" "$(sed -n 's/^IDS=//p' -- "$sdir/state")" "200 201 203"
is "the files that didn't exist are recorded" "$(sed -n 's/^CREATED=//p' -- "$sdir/state")" "200 203"
has "the timer is armed before the script runs" "systemd-run" "$log"
has "the timer waits the requested time" "--on-active=60s" "$log"
has "the timer runs the wrapper's rollback" "--rollback-timer $sdir" "$log"
hasnt "nothing is cancelled before confirmation" "systemctl stop" "$log"
has "the confirmation command is printed" "--confirm $sdir" "$tmp/out"
has "the wrapper says a good run isn't confirmation" "check you can still" "$tmp/out"

printf '\nNothing is settled until the operator confirms\n'
run --confirm "$sdir"
is "--confirm exits 0" "$rc" 0
has "the timer is cancelled" "systemctl stop -- lanternfish-fw-" "$log"
has "it says the rules stay" "the firewall files stay as" "$tmp/out"
has "the new rules are still there" "policy_in: DROP" "$fw/201.fw"
exists "the created file is still there" "$fw/203.fw"

run --rollback-timer "$sdir"
is "a timer racing confirmation exits safely" "$rc" 0
has "a late timer does not restore confirmed rules" "policy_in: DROP" "$fw/201.fw"
hasnt "rollback must never stop its own service" ".service" "$log"

printf '\nRollback restores exactly the captured files\n'
run --rollback "$sdir"
is "--rollback exits 0" "$rc" 0
is "201.fw is back the way it was" "$(cat "$fw/201.fw")" "old-jellyfin"
absent "the newly created 203.fw is gone" "$fw/203.fw"
absent "the newly created 200.fw is gone" "$fw/200.fw"
has "cluster.fw is untouched" "enable: 1" "$fw/cluster.fw"
is "an unrelated 299.fw is untouched" "$(cat "$fw/299.fw")" "unrelated"
is "rolling back twice does nothing" "$(run --rollback "$sdir"; printf '%s' "$rc")" 0
has "and says so" "already rolled back" "$tmp/out"

printf '\nA failed apply rolls back immediately\n'
reset_fw
run --rollback-after 60 "$tmp/generated-fail.sh"
refused "a failed script exits non-zero"
is "201.fw was put back" "$(cat "$fw/201.fw")" "old-jellyfin"
absent "the extra file the failed run created is gone" "$fw/203.fw"
has "the timer was cancelled" "systemctl stop -- lanternfish-fw-" "$log"
has "it says why" "rolling back now" "$tmp/err"

printf '\nThe preflight refuses what it cannot run\n'
printf '#!/bin/bash\nif\n' >"$tmp/broken.sh"
run --verify-only "$tmp/broken.sh"
refused "a syntax error is refused"
has "and says so" "syntax error" "$tmp/err"
printf '#!/bin/bash\necho hi\n' >"$tmp/nothing.sh"
run --verify-only "$tmp/nothing.sh"
refused "a script without write_fw lines is refused"
has "and says so" "write_fw" "$tmp/err"
run --verify-only "$tmp/missing.sh"
refused "a missing script is refused"
# The datacenter firewall being off is reported, but it isn't fatal: the
# script's own rules simply don't apply yet.
printf '[OPTIONS]\nenable: 0\n' >"$fw/cluster.fw"
run --verify-only "$tmp/generated.sh"
refused "an off datacenter firewall is refused"
has "and is reported" "datacenter firewall isn't on" "$tmp/err"
printf '[OPTIONS]\nenable: 1\n' >"$fw/cluster.fw"
# A NIC without firewall=1 is reported too.
mock pct 'echo "net0: name=eth0,bridge=vmbr1"'
run --verify-only "$tmp/generated.sh"
has "a NIC without firewall=1 is reported" "has no firewall=1" "$tmp/err"
refused "missing NIC firewall refuses preflight"
mock pct 'echo "net0: name=eth0,bridge=vmbr1,firewall=1"'

printf '\nThe timer only ever gets a number of seconds\n'
: >"$log"
run --rollback-after 0 "$tmp/generated.sh"
refused "zero seconds is refused"
has "and says the range" "must be 30-604800 seconds" "$tmp/err"
run --rollback-after '60; rm -rf /' "$tmp/generated.sh"
refused "a command instead of a number is refused"
run --rollback-after forever "$tmp/generated.sh"
refused "a word instead of a number is refused"
hasnt "no timer was armed" "systemd-run" "$log"
is "and the script never ran" "$(cat "$fw/201.fw")" "old-jellyfin"

printf '\nState directories are validated before use\n'
sdir=$(find "$state" -mindepth 1 -maxdepth 1 -type d | head -1)
run --confirm "$fw"
refused "a state outside the state root is refused"
has "and says where STATE must live" "STATE must be a directory under" "$tmp/err"
run --confirm "$tmp/elsewhere"
refused "another outside state is refused"
chmod 755 -- "$sdir"
run --confirm "$sdir"
refused "a loose state directory is refused"
has "and reports the permissions" "expected 700" "$tmp/err"
chmod 700 -- "$sdir"
run --rollback "$sdir"
is "a private state directory is still usable" "$rc" 0

printf '\nA state file is data, never code\n'
mkdir -p -- "$state/handmade/original"
chmod 700 -- "$state/handmade"
{
  printf 'ID=handmade\n'
  printf 'FW_DIR=%s\n' "$fw"
  printf 'SCRIPT=$(touch %s/pwned)\n' "$tmp"
  printf 'UNIT=lanternfish-fw-handmade\n'
  printf 'IDS=201 $(touch %s/pwned2)\n' "$tmp"
  printf 'CREATED=\n'
} >"$state/handmade/state"
chmod 600 -- "$state/handmade/state"
printf 'old-jellyfin\n' >"$fw/201.fw"
run --rollback "$state/handmade"
refused "a state file with a command in it is refused"
has "the reason is the guest id" "isn't a number" "$tmp/err"
absent "the injected command did not run" "$tmp/pwned"
absent "nor the second one" "$tmp/pwned2"
is "201.fw was not touched by the refused rollback" "$(cat "$fw/201.fw")" "old-jellyfin"

printf '\nPending transactions and unsafe paths are refused\n'
reset_fw
run --rollback-after 60 "$tmp/generated.sh"
is "first guarded apply succeeds" "$rc" 0
sdir=$(find "$state" -mindepth 1 -maxdepth 1 -type d | head -1)
run --rollback-after 60 "$tmp/generated.sh"
refused "second apply cannot overlap a pending rollback"
run "$tmp/generated.sh"
refused "ordinary apply cannot bypass a pending rollback"
run --confirm "$sdir/../$(basename -- "$sdir")"
refused "traversal spelling of a state is refused"
run --rollback "$sdir"
run --confirm "$sdir"
refused "a rolled-back state cannot be confirmed"
reset_fw
run "$tmp/generated.sh"
is "ordinary explicit apply works without an extra argument" "$rc" 0
has "ordinary apply writes the requested rules" "policy_in: DROP" "$fw/201.fw"
hasnt "ordinary apply does not arm a timer" "systemd-run" "$log"

printf '\nPreparation failures cannot leave unusable pending state\n'
reset_fw
mock cp 'case "$1" in -p) exit 1 ;; esac; exec /usr/bin/cp "$@"'
run --rollback-after 60 "$tmp/generated.sh"
refused "failed backup aborts before changing firewall"
is "failed preparation leaves old rules intact" "$(cat "$fw/201.fw")" "old-jellyfin"
mock cp 'exec /usr/bin/cp "$@"'
run --rollback-after 60 "$tmp/generated.sh"
is "a later guarded apply can recover after preparation failure" "$rc" 0
sdir=$(find "$state" -mindepth 1 -maxdepth 1 -type d ! -exec test -e '{}/rolled-back' \; -print | head -1)
run --rollback "$sdir"
mkdir -m 0700 -- "$state/killed-before-metadata"
run --rollback-after 60 "$tmp/generated.sh"
is "a killed pre-metadata preparation is retired under the lock" "$rc" 0
exists "abandoned state is marked inactive" "$state/killed-before-metadata/rolled-back"
sdir=$(find "$state" -mindepth 1 -maxdepth 1 -type d ! -exec test -e '{}/rolled-back' \; -print | head -1)
run --rollback "$sdir"

printf '\nCompilation cannot hold the rollback lock forever\n'
reset_fw
mock pve-firewall 'if [ "$1" = compile ]; then n=$(grep -c "^compile$" "$CALLS" || true); printf "compile\n" >>"$CALLS"; if [ "$n" -gt 0 ]; then sleep 60; fi; else echo running; fi'
run --rollback-after 60 "$tmp/generated.sh"
refused "hung post-apply compilation is bounded"
is "timed-out compilation restores the old firewall" "$(cat "$fw/201.fw")" "old-jellyfin"
absent "timed-out compilation removes newly created rules" "$fw/203.fw"
mock pve-firewall 'echo running'

printf '\nThe paths cannot be moved outside the test suite\n'
if [ ! -e /etc/pve/firewall ]; then
  (
    export FW_DIR="$fw" STATE_ROOT="$state" CALLS="$log" PATH="$bin:$PATH"
    unset LANTERNFISH_FIREWALL_TEST
    bash "$wrapper" --verify-only "$tmp/generated.sh"
  ) >"$tmp/out" 2>"$tmp/err"
  rc=$?
  if [ "$rc" != 0 ]; then
    ok "FW_DIR is ignored without the test flag"
  else
    bad "FW_DIR was honoured without the test flag"
  fi
  has "and the real path is used" "/etc/pve/firewall" "$tmp/err"
else
  printf '  skip    /etc/pve/firewall exists on this host\n'
fi

printf '\n'
if [ "$fails" = 0 ]; then
  printf 'all checks passed\n'
  exit 0
fi
printf '%d check(s) failed\n' "$fails"
exit 1
