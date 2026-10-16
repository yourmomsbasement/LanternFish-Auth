#!/bin/bash
# guarded-firewall.sh: run a generated Lanternfish firewall script with a
# safety net around it.
#
#   bash guarded-firewall.sh --verify-only SCRIPT
#   bash guarded-firewall.sh --rollback-after 600 SCRIPT
#   bash guarded-firewall.sh --confirm STATE
#   bash guarded-firewall.sh --rollback STATE
#   bash guarded-firewall.sh SCRIPT
#
# The Gate renders a script (lanternfish-firewall.sh) that writes
# /etc/pve/firewall/<ID>.fw for the Gate and each guest. Run it on the Proxmox
# host as root. This wrapper adds:
#
#   --verify-only        checks the script and the host and changes nothing.
#   --rollback-after N   backs up every <ID>.fw the script says it writes,
#                        arms a systemd timer that puts those files back
#                        after N seconds, then runs the script. A successful
#                        run is not a confirmation: nothing is settled until
#                        you say so.
#   --confirm STATE      cancels that timer once you know you still have
#                        access; the new rules stay.
#   --rollback STATE     puts the old files back now.
#
# Without a mode flag it verifies the script and then runs it the way the
# Gate's instructions always have: the operator asked for it.
#
# WHAT THIS CANNOT DO
# SCRIPT is executable code that you reviewed and chose to run: it is not an
# untrusted upload. The preflight checks its syntax, the write_fw lines that
# say which files it writes, and the host's prerequisites, and it can restore
# those files byte for byte, but it cannot prove what the code does when it
# runs. Read the script before running it. Only the /etc/pve/firewall/<ID>.fw
# files named by the script's own write_fw lines are ever backed up or
# restored; cluster.fw and everything else are left alone.
#
# The preflight only reads host state (cluster.fw, and pct/qm config for the
# guests): it never writes, never schedules a timer and never runs SCRIPT.
#
# The paths below are fixed on purpose. The environment variables that move
# them exist for the test suite only and are ignored unless
# LANTERNFISH_FIREWALL_TEST=1.

set -euo pipefail

DEFAULT_FW_DIR=/etc/pve/firewall
DEFAULT_STATE_ROOT=/var/lib/lanternfish-firewall
MAX_ROLLBACK=604800 # a week
CHECK_TIMEOUT=5
PREPARING_STATE=
CURRENT_APPLY_PID=

if [ "${LANTERNFISH_FIREWALL_TEST:-0}" = 1 ]; then
  FW_DIR=${FW_DIR:-$DEFAULT_FW_DIR}
  STATE_ROOT=${STATE_ROOT:-$DEFAULT_STATE_ROOT}
  CHECK_TIMEOUT=1
else
  # Operator-supplied values are ignored: only the real firewall directory is
  # ever read or written.
  FW_DIR=$DEFAULT_FW_DIR
  STATE_ROOT=$DEFAULT_STATE_ROOT
fi
export FW_DIR

SCRIPT=
SELF=$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "$0")

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

bounded_check() {
  timeout --kill-after=2s "${CHECK_TIMEOUT}s" "$@" 9>&-
}

cleanup_interrupted() {
  if [ -n "$CURRENT_APPLY_PID" ]; then
    kill -KILL -- "-$CURRENT_APPLY_PID" >/dev/null 2>&1 || true
    wait "$CURRENT_APPLY_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$PREPARING_STATE" && -d "$PREPARING_STATE" && ! -L "$PREPARING_STATE" ]]; then
    : >"$PREPARING_STATE/rolled-back"
    chmod 0600 -- "$PREPARING_STATE/rolled-back"
  fi
}
trap cleanup_interrupted EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat >&2 <<'EOF'
usage: guarded-firewall.sh --verify-only SCRIPT
       guarded-firewall.sh --rollback-after SECONDS SCRIPT
       guarded-firewall.sh --confirm STATE
       guarded-firewall.sh --rollback STATE
       guarded-firewall.sh SCRIPT
EOF
  exit 2
}

# ---- preflight ------------------------------------------------------------

# script_targets prints "KIND ID" for every write_fw line the generated script
# declares, in order and without duplicates. The script is read, never run.
script_targets() {
  grep -E '^write_fw[[:space:]]+(ct|vm)[[:space:]]+[0-9]+[[:space:]]' -- "$SCRIPT" |
    awk '{ print $2, $3 }' |
    awk '!seen[$2]++'
}

# nic_warnings reads (never writes) the guests' configs: every NIC needs
# firewall=1 or its rules don't apply. The generated script checks the same
# thing when it runs.
nic_warnings() {
  local kind id cfg nic problems=0 nics
  while read -r kind id; do
    if [ "$kind" = ct ]; then
      command -v pct >/dev/null 2>&1 || die "pct is required for CT preflight"
      cfg=$(bounded_check pct config "$id" 2>/dev/null || true)
    else
      command -v qm >/dev/null 2>&1 || die "qm is required for VM preflight"
      cfg=$(bounded_check qm config "$id" 2>/dev/null || true)
    fi
    if [ -z "$cfg" ]; then
      warn "there is no $kind $id on this host"
      problems=$((problems + 1)); continue
    fi
    nics=$(printf '%s\n' "$cfg" | grep -E '^net[0-9]+:' || true)
    [ -n "$nics" ] || { warn "$kind $id has no network interfaces"; problems=$((problems + 1)); }
    while IFS= read -r nic; do
      case "$nic" in
        *firewall=1*) ;;
        *) warn "$kind $id: ${nic%%:*} has no firewall=1: set it under $id > Network > ${nic%%:*} > Firewall or its rules won't apply"; problems=$((problems + 1)) ;;
      esac
    done < <(printf '%s\n' "$cfg" | grep -E '^net[0-9]+:' || true)
  done < <(script_targets)
  [ "$problems" = 0 ] || die "guest firewall prerequisites failed"
}

preflight() {
  local targets n fw_status
  [ -n "$SCRIPT" ] || usage
  case "$SCRIPT" in *$'\n'* | *$'\r'*) die "script path contains a newline" ;; esac
  [ -f "$SCRIPT" ] || die "$SCRIPT isn't a file"
  [ -r "$SCRIPT" ] || die "can't read $SCRIPT"
  case "$(head -n 1 -- "$SCRIPT")" in
    '#!/bin/bash' | '#!/usr/bin/bash' | '#!/usr/bin/env bash' | '#!/bin/sh') ;;
    *) die "$SCRIPT doesn't start with a bash shebang: it isn't a generated firewall script" ;;
  esac
  command -v bash >/dev/null 2>&1 || die "bash isn't installed"
  command -v timeout >/dev/null 2>&1 || die "timeout is required for bounded preflight"
  bash -n "$SCRIPT" || die "$SCRIPT has a syntax error; nothing was run"
  [ "$(id -u)" = 0 ] || die "run this as root on the Proxmox host: the script writes $FW_DIR"
  command -v pve-firewall >/dev/null 2>&1 || die "pve-firewall isn't installed: is this the Proxmox host?"
  [ -d "$FW_DIR" ] || die "$FW_DIR doesn't exist"
  targets=$(script_targets || true)
  [ -n "$targets" ] || die "$SCRIPT has no write_fw lines: it isn't a Lanternfish firewall script"
  if ! grep -qs '^enable: 1' -- "$FW_DIR/cluster.fw"; then
    die "the datacenter firewall isn't on ($FW_DIR/cluster.fw has no 'enable: 1')"
  fi
  fw_status=$(bounded_check pve-firewall status 2>/dev/null) || die "cannot query firewall daemon"
  if ! grep -qi 'running' <<< "$fw_status" || grep -qiE 'not running|stopped|disabled' <<< "$fw_status"; then
    die "the firewall daemon is not running"
  fi
  bounded_check pve-firewall compile >/dev/null 2>&1 || die "existing firewall rules do not compile"
  local kind gid
  while read -r kind gid; do
    [[ "$gid" =~ ^[1-9][0-9]{2,8}$ ]] || die "invalid guest id $gid"
    [ ! -L "$FW_DIR/$gid.fw" ] || die "$FW_DIR/$gid.fw is a symlink"
  done <<< "$targets"
  nic_warnings
  n=$(printf '%s\n' "$targets" | awk 'END { print NR }')
  say "Preflight: syntax OK, running as root, $n guest file(s) to write under $FW_DIR."
}

# ---- rollback state -------------------------------------------------------

# state_value STATE KEY prints the value of KEY= in STATE/state. The file is
# read line by line: it is never sourced, eval'd or run as a command, and the
# caller validates every value.
state_value() {
  local state=$1 key=$2 line
  while IFS= read -r line; do
    case "$line" in
      "$key="*) printf '%s' "${line#"$key="}" && return 0 ;;
    esac
  done < "$state/state"
  return 1
}

# check_token VALUE WHAT: the state file only ever holds names we wrote.
check_token() {
  case "$1" in
    '' | *[!A-Za-z0-9._-]*) die "$2 in the state file isn't something we wrote: $1" ;;
  esac
}

# check_state validates a state directory before it is used: it must be under
# the state root, owned like the state root, private, and hold a state file we
# can parse.
check_root() {
  local owner mode
  [[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] || die "invalid rollback state root"
  [ "$(readlink -f -- "$STATE_ROOT")" = "$STATE_ROOT" ] || die "rollback root must be canonical"
  owner=$(stat -c '%u' -- "$STATE_ROOT")
  mode=$(stat -c '%a' -- "$STATE_ROOT")
  if [ "${LANTERNFISH_FIREWALL_TEST:-0}" != 1 ]; then
    [ "$owner" = 0 ] || die "rollback root must be owned by root"
  fi
  [ "$mode" = 700 ] || die "rollback root must have permissions 700"
}

lock_root() {
  check_root
  command -v flock >/dev/null 2>&1 || die "flock is required for safe rollback coordination"
  command -v timeout >/dev/null 2>&1 || die "timeout is required for bounded rollback operations"
  [ ! -L "$STATE_ROOT/.lock" ] || die "rollback lock is a symlink"
  exec 9>>"$STATE_ROOT/.lock"
  chmod 0600 -- "$STATE_ROOT/.lock"
  flock -x 9
}

check_state() {
  local state=$1 owner mode
  case "$state" in "$STATE_ROOT"/*) ;; *) die "STATE must be a directory under $STATE_ROOT" ;; esac
  check_root
  [[ -d "$state" && ! -L "$state" ]] || die "invalid state directory"
  [[ "$(readlink -f -- "$state")" = "$state" && "$(dirname -- "$state")" = "$STATE_ROOT" ]] || die "STATE must be a direct canonical child of $STATE_ROOT"
  owner=$(stat -c '%u' -- "$state")
  mode=$(stat -c '%a' -- "$state")
  [ "$owner" = "$(stat -c '%u' -- "$STATE_ROOT")" ] || die "state owner differs from rollback root"
  [ "$mode" = 700 ] || die "$state has permissions $mode, expected 700"
  [[ -f "$state/state" && ! -L "$state/state" ]] || die "invalid state metadata"
  [[ "$(stat -c '%u' -- "$state/state")" = "$owner" && "$(stat -c '%a' -- "$state/state")" = 600 ]] || die "invalid state metadata ownership or mode"
}

# load_state sets STATE_ID, STATE_FW, STATE_SCRIPT, STATE_UNIT, STATE_IDS and
# STATE_CREATED, after checking everything it read.
load_state() {
  STATE=$1
  check_state "$STATE"
  lock_root
  STATE_ID=$(state_value "$STATE" ID || true)
  STATE_FW=$(state_value "$STATE" FW_DIR || true)
  STATE_SCRIPT=$(state_value "$STATE" SCRIPT || true)
  STATE_UNIT=$(state_value "$STATE" UNIT || true)
  STATE_IDS=$(state_value "$STATE" IDS || true)
  STATE_CREATED=$(state_value "$STATE" CREATED || true)
  check_token "$STATE_ID" "the id"
  case "$STATE_UNIT" in lanternfish-fw-*) ;; *) die "the timer unit in $STATE/state isn't one we wrote" ;; esac
  check_token "$STATE_UNIT" "the timer unit"
  [[ "$(basename -- "$STATE")" = "$STATE_ID" && "$STATE_UNIT" = "lanternfish-fw-$STATE_ID" ]] || die "state identity mismatch"
  [ "$STATE_FW" = "$FW_DIR" ] || die "$STATE was made for $STATE_FW, not $FW_DIR"
  [ -n "$STATE_IDS" ] || die "$STATE/state lists no guest files"
  local gid
  for gid in $STATE_IDS; do
    case "$gid" in '' | *[!0-9]*) die "$STATE/state lists a guest id that isn't a number: $gid" ;; esac
  done
  for gid in $STATE_CREATED; do
    case " $STATE_IDS " in *" $gid "*) ;; *) die "created-file id was not captured" ;; esac
  done
}

# stop_timer cancels the transient rollback timer for a state.
stop_timer() {
  local unit=$1
  command -v systemctl >/dev/null 2>&1 || {
    warn "no systemctl here: cancel $unit by hand if it is still armed"
    return 0
  }
  bounded_check systemctl stop -- "$unit.timer" >/dev/null 2>&1 || true
  bounded_check systemctl reset-failed -- "$unit.timer" >/dev/null 2>&1 || true
}

# restore_files puts back exactly the numeric guest .fw files captured when
# the state was made: the old contents return, and files that didn't exist
# before are removed. Anything else in FW_DIR, cluster.fw included, is left
# alone.
restore_files() {
  local state=$1 gid
  local ids created
  ids=$(state_value "$state" IDS || true)
  created=$(state_value "$state" CREATED || true)
  [ -n "$ids" ] || die "$state/state lists no guest files"
  for gid in $ids; do
    case "$gid" in '' | *[!0-9]*) die "$state/state lists a guest id that isn't a number: $gid" ;; esac
    case " $created " in
      *" $gid "*)
        rm -f -- "$FW_DIR/$gid.fw"
        say "removed $FW_DIR/$gid.fw (it didn't exist before)"
        continue
        ;;
    esac
    [[ -d "$state/original" && ! -L "$state/original" ]] || die "invalid backup directory"
    [[ -f "$state/original/$gid.fw" && ! -L "$state/original/$gid.fw" ]] || die "$state has no regular backup of $gid.fw"
    [ -L "$FW_DIR/$gid.fw" ] && die "$FW_DIR/$gid.fw is a symlink: refusing to write through it"
    bounded_check cp -p -- "$state/original/$gid.fw" "$FW_DIR/$gid.fw"
    say "restored $FW_DIR/$gid.fw"
  done
}

run_generated() {
  say "Running $SCRIPT ..."
  bash "$SCRIPT"
}

# ---- modes ----------------------------------------------------------------

ensure_no_pending() {
  local pending
  for pending in "$STATE_ROOT"/*; do
    [ -d "$pending" ] || continue
    if [ -e "$pending/preparing" ] || [[ ! -e "$pending/state" && ! -e "$pending/armed" ]]; then
      # Under the global lock, a preparation cannot still be active. No
      # generated script runs before complete metadata and the armed marker.
      : >"$pending/rolled-back"
      chmod 0600 -- "$pending/rolled-back"
      warn "abandoned pre-apply preparation marked inactive: $pending"
    fi
    [ -e "$pending/confirmed" ] || [ -e "$pending/rolled-back" ] || die "an earlier rollback is still pending: $pending"
  done
}

guarded_apply() {
  local after=$1 state id unit kind gid ids='' created='' n=0 rc=0
  case "$after" in '' | *[!0-9]*) die "--rollback-after wants a whole number of seconds" ;; esac
  if [ "$after" -lt 30 ] || [ "$after" -gt "$MAX_ROLLBACK" ]; then
    die "--rollback-after must be 30-$MAX_ROLLBACK seconds"
  fi
  command -v systemd-run >/dev/null 2>&1 ||
    die "--rollback-after needs systemd-run, so the rollback survives this shell exiting"
  command -v systemctl >/dev/null 2>&1 ||
    die "--rollback-after needs systemctl to cancel the timer later"
  preflight

  command -v timeout >/dev/null 2>&1 || die "timeout is required for bounded apply"
  if [ ! -e "$STATE_ROOT" ]; then mkdir -m 0700 -- "$STATE_ROOT"; fi
  lock_root
  ensure_no_pending
  id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  state=$STATE_ROOT/$id
  unit=lanternfish-fw-$id
  mkdir -m 0700 -- "$state"
  PREPARING_STATE=$state
  : >"$state/preparing"
  chmod 0600 -- "$state/preparing"
  mkdir -m 0700 -- "$state/original"
  bounded_check cp -- "$SELF" "$state/rollback-wrapper.sh"
  chmod 0700 -- "$state/rollback-wrapper.sh"
  bounded_check cp -- "$SCRIPT" "$state/generated.sh"
  chmod 0600 -- "$state/generated.sh"

  # Capture the files the generated script says it will write, before arming
  # anything.
  while read -r kind gid; do
    [ -n "$gid" ] || continue
    ids="$ids $gid"
    n=$((n + 1))
    if [ -f "$FW_DIR/$gid.fw" ]; then
      bounded_check cp -p -- "$FW_DIR/$gid.fw" "$state/original/$gid.fw" ||
        die "couldn't back up $FW_DIR/$gid.fw"
    else
      created="$created $gid"
    fi
  done < <(script_targets || true)
  ids=${ids# }
  created=${created# }

  {
    printf 'ID=%s\n' "$id"
    printf 'FW_DIR=%s\n' "$FW_DIR"
    printf 'SCRIPT=%s\n' "$SCRIPT"
    printf 'UNIT=%s\n' "$unit"
    printf 'IDS=%s\n' "$ids"
    printf 'CREATED=%s\n' "$created"
  } >"$state/state"
  chmod 0600 -- "$state/state"

  # The timer survives this shell exiting, but transient systemd timers do
  # NOT survive host reboot. Pending state must be reviewed after a reboot.
  if ! bounded_check systemd-run --quiet --collect --unit="$unit" --on-active="${after}s" \
    --description="Lanternfish firewall rollback ($id)" \
    -- /bin/bash "$state/rollback-wrapper.sh" --rollback-timer "$state"; then
    : >"$state/rolled-back"
    die "couldn't arm the rollback timer; nothing was changed (the backup is in $state)"
  fi
  mv -- "$state/preparing" "$state/armed"
  PREPARING_STATE=
  say "Backed up $n guest file(s) in $state; $unit fires in ${after}s."

  say "Running the captured generated script ..."
  timeout --kill-after=5s "$((after - 20))s" bash "$state/generated.sh" 9>&- &
  CURRENT_APPLY_PID=$!
  wait "$CURRENT_APPLY_PID" || rc=$?
  CURRENT_APPLY_PID=
  if [ "$rc" = 0 ] && ! bounded_check pve-firewall compile >/dev/null 2>&1; then
    warn "the newly written firewall rules did not compile"
    rc=1
  fi
  if [ "$rc" != 0 ]; then
    warn "the generated script exited $rc: rolling back now"
    restore_files "$state" || die "rolling back failed: the backup is still in $state"
    : >"$state/rolled-back"
    chmod 0600 -- "$state/rolled-back"
    stop_timer "$unit"
    exit "$rc"
  fi

  say ""
  say "The script ran. That doesn't mean the rules work: check you can still"
  say "reach the Proxmox web UI, SSH and the services you need."
  say "Then keep these rules by cancelling the timer:"
  say "  bash $(printf '%q' "$SELF") --confirm $(printf '%q' "$state")"
  say "Or put the old files back right now:"
  say "  bash $(printf '%q' "$SELF") --rollback $(printf '%q' "$state")"
  say "Doing nothing puts them back in ${after}s."
}

confirm_state() {
  local state=$1
  load_state "$state"
  [ "$(id -u)" = 0 ] || die "run this as root"
  [ ! -e "$state/rolled-back" ] || die "state already rolled back; cannot confirm"
  : >"$state/confirmed"
  chmod 0600 -- "$state/confirmed"
  stop_timer "$STATE_UNIT"
  say "Cancelled the rollback timer ($STATE_UNIT): the firewall files stay as $STATE_SCRIPT left them."
  say "The backup in $state is no longer needed; delete it when you're sure."
}

rollback_state() {
  local state=$1
  load_state "$state"
  if [ "${2:-manual}" = timer ] && [ -e "$state/confirmed" ]; then
    say "Confirmed state; automatic rollback skipped."
    return 0
  fi
  if [ -e "$state/rolled-back" ]; then
    say "$state was already rolled back; nothing to do."
    return 0
  fi
  [ "$(id -u)" = 0 ] || die "run this as root: it writes $FW_DIR"
  restore_files "$state"
  : >"$state/rolled-back"
  chmod 0600 -- "$state/rolled-back"
  stop_timer "$STATE_UNIT"
  say "Rolled back: the files captured when $state was made are back."
}

# ---- dispatch -------------------------------------------------------------

mode=${1:-}
[ -n "$mode" ] || usage
shift
case "$mode" in
  --verify-only)
    [ $# = 1 ] || usage
    SCRIPT=$1
    preflight
    say "Nothing was changed. This is a structural check only: it can't prove what the script does when it runs."
    ;;
  --rollback-after)
    [ $# = 2 ] || usage
    SCRIPT=$2
    guarded_apply "$1"
    ;;
  --confirm)
    [ $# = 1 ] || usage
    confirm_state "$1"
    ;;
  --rollback)
    [ $# = 1 ] || usage
    rollback_state "$1"
    ;;
  --rollback-timer)
    [ $# = 1 ] || usage
    rollback_state "$1" timer
    ;;
  -*)
    usage
    ;;
  *)
    # A script path and nothing else: verify it, then run it the way the
    # Gate's instructions always have.
    [ $# = 0 ] || usage
    SCRIPT=$mode
    preflight
    if [ -e "$STATE_ROOT" ]; then lock_root; ensure_no_pending; fi
    run_generated
    bounded_check pve-firewall compile >/dev/null 2>&1 || die "new firewall rules did not compile"
    say "Done. The wrapper did not watch the result: check the guests before trusting these rules."
    ;;
esac
