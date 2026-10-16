#!/usr/bin/env bash
# Sign Lanternfish Gate releases on your admin PC.
#
#   sign-releases.sh keygen      create your signing key (once)
#   sign-releases.sh pubkey      print its public key line for internal/update/trusted-keys
#   sign-releases.sh pending     list releases waiting for a signature (exit status 3 if any)
#   sign-releases.sh sign [TAG]  check every file, sign and upload (default: all pending)
#   sign-releases.sh notify      post to LANTERNFISH_ALERT_WEBHOOK if any are waiting (for a timer)
#
# Needs bash, openssl 1.1.1+, curl, jq and sha256sum. Settings come from the
# environment or ~/.config/lanternfish/sign.env:
#   LANTERNFISH_SIGNING_KEY   encrypted private key (default ~/.config/lanternfish/release-key.pem)
#   LANTERNFISH_REPO          owner/name (default yourmomsbasement/LanternFish-Auth)
#   GITHUB_TOKEN_FILE         token for uploads (default ~/.config/lanternfish/github-token, mode 600);
#                             a fine-grained token for this repository with Contents: read and write
#   LANTERNFISH_ALERT_WEBHOOK Discord webhook for "notify"
#
# The key never leaves this machine and is never decrypted to disk. Each run
# asks for the passphrase once; don't store it anywhere. See docs/RELEASES.md.
set -euo pipefail
umask 077

CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/lanternfish"
[ -f "$CONF_DIR/sign.env" ] && . "$CONF_DIR/sign.env"
KEY="${LANTERNFISH_SIGNING_KEY:-$CONF_DIR/release-key.pem}"
REPO="${LANTERNFISH_REPO:-yourmomsbasement/LanternFish-Auth}"
API="${LANTERNFISH_UPDATE_API:-https://api.github.com}"
TOKEN_FILE="${GITHUB_TOKEN_FILE:-$CONF_DIR/github-token}"
MANIFEST=lanternfish-release.json
SIG=lanternfish-release.json.sig
CONTEXT='lanternfish-release/v1'

die() { echo "sign-releases: $*" >&2; exit 1; }
for tool in openssl curl jq sha256sum base64; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "LANTERNFISH_REPO must be owner/name"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

TOKEN=""
if [ -f "$TOKEN_FILE" ]; then
  perms=$(stat -c %a "$TOKEN_FILE" 2>/dev/null || stat -f %Lp "$TOKEN_FILE")
  [ "${perms: -2}" = "00" ] || die "$TOKEN_FILE is readable by other users; chmod 600 it"
  TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
fi

# Passphrase: asked once per run, handed to openssl through the environment
# of each openssl process only.
PASS=""
ask_pass() {
  if [ -n "${LANTERNFISH_SIGNING_PASSPHRASE:-}" ]; then PASS=$LANTERNFISH_SIGNING_PASSPHRASE; return; fi
  read -rsp "$1" PASS </dev/tty; echo >&2
}
ossl() { LF_PASS="$PASS" openssl "$@"; }

api() { # api PATH -> JSON on stdout
  local auth=()
  [ -n "$TOKEN" ] && auth=(-H "Authorization: Bearer $TOKEN")
  curl -fsS -H "Accept: application/vnd.github+json" -H "User-Agent: lanternfish-sign-releases" \
    ${auth[@]+"${auth[@]}"} "$API/repos/$REPO/$1"
}

download_asset() { # download_asset ASSET_JSON OUT
  local url
  if [ -n "$TOKEN" ]; then
    # The API URL works for drafts too; curl doesn't forward the token on the
    # redirect to GitHub's file storage.
    url=$(jq -r .url <<<"$1")
    curl -fsSL -H "Accept: application/octet-stream" -H "Authorization: Bearer $TOKEN" \
      -H "User-Agent: lanternfish-sign-releases" -o "$2" "$url"
  else
    url=$(jq -r .browser_download_url <<<"$1")
    curl -fsSL -H "User-Agent: lanternfish-sign-releases" -o "$2" "$url"
  fi
}

pending_json() { # releases with a manifest but no signature, oldest first
  local list
  list=$(api "releases?per_page=30") || die "couldn't list releases of $REPO"
  jq -c --arg m "$MANIFEST" --arg s "$SIG" '
    [ .[] | select(.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?$"))
          | select(any(.assets[]; .name == $m) and (any(.assets[]; .name == $s) | not)) ] | reverse | .[]' <<<"$list"
}

pub_raw() { # the key's 32-byte public key
  ossl pkey -in "$KEY" -passin env:LF_PASS -pubout -outform DER | tail -c 32
}

cmd_keygen() {
  [ -e "$KEY" ] && die "$KEY exists; refusing to overwrite a key"
  mkdir -p "$(dirname "$KEY")"
  local again
  ask_pass "Passphrase for the new signing key (12+ characters): "
  [ ${#PASS} -ge 12 ] || die "use at least 12 characters"
  if [ -z "${LANTERNFISH_SIGNING_PASSPHRASE:-}" ]; then
    read -rsp "Repeat it: " again </dev/tty; echo >&2
    [ "$PASS" = "$again" ] || die "the passphrases differ"
  fi
  # Encrypted PKCS#8, scrypt-derived key: the plain key only ever exists in the pipe.
  openssl genpkey -algorithm ed25519 | ossl pkcs8 -topk8 -v2 aes-256-cbc -scrypt -passout env:LF_PASS -out "$KEY"
  chmod 600 "$KEY"
  echo "Wrote $KEY. Back it up offline (USB stick, password manager); never upload it." >&2
  echo "Put this line in internal/update/trusted-keys in the repository, commit it, and release:" >&2
  cmd_pubkey_with_pass
}

cmd_pubkey() {
  [ -f "$KEY" ] || die "no key at $KEY (run: $0 keygen)"
  ask_pass "Signing key passphrase: "
  cmd_pubkey_with_pass
}

cmd_pubkey_with_pass() {
  local b64 comment
  b64=$(pub_raw | base64 | tr -d '\n') || die "wrong passphrase, or $KEY is damaged"
  comment="${LANTERNFISH_KEY_COMMENT:-$(whoami)@$(hostname -s 2>/dev/null || hostname) $(date +%Y-%m-%d)}"
  echo "lfrk1 $b64 $comment"
}

cmd_pending() {
  local list
  list=$(pending_json)
  if [ -z "$list" ]; then echo "No releases are waiting for a signature." >&2; return; fi
  jq -r '"waiting for a signature: \(.tag_name)" + (if .draft then " (draft)" elif .prerelease then " (pre-release)" else "" end)' <<<"$list"
  exit 3
}

cmd_notify() {
  local list tags
  list=$(pending_json)
  tags=$(jq -r .tag_name <<<"$list" | paste -sd, - | sed 's/,/, /g')
  [ -n "$tags" ] || exit 0
  [ -n "${LANTERNFISH_ALERT_WEBHOOK:-}" ] || { echo "waiting: $tags"; exit 3; }
  curl -fsS -H "Content-Type: application/json" -d \
    "$(jq -n --arg t "$tags" '{content: ("🔏 Lanternfish release \($t) is waiting for your signature: run sign-releases.sh sign")}')" \
    "$LANTERNFISH_ALERT_WEBHOOK" >/dev/null
}

# check_release REL_JSON DIR: download the manifest and every file it lists,
# and check each against the manifest.
check_release() {
  local rel=$1 dir=$2 tag version asset name want_sha want_size got_sha got_size
  tag=$(jq -r .tag_name <<<"$rel")
  version=${tag#v}
  asset=$(jq -c --arg n "$MANIFEST" '.assets[] | select(.name == $n)' <<<"$rel")
  download_asset "$asset" "$dir/$MANIFEST"
  jq -e --arg v "$version" '.schema == 1 and .product == "lanternfish-gate" and .version == $v and (.files | length > 0)' \
    "$dir/$MANIFEST" >/dev/null || die "$tag: the manifest isn't a Lanternfish Gate $version manifest"
  while IFS=$'\t' read -r name want_sha want_size; do
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "$tag: unsafe file name in the manifest: $name"
    asset=$(jq -c --arg n "$name" '.assets[] | select(.name == $n)' <<<"$rel")
    [ -n "$asset" ] || die "$tag: $name is in the manifest but not attached to the release"
    download_asset "$asset" "$dir/$name"
    got_sha=$(sha256sum "$dir/$name" | cut -d' ' -f1)
    got_size=$(wc -c < "$dir/$name" | tr -d ' ')
    [ "$got_sha" = "$want_sha" ] && [ "$got_size" = "$want_size" ] ||
      die "$tag: $name does not match the manifest; NOT signing"
    printf '  ok  %s  %s\n' "${got_sha:0:16}" "$name" >&2
  done < <(jq -r '.files[] | [.name, .sha256, (.size | tostring)] | @tsv' "$dir/$MANIFEST")
}

upload_sig() { # upload_sig REL_JSON FILE
  local url code
  [ -n "$TOKEN" ] || die "uploading needs a GitHub token in $TOKEN_FILE"
  url=$(jq -r .upload_url <<<"$1"); url=${url%%\{*}
  code=$(curl -sS -o "$WORK/upload.out" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/octet-stream" -H "User-Agent: lanternfish-sign-releases" \
    --data-binary @"$2" "$url?name=$SIG")
  case "$code" in
    201) ;;
    422) die "$(jq -r .tag_name <<<"$1") already has a $SIG" ;;
    401|403|404) die "upload refused ($code): the token needs Contents: read and write on $REPO" ;;
    *) die "upload failed ($code): $(head -c 300 "$WORK/upload.out")" ;;
  esac
}

cmd_sign() {
  [ -f "$KEY" ] || die "no key at $KEY (run: $0 keygen)"
  local rels=() rel tag
  if [ $# -gt 0 ]; then
    local all
    all=$(api "releases?per_page=30") || die "couldn't list releases of $REPO"
    for tag in "$@"; do
      rel=$(jq -c --arg t "$tag" '.[] | select(.tag_name == $t)' <<<"$all")
      [ -n "$rel" ] || die "release $tag not found (drafts need a token)"
      jq -e --arg s "$SIG" 'any(.assets[]; .name == $s) | not' <<<"$rel" >/dev/null ||
        die "$tag is already signed (delete its $SIG on GitHub first to re-sign)"
      rels+=("$rel")
    done
  else
    local list
    list=$(pending_json)
    while read -r rel; do [ -n "$rel" ] && rels+=("$rel"); done <<<"$list"
  fi
  [ ${#rels[@]} -gt 0 ] || { echo "No releases are waiting for a signature." >&2; return; }

  # Check everything before asking for the passphrase.
  local i=0
  for rel in "${rels[@]}"; do
    tag=$(jq -r .tag_name <<<"$rel")
    echo "$tag:" >&2
    mkdir -p "$WORK/$i"
    check_release "$rel" "$WORK/$i"
    i=$((i + 1))
  done

  ask_pass "Sign ${#rels[@]} release(s)? Signing key passphrase (Ctrl-C to stop): "
  ossl pkey -in "$KEY" -passin env:LF_PASS -noout 2>/dev/null || die "wrong passphrase, or $KEY is damaged"
  local keyid
  pub_raw > "$WORK/pub.raw"
  keyid=$(sha256sum "$WORK/pub.raw" | cut -c1-16)
  ossl pkey -in "$KEY" -passin env:LF_PASS -pubout -out "$WORK/pub.pem"

  i=0
  for rel in "${rels[@]}"; do
    tag=$(jq -r .tag_name <<<"$rel")
    local d="$WORK/$i"
    { printf '%s\n' "$CONTEXT"; cat "$d/$MANIFEST"; } > "$d/message"
    ossl pkeyutl -sign -rawin -inkey "$KEY" -passin env:LF_PASS -in "$d/message" -out "$d/sig.bin"
    openssl pkeyutl -verify -rawin -pubin -inkey "$WORK/pub.pem" -in "$d/message" -sigfile "$d/sig.bin" >/dev/null ||
      die "$tag: the new signature doesn't verify"
    jq -n --arg k "$keyid" --arg s "$(base64 < "$d/sig.bin" | tr -d '\n')" '{key_id: $k, signature: $s}' > "$d/$SIG"
    mkdir -p "signed/$tag" && cp "$d/$SIG" "signed/$tag/$SIG"
    if [ -n "$TOKEN" ]; then
      upload_sig "$rel" "$d/$SIG"
      echo "$tag: signed and uploaded$(jq -r 'if .draft then " (draft: publish it on GitHub)" else "" end' <<<"$rel")." >&2
    else
      echo "$tag: signed. No token, so attach signed/$tag/$SIG to the release by hand." >&2
    fi
    i=$((i + 1))
  done
}

case "${1:-}" in
  keygen) cmd_keygen ;;
  pubkey) cmd_pubkey ;;
  pending) cmd_pending ;;
  notify) cmd_notify ;;
  sign) shift; cmd_sign "$@" ;;
  *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
