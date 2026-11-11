#!/usr/bin/env bash
# Plex Media Server indicator check for Linux and Docker.
# Read only: does not remove, install, or update files or containers.
# Exit codes: 0 = no selected indicators found (warnings possible)
#             1 = vulnerable version or an indicator needs investigation
#             2 = Plex not detected
#             3 = required checks incomplete / version unknown

set -u
FIX_MIN='1.43.3.10861' # Plex2Shell fixed version: CVE-2026-96652/54/55/56.
# Public releases by default. Set PLEX_RELEASE_CHANNEL=plexpass for Plex Pass beta.
PLEX_RELEASE_CHANNEL=${PLEX_RELEASE_CHANNEL:-public}
RELEASE_URL='https://plex.tv/api/downloads/5.json'
SELF=${0##*/}

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; Z=$'\033[0m'
else G=''; Y=''; R=''; B=''; Z=''; fi
FAILS=0; WARNS=0; SKIPS=0; UNKNOWN=0; VULNERABLE=0; UPDATE_WARNS=0
INSTALLED_VERSIONS=()
PASS() { printf '%s[PASS]%s  %s\n' "$G" "$Z" "$*"; }
WARN() { printf '%s[WARN]%s  %s\n' "$Y" "$Z" "$*"; WARNS=$((WARNS+1)); }
FAIL() { printf '%s[FAIL]%s  %s\n' "$R" "$Z" "$*"; FAILS=$((FAILS+1)); }
SKIP() { printf '%s[SKIP]%s  %s\n' "$B" "$Z" "$*"; SKIPS=$((SKIPS+1)); }

valid_version() {
  local v=${1:-} part
  [[ $v =~ ^[0-9]+(\.[0-9]+){2,3}(-[[:alnum:]_.-]+)?$ ]] || return 1
  local -a parts=()
  IFS=. read -r -a parts <<< "${v%%-*}"
  for part in "${parts[@]}"; do
    # Bound numeric segments to avoid overflow in arithmetic comparison.
    (( ${#part} <= 9 )) || return 1
  done
}
version_ge() {
  valid_version "$1" && valid_version "$2" || return 2
  local v1=${1%%-*} v2=${2%%-*} i x y
  local -a a=() b=()
  IFS=. read -r -a a <<< "$v1"
  IFS=. read -r -a b <<< "$v2"
  for i in 0 1 2 3; do
    x=$((10#${a[i]:-0})); y=$((10#${b[i]:-0}))
    if (( x > y )); then return 0; fi
    if (( x < y )); then return 1; fi
  done
  return 0
}
# Read only the version attribute on the MediaContainer element.
# The XML declaration also has version="1.0" and is NOT the Plex version.
parse_identity() {
  sed -n '/<MediaContainer[[:space:]>]/s/.*[[:space:]]version="\([^"]*\)".*/\1/p' | head -n 1
}
# Bypass proxy variables: Plex identity must be local to this machine/container.
host_identity() {
  command -v curl >/dev/null 2>&1 || return 1
  local xml
  xml=$(curl --noproxy '*' -fsS --max-time 5 'http://127.0.0.1:32400/identity' 2>/dev/null) || return 1
  printf '%s\n' "$xml" | parse_identity
}
container_identity() {
  local c=$1 xml
  xml=$(docker exec "$c" sh -c '
    if command -v curl >/dev/null 2>&1; then
      curl --noproxy "*" -fsS --max-time 5 http://127.0.0.1:32400/identity
    elif command -v wget >/dev/null 2>&1; then
      http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= wget -q -T 5 -O - http://127.0.0.1:32400/identity
    else exit 127; fi' 2>/dev/null) || return 1
  printf '%s\n' "$xml" | parse_identity
}
check_version() {
  local ver=$1 source=$2 rc
  if ! valid_version "$ver"; then
    WARN "Could not determine the running Plex version ($source)"
    UNKNOWN=1
    return
  fi
  version_ge "$ver" "$FIX_MIN"; rc=$?
  INSTALLED_VERSIONS+=("$ver")
  if (( rc == 0 )); then
    PASS "Plex version $ver meets Plex2Shell security minimum ($FIX_MIN)"
  elif (( rc == 1 )); then
    FAIL "Plex version $ver is below the configured minimum ($FIX_MIN). Upgrade now."
    VULNERABLE=1
  else
    WARN "Cannot compare Plex version $ver"
    UNKNOWN=1
  fi
}
# Fetch the latest *public* Plex Media Server release from Plex's own download feed.
# No downloads are installed; a failure here is an update-status warning, not a
# failure of the independent local compromise checks.
fetch_latest_version() {
  command -v curl >/dev/null 2>&1 || return 1
  local body url=$RELEASE_URL
  case "$PLEX_RELEASE_CHANNEL" in
    public) ;;
    plexpass) url+='?channel=plexpass' ;;
    *) return 1 ;;
  esac
  body=$(curl --noproxy '*' --proto '=https' --tlsv1.2 -fLsS \
    --connect-timeout 5 --max-time 12 "$url" 2>/dev/null) || return 1
  # jq is optional: Python 3 can decode the same response.
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$body" | jq -er '.computer.Linux.version | strings' 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$body" | python3 -c '
import json,sys
try:
    v=json.load(sys.stdin)["computer"]["Linux"]["version"]
    if not isinstance(v,str): raise ValueError("invalid version")
    print(v)
except (ValueError,KeyError,TypeError,UnicodeError):
    sys.exit(1)
' 2>/dev/null
  else
    return 1
  fi
}
check_latest_release() {
  local latest rc installed outdated=0
  printf '%s--- Checking: latest official Plex release (%s) ---%s\n' "$B" "$PLEX_RELEASE_CHANNEL" "$Z"
  latest=$(fetch_latest_version || :)
  if ! valid_version "$latest"; then
    WARN 'Could not verify latest Plex release from plex.tv (network or JSON parser unavailable)'
    UPDATE_WARNS=$((UPDATE_WARNS+1))
    return
  fi
  printf 'Official Plex release version: %s\n' "$latest"
  for installed in "${INSTALLED_VERSIONS[@]}"; do
    version_ge "$installed" "$latest"; rc=$?
    if (( rc == 0 )); then
      PASS "Installed Plex $installed is current or newer than the $PLEX_RELEASE_CHANNEL release"
    elif (( rc == 1 )); then
      WARN "Plex update available: installed $installed; latest $PLEX_RELEASE_CHANNEL $latest"
      UPDATE_WARNS=$((UPDATE_WARNS+1))
      outdated=1
    else
      WARN "Could not compare installed Plex $installed against latest $latest"
      UPDATE_WARNS=$((UPDATE_WARNS+1))
    fi
  done
  if (( ${#INSTALLED_VERSIONS[@]} == 0 )); then
    WARN 'Running Plex version was not established; cannot compare with official release'
    UPDATE_WARNS=$((UPDATE_WARNS+1))
  fi
}
# Can read local-only system files when already root, without prompting otherwise.
read_cmd() {
  if (( EUID == 0 )); then "$@"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then sudo -n "$@"
  else "$@"; fi
}
# A host `ss` command in the target container's network namespace avoids
# installing `ss` inside a minimal container image.
container_network() {
  local c=$1 pid
  if command -v nsenter >/dev/null 2>&1 && command -v ss >/dev/null 2>&1; then
    pid=$(docker inspect --format '{{.State.Pid}}' "$c" 2>/dev/null) || return 1
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    read_cmd nsenter -t "$pid" -n ss -tunp state established
  elif docker exec "$c" sh -c 'command -v ss >/dev/null 2>&1' >/dev/null 2>&1; then
    docker exec "$c" ss -tunp state established
  else
    return 1
  fi
}
check_network() {
  local data=$1 label=$2
  if printf '%s\n' "$data" | grep -aE ':(3333|14444|14433|45700)([^0-9]|$)' >/dev/null; then
    FAIL "Connections to selected mining ports detected ($label); review connection details"
    # Avoid printing unredacted network tables unless needed for investigation.
  else
    PASS "No connections to selected mining ports ($label)"
  fi
}
check_logs() {
  local log=$1 label=$2
  if printf '%s\n' "$log" | grep -aiE 'transcode/universal\?[^ ]*url=(https?|ftp|gopher)|GET /player/timeline\?\$|\$X-Plex-Token|myawesomeproxy' >/dev/null; then
    FAIL "Potential exploit signature in $label (inspect logs privately; tokens may be present)"
  else
    PASS "No selected exploit signatures in $label"
  fi
}

printf 'Plex Media Server compromise check (configured Plex2Shell indicators)\n'
printf 'Read-only. Nothing is intentionally modified. Run with sudo for the deepest checks.\n\n'

DOCKER=(); NATIVE=0; DOCKER_BLOCKED=0
if command -v docker >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' >/dev/null 2>&1; then
    while IFS=$'\t' read -r name image; do
      [[ -n $name ]] || continue
      if printf '%s %s\n' "$name" "$image" | grep -qi plex; then DOCKER+=("$name"); fi
    done < <(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null)
  else DOCKER_BLOCKED=1; fi
fi
if (command -v dpkg >/dev/null 2>&1 && dpkg -s plexmediaserver >/dev/null 2>&1) ||
   (command -v rpm >/dev/null 2>&1 && rpm -q plexmediaserver >/dev/null 2>&1) ||
   [[ -f /lib/systemd/system/plexmediaserver.service || -f /etc/systemd/system/plexmediaserver.service ]]; then
  NATIVE=1
fi
if (( ${#DOCKER[@]} == 0 && NATIVE == 0 )); then
  if (( DOCKER_BLOCKED )); then
    printf '[SKIP]  Docker containers could not be listed\nRESULT: INCOMPLETE\n'; exit 3
  fi
  printf 'Plex Media Server not found.\n'; exit 2
fi
INSTALLS=()
for c in "${DOCKER[@]}"; do INSTALLS+=("docker $c"); done
(( NATIVE )) && INSTALLS+=(native)
printf 'Detected install(s): %s\n\n' "${INSTALLS[*]}"
(( DOCKER_BLOCKED )) && SKIP 'Docker could not be inspected; other installations may have been missed'

for c in "${DOCKER[@]}"; do
  printf '%s--- Checking: docker %s ---%s\n' "$B" "$c" "$Z"
  VER=$(container_identity "$c" || :)
  SOURCE='container identity endpoint'
  # Host fallback applies only when there is one Plex container and no native Plex.
  if ! valid_version "$VER" && (( ${#DOCKER[@]} == 1 && NATIVE == 0 )); then
    VER=$(host_identity || :)
    SOURCE='host identity endpoint'
  fi
  check_version "$VER" "$SOURCE"

  if P=$(docker top "$c" aux 2>/dev/null) || P=$(docker top "$c" -eo user,pid,comm 2>/dev/null); then
    if printf '%s\n' "$P" | grep -aiE 'xmrig|myawesomeproxy|cryptonight|stratum\+tcp|minerd|kdevtmpfsi|kinsing|/tmp/[a-z0-9]{6,}' >/dev/null; then
      FAIL "Suspicious process pattern found in container $c (review docker top)"
    else PASS "No miner/proxy process patterns in container $c"; fi
  else SKIP "Cannot list container processes ($c)"; fi

  # Check temporary files separately from Plex's normal codec cache.
  if F=$(docker exec "$c" sh -c '
    command -v find >/dev/null 2>&1 || exit 127
    for dir in /tmp /var/tmp; do
      [ ! -d "$dir" ] || find "$dir" -maxdepth 2 -type f \( -iname "*xmrig*" -o -iname "*miner*" -o -iname "*myawesomeproxy*" -o -iname "*.sh" -o -iname "*.so" \) || exit 1
    done' 2>/dev/null); then
    if [[ -n $F ]]; then
      WARN "Potentially suspicious files in /tmp or /var/tmp of container $c (inspect):"
      printf '%s\n' "$F" | sed 's/^/       /'
    else PASS "No suspicious files in /tmp or /var/tmp of container $c"; fi
  else SKIP "Cannot inspect temporary files in container $c"; fi

  # Normal Plex lib*_encoder.so and lib*_decoder.so files are not evidence.
  if CODECS=$(docker exec "$c" sh -c '
    command -v find >/dev/null 2>&1 || exit 127
    for base in "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server" "/config/Library/Application Support/Plex Media Server"; do
      [ ! -d "$base/Codecs" ] || find "$base/Codecs" -type f \( -name "*.so" -o -name "*.sh" \) || exit 1
    done' 2>/dev/null); then
    BAD_CODECS=$(printf '%s\n' "$CODECS" | grep -aiE 'xmrig|myawesomeproxy|/tmp/|\.sh$' || :)
    if [[ -n $BAD_CODECS ]]; then
      WARN "Unusual codec files in container $c; investigate their origin:"
      printf '%s\n' "$BAD_CODECS" | sed 's/^/       /'
    else PASS "No selected suspicious file patterns in Plex Codecs folder ($c)"; fi
  else SKIP "Cannot inspect Plex Codecs folder in container $c"; fi

  if N=$(container_network "$c" 2>/dev/null); then
    check_network "$N" "container $c"
  else SKIP "Cannot inspect container network ($c); requires host nsenter/ss or container ss"; fi

  if L=$(docker logs "$c" --since 72h 2>/dev/null); then
    check_logs "$L" "container Docker logs ($c, last 72h)"
  else SKIP "Cannot read container Docker logs ($c)"; fi

  if L=$(docker exec "$c" sh -c '
    for base in "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server" "/config/Library/Application Support/Plex Media Server"; do
      log="$base/Logs/Plex Media Server.log"
      if [ -r "$log" ]; then cat "$log"; exit $?; fi
    done
    exit 3' 2>/dev/null); then
    check_logs "$L" "Plex application log ($c)"
  else SKIP "Cannot read Plex application log in container $c"; fi
  printf '\n'
done

if (( NATIVE )); then
  printf '%s--- Checking: native ---%s\n' "$B" "$Z"
  DATA='/var/lib/plexmediaserver/Library/Application Support/Plex Media Server'
  VER=''
  if command -v dpkg >/dev/null 2>&1; then
    VER=$(dpkg -s plexmediaserver 2>/dev/null | sed -n 's/^Version: *//p' | head -n 1)
  fi
  if ! valid_version "$VER" && command -v rpm >/dev/null 2>&1; then
    VER=$(rpm -q --qf '%{VERSION}\n' plexmediaserver 2>/dev/null | head -n 1)
  fi
  if ! valid_version "$VER"; then VER=$(host_identity || :); fi
  check_version "$VER" 'native installation'
  if P=$(ps aux 2>/dev/null); then
    if printf '%s\n' "$P" | grep -aiE 'xmrig|myawesomeproxy|cryptonight|stratum\+tcp|minerd|kdevtmpfsi|kinsing' | grep -av 'Plex Plug-in' >/dev/null; then
      WARN 'Possible miner/proxy process pattern on host (review ps output)'
    else PASS 'No miner/proxy process patterns on host'; fi
  else SKIP 'Cannot inspect host processes'; fi
  if T=$(read_cmd find /tmp /var/tmp -maxdepth 2 -type f \( -iname '*xmrig*' -o -iname '*miner*' -o -iname '*proxy*' -o -name '*.so' \) 2>/dev/null); then
    if [[ -n $T ]]; then
      WARN 'Potentially suspicious files in host temporary directories:'
      printf '%s\n' "$T" | sed 's/^/       /'
    else PASS 'No suspicious files in host temporary directories'; fi
  else SKIP 'Cannot inspect host temporary directories'; fi
  if N=$(read_cmd ss -tunp state established 2>/dev/null); then
    check_network "$N" 'host'
  else SKIP 'Cannot inspect host network'; fi
  LOG="$DATA/Logs/Plex Media Server.log"
  if L=$(read_cmd cat "$LOG" 2>/dev/null); then
    check_logs "$L" 'native Plex application log'
  else SKIP "Cannot read native Plex log ($LOG)"; fi
  sshdirs=()
  [[ -d /root/.ssh ]] && sshdirs+=(/root/.ssh)
  for d in /home/*/.ssh; do [[ -d $d ]] && sshdirs+=("$d"); done
  if (( ${#sshdirs[@]} )); then
    if K=$(read_cmd find "${sshdirs[@]}" -name authorized_keys -mtime -30 2>/dev/null); then
      if [[ -n $K ]]; then WARN 'SSH authorized_keys modified in last 30 days:'; printf '%s\n' "$K" | sed 's/^/       /'
      else PASS 'No recently modified authorized_keys'; fi
    else SKIP 'Cannot inspect SSH authorized_keys'; fi
  else PASS 'No SSH key directories at standard paths'; fi
  cronpaths=()
  [[ -d /etc/cron.d ]] && cronpaths+=(/etc/cron.d)
  [[ -d /var/spool/cron/crontabs ]] && cronpaths+=(/var/spool/cron/crontabs)
  if (( ${#cronpaths[@]} )); then
    CR=$(read_cmd grep -rlE 'curl|wget|/tmp/' "${cronpaths[@]}" 2>/dev/null); rc=$?
    if (( rc == 0 )); then WARN 'Cron entries reference curl, wget, or /tmp:'; printf '%s\n' "$CR" | sed 's/^/       /'
    elif (( rc == 1 )); then PASS 'No suspicious cron entries'; else SKIP 'Cannot inspect cron entries'; fi
  else SKIP 'No cron directories to inspect'; fi
fi

check_latest_release
printf '\n'
printf '%s============================== summary ==============================%s\n' "$B" "$Z"
printf 'Indicators: %s | Warnings: %s | Skipped: %s\n' "$FAILS" "$WARNS" "$SKIPS"
if (( FAILS > 0 || VULNERABLE )); then
  printf '%sRESULT: FAIL — investigate the indicators above.%s\n' "$R" "$Z"
  (( UNKNOWN || SKIPS )) && printf 'Some checks could not be completed.\n'
  EXIT=1
elif (( UNKNOWN || SKIPS )); then
  printf '%sRESULT: INCOMPLETE — at least one required check could not be completed.%s\n' "$Y" "$Z"
  EXIT=3
elif (( WARNS > 0 )); then
  printf '%sRESULT: PASS with %s warning(s) to review manually.%s\n' "$Y" "$WARNS" "$Z"
  EXIT=0
else
  printf '%sRESULT: PASS — no selected compromise indicators found.%s\n' "$G" "$Z"
  EXIT=0
fi
printf 'A PASS does not prove the server has never been compromised.\n'
printf 'Plex2Shell security threshold: %s. Latest-release lookup: %s.\n' "$FIX_MIN" "$PLEX_RELEASE_CHANNEL"
printf 'An update notice does not by itself indicate compromise.\n'
exit "$EXIT"
