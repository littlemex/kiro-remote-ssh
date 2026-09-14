# Bootstrap a Kiro remote extension host on this machine.
#
# Delivered on stdin to `sh`, never as a quoted argument. Placeholders of the
# form %%NAME%% are substituted by the client before delivery.
#
# The report is written between two lines carrying a per-invocation random
# marker, so that an MOTD, a chatty shell profile, or a non-POSIX login shell
# cannot be mistaken for the report.

set -u

MARKER='%%MARKER%%'
COMMIT='%%COMMIT%%'
DOWNLOAD_URL='%%DOWNLOAD_URL%%'
SERVER_APP_NAME='%%SERVER_APP_NAME%%'
SERVER_DATA_DIR="$HOME/%%SERVER_DATA_FOLDER_NAME%%"
EXPECTED_SHA256='%%EXPECTED_SHA256%%'
ARCHIVE_ON_STDIN='%%ARCHIVE_ON_STDIN%%'

SERVER_DIR="$SERVER_DATA_DIR/bin/$COMMIT"
SERVER_SCRIPT="$SERVER_DIR/bin/$SERVER_APP_NAME"
STATE_PREFIX="$SERVER_DATA_DIR/.$COMMIT"
LOG_FILE="$STATE_PREFIX.log"
PID_FILE="$STATE_PREFIX.pid"
TOKEN_FILE="$STATE_PREFIX.token"
LOCK_FILE="$STATE_PREFIX.lock"

umask 077

listening_on=
token=
reused=false

report() {
    echo "$MARKER begin"
    echo "exitCode=$1"
    echo "listeningOn=$listening_on"
    echo "connectionToken=$token"
    echo "reusedServer=$reused"
    echo "logFile=$LOG_FILE"
    echo "serverDir=$SERVER_DIR"
    echo "$MARKER end"
    exit 0
}

fail() {
    echo "error: $1" >&2
    report 1
}

# --- prerequisites ------------------------------------------------------------
# Each refusal names its own reason. A download error is not an acceptable way
# to tell someone their host is unsupported.

[ "$(uname -s)" = Linux ] || fail "this host runs $(uname -s); Kiro publishes a remote server for Linux only"

case "$(uname -m)" in
    x86_64 | amd64) arch=x64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "unsupported architecture $(uname -m); Kiro publishes x64 and arm64 remote servers only" ;;
esac

# The published server is a glibc build, so a musl host cannot run it however
# complete the rest of the environment looks.
if ! (ldd --version 2>&1 | head -1 | grep -qi 'glibc\|GNU libc'); then
    fail "this host does not use glibc; the Kiro remote server is a glibc build and cannot run here"
fi

command -v tar >/dev/null 2>&1 || fail "tar was not found on this host"

DOWNLOAD_URL=$(printf '%s' "$DOWNLOAD_URL" | sed "s/\${arch}/$arch/g")

mkdir -p "$SERVER_DATA_DIR" || fail "could not create $SERVER_DATA_DIR"

# --- install lock ------------------------------------------------------------
# Two windows, or two client machines, connecting for the first time must not
# interleave check, download, extract and start.

: > "$LOCK_FILE" 2>/dev/null || true
if command -v flock >/dev/null 2>&1; then
    exec 9<>"$LOCK_FILE" || fail "could not open the install lock $LOCK_FILE"
    flock -x -w 120 9 || fail "timed out waiting for the install lock held by another connection"
else
    waited=0
    until mkdir "$LOCK_FILE.d" 2>/dev/null; do
        waited=$((waited + 1))
        [ "$waited" -lt 120 ] || fail "timed out waiting for the install lock held by another connection"
        sleep 1
    done
    trap 'rmdir "$LOCK_FILE.d" 2>/dev/null' EXIT INT HUP TERM
fi

# --- reuse a live server -----------------------------------------------------
# A recorded pid is not evidence. Reuse requires that the pid exists, that it is
# a server for this commit, that the recorded port is listening, and that the
# token is readable. Anything less and a pid that was recycled looks alive.

server_is_live() {
    [ -f "$PID_FILE" ] && [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ] || return 1
    pid=$(cat "$PID_FILE" 2>/dev/null) || return 1
    [ -n "${pid:-}" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    ps -o args= -p "$pid" 2>/dev/null | grep -q "$COMMIT" || return 1
    [ -f "$LOG_FILE" ] || return 1
    port=$(sed -n 's/.*Extension host agent listening on \([0-9][0-9]*\).*/\1/p' "$LOG_FILE" | tail -1)
    [ -n "${port:-}" ] || return 1
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q "127.0.0.1:$port " || return 1
    fi
    listening_on=$port
    return 0
}

if server_is_live; then
    token=$(cat "$TOKEN_FILE")
    reused=true
    report 0
fi

# Not live. Clear the stale bookkeeping so a later probe cannot believe it.
rm -f "$PID_FILE" "$LOG_FILE" 2>/dev/null

# --- install ------------------------------------------------------------------

if [ ! -x "$SERVER_SCRIPT" ]; then
    staging="$SERVER_DATA_DIR/.staging.$COMMIT.$$"
    rm -rf "$staging"
    mkdir -p "$staging" || fail "could not create the staging directory $staging"
    archive="$staging/server.tar.gz"

    if [ "$ARCHIVE_ON_STDIN" = true ]; then
        # The client already holds the archive, so it streams it and keeps the
        # digest check on its own side.
        cat > "$archive" || fail "could not receive the server archive on stdin"
    elif command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --retry 3 --connect-timeout 10 \
            --output "$archive" "$DOWNLOAD_URL" || fail "could not download the server from the vendor endpoint"
    elif command -v wget >/dev/null 2>&1; then
        wget --tries=3 --timeout=10 --quiet -O "$archive" "$DOWNLOAD_URL" \
            || fail "could not download the server from the vendor endpoint"
    else
        fail "neither curl nor wget was found, and the archive was not supplied by the client"
    fi

    # Digest before extraction, never after: extraction is the step that can do
    # damage, so an archive already known to be wrong must not reach it.
    if [ -n "$EXPECTED_SHA256" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            actual=$(sha256sum "$archive" | cut -d' ' -f1)
        elif command -v shasum >/dev/null 2>&1; then
            actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
        else
            rm -rf "$staging"
            fail "a digest was pinned for this server but neither sha256sum nor shasum is available to check it"
        fi
        if [ "$actual" != "$EXPECTED_SHA256" ]; then
            rm -rf "$staging"
            fail "the server archive does not match the digest recorded for commit $COMMIT"
        fi
    fi

    # Inspect entries before writing any of them. An archive may not place files
    # outside the staging directory, whether by path or by link.
    if tar -tzf "$archive" > "$staging/manifest" 2>/dev/null; then
        if grep -qE '^/|(^|/)\.\.(/|$)' "$staging/manifest"; then
            rm -rf "$staging"
            fail "the server archive contains an absolute or parent-relative path and was refused"
        fi
    else
        rm -rf "$staging"
        fail "the server archive is not readable as a gzip tar"
    fi
    if tar -tvzf "$archive" 2>/dev/null | grep -qE '^[hl]'; then
        rm -rf "$staging"
        fail "the server archive contains a link entry and was refused"
    fi

    mkdir -p "$staging/root" || fail "could not create the staging root"
    tar -xzf "$archive" -C "$staging/root" --strip-components 1 \
        || { rm -rf "$staging"; fail "the server archive could not be extracted"; }

    [ -s "$staging/root/bin/$SERVER_APP_NAME" ] \
        || { rm -rf "$staging"; fail "the extracted server does not contain bin/$SERVER_APP_NAME"; }

    # Cheap catch for an honest mistake: the wrong commit's archive landing here.
    # This is not an integrity check; an attacker able to replace the archive can
    # also write this field.
    extracted_commit=$(sed -n 's/.*"commit"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$staging/root/product.json" | head -1)
    [ "$extracted_commit" = "$COMMIT" ] \
        || { rm -rf "$staging"; fail "the extracted server reports commit ${extracted_commit:-none} but $COMMIT was requested"; }

    # A partial install must never become a live one, so publish by rename.
    mkdir -p "$SERVER_DATA_DIR/bin" || fail "could not create $SERVER_DATA_DIR/bin"
    rm -rf "$SERVER_DIR.incoming"
    mv "$staging/root" "$SERVER_DIR.incoming" || { rm -rf "$staging"; fail "could not stage the server directory"; }
    rm -rf "$staging"
    rm -rf "$SERVER_DIR"
    mv "$SERVER_DIR.incoming" "$SERVER_DIR" || fail "could not publish the server directory"
    chmod +x "$SERVER_SCRIPT" 2>/dev/null || true
fi

[ -x "$SERVER_SCRIPT" ] || fail "the server is installed but $SERVER_SCRIPT is not executable"

# --- start --------------------------------------------------------------------
# The token is passed by path, so it never appears in this host's process list.

if command -v od >/dev/null 2>&1 && [ -r /dev/urandom ]; then
    token=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
else
    fail "could not read /dev/urandom to generate a connection token"
fi
[ ${#token} -eq 64 ] || fail "could not generate a 32-byte connection token"

rm -f "$TOKEN_FILE"
(umask 077; printf '%s' "$token" > "$TOKEN_FILE") || fail "could not write the connection token file"
chmod 600 "$TOKEN_FILE" 2>/dev/null || true

# setsid detaches the server from this session, so a host configured with
# systemd KillUserProcesses=yes does not take it down when the bootstrap exits.
#
# 9>&- matters more than it looks. The install lock is held on file descriptor 9,
# and a child inherits open descriptors, so a server started without closing it
# keeps the lock for its whole lifetime. The next connection then waits on a lock
# whose holder is the very server it was about to reuse, and times out. Closing
# the descriptor in the child is what makes the lock release when this shell
# exits, as intended.
if command -v setsid >/dev/null 2>&1; then
    setsid "$SERVER_SCRIPT" --start-server --host=127.0.0.1 --port=0 \
        --connection-token-file "$TOKEN_FILE" \
        --telemetry-level off --enable-remote-auto-shutdown \
        --accept-server-license-terms > "$LOG_FILE" 2>&1 9>&- &
else
    "$SERVER_SCRIPT" --start-server --host=127.0.0.1 --port=0 \
        --connection-token-file "$TOKEN_FILE" \
        --telemetry-level off --enable-remote-auto-shutdown \
        --accept-server-license-terms > "$LOG_FILE" 2>&1 9>&- &
fi
printf '%s' "$!" > "$PID_FILE"

waited=0
while [ "$waited" -lt 120 ]; do
    if [ -f "$LOG_FILE" ]; then
        if grep -q 'Error loading shared library libstdc++' "$LOG_FILE" 2>/dev/null; then
            fail "the server could not start because libstdc++ is missing on this host"
        fi
        listening_on=$(sed -n 's/.*Extension host agent listening on \([0-9][0-9]*\).*/\1/p' "$LOG_FILE" | tail -1)
        [ -n "${listening_on:-}" ] && break
    fi
    waited=$((waited + 1))
    sleep 0.5 2>/dev/null || sleep 1
done

[ -n "${listening_on:-}" ] || fail "the server did not report a listening port within the timeout; see $LOG_FILE"

# The recorded pid must be the process actually serving, not the shell that
# launched it, or the liveness probe above will reject its own work.
actual_pid=$(ps -eo pid=,args= 2>/dev/null | grep "$SERVER_DIR" | grep -v grep | awk 'NR==1{print $1}')
[ -n "${actual_pid:-}" ] && printf '%s' "$actual_pid" > "$PID_FILE"

report 0
