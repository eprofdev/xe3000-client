#!/bin/bash
# shellcheck shell=bash
# =====================================================================
#  OpenWrt "container" for the system tests: the real OpenWrt x86-64
#  rootfs in a chroot, booted by its own procd as PID 1 (container mode,
#  env container=lxc) inside private mount + network + PID namespaces.
#
#    ow_create VER      extract a fresh rootfs + host-side preparation
#    ow_boot            boot it (procd, ubusd, logd, netifd, dropbear...)
#    ow_exec CMD...     run CMD inside (chroot + all namespaces)
#    ow_net CMD...      run a HOST binary inside the container netns only
#    ow_halt            kill the container (all namespaces go away)
#    ow_destroy         ow_halt + remove rootfs
#
#  Nothing is mounted in the host mount namespace, no host network
#  change: Internet for opkg/curl comes from tests/system/openwrt/netproxy.py
#  on a UNIX socket, bridged into the netns by socat on 127.0.0.1:3128.
# =====================================================================
OW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OW_CACHE="${EW_TEST_CACHE:-/root/.cache/ew-tests}"
OW_BASE="${OW_BASE:-/var/tmp/ew-chroots}"
OW_PROXY_PORT=3128
OW_PID=""        # host PID of the container's PID 1 (procd)
OW_UNSHARE=""    # host PID of the unshare process
OW_NETPROXY=""   # host PID of netproxy.py

ow_log() { printf '[ow %s] %s\n' "$(date +%T)" "$*" >&2; }

ow_create() { # VER
    OW_VER="$1"
    OW_ROOT="$OW_BASE/openwrt-$OW_VER"
    OW_RUN="$OW_BASE/openwrt-$OW_VER.run"
    local tgz="$OW_CACHE/openwrt-$OW_VER.tar.gz"
    [ -f "$tgz" ] || { ow_log "missing fixture $tgz (tests/system/fetch-fixtures.sh)"; return 1; }
    ow_destroy
    mkdir -p "$OW_ROOT" "$OW_RUN"
    tar -xzf "$tgz" -C "$OW_ROOT" || return 1
    # opkg over plain http (goes through the netproxy bridge)
    sed -i 's#https://downloads.openwrt.org#http://downloads.openwrt.org#' "$OW_ROOT/etc/opkg/distfeeds.conf"
    # trust the host's HTTPS interception proxy inside the chroot
    if [ -f /root/.ccr/ca-bundle.crt ]; then
        mkdir -p "$OW_ROOT/etc/ssl/certs"
        cat /root/.ccr/ca-bundle.crt >>"$OW_ROOT/etc/ssl/certs/ca-certificates.crt"
        cp /root/.ccr/ca-bundle.crt "$OW_ROOT/etc/ssl/certs/ew-test-proxy-ca.crt"
    fi
    mkdir -p "$OW_ROOT/fixtures"
    return 0
}

ow_start_netproxy() {
    OW_SOCK="$OW_RUN/proxy.sock"
    rm -f "$OW_SOCK"
    python3 "$OW_DIR/netproxy.py" "$OW_SOCK" >"$OW_RUN/netproxy.log" 2>&1 &
    OW_NETPROXY=$!
    local i=0
    while [ ! -S "$OW_SOCK" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    [ -S "$OW_SOCK" ]
}

ow_boot() {
    [ -n "$OW_ROOT" ] || return 1
    [ -n "$OW_NETPROXY" ] && kill -0 "$OW_NETPROXY" 2>/dev/null || ow_start_netproxy || { ow_log "netproxy failed"; return 1; }
    cat >"$OW_RUN/init.sh" <<EOF
#!/bin/bash
# PID 1 of the container until it execs procd
set -e
R="$OW_ROOT"
mount -t proc proc "\$R/proc"
mount -t sysfs sysfs "\$R/sys" 2>/dev/null || mount --rbind /sys "\$R/sys"
mount -t tmpfs -o mode=755,size=4m tmpfs "\$R/dev"
for d in null zero full random urandom tty; do
    touch "\$R/dev/\$d"; mount --bind "/dev/\$d" "\$R/dev/\$d"
done
mkdir -p "\$R/dev/pts" "\$R/dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666,mode=620 devpts "\$R/dev/pts"
ln -sf pts/ptmx "\$R/dev/ptmx"
touch "\$R/dev/console"; mount --bind /dev/null "\$R/dev/console"
mount -t tmpfs -o mode=1777,size=512m tmpfs "\$R/tmp"
mount --bind "$OW_CACHE" "\$R/fixtures"
mount -o remount,bind,ro "\$R/fixtures" 2>/dev/null || true
ip link set lo up
exec env -i container=lxc PATH=/usr/sbin:/usr/bin:/sbin:/bin chroot "\$R" /sbin/init
EOF
    chmod 755 "$OW_RUN/init.sh"
    unshare --mount --net --pid --fork --propagation private "$OW_RUN/init.sh" >"$OW_RUN/console.log" 2>&1 &
    OW_UNSHARE=$!
    local i=0
    OW_PID=""
    while [ "$i" -lt 100 ]; do
        OW_PID=$(pgrep -P "$OW_UNSHARE" | head -n 1)
        if [ -n "$OW_PID" ] && [ "$(readlink "/proc/$OW_PID/exe" 2>/dev/null)" != "" ] &&
            ow_exec ubus call service list >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
        i=$((i + 1))
    done
    [ -n "$OW_PID" ] || { ow_log "container did not start"; cat "$OW_RUN/console.log" >&2; return 1; }
    # wait for the boot to finish (rc.d S* done -> "init complete")
    i=0
    while [ "$i" -lt 120 ]; do
        ow_exec logread 2>/dev/null | grep -q 'init complete' && break
        sleep 0.5
        i=$((i + 1))
    done
    # Internet bridge inside the container netns (host socat, dies with the PID ns)
    ( nsenter -t "$OW_PID" -n -p -- socat "TCP-LISTEN:$OW_PROXY_PORT,bind=127.0.0.1,reuseaddr,fork" \
        "UNIX-CONNECT:$OW_SOCK" >/dev/null 2>&1 & )
    i=0
    while [ "$i" -lt 50 ]; do
        ow_net bash -c "exec 3<>/dev/tcp/127.0.0.1/$OW_PROXY_PORT" 2>/dev/null && break
        sleep 0.1
        i=$((i + 1))
    done
    ow_log "OpenWrt $OW_VER booted (PID 1 = host pid $OW_PID)"
    return 0
}

# run inside the container (chroot + namespaces), minimal OpenWrt env
ow_exec() {
    [ -n "$OW_PID" ] || return 125
    nsenter -t "$OW_PID" -m -n -p -r -w -- /usr/bin/env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TERM=xterm USER=root LOGNAME=root \
        http_proxy="http://127.0.0.1:$OW_PROXY_PORT" https_proxy="http://127.0.0.1:$OW_PROXY_PORT" \
        ${OW_EXTRA_ENV:-} "$@"
}

# run a host binary inside the container network namespace (+ pid ns)
ow_net() {
    [ -n "$OW_PID" ] || return 125
    nsenter -t "$OW_PID" -n -- env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy \
        -u ALL_PROXY -u all_proxy "$@"
}

ow_halt() {
    if [ -n "$OW_PID" ] && kill -0 "$OW_PID" 2>/dev/null; then
        kill -9 "$OW_PID" 2>/dev/null
    fi
    if [ -n "$OW_UNSHARE" ]; then
        local i=0
        while kill -0 "$OW_UNSHARE" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
        kill -9 "$OW_UNSHARE" 2>/dev/null
    fi
    OW_PID="" OW_UNSHARE=""
    return 0
}

ow_stop_netproxy() {
    [ -n "$OW_NETPROXY" ] && kill "$OW_NETPROXY" 2>/dev/null
    OW_NETPROXY=""
    [ -n "${OW_SOCK:-}" ] && rm -f "$OW_SOCK"
    return 0
}

ow_destroy() {
    ow_halt
    ow_stop_netproxy
    [ -n "${OW_ROOT:-}" ] || return 0
    # refuse to delete if anything is still mounted below it
    if grep -q " $OW_ROOT/" /proc/mounts 2>/dev/null; then
        ow_log "WARNING: mounts still present under $OW_ROOT - not deleting"
        return 1
    fi
    rm -rf "$OW_ROOT" "$OW_RUN"
    return 0
}
