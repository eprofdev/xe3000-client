#!/bin/bash
# shellcheck shell=bash disable=SC2016
# =====================================================================
#  System test of xe3000-client.sh on the real OpenWrt 21.02 rootfs
#  (same release family as the GL-XE3000 firmware 4.x), booted with its
#  own procd in private namespaces (tests/lib/container.sh).
#
#  Topology (all inside the router's network namespace unless noted):
#    LAN client netns "xeclan"  192.168.8.100 --veth-- xlan 192.168.8.1 (router)
#    "internet" netns "xecnet", routed via the router (xwan 10.200.0.1 - 10.200.0.2):
#                  203.0.113.10:80  web target (logs the peer address)
#                  203.0.113.53:53  DNS (UDP+TCP)
#    your server:  198.51.100.20    Xray: REALITY+Vision :443, +ML-DSA-65 :2443,
#                                   VLESS Encryption (ML-KEM-768) :3443, XHTTP+REALITY :4443
#                  198.51.100.30    OpenSSH :2222 (dropbear owns :22), TLS front :443 (logs SNI),
#                                   WebSocket relay :80, WebSocket+TLS :8443
#  A packet from the LAN client that reaches 203.0.113.10 directly shows
#  peer 192.168.8.100 in the web log; through the tunnel it shows the server.
#
#  Needs: root, unshare/nsenter, iproute2, socat, python3, openssl, sshd,
#  an Xray linux-amd64 binary (XEC_TEST_XRAY, default: build/xray) and the
#  OpenWrt 21.02 x86-64 rootfs (downloaded on first run).
# =====================================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../xe3000-client.sh"
export EW_TEST_CACHE="${XEC_TEST_CACHE:-/root/.cache/xec-tests}"
mkdir -p "$EW_TEST_CACHE"
# shellcheck source=lib/container.sh
. "$HERE/lib/container.sh"

XRAY_HOST="${XEC_TEST_XRAY:-$EW_TEST_CACHE/xray}"
W="$OW_BASE/xec-work"
PASS=0 FAIL=0
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
step() {
    # XEC_TEST_STOP="words": stop before that step and keep the container (debugging)
    if [ -n "${XEC_TEST_STOP:-}" ] && case "$*" in "$XEC_TEST_STOP"*) true ;; *) false ;; esac; then
        echo "$OW_PID" >"$W/ow.pid"; echo "stopped before: $* (router PID $OW_PID)"; trap - EXIT; exit 0
    fi
    printf '\n== %s\n' "$*"
}
t() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
X() { OW_EXTRA_ENV="NO_COLOR=1 no_proxy=*" ow_exec "$@"; }   # inside the router, no proxy
XP() { OW_EXTRA_ENV="NO_COLOR=1" ow_exec "$@"; }             # inside the router, Internet proxy (opkg)
N() { ow_net "$@"; }                                          # host binary in the router netns
I() { ip netns exec xecnet env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy "$@"; }     # the Internet
C() { ip netns exec xeclan env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy "$@"; }                            # LAN client
lastpeer() { tail -n 1 "$W/http.log" 2>/dev/null | cut -d' ' -f1; }
lan_get() { : >"$W/http.log.mark"; C curl -s --max-time "${2:-10}" "http://203.0.113.10$1"; }

kill_servers() {
    pkill -f "$HERE/helpers.py" 2>/dev/null; pkill -f "sshd -D -f $W/sshd_config" 2>/dev/null
    pkill -f "s_server -quiet -accept 127.0.0.1:19443" 2>/dev/null; pkill -f "run -c $W/server.json" 2>/dev/null
    return 0
}
cleanup() {
    kill_servers
    ip netns del xeclan 2>/dev/null; ip netns del xecnet 2>/dev/null
    ow_destroy >/dev/null 2>&1
}
trap cleanup EXIT

# ------------------------------------------------------------ fixtures
step "fixtures"
tgz="$EW_TEST_CACHE/openwrt-21.02.tar.gz"
[ -s "$tgz" ] || curl -fsSL -m 600 -o "$tgz" https://downloads.openwrt.org/releases/21.02.7/targets/x86/64/openwrt-21.02.7-x86-64-rootfs.tar.gz
t "OpenWrt 21.02.7 x86-64 rootfs" test -s "$tgz"
[ -x "$XRAY_HOST" ] || { echo "no Xray binary at $XRAY_HOST (set XEC_TEST_XRAY)"; exit 1; }
XV=$("$XRAY_HOST" version | head -n 1)
echo "  server/client Xray: $XV"
# release-style zip + .dgst (the installer verifies SHA2-256 exactly like a GitHub release)
python3 - "$XRAY_HOST" "$EW_TEST_CACHE/xray.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    zi = zipfile.ZipInfo("xray"); zi.external_attr = 0o755 << 16
    z.writestr(zi, open(sys.argv[1], "rb").read(), zipfile.ZIP_DEFLATED)
PY
printf 'SHA2-256= %s\n' "$(sha256sum "$EW_TEST_CACHE/xray.zip" | cut -d' ' -f1)" >"$EW_TEST_CACHE/xray.dgst"
printf 'SHA2-256= %064d\n' 0 >"$EW_TEST_CACHE/xray-bad.dgst"

rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
UUID=$("$XRAY_HOST" uuid)
"$XRAY_HOST" x25519 >"$W/x25519"
PK=$(sed -n 's/^PrivateKey: *//p' "$W/x25519"); PBK=$(sed -n 's/^Password (PublicKey): *//p' "$W/x25519")
"$XRAY_HOST" mldsa65 >"$W/mldsa"; SEED=$(sed -n 's/^Seed: *//p' "$W/mldsa"); VERIFY=$(sed -n 's/^Verify: *//p' "$W/mldsa")
VERIFY2=$("$XRAY_HOST" mldsa65 | sed -n 's/^Verify: *//p')
"$XRAY_HOST" vlessenc >"$W/venc"
DEC=$(grep -m1 '"decryption"' "$W/venc" | sed 's/.*: *"\(.*\)"/\1/'); ENC=$(grep -m1 '"encryption"' "$W/venc" | sed 's/.*: *"\(.*\)"/\1/')
t "server keys (x25519, ML-DSA-65, ML-KEM-768 VLESS Encryption)" test -n "$PBK" -a -n "$VERIFY" -a -n "$ENC"
# REALITY target with a real-world sized chain (root -> intermediate -> leaf, RSA-4096):
# the ML-DSA-65 signature makes the certificate message > 3.3 KB and REALITY must fit
# it into the target's record sizes (same requirement as a real REALITY target)
openssl req -x509 -newkey rsa:4096 -nodes -days 30 -subj /CN=Test-Root -keyout "$W/root.key" -out "$W/root.crt" 2>/dev/null
openssl req -newkey rsa:4096 -nodes -subj /CN=Test-Intermediate -keyout "$W/int.key" -out "$W/int.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:true\nkeyUsage=keyCertSign,cRLSign\n' >"$W/int.ext"
openssl x509 -req -in "$W/int.csr" -CA "$W/root.crt" -CAkey "$W/root.key" -CAcreateserial -days 30 -extfile "$W/int.ext" -out "$W/int.crt" 2>/dev/null
openssl req -newkey rsa:4096 -nodes -subj /CN=www.example.com -keyout "$W/www.key" -out "$W/www.csr" 2>/dev/null
printf 'subjectAltName=DNS:www.example.com\n' >"$W/www.ext"
openssl x509 -req -in "$W/www.csr" -CA "$W/int.crt" -CAkey "$W/int.key" -CAcreateserial -days 30 -extfile "$W/www.ext" -out "$W/www.crt" 2>/dev/null
cat "$W/int.crt" "$W/root.crt" >"$W/chain.crt"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=bug.example.com -keyout "$W/bug.key" -out "$W/bug.crt" 2>/dev/null
# Xray blocks "private" targets (TEST-NET included) behind VLESS by default: allow the fake Internet
cat >"$W/server.json" <<EOF
{"log":{"loglevel":"warning","error":"$W/xray-server.log"},
"inbounds":[
{"tag":"A","listen":"198.51.100.20","port":443,"protocol":"vless","settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
 "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:19443","serverNames":["www.example.com"],"privateKey":"$PK","shortIds":["a1b2c3d4"]}}},
{"tag":"B","listen":"198.51.100.20","port":2443,"protocol":"vless","settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
 "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:19443","serverNames":["www.example.com"],"privateKey":"$PK","shortIds":["a1b2c3d4"],"mldsa65Seed":"$SEED"}}},
{"tag":"C","listen":"198.51.100.20","port":3443,"protocol":"vless","settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"$DEC"},
 "streamSettings":{"network":"raw","security":"none"}},
{"tag":"D","listen":"198.51.100.20","port":4443,"protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
 "streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/xh"},"security":"reality","realitySettings":{"target":"127.0.0.1:19443","serverNames":["www.example.com"],"privateKey":"$PK","shortIds":["a1b2c3d4"]}}},
{"tag":"E","listen":"198.51.100.20","port":6443,"protocol":"vmess","settings":{"clients":[{"id":"$UUID"}]},
 "streamSettings":{"network":"ws","wsSettings":{"path":"/vm"},"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$W/www.crt","keyFile":"$W/www.key"}]}}},
{"tag":"F","listen":"198.51.100.20","port":6444,"protocol":"vmess","settings":{"clients":[{"id":"$UUID"}]},"streamSettings":{"network":"raw","security":"none"}},
{"tag":"G","listen":"198.51.100.20","port":7443,"protocol":"trojan","settings":{"clients":[{"password":"Tr0jan-pass"}]},
 "streamSettings":{"network":"raw","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$W/www.crt","keyFile":"$W/www.key"}]}}},
{"tag":"H","listen":"198.51.100.20","port":7444,"protocol":"trojan","settings":{"clients":[{"password":"Tr0jan-pass"}]},
 "streamSettings":{"network":"ws","wsSettings":{"path":"/tj"},"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$W/www.crt","keyFile":"$W/www.key"}]}}}],
"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["203.0.113.0/24"]}]}}]}
EOF
t "server config valid" "$XRAY_HOST" run -test -c "$W/server.json"
# SSH server account + config
id xectest >/dev/null 2>&1 || useradd -m -s /bin/bash xectest
echo 'xectest:Pa55-w0rd' | chpasswd
mkdir -p /home/xectest/.ssh /run/sshd; : >/home/xectest/.ssh/authorized_keys
chown -R xectest: /home/xectest/.ssh; chmod 700 /home/xectest/.ssh; chmod 600 /home/xectest/.ssh/authorized_keys
ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey" <<<y >/dev/null 2>&1
cat >"$W/sshd_config" <<EOF
ListenAddress 198.51.100.30:2222
HostKey $W/hostkey
PidFile $W/sshd.pid
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
AllowTcpForwarding yes
PermitTTY no
EOF
LINK_A="vless://$UUID@198.51.100.20:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=$PBK&sid=a1b2c3d4&spx=%2F&type=tcp&headerType=none#REALITY%20Vision"
LINK_B="vless://$UUID@198.51.100.20:2443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=$PBK&sid=a1b2c3d4&pqv=$VERIFY&type=tcp#PQ%20signature"
LINK_C="vless://$UUID@198.51.100.20:3443?encryption=$ENC&flow=xtls-rprx-vision&security=none&type=tcp#VLESS%20Encryption"
LINK_D="vless://$UUID@198.51.100.20:4443?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=$PBK&sid=a1b2c3d4&type=xhttp&path=%2Fxh&mode=auto#XHTTP%20REALITY"
# VMess / Trojan over TLS: the test certificate is not from a public CA, so the
# client pins it (pcs = SHA-256 of the certificate, Xray's replacement for allowInsecure)
PCS=$(openssl x509 -in "$W/www.crt" -outform der | sha256sum | cut -d' ' -f1)
vmess_link() { printf 'vmess://%s' "$(printf '%s' "$1" | base64 -w0)"; }
LINK_VMWS=$(vmess_link "{\"v\":\"2\",\"ps\":\"VMess WS TLS\",\"add\":\"198.51.100.20\",\"port\":\"6443\",\"id\":\"$UUID\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"www.example.com\",\"path\":\"/vm\",\"tls\":\"tls\",\"sni\":\"www.example.com\",\"fp\":\"chrome\",\"pcs\":\"$PCS\"}")
LINK_VMTCP=$(vmess_link "{\"v\":\"2\",\"ps\":\"سيرفر VMess\",\"add\":\"198.51.100.20\",\"port\":6444,\"id\":\"$UUID\",\"aid\":0,\"scy\":\"chacha20-poly1305\",\"net\":\"tcp\",\"type\":\"none\",\"tls\":\"\"}")
LINK_VMBADPIN=$(vmess_link "{\"v\":\"2\",\"ps\":\"badpin\",\"add\":\"198.51.100.20\",\"port\":\"6443\",\"id\":\"$UUID\",\"net\":\"ws\",\"path\":\"/vm\",\"tls\":\"tls\",\"sni\":\"www.example.com\",\"pcs\":\"$(printf '%064d' 7)\"}")
LINK_TJ="trojan://Tr0jan-pass@198.51.100.20:7443?security=tls&sni=www.example.com&fp=chrome&pcs=$PCS&type=tcp#Trojan%20TLS"
LINK_TJWS="trojan://Tr0jan-pass@198.51.100.20:7444?security=tls&sni=www.example.com&type=ws&path=%2Ftj&host=www.example.com&pcs=$PCS#Trojan%20WS"
LINK_TJBAD="trojan://wrong-pass@198.51.100.20:7443?security=tls&sni=www.example.com&pcs=$PCS#tjbad"
LINK_BADSNI="vless://$UUID@198.51.100.20:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=not-allowed.example.net&fp=chrome&pbk=$PBK&sid=a1b2c3d4&type=tcp"
LINK_BADPQ="vless://$UUID@198.51.100.20:2443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=$PBK&sid=a1b2c3d4&pqv=$VERIFY2&type=tcp"

# --------------------------------------------------- network + servers
net_up() {
    kill_servers
    # the stock OpenWrt image runs uhttpd (LuCI) on 0.0.0.0:80/443 - the fake
    # Internet below needs those ports (on the XE3000 the GL UI is nginx on the LAN IP)
    X sh -c '/etc/init.d/uhttpd stop; /etc/init.d/uhttpd disable' >/dev/null 2>&1
    # the LAN has to be forwarded to the "internet" like on a real router
    X sh -c 'uci set firewall.@defaults[0].forward=ACCEPT; uci commit firewall; /etc/init.d/firewall reload' >/dev/null 2>&1
    ip netns del xeclan 2>/dev/null; ip netns del xecnet 2>/dev/null
    ip netns add xeclan; ip netns add xecnet
    ip link add xlan type veth peer name xcl
    ip link set xlan netns "$OW_PID"
    ip link set xcl netns xeclan
    ip link add xwan type veth peer name xinet
    ip link set xwan netns "$OW_PID"
    ip link set xinet netns xecnet
    N ip addr add 192.168.8.1/24 dev xlan; N ip link set xlan up
    N ip addr add 10.200.0.1/30 dev xwan; N ip link set xwan up
    N ip route add 203.0.113.0/24 via 10.200.0.2
    # your server lives on the router's loopback here (Xray refuses targets that are
    # local to the server itself, so the "internet" is a separate namespace)
    for a in 198.51.100.20 198.51.100.30; do N ip addr add "$a/32" dev lo; done
    N sysctl -qw net.ipv4.ip_forward=1
    C ip link set lo up; C ip addr add 192.168.8.100/24 dev xcl; C ip link set xcl up
    C ip route add default via 192.168.8.1
    I ip link set lo up; I ip addr add 10.200.0.2/30 dev xinet; I ip link set xinet up
    for a in 203.0.113.10 203.0.113.53; do I ip addr add "$a/32" dev lo; done
    I ip route add default via 10.200.0.1
    : >"$W/http.log"
    I python3 "$HERE/helpers.py" http 203.0.113.10 80 "$W/http.log" >"$W/h-http.out" 2>&1 &
    I python3 "$HERE/helpers.py" dns 203.0.113.53 "$W/dns.log" >"$W/h-dns.out" 2>&1 &
    N openssl s_server -quiet -accept 127.0.0.1:19443 -cert "$W/www.crt" -key "$W/www.key" -cert_chain "$W/chain.crt" -www >/dev/null 2>&1 &
    N "$XRAY_HOST" run -c "$W/server.json" >"$W/xray-server.out" 2>&1 &
    N /usr/sbin/sshd -D -f "$W/sshd_config" -E "$W/sshd.log" &
    N python3 "$HERE/helpers.py" tls 198.51.100.30:443 198.51.100.30:2222 "$W/bug.crt" "$W/bug.key" "$W/tls.log" >"$W/h-tls.out" 2>&1 &
    N python3 "$HERE/helpers.py" ws 198.51.100.30:80 198.51.100.30:2222 "$W/ws.log" >"$W/h-ws.out" 2>&1 &
    N python3 "$HERE/helpers.py" tls 198.51.100.30:8443 198.51.100.30:80 "$W/bug.crt" "$W/bug.key" "$W/tls2.log" >"$W/h-tls2.out" 2>&1 &
    echo $! >"$W/tls2.pid"
    sleep 2
}

step "boot OpenWrt 21.02 container"
ow_create 21.02 || exit 1
ow_boot || exit 1
X cat /etc/openwrt_release | grep DESCRIPTION
cp "$SCRIPT" "$OW_ROOT/root/xec.sh"
net_up
i=0; while [ $i -lt 15 ] && [ "$(lan_get /hello 2)" != HELLO-XE3000 ]; do sleep 1; i=$((i + 1)); done
t "LAN client reaches the web target directly (before install)" test "$(lan_get /hello)" = "HELLO-XE3000"
t "  ... and the target sees the client address" test "$(lastpeer)" = 192.168.8.100

# ----------------------------------------------------------- install
step "install (real opkg from downloads.openwrt.org)"
X sh /root/xec.sh install --xray-zip /fixtures/xray.zip --xray-dgst /fixtures/xray-bad.dgst >"$W/install-bad.log" 2>&1
t "wrong SHA-256 refused" grep -q 'checksum mismatch' "$W/install-bad.log"
XP sh /root/xec.sh install --xray-zip /fixtures/xray.zip --xray-dgst /fixtures/xray.dgst --web-password 'Web-pass-123' </dev/null >"$W/install.log" 2>&1
rc=$?
sed 's/^/    | /' "$W/install.log"
t "installer exit 0" test $rc = 0
t "SHA-256 verified" grep -q 'SHA-256 verified' "$W/install.log"
t "xec installed" X test -x /usr/bin/xec
t "menu1 command installed" X test -x /usr/bin/menu1
t "menu1 opens the menu (0 = exit)" sh -c "echo 0 | nsenter -t $OW_PID -m -n -p -r -w -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin NO_COLOR=1 menu1 2>&1 | grep -q 'XE3000 CLIENT'"
t "xray runs on the router" X /opt/xe-client/bin/xray version
t "OpenSSH client (not dropbear) for ssh -D" X sh -c '/usr/bin/ssh -V 2>&1 | grep -q OpenSSH || /usr/libexec/ssh-openssh -V 2>&1 | grep -q OpenSSH'
t "sshpass + openssl present" X sh -c 'command -v sshpass && command -v openssl'
X ls /etc/rc.d/ | grep xe | sed "s/^/    | rc.d: /"
t "web service enabled (tunnel is enabled by xec start)" X sh -c 'ls /etc/rc.d/ | grep -q xe-client-web'
t "fw3 include registered" X sh -c '[ "$(uci -q get firewall.xe_client.path)" = /opt/xe-client/firewall.sh ]'
t "watchdog cron entry" X grep -q 'xec watchdog' /etc/crontabs/root
t "settings kept on sysupgrade" X grep -qx /etc/xe-client/ /etc/sysupgrade.conf

step "configure (test network)"
X xec set LAN_IF xlan >/dev/null
X xec set LAN_IP 192.168.8.1 >/dev/null
X xec set CHECK_URL http://203.0.113.10/generate_204 >/dev/null
X xec set TRACE_URL http://203.0.113.10/cdn-cgi/trace >/dev/null
X xec set DNS_SERVER 203.0.113.53 >/dev/null
t "web panel answers on the LAN" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s --max-time 5 http://192.168.8.1:8899/ | grep -q 'XE3000 Client'"

step "profiles: VLESS REALITY family"
X xec add A "$LINK_A" | sed 's/^/    | /'
X xec add B "$LINK_B" | sed 's/^/    | /'
X xec add C "$LINK_C" | sed 's/^/    | /'
X xec add "$LINK_D" | sed 's/^/    | /'
X xec add badsni "$LINK_BADSNI" >/dev/null
X xec add badpq "$LINK_BADPQ" >/dev/null
X xec add bad "vless://$UUID@1.2.3.4:443?security=reality&sni=a.com" >/dev/null 2>&1 && fail "link without pbk accepted" || pass "link without pbk rejected"
X xec add bad2 "vless://$UUID@1.2.3.4:443?security=reality&sni=a.com;reboot&pbk=$PBK" >/dev/null 2>&1 && fail "SNI with ';' accepted" || pass "SNI with shell characters rejected"
X xec list | sed 's/^/    | /'
t "remark became the name (XHTTP_REALITY)" X test -f /etc/xe-client/profiles/XHTTP_REALITY.conf
t "profile files are 600" X sh -c '[ "$(ls -l /etc/xe-client/profiles/A.conf | cut -c1-10)" = "-rw-------" ]'
for p in A B C XHTTP_REALITY; do
    r=$(X xec test "$p"); echo "    | $r"
    case $p in A) d="REALITY + XTLS-Vision (sni=www.example.com)" ;; B) d="REALITY + ML-DSA-65 post-quantum signature (pqv)" ;;
        C) d="VLESS Encryption ML-KEM-768 + Vision" ;; *) d="XHTTP over REALITY" ;; esac
    case $r in *OK*) pass "$d" ;; *) fail "$d" ;; esac
done
r=$(X xec test badsni); echo "    | $r"; case $r in *FAIL*) pass "wrong SNI is refused by the server" ;; *) fail "wrong SNI worked" ;; esac
r=$(X xec test badpq); echo "    | $r"; case $r in *FAIL*) pass "wrong ML-DSA-65 key (pqv) is detected" ;; *) fail "wrong pqv worked" ;; esac

step "profiles: VMess + Trojan"
X xec add vmws "$LINK_VMWS" | sed 's/^/    | /'
X xec add "$LINK_VMTCP" | sed 's/^/    | /'
X xec add vmbadpin "$LINK_VMBADPIN" >/dev/null
X xec add tj "$LINK_TJ" | sed 's/^/    | /'
X xec add tjws "$LINK_TJWS" | sed 's/^/    | /'
X xec add tjbad "$LINK_TJBAD" >/dev/null
VMTCP=$(X sh -c 'grep -l "P_PORT=.6444" /etc/xe-client/profiles/*.conf' | head -n 1); VMTCP=$(basename "$VMTCP" .conf)
t "vmess:// base64 JSON parsed (Arabic remark kept)" X grep -q "P_REMARK='سيرفر VMess'" "/etc/xe-client/profiles/$VMTCP.conf"
for p in vmws "$VMTCP" tj tjws; do
    r=$(X xec test "$p"); echo "    | $r"
    case $p in vmws) d="VMess + WebSocket + TLS (pinned certificate)" ;; tj) d="Trojan + TLS" ;; tjws) d="Trojan + WebSocket + TLS" ;; *) d="VMess TCP (chacha20-poly1305)" ;; esac
    case $r in *OK*) pass "$d" ;; *) fail "$d" ;; esac
done
r=$(X xec test tjbad); echo "    | $r"; case $r in *FAIL*) pass "wrong Trojan password fails" ;; *) fail "wrong Trojan password worked" ;; esac
r=$(X xec test vmbadpin); echo "    | $r"; case $r in *FAIL*) pass "wrong certificate pin (pcs) is refused" ;; *) fail "wrong pcs worked" ;; esac

step "manual entry (SNI + Host without a link)"
X xec add-proxy tjm --type trojan --addr 198.51.100.20 --port 7444 --pass Tr0jan-pass --net ws --path /tj \
    --sni www.example.com --host www.example.com --pcs "$PCS" | sed 's/^/    | /'
r=$(X xec test tjm); echo "    | $r"; case $r in *OK*) pass "xec add-proxy: Trojan WS TLS with SNI + Host" ;; *) fail "xec add-proxy Trojan" ;; esac
X xec add-proxy tjm --type trojan --addr 198.51.100.20 --port 7444 --net ws --path /tj --sni www.example.com --host www.example.com --pcs "$PCS" >/dev/null
r=$(X xec test tjm); echo "    | $r"; case $r in *OK*) pass "edit without re-typing the password keeps it" ;; *) fail "edit lost the password" ;; esac
printf '14\nmenuvm\nvmess\n198.51.100.20\n6443\n%s\nws\ntls\nwww.example.com\nwww.example.com\n/vm\n%s\n0\n' "$UUID" "$PCS" |
    OW_EXTRA_ENV="NO_COLOR=1" ow_exec menu1 >"$W/menu14.out" 2>&1
grep -E 'saved profile|\[x\]' "$W/menu14.out" | sed 's/^/    | /'
r=$(X xec test menuvm); echo "    | $r"; case $r in *OK*) pass "menu1 option 14: VMess WS TLS with SNI + Host" ;; *) fail "menu1 option 14" ;; esac

step "profiles: SSH (direct / TLS+SNI / WebSocket / WebSocket+TLS / key)"
X xec add-ssh sdirect --host 198.51.100.30 --port 2222 --user xectest --pass 'Pa55-w0rd' | sed 's/^/    | /'
X xec add stls 'ssh://xectest:Pa55-w0rd@198.51.100.30:443?transport=tls&sni=bug.example.com#SSH%20TLS' | sed 's/^/    | /'
echo 'Pa55-w0rd' | X xec add-ssh sws --host 198.51.100.30 --port 80 --user xectest --pass-stdin --transport ws --ws-host bug.example.com | sed 's/^/    | /'
X xec add-ssh swss --host 198.51.100.30 --port 8443 --user xectest --pass 'Pa55-w0rd' --transport wss --sni bug.example.com --ws-host cdn.example.com --ws-path /ssh | sed 's/^/    | /'
X xec add-ssh skey --host 198.51.100.30 --port 2222 --user xectest --key | sed 's/^/    | /'
X xec ssh-key >>/home/xectest/.ssh/authorized_keys
t "password file is 600" X sh -c '[ "$(ls -l /etc/xe-client/profiles/sdirect.pass | cut -c1-10)" = "-rw-------" ]'
for p in sdirect stls sws swss skey; do
    r=$(X xec test "$p"); echo "    | $r"
    case $r in *OK*) pass "SSH $p" ;; *) fail "SSH $p" ;; esac
done
t "TLS front received SNI bug.example.com" grep -q 'sni=bug.example.com' "$W/tls.log"
t "WebSocket relay received Host bug.example.com" grep -q 'host=bug.example.com' "$W/ws.log"
t "WS+TLS: SNI bug.example.com + Host cdn.example.com + path /ssh" sh -c "grep -q 'sni=bug.example.com' '$W/tls2.log' && grep -q 'host=cdn.example.com first=GET /ssh ' '$W/ws.log'"
t "password never in the process list" sh -c "! ps -eo args | grep -v grep | grep -q 'Pa55-w0rd'"
X xec add-ssh sbad --host 198.51.100.30 --port 2222 --user xectest --pass 'wrong-pass' >/dev/null
r=$(X xec test sbad); echo "    | $r"; case $r in *FAIL*) pass "wrong SSH password fails" ;; *) fail "wrong SSH password worked" ;; esac
X xec del sbad >/dev/null

step "whole LAN through REALITY (profile A)"
X xec use A >/dev/null
# another program (e.g. another Xray panel's API) already holds 10085 - the case seen on a real XE3000
N socat TCP-LISTEN:10085,bind=127.0.0.1,reuseaddr,fork /dev/null >/dev/null 2>&1 &
sleep 1
X xec start | sed 's/^/    | /'
t "tunnel running" X pgrep -f 'run -c /var/run/xe-client/xray.json'
t "busy port 10085 detected and moved (API_PORT)" X sh -c "grep -q 'port 10085 (API_PORT) is already used' /tmp/xe-client/xec.log && grep -q \"^API_PORT='10086'\" /etc/xe-client/client.conf"
X xec diag >"$W/diag.txt" 2>&1; sed -n '1,12p' "$W/diag.txt" | sed 's/^/    | /'
t "xec diag: report with server, ports and config test" sh -c "grep -q 'Configuration OK' '$W/diag.txt' && grep -q '^server : vless tcp/reality' '$W/diag.txt'"
t "xec diag: no UUID / password inside" sh -c "! grep -q '$UUID' '$W/diag.txt' && ! grep -q 'Pa55-w0rd' '$W/diag.txt' && ! grep -q 'Tr0jan-pass' '$W/diag.txt'"
out=$(lan_get /hello)
t "LAN client gets the page" test "$out" = "HELLO-XE3000"
p=$(lastpeer); echo "    | target saw: $p"
t "  ... through the tunnel (not from 192.168.8.100)" test -n "$p" -a "$p" != 192.168.8.100
C busybox nslookup check.example 192.168.8.1 >"$W/nsl.out" 2>&1
t "LAN DNS answered through the tunnel" grep -q 203.0.113.99 "$W/nsl.out"
t "  ... reached the DNS server over TCP from the server side" sh -c "tail -n 3 '$W/dns.log' | grep -q '^tcp .* check.example'"
X xec test >"$W/xtest.out" 2>&1; sed 's/^/    | /' "$W/xtest.out"
t "xec test: exit IP + Cloudflare station" grep -q 'Cloudflare: JED' "$W/xtest.out"
for i in 1 2 3; do lan_get /hello >/dev/null; done
st=$(X xec stats); echo "    | $st"
t "traffic counters (Xray stats API)" sh -c "echo '$st' | grep -qv 'down 0 B'"
X iptables -t nat -S XEC_PRE | sed 's/^/    | /'
X iptables -S XEC_FWD >"$W/fwd" 2>&1; X ip6tables -S XEC_FWD6 >"$W/fwd6" 2>&1
t "QUIC (UDP 443) blocked for the LAN" grep -q -- '--dport 443 -j REJECT' "$W/fwd"
if X ip6tables -S FORWARD >/dev/null 2>&1; then t "IPv6 forwarding blocked for the LAN" grep -q REJECT "$W/fwd6"; else echo "    | (no IPv6 in this container - IPv6 block skipped)"; fi
X /etc/init.d/firewall restart >/dev/null 2>&1
X iptables -t nat -S PREROUTING >"$W/pre" 2>&1
t "rules survive a firewall restart (fw3 include)" grep -q XEC_PRE "$W/pre"
X xec bypass add 192.168.8.100 >/dev/null
lan_get /hello >/dev/null
t "bypassed device goes direct" test "$(lastpeer)" = 192.168.8.100
X xec bypass del 192.168.8.100 >/dev/null
lan_get /hello >/dev/null
t "  ... and back through the tunnel after removal" test "$(lastpeer)" != 192.168.8.100

step "web panel API"
J="$W/cookies"; rm -f "$J"
api() { C curl -s --max-time 60 -b "$J" -c "$J" "$@"; }
code=$(C curl -s -o /dev/null -w '%{http_code}' "http://192.168.8.1:8899/cgi-bin/api?a=status")
t "no session -> 401" test "$code" = 401
t "wrong password refused" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s -d 'a=login&pass=nope' http://192.168.8.1:8899/cgi-bin/api | grep -q 'wrong password'"
CS=$(api -d 'a=login&pass=Web-pass-123' http://192.168.8.1:8899/cgi-bin/api | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])')
t "login -> session + CSRF token" test ${#CS} = 32
api "http://192.168.8.1:8899/cgi-bin/api?a=status" >"$W/status.json"
t "status JSON valid, running, 19 profiles" python3 -c "import json; j=json.load(open('$W/status.json')); assert j['running'] and j['active']=='A' and len(j['profiles'])==19, j"
t "status never contains passwords" sh -c "! grep -q 'Pa55-w0rd' '$W/status.json'"
t "POST without CSRF refused" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s -b '$J' -d 'a=set&key=LOGLEVEL&value=info' http://192.168.8.1:8899/cgi-bin/api | grep -q 'CSRF'"
r=$(api -d "a=set&key=LOGLEVEL&value=info&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
t "set via web" X grep -q "^LOGLEVEL='info'" /etc/xe-client/client.conf
r=$(api --data-urlencode "link=$LINK_A" -d "a=add&name=webA&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
t "add link via web" X test -f /etc/xe-client/profiles/webA.conf
r=$(api -d "a=addssh&name=webssh&host=198.51.100.30&port=443&user=xectest&auth=pass&trans=tls&sni=bug.example.com&csrf=$CS" --data-urlencode 'pass=Pa55-w0rd' http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
t "add SSH via web (password stored)" X grep -qx 'Pa55-w0rd' /etc/xe-client/profiles/webssh.pass
r=$(api -d "a=probe&name=webssh&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
r=$(api -d "a=addproxy&name=webvl&type=vless&addr=198.51.100.20&port=4443&net=xhttp&sec=reality&sni=www.example.com&path=%2Fxh&pbk=$PBK&sid=a1b2c3d4&fp=chrome&csrf=$CS" --data-urlencode "id=$UUID" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
r=$(api -d "a=probe&name=webvl&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
t "web manual form: VLESS XHTTP REALITY with SNI" sh -c "echo '$r' | grep -q 'OK'"
api -d "a=del&name=webvl&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api >/dev/null
t "test profile via web" sh -c "echo '$r' | grep -q 'OK'"
r=$(api -d "a=exitinfo&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
t "exit IP / Cloudflare station via web" python3 -c "import json; j=json.loads('''$r'''); assert j['ok'] and j['colo']=='JED'"
t "backup export" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s -b '$J' 'http://192.168.8.1:8899/cgi-bin/api?a=export' | grep -q '@@FILE profiles/A.conf'"
api "http://192.168.8.1:8899/cgi-bin/api?a=logs" >"$W/logs.json"
api "http://192.168.8.1:8899/cgi-bin/api?a=diag" >"$W/diag.json"
t "logs screen: diagnostic report via web" python3 -c "import json; j=json.load(open('$W/diag.json')); assert j['ok'] and 'XE3000 CLIENT report' in j['msg'] and '$UUID' not in j['msg']"
t "logs via web" python3 -c "import json; assert json.load(open('$W/logs.json'))['ok']"
api -d "a=del&name=webA&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api >/dev/null
api -d "a=del&name=webssh&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api >/dev/null
api -d "a=logout&csrf=$CS" http://192.168.8.1:8899/cgi-bin/api >/dev/null
code=$(api -o /dev/null -w '%{http_code}' "http://192.168.8.1:8899/cgi-bin/api?a=status")
t "logout ends the session" test "$code" = 401
for i in 1 2 3 4 5; do C curl -s -d 'a=login&pass=bad' http://192.168.8.1:8899/cgi-bin/api >/dev/null; done
t "brute force lock after 5 wrong passwords" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s -d 'a=login&pass=Web-pass-123' http://192.168.8.1:8899/cgi-bin/api | grep -q 'too many'"
X rm -f /var/run/xe-client/web-fails

step "web panel without password (default)"
X xec web auth off | sed 's/^/    | /'
code=$(C curl -s -o "$W/na.json" -w '%{http_code}' "http://192.168.8.1:8899/cgi-bin/api?a=status")
t "no password: status opens without login" sh -c "[ $code = 200 ] && grep -q '\"auth\":false' '$W/na.json'"
t "no password: POST without CSRF still refused" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s -d 'a=set&key=LOGLEVEL&value=warning' http://192.168.8.1:8899/cgi-bin/api | grep -q CSRF"
NCS=$(C curl -s "http://192.168.8.1:8899/cgi-bin/api?a=csrf" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])')
r=$(C curl -s -d "a=set&key=LOGLEVEL&value=warning&csrf=$NCS" http://192.168.8.1:8899/cgi-bin/api); echo "    | $r"
t "no password: change a setting with the page token" X grep -q "^LOGLEVEL='warning'" /etc/xe-client/client.conf
code=$(C curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example.com' "http://192.168.8.1:8899/cgi-bin/api?a=status")
t "foreign Host refused (DNS rebinding)" test "$code" = 403
X xec web auth on >/dev/null
code=$(C curl -s -o /dev/null -w '%{http_code}' "http://192.168.8.1:8899/cgi-bin/api?a=status")
t "password turned back on -> 401" test "$code" = 401

step "whole LAN through SSH over WebSocket + TLS (SNI)"
X xec use swss | sed 's/^/    | /'
sleep 3
out=$(lan_get /hello 15)
t "LAN client gets the page over SSH" test "$out" = "HELLO-XE3000"
t "  ... through the tunnel" test "$(lastpeer)" != 192.168.8.100
t "ssh process managed by procd" X sh -c "pgrep -f '_pc swss' || pgrep -f 'D 127.0.0.1:10811'"
C busybox nslookup viassh.example 192.168.8.1 >"$W/nsl2.out" 2>&1
t "DNS over the SSH tunnel" grep -q 203.0.113.99 "$W/nsl2.out"

step "kill switch + failover"
X xec set FAILOVER 0 >/dev/null
kill "$(cat "$W/tls2.pid")" 2>/dev/null; pkill -f "helpers.py tls 198.51.100.30:8443" 2>/dev/null
X sh -c 'kill $(pgrep -f "D 127.0.0.1:10811") 2>/dev/null'
sleep 2
out=$(lan_get /hello 6)
t "server down + kill switch on: NO direct leak" test "$out" != "HELLO-XE3000"
X xec set KILLSWITCH 0 >/dev/null
X xec watchdog; X xec watchdog
out=$(lan_get /hello 6)
t "kill switch off: LAN falls back to normal internet" sh -c "[ '$out' = HELLO-XE3000 ] && [ '$(lastpeer)' = 192.168.8.100 ]"
X xec set KILLSWITCH 1 >/dev/null
X xec set FAILOVER 1 >/dev/null
X xec watchdog; X xec watchdog
sleep 3
act=$(X sh -c '. /etc/xe-client/client.conf; echo $ACTIVE'); echo "    | active after failover: $act"
t "failover switched to another working server" test -n "$act" -a "$act" != swss
out=$(lan_get /hello 10)
t "  ... LAN works through the new server" sh -c "[ '$out' = HELLO-XE3000 ] && [ '$(lastpeer)' != 192.168.8.100 ]"
X tail -n 8 /tmp/xe-client/xec.log | sed 's/^/    | /'

step "reboot"
X xec use A >/dev/null
ow_halt; kill_servers; sleep 1
ow_boot || exit 1
net_up
sleep 4
t "tunnel starts at boot" X pgrep -f 'run -c /var/run/xe-client/xray.json'
# the test's LAN veth only exists after boot (a real router has br-lan at boot)
X /etc/init.d/xe-client restart; X /etc/init.d/xe-client-web restart; sleep 3
out=$(lan_get /hello 10)
t "LAN through the tunnel after reboot" sh -c "[ '$out' = HELLO-XE3000 ] && [ '$(lastpeer)' != 192.168.8.100 ]"
t "web panel after reboot" sh -c "ip netns exec xeclan env -u HTTP_PROXY -u http_proxy curl -s --max-time 5 http://192.168.8.1:8899/ | grep -q 'XE3000 Client'"

step "stop + uninstall"
X xec stop | sed 's/^/    | /'
out=$(lan_get /hello)
t "stop: normal internet again" sh -c "[ '$out' = HELLO-XE3000 ] && [ '$(lastpeer)' = 192.168.8.100 ]"
X iptables-save >"$W/save" 2>&1
t "stop: no XEC rules left" sh -c "! grep -q XEC_ '$W/save'"
X xec uninstall --purge | sed 's/^/    | /'
t "uninstall: files removed" X sh -c '[ ! -e /usr/bin/xec ] && [ ! -e /usr/bin/menu1 ] && [ ! -e /opt/xe-client ] && [ ! -e /etc/xe-client ] && [ ! -e /etc/init.d/xe-client ]'
t "uninstall: firewall include + cron removed" X sh -c '! uci -q get firewall.xe_client && ! grep -q xec /etc/crontabs/root'

printf '\n== RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
