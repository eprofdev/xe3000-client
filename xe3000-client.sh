#!/bin/sh
# =====================================================================
#  XE3000 CLIENT (xec) - standalone tunnel client for GL.iNet GL-XE3000
#  (Puli AX, OpenWrt 21.02 / GL firmware 4.x) and other OpenWrt routers.
#
#  Connects the router to YOUR external server and sends the LAN through it:
#    * VLESS + XTLS-Vision + REALITY (SNI, pbk, sid, spx, fp) with the
#      post-quantum ML-DSA-65 signature (pqv) and post-quantum VLESS
#      Encryption (mlkem768x25519plus) - also XHTTP / gRPC / WS / TLS links
#    * SSH: direct, SSH over TLS with SNI, SSH over WebSocket (payload),
#      SSH over WebSocket + TLS with SNI - password or ed25519 key
#  Engine: official Xray-core (latest release, SHA-256 checked) + OpenSSH.
#
#  Install (on the router, as root):
#    wget -O /tmp/xec.sh <raw url of this file> && sh /tmp/xec.sh install
#  then open  http://192.168.8.1:8899  (password printed once) or run  menu1
#
#  Everything else:  xec help
# =====================================================================
XEC_VERSION=1.0.0

ETC=/etc/xe-client
PROF=$ETC/profiles
CONF=$ETC/client.conf
OPT=/opt/xe-client
XRAY=$OPT/bin/xray
WWW=$OPT/www
RUN=/var/run/xe-client
LOGD=/tmp/xe-client
LOGF=$LOGD/xec.log
SELF=/usr/bin/xec
MENU_CMD=/usr/bin/menu1
INIT=/etc/init.d/xe-client
INIT_WEB=/etc/init.d/xe-client-web
XRAY_REPO=https://github.com/XTLS/Xray-core

umask 022

# ---------------------------------------------------------------- output
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_R='\033[31m' C_G='\033[32m' C_Y='\033[33m' C_B='\033[36m' C_0='\033[0m'
else
    C_R='' C_G='' C_Y='' C_B='' C_0=''
fi
say() { printf '%s\n' "$*"; }
ok() { printf "${C_G}[OK]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*" >&2; }
err() { printf "${C_R}[x]${C_0} %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }
log() {
    mkdir -p "$LOGD" 2>/dev/null
    printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOGF" 2>/dev/null
    logger -t xe-client "$*" 2>/dev/null
    return 0
}

# ------------------------------------------------------------- validation
# match ERE VALUE - whole-value match, never multi-line
match() {
    case $2 in *'
'*) return 1 ;; esac
    printf '%s' "$2" | grep -Eq "^($1)\$"
}
RE_IP4='([0-9]{1,3}\.){3}[0-9]{1,3}'
RE_HOST='[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9A-Fa-f:.]{2,45}'
RE_PORT='[0-9]{1,5}'
RE_NAME='[A-Za-z0-9_-]{1,32}'
RE_B64='[A-Za-z0-9_=+/-]{8,}'
RE_URL='https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{3,255}'
# busybox/musl regex: repeat counts max 255 - longer values use + and maxlen
maxlen() { [ ${#2} -le "$1" ]; }
valid_port() { match "$RE_PORT" "$1" && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# JSON string body (no quotes); control characters dropped
jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037'; }
js() { printf '"%s"' "$(jesc "$1")"; }
# multi-line text -> JSON string (newlines kept as \n)
jtext() {
    awk 'BEGIN{printf "\""} {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/," "); gsub(/\r/,""); gsub(/[\001-\037]/,""); printf "%s\\n",$0} END{printf "\""}'
}
# shell single quote
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
# percent-decoding ("+" -> space when $2 = form)
urldec() {
    printf '%s' "$1" | awk -v form="${2:-}" '{
        s=$0; gsub(/\\/,"\\\\",s); if (form!="") gsub(/\+/," ",s)
        out=""
        while ((i=index(s,"%"))>0) {
            h=substr(s,i+1,2)
            if (h ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { out=out substr(s,1,i-1) "\\x" h; s=substr(s,i+3) }
            else { out=out substr(s,1,i); s=substr(s,i+1) }
        }
        printf "%s", out s
    }' | { IFS= read -r v || [ -n "$v" ]; printf '%b' "$v"; }
}
urlenc() {
    printf '%s' "$1" | hexdump -v -e '/1 "%02X\n"' | awk '{
        c=sprintf("%c", ("0x" $1)+0); n=index("0123456789ABCDEF",substr($1,1,1))*16+index("0123456789ABCDEF",substr($1,2,1))-17
        if ((n>=48&&n<=57)||(n>=65&&n<=90)||(n>=97&&n<=122)||n==45||n==46||n==95||n==126) printf "%c", n; else printf "%%%s", $1 }'
}
rand_hex() { head -c "${1:-16}" /dev/urandom | hexdump -v -e '/1 "%02x"'; }

# ---------------------------------------------------------------- config
defaults() {
    ACTIVE='' ROUTE=all DNS_TUNNEL=1 DNS_SERVER=1.1.1.1 BLOCK_QUIC=1 BLOCK_V6=1
    KILLSWITCH=1 FAILOVER=1 BYPASS_SRC='' BYPASS_DST='' LAN_IF='' LAN_IP=''
    SOCKS_PORT=10808 HTTP_PORT=10809 REDIR_PORT=10810 DNS_PORT=10853 API_PORT=10085 SSH_SOCKS=10811
    WEB=1 WEB_PORT=8899 LOGLEVEL=warning SNIFF=1
    CHECK_URL=https://www.gstatic.com/generate_204
    TRACE_URL=https://www.cloudflare.com/cdn-cgi/trace
}
load_conf() {
    defaults
    [ -f "$CONF" ] && . "$CONF"
    return 0
}
# conf_set FILE KEY VALUE
conf_set() {
    mkdir -p "$(dirname "$1")"
    [ -f "$1" ] || : >"$1"
    grep -v "^$2=" "$1" >"$1.tmp.$$"
    printf '%s=%s\n' "$2" "$(shq "$3")" >>"$1.tmp.$$"
    chmod 600 "$1.tmp.$$" && mv -f "$1.tmp.$$" "$1"
}
PKEYS='TYPE REMARK ADDR PORT UUID FLOW ENC SEC SNI PBK SID SPX FP PQV NET PATH HOST MODE SVC ALPN USER AUTH TRANS WSHOST WSPATH PAYLOAD'
prof_clear() { for k in $PKEYS; do eval "P_$k=''"; done; }
prof_exists() { match "$RE_NAME" "$1" && [ -f "$PROF/$1.conf" ]; }
load_prof() {
    prof_clear
    prof_exists "$1" || { err "profile not found: $1"; return 1; }
    . "$PROF/$1.conf"
    P_NAME=$1
}
save_prof() { # NAME (writes all P_*)
    mkdir -p "$PROF"; chmod 700 "$ETC" "$PROF" 2>/dev/null
    f="$PROF/$1.conf.new"
    : >"$f"; chmod 600 "$f"
    for k in $PKEYS; do eval "v=\${P_$k}"; [ -n "$v" ] && printf 'P_%s=%s\n' "$k" "$(shq "$v")" >>"$f"; done
    mv -f "$f" "$PROF/$1.conf"
}
prof_list() { for f in "$PROF"/*.conf; do [ -f "$f" ] && basename "$f" .conf; done; }

# ------------------------------------------------------------------- LAN
lan_detect() {
    if [ -z "$LAN_IF" ] || [ -z "$LAN_IP" ]; then
        st=$(ubus call network.interface.lan status 2>/dev/null)
        [ -n "$LAN_IF" ] || LAN_IF=$(printf '%s' "$st" | jsonfilter -e '@.l3_device' 2>/dev/null)
        [ -n "$LAN_IP" ] || LAN_IP=$(printf '%s' "$st" | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null)
    fi
    [ -n "$LAN_IF" ] || LAN_IF=br-lan
    [ -n "$LAN_IP" ] || LAN_IP=$(uci -q get network.lan.ipaddr 2>/dev/null | cut -d/ -f1)
    [ -n "$LAN_IP" ] || LAN_IP=192.168.8.1
}

# ------------------------------------------------------------ link parse
# qp NAME - query parameter of the link being parsed ($LQ), decoded
qp() {
    printf '%s' "&$LQ&" | awk -v k="$1" 'BEGIN{RS="&"} { i=index($0,"="); if (i>0 && substr($0,1,i-1)==k) { print substr($0,i+1); exit } }' |
        { IFS= read -r v || [ -n "$v" ]; urldec "$v"; }
}
split_hostport() { # HOSTPORT -> H P
    case $1 in
        \[*) H=${1#\[}; H=${H%%]*}; P=${1##*]}; P=${P#:} ;;
        *:*) H=${1%:*}; P=${1##*:} ;;
        *) H=$1; P='' ;;
    esac
}
# parse_link LINK -> P_* ; LNAME = remark from #fragment
parse_link() {
    prof_clear
    l=$1
    case $l in *'
'*) err "one link per line"; return 1 ;; esac
    LNAME=''
    case $l in *'#'*) LNAME=$(urldec "${l#*#}"); l=${l%%#*} ;; esac
    LQ=''
    case $l in *'?'*) LQ=${l#*\?}; l=${l%%\?*} ;; esac
    case $l in
        vless://*)
            l=${l#vless://}; l=${l%/}
            P_TYPE=vless
            P_UUID=$(urldec "${l%%@*}")
            split_hostport "${l#*@}"; P_ADDR=$H; P_PORT=${P:-443}
            P_ENC=$(qp encryption); P_ENC=${P_ENC:-none}
            P_FLOW=$(qp flow)
            P_SEC=$(qp security); P_SEC=${P_SEC:-none}
            P_SNI=$(qp sni); [ -n "$P_SNI" ] || P_SNI=$(qp peer)
            P_PBK=$(qp pbk); P_SID=$(qp sid); P_SPX=$(qp spx); P_FP=$(qp fp); P_PQV=$(qp pqv)
            P_NET=$(qp type); P_NET=${P_NET:-tcp}
            P_PATH=$(qp path); P_HOST=$(qp host); P_MODE=$(qp mode); P_SVC=$(qp serviceName); P_ALPN=$(qp alpn)
            ;;
        ssh://*)
            l=${l#ssh://}; l=${l%/}
            P_TYPE=ssh
            ui=${l%@*}
            P_USER=$(urldec "${ui%%:*}")
            SSH_PASS=''
            case $ui in *:*) SSH_PASS=$(urldec "${ui#*:}") ;; esac
            split_hostport "${l##*@}"; P_ADDR=$H; P_PORT=${P:-22}
            P_TRANS=$(qp transport); P_TRANS=${P_TRANS:-direct}
            P_SNI=$(qp sni); P_WSHOST=$(qp host); P_WSPATH=$(qp path); P_PAYLOAD=$(qp payload)
            if [ -n "$SSH_PASS" ]; then P_AUTH=pass; else P_AUTH=key; fi
            ;;
        *) err "unsupported link (vless:// or ssh://)"; return 1 ;;
    esac
    P_REMARK=$LNAME
    check_prof
}
# check_prof - validate / normalise P_*
check_prof() {
    match "$RE_HOST" "$P_ADDR" || { err "bad server address: $P_ADDR"; return 1; }
    valid_port "$P_PORT" || { err "bad port: $P_PORT"; return 1; }
    [ -z "$P_REMARK" ] || match '[^"\\]{1,64}' "$P_REMARK" || P_REMARK=''
    if [ "$P_TYPE" = vless ]; then
        match '[A-Za-z0-9_-]{1,64}' "$P_UUID" || { err "bad UUID"; return 1; }
        match '[A-Za-z0-9._-]+' "$P_ENC" && maxlen 2000 "$P_ENC" || { err "bad encryption"; return 1; }
        [ -z "$P_FLOW" ] || match 'xtls-rprx-vision(-udp443)?' "$P_FLOW" || { err "bad flow: $P_FLOW"; return 1; }
        match 'reality|tls|none' "$P_SEC" || { err "bad security: $P_SEC"; return 1; }
        [ "$P_NET" = raw ] && P_NET=tcp
        match 'tcp|xhttp|grpc|ws|httpupgrade' "$P_NET" || { err "unsupported transport: $P_NET"; return 1; }
        [ -z "$P_SNI" ] || match "$RE_HOST" "$P_SNI" || { err "bad SNI: $P_SNI"; return 1; }
        [ -n "$P_FP" ] || P_FP=chrome
        match '[a-z0-9_]{1,20}' "$P_FP" || { err "bad fingerprint"; return 1; }
        if [ "$P_SEC" = reality ]; then
            [ -n "$P_SNI" ] || { err "REALITY needs sni="; return 1; }
            match '[A-Za-z0-9_-]{43}' "$P_PBK" || { err "REALITY needs a valid pbk= (public key)"; return 1; }
            [ -z "$P_SID" ] || match '[0-9a-fA-F]{1,16}' "$P_SID" || { err "bad sid"; return 1; }
            [ -z "$P_PQV" ] || { match "$RE_B64" "$P_PQV" && maxlen 6000 "$P_PQV"; } || { err "bad pqv (ML-DSA-65 verify key)"; return 1; }
            [ -n "$P_SPX" ] || P_SPX=/
        fi
        [ -z "$P_SPX" ] || match '/[ -~]{0,200}' "$P_SPX" || { err "bad spx"; return 1; }
        [ -z "$P_PATH" ] || match '/[ -~]{0,200}' "$P_PATH" || { err "bad path"; return 1; }
        [ -z "$P_HOST" ] || match "$RE_HOST" "$P_HOST" || { err "bad host"; return 1; }
        [ -z "$P_MODE" ] || match 'auto|packet-up|stream-up|stream-one' "$P_MODE" || { err "bad xhttp mode"; return 1; }
        [ -z "$P_SVC" ] || match '[A-Za-z0-9._/-]{1,100}' "$P_SVC" || { err "bad serviceName"; return 1; }
        [ -z "$P_ALPN" ] || match '[A-Za-z0-9./,-]{1,50}' "$P_ALPN" || { err "bad alpn"; return 1; }
        # Vision needs the raw TCP transport
        [ "$P_NET" = tcp ] || P_FLOW=''
    elif [ "$P_TYPE" = ssh ]; then
        match '[A-Za-z0-9._-]{1,32}' "$P_USER" || { err "bad SSH user"; return 1; }
        match 'pass|key' "$P_AUTH" || { err "bad auth (pass|key)"; return 1; }
        match 'direct|tls|ws|wss' "$P_TRANS" || { err "bad transport (direct|tls|ws|wss)"; return 1; }
        [ -z "$P_SNI" ] || match "$RE_HOST" "$P_SNI" || { err "bad SNI"; return 1; }
        [ -z "$P_WSHOST" ] || match "$RE_HOST" "$P_WSHOST" || { err "bad WebSocket host"; return 1; }
        [ -z "$P_WSPATH" ] || match '/[ -~]{0,200}' "$P_WSPATH" || { err "bad WebSocket path"; return 1; }
        [ -z "$P_PAYLOAD" ] || { match '[ -~]+' "$P_PAYLOAD" && maxlen 2000 "$P_PAYLOAD"; } || { err "bad payload (printable ASCII)"; return 1; }
    else
        err "bad type"; return 1
    fi
    return 0
}
name_from() { # suggestion from remark
    n=$(printf '%s' "$1" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-32)
    match "$RE_NAME" "$n" && ! match '_+' "$n" || n=''
    if [ -z "$n" ]; then i=1; while prof_exists "p$i"; do i=$((i + 1)); done; n="p$i"; fi
    printf '%s' "$n"
}

# ------------------------------------------------------------ xray config
outbound_json() { # uses P_*, $1 = ssh socks port
    if [ "$P_TYPE" = ssh ]; then
        printf '{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":%s}]}}' "$1"
        return
    fi
    net=$P_NET; [ "$net" = tcp ] && net=raw
    u="{\"id\":$(js "$P_UUID"),\"encryption\":$(js "$P_ENC")"
    [ -n "$P_FLOW" ] && u="$u,\"flow\":$(js "$P_FLOW")"
    u="$u}"
    s="\"network\":\"$net\",\"security\":\"$P_SEC\""
    case $P_SEC in
        reality)
            s="$s,\"realitySettings\":{\"serverName\":$(js "$P_SNI"),\"fingerprint\":$(js "$P_FP"),\"publicKey\":$(js "$P_PBK"),\"shortId\":$(js "$P_SID"),\"spiderX\":$(js "$P_SPX")"
            [ -n "$P_PQV" ] && s="$s,\"mldsa65Verify\":$(js "$P_PQV")"
            s="$s}" ;;
        tls)
            s="$s,\"tlsSettings\":{\"serverName\":$(js "${P_SNI:-$P_ADDR}"),\"fingerprint\":$(js "$P_FP")"
            if [ -n "$P_ALPN" ]; then
                s="$s,\"alpn\":[$(printf '%s' "$P_ALPN" | awk -F, '{for(i=1;i<=NF;i++) printf "%s\"%s\"", (i>1?",":""), $i}')]"
            fi
            s="$s}" ;;
    esac
    case $net in
        xhttp) s="$s,\"xhttpSettings\":{\"path\":$(js "${P_PATH:-/}"),\"host\":$(js "$P_HOST"),\"mode\":$(js "${P_MODE:-auto}")}" ;;
        grpc) s="$s,\"grpcSettings\":{\"serviceName\":$(js "$P_SVC")}" ;;
        ws) s="$s,\"wsSettings\":{\"path\":$(js "${P_PATH:-/}"),\"host\":$(js "$P_HOST")}" ;;
        httpupgrade) s="$s,\"httpupgradeSettings\":{\"path\":$(js "${P_PATH:-/}"),\"host\":$(js "$P_HOST")}" ;;
    esac
    printf '{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":%s,"port":%s,"users":[%s]}]},"streamSettings":{%s}}' \
        "$(js "$P_ADDR")" "$P_PORT" "$u" "$s"
}
# gen_xray NAME OUT [PROBE_PORT PROBE_SSH_PORT]
gen_xray() {
    load_conf
    load_prof "$1" || return 1
    out=$2
    mkdir -p "$(dirname "$out")" "$LOGD"
    if [ -n "${3:-}" ]; then
        {
            printf '{"log":{"loglevel":"error"},"inbounds":[{"tag":"probe","listen":"127.0.0.1","port":%s,"protocol":"socks","settings":{"udp":true}}],' "$3"
            printf '"outbounds":[%s]}\n' "$(outbound_json "${4:-$SSH_SOCKS}")"
        } >"$out"
        return 0
    fi
    lan_detect
    sniff='"sniffing":{"enabled":false}'
    [ "$SNIFF" = 1 ] && sniff='"sniffing":{"enabled":true,"destOverride":["http","tls"]}'
    direct_ip='"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","100.64.0.0/10","224.0.0.0/4","fc00::/7","fe80::/10","::1/128"'
    by_ip='' by_dom=''
    for d in $BYPASS_DST; do
        case $d in
            domain:* | full:* | keyword:*) by_dom="$by_dom${by_dom:+,}$(js "$d")" ;;
            *) by_ip="$by_ip${by_ip:+,}$(js "$d")" ;;
        esac
    done
    {
        printf '{"log":{"loglevel":"%s","access":"none","error":"%s/xray.log"},\n' "$LOGLEVEL" "$LOGD"
        # Xray's dns outbound answers A/AAAA from the DNS module: make that module ask
        # DNS_SERVER over TCP through the tunnel (works for REALITY and SSH alike)
        printf '"dns":{"tag":"dns-module","servers":["tcp://%s"]},\n' "$DNS_SERVER"
        printf '"api":{"tag":"api","listen":"127.0.0.1:%s","services":["StatsService"]},"stats":{},\n' "$API_PORT"
        printf '"policy":{"levels":{"0":{"handshake":8,"connIdle":300}},"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},\n'
        printf '"inbounds":[\n'
        printf '{"tag":"socks-lo","listen":"127.0.0.1","port":%s,"protocol":"socks","settings":{"udp":true},%s},\n' "$SOCKS_PORT" "$sniff"
        printf '{"tag":"socks-lan","listen":"%s","port":%s,"protocol":"socks","settings":{"udp":true},%s},\n' "$LAN_IP" "$SOCKS_PORT" "$sniff"
        printf '{"tag":"http-lan","listen":"%s","port":%s,"protocol":"http","settings":{}},\n' "$LAN_IP" "$HTTP_PORT"
        printf '{"tag":"redir-in","listen":"%s","port":%s,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true},%s},\n' "$LAN_IP" "$REDIR_PORT" "$sniff"
        printf '{"tag":"dns-in","listen":"%s","port":%s,"protocol":"dokodemo-door","settings":{"address":"%s","port":53,"network":"tcp,udp"}}\n' "$LAN_IP" "$DNS_PORT" "$DNS_SERVER"
        printf '],\n"outbounds":[\n%s,\n' "$(outbound_json "$SSH_SOCKS")"
        printf '{"tag":"dns-out","protocol":"dns","settings":{"network":"tcp","address":"%s","port":53},"streamSettings":{"sockopt":{"dialerProxy":"proxy"}}},\n' "$DNS_SERVER"
        printf '{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],\n'
        printf '"routing":{"domainStrategy":"AsIs","rules":[\n'
        printf '{"inboundTag":["dns-in"],"outboundTag":"dns-out"},\n'
        printf '{"inboundTag":["dns-module"],"outboundTag":"proxy"},\n'
        [ -n "$by_dom" ] && printf '{"domain":[%s],"outboundTag":"direct"},\n' "$by_dom"
        [ -n "$by_ip" ] && printf '{"ip":[%s],"outboundTag":"direct"},\n' "$by_ip"
        printf '{"ip":[%s],"outboundTag":"direct"}\n]}}\n' "$direct_ip"
    } >"$out"
}

# ------------------------------------------------------------------- SSH
ssh_bin() {
    for s in /usr/libexec/ssh-openssh /usr/bin/ssh; do
        [ -x "$s" ] && "$s" -V 2>&1 | grep -q OpenSSH && { printf '%s' "$s"; return 0; }
    done
    return 1
}
# ssh_exec NAME BIND_PORT - exec OpenSSH with a SOCKS (-D) listener
ssh_exec() {
    load_prof "$1" || exit 1
    [ "$P_TYPE" = ssh ] || die "not an SSH profile: $1"
    S=$(ssh_bin) || die "OpenSSH client missing (opkg install openssh-client)"
    set -- "$S" -N -T -D "127.0.0.1:$2" -p "$P_PORT" -l "$P_USER" \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$ETC/known_hosts" \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
        -o ConnectTimeout=20 -o TCPKeepAlive=yes -o LogLevel=ERROR -o Compression=no
    [ "$P_TRANS" = direct ] || set -- "$@" -o "ProxyCommand=$SELF _pc $P_NAME"
    if [ "$P_AUTH" = key ]; then
        [ -f "$ETC/id_ed25519" ] || die "no SSH key - run: xec ssh-key"
        exec "$@" -i "$ETC/id_ed25519" -o BatchMode=yes -o PasswordAuthentication=no \
            -o KbdInteractiveAuthentication=no "$P_ADDR"
    fi
    [ -s "$PROF/$P_NAME.pass" ] || die "no password stored for $P_NAME"
    command -v sshpass >/dev/null 2>&1 || die "sshpass missing (opkg install sshpass)"
    exec sshpass -f "$PROF/$P_NAME.pass" "$@" -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 "$P_ADDR"
}
# _pc NAME - ssh ProxyCommand: TLS with SNI and/or WebSocket payload
proxy_cmd() {
    load_prof "$1" || exit 1
    sni=${P_SNI:-$P_ADDR}
    case $P_ADDR in *:*) hp="[$P_ADDR]:$P_PORT" ;; *) hp="$P_ADDR:$P_PORT" ;; esac
    case $P_TRANS in
        tls) exec openssl s_client -quiet -connect "$hp" -servername "$sni" 2>/dev/null ;;
        ws) { ws_payload; exec cat; } | exec nc "$P_ADDR" "$P_PORT" ;;
        wss) { ws_payload; exec cat; } | exec openssl s_client -quiet -connect "$hp" -servername "$sni" 2>/dev/null ;;
        *) die "direct profile needs no ProxyCommand" ;;
    esac
}
# HTTP Upgrade request; [host] [path] [sni] [crlf] [lf] [cr] placeholders
ws_payload() {
    p=${P_PAYLOAD:-'GET [path] HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]'}
    printf '%s' "$p" | awk -v h="${P_WSHOST:-${P_SNI:-$P_ADDR}}" -v pa="${P_WSPATH:-/}" -v sn="${P_SNI:-$P_ADDR}" '
        function rep(s, a, b,   o, i) { o=""; while ((i=index(s,a))>0) { o=o substr(s,1,i-1) b; s=substr(s,i+length(a)) } return o s }
        { if (NR>1) printf "\n"; s=$0
          s=rep(s,"[crlf]","\r\n"); s=rep(s,"[lf]","\n"); s=rep(s,"[cr]","\r")
          s=rep(s,"\\r","\r"); s=rep(s,"\\n","\n")
          s=rep(s,"[host]",h); s=rep(s,"[path]",pa); s=rep(s,"[sni]",sn); printf "%s", s }'
}

# --------------------------------------------------------------- firewall
IPT="iptables -w"
IP6T="ip6tables -w"
fw_off() {
    for c in "nat PREROUTING XEC_PRE" "filter FORWARD XEC_FWD"; do
        set -- $c
        while $IPT -t "$1" -D "$2" -i "${LAN_IF:-br-lan}" -j "$3" 2>/dev/null; do :; done
        while $IPT -t "$1" -D "$2" -j "$3" 2>/dev/null; do :; done
        $IPT -t "$1" -F "$3" 2>/dev/null; $IPT -t "$1" -X "$3" 2>/dev/null
    done
    if $IP6T -S FORWARD >/dev/null 2>&1; then
        while $IP6T -D FORWARD -i "${LAN_IF:-br-lan}" -j XEC_FWD6 2>/dev/null; do :; done
        while $IP6T -D FORWARD -j XEC_FWD6 2>/dev/null; do :; done
        $IP6T -F XEC_FWD6 2>/dev/null; $IP6T -X XEC_FWD6 2>/dev/null
    fi
    return 0
}
fw_on() {
    load_conf; lan_detect
    fw_off
    [ "$ROUTE" = all ] || return 0
    command -v iptables >/dev/null 2>&1 || { warn "iptables missing - LAN routing off (SOCKS/HTTP proxy only)"; return 0; }
    $IPT -t nat -N XEC_PRE || return 1
    for s in $BYPASS_SRC; do $IPT -t nat -A XEC_PRE -s "$s" -j RETURN; done
    if [ "$DNS_TUNNEL" = 1 ]; then
        $IPT -t nat -A XEC_PRE -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
        $IPT -t nat -A XEC_PRE -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    fi
    for d in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        $IPT -t nat -A XEC_PRE -d "$d" -j RETURN
    done
    for d in $BYPASS_DST; do
        case $d in *:*) ;; *) $IPT -t nat -A XEC_PRE -d "$d" -j RETURN ;; esac
    done
    $IPT -t nat -A XEC_PRE -p tcp -j REDIRECT --to-ports "$REDIR_PORT"
    $IPT -t nat -I PREROUTING 1 -i "$LAN_IF" -j XEC_PRE
    $IPT -t filter -N XEC_FWD
    for s in $BYPASS_SRC; do $IPT -t filter -A XEC_FWD -s "$s" -j RETURN; done
    [ "$BLOCK_QUIC" = 1 ] && $IPT -t filter -A XEC_FWD -p udp --dport 443 -j REJECT
    $IPT -t filter -I FORWARD 1 -i "$LAN_IF" -j XEC_FWD
    if [ "$BLOCK_V6" = 1 ] && $IP6T -S FORWARD >/dev/null 2>&1; then
        $IP6T -N XEC_FWD6 && $IP6T -A XEC_FWD6 -j REJECT && $IP6T -I FORWARD 1 -i "$LAN_IF" -j XEC_FWD6
    fi
    return 0
}
is_running() { pgrep -f "run -c $RUN/xray.json" >/dev/null 2>&1; }
# wait (max ~8 s) until xray listens on the LAN redirect port
wait_ready() {
    i=0
    while [ $i -lt 16 ]; do
        netstat -ltn 2>/dev/null | grep -q ":$REDIR_PORT " && return 0
        sleep 1; i=$((i + 2))
    done
    return 1
}
fw_auto() { # firewall include / reload hook
    load_conf; lan_detect
    if is_running && [ ! -f "$RUN/fw-suspended" ]; then fw_on; else fw_off; fi
}

# ---------------------------------------------------------------- service
cmd_prepare() { # called by the init script
    load_conf
    mkdir -p "$RUN" "$LOGD"
    rm -f "$RUN/fw-suspended" "$RUN/fails"
    if [ -z "$ACTIVE" ] || ! prof_exists "$ACTIVE"; then
        fw_off; log "no active profile - tunnel not started"; return 1
    fi
    [ -x "$XRAY" ] || { log "xray missing"; return 1; }
    gen_xray "$ACTIVE" "$RUN/xray.json" || return 1
    if ! "$XRAY" run -test -c "$RUN/xray.json" >"$RUN/test.out" 2>&1; then
        log "xray config test failed: $(tail -n 1 "$RUN/test.out")"; return 1
    fi
    printf 'XEC_TYPE=%s\n' "$P_TYPE" >"$RUN/procd.env"
    fw_on
    log "starting profile $ACTIVE ($P_TYPE $P_ADDR:$P_PORT)"
    return 0
}
svc() { [ -x "$INIT" ] || die "not installed - run: sh $0 install"; "$INIT" "$1"; }
# restart without the "Command failed: Not found" noise when it was not running
restart() { "$1" stop >/dev/null 2>&1; "$1" start; }
cmd_start() {
    load_conf
    [ -n "$ACTIVE" ] || die "no active profile - add one: xec add NAME 'vless://...'"
    "$INIT" enable 2>/dev/null
    [ -x "$INIT" ] || die "not installed - run: sh $0 install"
    restart "$INIT"
    i=0
    while [ $i -lt 10 ]; do is_running && break; sleep 1; i=$((i + 1)); done
    is_running && wait_ready
    if is_running; then ok "tunnel running: $ACTIVE"; else
        err "tunnel did not start"; tail -n 5 "$RUN/test.out" 2>/dev/null >&2; tail -n 5 "$LOGD/xray.log" 2>/dev/null >&2; return 1
    fi
}
cmd_stop() {
    [ -x "$INIT" ] && { "$INIT" stop; "$INIT" disable; }
    fw_off
    ok "tunnel stopped - LAN uses the normal internet"
}

# ------------------------------------------------------------------ tests
# curl_socks PORT URL -> "HTTPCODE SECONDS"
# (no_proxy / NO_PROXY would make curl ignore -x, so drop the proxy environment)
curl_socks() {
    env -u no_proxy -u NO_PROXY -u http_proxy -u https_proxy -u all_proxy curl -s -o /dev/null -w '%{http_code} %{time_total}' --connect-timeout 6 --max-time 12 \
        -x "socks5h://127.0.0.1:$1" "$2" 2>/dev/null
}
code_ok() { case $1 in 2?? | 3??) return 0 ;; esac; return 1; }
# probe NAME - start a private client for NAME and fetch CHECK_URL through it
probe() {
    load_conf
    load_prof "$1" || return 1
    pp=$((20000 + $$ % 20000)); sp=$((pp + 1))
    [ -x "$XRAY" ] || { say "FAIL xray missing"; return 1; }
    mkdir -p "$RUN"
    sshpid='' xpid=''
    if [ "$P_TYPE" = ssh ]; then
        ("$SELF" _ssh_probe "$1" "$sp" >"$RUN/probe-$pp.ssh" 2>&1) &
        sshpid=$!
    fi
    gen_xray "$1" "$RUN/probe-$pp.json" "$pp" "$sp" || return 1
    "$XRAY" run -c "$RUN/probe-$pp.json" >"$RUN/probe-$pp.log" 2>&1 &
    xpid=$!
    r='000 0' i=0
    while [ $i -lt 6 ]; do
        sleep 1
        # stop early when the client (or ssh, e.g. wrong password) is gone
        kill -0 "$xpid" 2>/dev/null || break
        [ -z "$sshpid" ] || kill -0 "$sshpid" 2>/dev/null || break
        r=$(curl_socks "$pp" "$CHECK_URL")
        code_ok "${r%% *}" && break
        i=$((i + 1))
    done
    kill "$xpid" 2>/dev/null
    if [ -n "$sshpid" ]; then
        for p in $(pgrep -f "127.0.0.1:$sp") $sshpid; do kill "$p" 2>/dev/null; done
    fi
    wait 2>/dev/null
    if code_ok "${r%% *}"; then
        ms=$(printf '%s' "${r#* }" | awk '{printf "%d", $1*1000}')
        rm -f "$RUN/probe-$pp".*
        say "OK ${ms}ms"; return 0
    fi
    why=$(cat "$RUN/probe-$pp.ssh" "$RUN/probe-$pp.log" 2>/dev/null | grep -v '^$' | tail -n 1)
    rm -f "$RUN/probe-$pp".*
    say "FAIL ${why:-no answer (HTTP ${r%% *})}"; return 1
}
cmd_test() {
    load_conf
    if [ -n "${1:-}" ]; then printf '%-16s ' "$1"; probe "$1"; return; fi
    is_running || die "tunnel is not running (xec start)"
    r=$(curl_socks "$SOCKS_PORT" "$CHECK_URL")
    if code_ok "${r%% *}"; then ok "tunnel works ($ACTIVE) - $(printf '%s' "${r#* }" | awk '{printf "%d", $1*1000}') ms"
    else err "no answer through the tunnel (HTTP ${r%% *})"; return 1; fi
    t=$(env -u no_proxy -u NO_PROXY curl -s --max-time 15 -x "socks5h://127.0.0.1:$SOCKS_PORT" "$TRACE_URL" 2>/dev/null)
    [ -n "$t" ] && say "exit IP: $(printf '%s\n' "$t" | sed -n 's/^ip=//p')  country: $(printf '%s\n' "$t" | sed -n 's/^loc=//p')  Cloudflare: $(printf '%s\n' "$t" | sed -n 's/^colo=//p')"
    return 0
}
cmd_ping() { for n in $(prof_list); do printf '%-16s ' "$n"; probe "$n"; done; }

# --------------------------------------------------------------- watchdog
cmd_watchdog() {
    load_conf
    [ -s "$LOGD/xray.log" ] && [ "$(wc -c <"$LOGD/xray.log")" -gt 524288 ] && tail -n 200 "$LOGD/xray.log" >"$LOGD/x.tmp" && mv "$LOGD/x.tmp" "$LOGD/xray.log"
    [ -s "$LOGF" ] && [ "$(wc -c <"$LOGF")" -gt 262144 ] && tail -n 300 "$LOGF" >"$LOGD/l.tmp" && mv "$LOGD/l.tmp" "$LOGF"
    [ -n "$ACTIVE" ] && is_running || return 0
    mkdir -p "$RUN"
    r=$(curl_socks "$SOCKS_PORT" "$CHECK_URL")
    if code_ok "${r%% *}"; then
        rm -f "$RUN/fails"
        if [ -f "$RUN/fw-suspended" ]; then rm -f "$RUN/fw-suspended"; fw_on; log "tunnel back - LAN routing restored"; fi
        return 0
    fi
    f=$(($(cat "$RUN/fails" 2>/dev/null || echo 0) + 1)); echo "$f" >"$RUN/fails"
    log "watchdog: $ACTIVE check failed ($f)"
    [ "$f" -ge 2 ] || return 0
    if [ "$FAILOVER" = 1 ]; then
        for n in $(prof_list); do
            [ "$n" = "$ACTIVE" ] && continue
            if probe "$n" >/dev/null 2>&1; then
                conf_set "$CONF" ACTIVE "$n"; log "failover: $ACTIVE -> $n"
                restart "$INIT"; return 0
            fi
        done
    fi
    [ $((f % 2)) -eq 0 ] && { log "watchdog: restarting $ACTIVE"; restart "$INIT"; echo "$f" >"$RUN/fails"; }
    # after the restart (it re-applies the rules): without kill switch, LAN goes direct
    if [ "$KILLSWITCH" != 1 ]; then
        fw_off; : >"$RUN/fw-suspended"; log "kill switch off - LAN uses the normal internet until the tunnel is back"
    fi
    return 0
}

# ------------------------------------------------------------------ stats
stat_val() { printf '%s' "$1" | jsonfilter -e "@.stat[@.name='outbound>>>proxy>>>traffic>>>$2'].value" 2>/dev/null || echo 0; }
cmd_stats() { # -> "UP DOWN" bytes
    load_conf
    s=$("$XRAY" api statsquery --server="127.0.0.1:$API_PORT" -pattern 'outbound>>>proxy' 2>/dev/null)
    u=$(stat_val "$s" uplink); d=$(stat_val "$s" downlink)
    printf '%s %s\n' "${u:-0}" "${d:-0}"
}
human() { awk -v b="$1" 'BEGIN{ split("B KB MB GB TB",u," "); i=1; while (b>=1024 && i<5) { b/=1024; i++ } printf (i==1?"%d %s":"%.1f %s"), b, u[i] }'; }

# --------------------------------------------------------------- profiles
store_pass() { # NAME PASS
    printf '%s\n' "$2" >"$PROF/$1.pass.new"; chmod 600 "$PROF/$1.pass.new"; mv -f "$PROF/$1.pass.new" "$PROF/$1.pass"
}
after_add() { # NAME
    load_conf
    if [ -z "$ACTIVE" ] || ! prof_exists "$ACTIVE"; then conf_set "$CONF" ACTIVE "$1"; say "active profile: $1"; fi
    [ "$P_TYPE" = ssh ] && [ "$P_AUTH" = key ] && [ ! -f "$ETC/id_ed25519.pub" ] && ssh_key >/dev/null
    return 0
}
cmd_add() { # NAME LINK | LINK
    if [ $# -ge 2 ]; then n=$1; link=$2; else n=''; link=${1:-}; fi
    [ -n "$link" ] || die "usage: xec add [NAME] 'vless://...'  or  'ssh://user:pass@host:port?transport=tls&sni=...'"
    parse_link "$link" || exit 1
    [ -n "$n" ] || n=$(name_from "$LNAME")
    match "$RE_NAME" "$n" || die "bad name (A-Z a-z 0-9 _ - , max 32)"
    save_prof "$n"
    [ "$P_TYPE" = ssh ] && [ -n "$SSH_PASS" ] && store_pass "$n" "$SSH_PASS"
    ok "saved profile $n ($P_TYPE $P_ADDR:$P_PORT${P_SEC:+ $P_SEC}${P_SNI:+ sni=$P_SNI})"
    after_add "$n"
}
cmd_import() { # links on stdin
    c=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        case $line in vless://* | ssh://*) (cmd_add "$line") && c=$((c + 1)) ;; esac
    done
    say "imported: $c"
}
cmd_add_ssh() { # NAME --host H [--port P] --user U [--pass P|--pass-stdin|--key] [--transport T] [--sni S] [--ws-host H] [--ws-path P] [--payload S]
    n=${1:-}; shift 2>/dev/null
    match "$RE_NAME" "$n" || die "usage: xec add-ssh NAME --host H --user U [--pass P | --pass-stdin | --key] [--port 22] [--transport direct|tls|ws|wss] [--sni S] [--ws-host H] [--ws-path /] [--payload STR]"
    prof_clear; P_TYPE=ssh; P_PORT=22; P_TRANS=direct; P_AUTH=''; pw=''
    while [ $# -gt 0 ]; do
        case $1 in
            --host) P_ADDR=$2; shift ;;
            --port) P_PORT=$2; shift ;;
            --user) P_USER=$2; shift ;;
            --pass) P_AUTH=pass; pw=$2; shift ;;
            --pass-stdin) P_AUTH=pass; IFS= read -r pw ;;
            --key) P_AUTH=key ;;
            --transport) P_TRANS=$2; shift ;;
            --sni) P_SNI=$2; shift ;;
            --ws-host) P_WSHOST=$2; shift ;;
            --ws-path) P_WSPATH=$2; shift ;;
            --payload) P_PAYLOAD=$2; shift ;;
            --remark) P_REMARK=$2; shift ;;
            *) die "unknown option: $1" ;;
        esac
        shift
    done
    [ -n "$P_AUTH" ] || { [ -s "$PROF/$n.pass" ] && P_AUTH=pass || P_AUTH=key; }
    check_prof || exit 1
    save_prof "$n"
    [ -n "$pw" ] && store_pass "$n" "$pw"
    [ "$P_AUTH" = pass ] && [ ! -s "$PROF/$n.pass" ] && warn "no password stored yet: xec add-ssh $n ... --pass-stdin"
    ok "saved SSH profile $n ($P_USER@$P_ADDR:$P_PORT $P_TRANS${P_SNI:+ sni=$P_SNI})"
    after_add "$n"
}
cmd_list() {
    load_conf
    for n in $(prof_list); do
        load_prof "$n" >/dev/null 2>&1 || continue
        mark=' '; [ "$n" = "$ACTIVE" ] && mark='*'
        if [ "$P_TYPE" = ssh ]; then d="ssh/$P_TRANS $P_USER@$P_ADDR:$P_PORT${P_SNI:+ sni=$P_SNI}"
        else d="vless/$P_NET/$P_SEC $P_ADDR:$P_PORT${P_SNI:+ sni=$P_SNI}${P_FLOW:+ vision}${P_PQV:+ pq-sig}"; [ "$P_ENC" != none ] && d="$d pq-enc"; fi
        printf '%s %-16s %s %s\n' "$mark" "$n" "$d" "${P_REMARK:+($P_REMARK)}"
    done
}
cmd_use() {
    prof_exists "${1:-}" || die "profile not found: ${1:-}"
    conf_set "$CONF" ACTIVE "$1"; ok "active profile: $1"
    is_running && cmd_start
    return 0
}
cmd_del() {
    prof_exists "${1:-}" || die "profile not found: ${1:-}"
    load_conf
    rm -f "$PROF/$1.conf" "$PROF/$1.pass"
    ok "deleted $1"
    if [ "$ACTIVE" = "$1" ]; then
        nx=$(prof_list | head -n 1); conf_set "$CONF" ACTIVE "$nx"
        if [ -n "$nx" ]; then is_running && cmd_start; else cmd_stop; fi
    fi
    return 0
}
cmd_show() { # NAME -> KEY=VALUE lines (no password)
    load_prof "${1:-}" || exit 1
    for k in $PKEYS; do eval "v=\${P_$k}"; [ -n "$v" ] && printf '%s=%s\n' "$k" "$v"; done
    [ -s "$PROF/$1.pass" ] && say "PASSWORD=(stored)"
    return 0
}
ssh_key() {
    mkdir -p "$ETC"
    if [ ! -f "$ETC/id_ed25519" ]; then
        command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen missing (opkg install openssh-keygen)"
        ssh-keygen -q -t ed25519 -N '' -C "xe3000-client@$(uci -q get system.@system[0].hostname || echo router)" -f "$ETC/id_ed25519" || die "ssh-keygen failed"
    fi
    cat "$ETC/id_ed25519.pub"
}
cmd_forget() { # NAME - forget the stored SSH host key
    load_prof "${1:-}" || exit 1
    ssh-keygen -R "[$P_ADDR]:$P_PORT" -f "$ETC/known_hosts" >/dev/null 2>&1
    ssh-keygen -R "$P_ADDR" -f "$ETC/known_hosts" >/dev/null 2>&1
    ok "host key of $P_ADDR forgotten"
}

# --------------------------------------------------------------- settings
SKEYS='ROUTE DNS_TUNNEL DNS_SERVER BLOCK_QUIC BLOCK_V6 KILLSWITCH FAILOVER SNIFF BYPASS_SRC BYPASS_DST LAN_IF LAN_IP SOCKS_PORT HTTP_PORT REDIR_PORT DNS_PORT API_PORT SSH_SOCKS WEB WEB_PORT LOGLEVEL CHECK_URL TRACE_URL'
valid_setting() { # KEY VALUE
    case $1 in
        ROUTE) match 'all|proxy' "$2" ;;
        DNS_TUNNEL | BLOCK_QUIC | BLOCK_V6 | KILLSWITCH | FAILOVER | WEB | SNIFF) match '0|1' "$2" ;;
        DNS_SERVER) match "$RE_IP4" "$2" ;;
        LAN_IP) [ -z "$2" ] || match "$RE_IP4" "$2" ;;
        LAN_IF) [ -z "$2" ] || match '[A-Za-z0-9._-]{1,15}' "$2" ;;
        BYPASS_SRC) [ -z "$2" ] || match "$RE_IP4( $RE_IP4)*" "$2" ;;
        BYPASS_DST) [ -z "$2" ] || match "(($RE_IP4(/[0-9]{1,2})?)|((domain|full|keyword):[A-Za-z0-9.-]{1,100}))( (($RE_IP4(/[0-9]{1,2})?)|((domain|full|keyword):[A-Za-z0-9.-]{1,100})))*" "$2" ;;
        *_PORT | SSH_SOCKS) valid_port "$2" ;;
        LOGLEVEL) match 'none|error|warning|info|debug' "$2" ;;
        CHECK_URL | TRACE_URL) match "$RE_URL" "$2" ;;
        *) return 1 ;;
    esac
}
cmd_set() { # KEY VALUE
    [ $# -eq 2 ] || { load_conf; for k in $SKEYS; do eval "printf '%s=%s\n' $k \"\$$k\""; done; return 0; }
    case " $SKEYS " in *" $1 "*) ;; *) die "unknown setting: $1 (xec set to list)" ;; esac
    valid_setting "$1" "$2" || die "bad value for $1: $2"
    conf_set "$CONF" "$1" "$2"
    ok "$1=$2"
    case $1 in WEB | WEB_PORT | LAN_IP) [ -x "$INIT_WEB" ] && restart "$INIT_WEB" ;; esac
    load_conf
    is_running && case $1 in WEB | WEB_PORT | CHECK_URL | TRACE_URL | FAILOVER | KILLSWITCH) ;; *) restart "$INIT"; wait_ready ;; esac
    return 0
}
cmd_bypass() { # add|del IP
    load_conf
    case ${1:-} in
        add) match "$RE_IP4" "${2:-}" || die "usage: xec bypass add 192.168.8.x"
            case " $BYPASS_SRC " in *" $2 "*) ;; *) cmd_set BYPASS_SRC "$(echo $BYPASS_SRC $2)" ;; esac ;;
        del) cmd_set BYPASS_SRC "$(printf '%s\n' $BYPASS_SRC | grep -vx "${2:-x}" | tr '\n' ' ' | sed 's/ $//')" ;;
        *) say "devices that skip the tunnel: ${BYPASS_SRC:-none}" ;;
    esac
}
cmd_route() {
    case ${1:-} in
        on) cmd_set ROUTE all ;;
        off) cmd_set ROUTE proxy ;;
        *) die "usage: xec route on|off" ;;
    esac
}

# --------------------------------------------------------------- web auth
pw_hash() { # SALT PASS
    h="$1$2" i=0
    while [ $i -lt 200 ]; do h=$(printf '%s%s' "$h" "$1" | sha256sum | cut -d' ' -f1); i=$((i + 1)); done
    printf '%s' "$h"
}
web_setpass() { # [PASS] - prints the password when generated
    p=${1:-}
    gen=0
    [ -n "$p" ] || { p=$(rand_hex 6); gen=1; }
    [ ${#p} -ge 6 ] || die "password: 6 characters or more"
    s=$(rand_hex 8)
    mkdir -p "$ETC"
    printf '%s:%s\n' "$s" "$(pw_hash "$s" "$p")" >"$ETC/web.pass.new"
    chmod 600 "$ETC/web.pass.new"; mv -f "$ETC/web.pass.new" "$ETC/web.pass"
    rm -rf "$RUN/sess"
    [ $gen = 1 ] && say "web password: $p"
    return 0
}
web_check() { # PASS
    [ -s "$ETC/web.pass" ] || return 1
    s=$(cut -d: -f1 "$ETC/web.pass"); h=$(cut -d: -f2 "$ETC/web.pass")
    [ "$(pw_hash "$s" "$1")" = "$h" ]
}
cmd_web() {
    load_conf; lan_detect
    case ${1:-url} in
        on) cmd_set WEB 1; "$INIT_WEB" enable ;;
        off) cmd_set WEB 0; "$INIT_WEB" stop; "$INIT_WEB" disable ;;
        password) web_setpass "${2:-}"; ok "web password changed" ;;
        url) say "http://$LAN_IP:$WEB_PORT/" ;;
        *) die "usage: xec web on|off|url|password [NEW]" ;;
    esac
}

# -------------------------------------------------------------------- CGI
FORM=''
fv() { # NAME - field from query string + POST body
    printf '%s' "&$QUERY_STRING&$FORM&" | awk -v k="$1" 'BEGIN{RS="&"} { i=index($0,"="); if (i>0 && substr($0,1,i-1)==k) { print substr($0,i+1); exit } }' |
        { IFS= read -r v || [ -n "$v" ]; urldec "$v" form; }
}
reply() { # JSON
    printf 'Status: 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n%s\n' "$1"
    exit 0
}
reply_err() { reply "{\"ok\":false,\"msg\":$(js "$1")}"; }
# run a command, answer {"ok":..,"msg":"output"}
run_json() {
    out="$RUN/cgi.$$"
    ( "$@" ) >"$out" 2>&1; rc=$?
    t=$(sed 's/\x1b\[[0-9;]*m//g' "$out" | tail -n 80 | jtext); rm -f "$out"
    if [ $rc -eq 0 ]; then reply "{\"ok\":true,\"msg\":$t}"; else reply "{\"ok\":false,\"msg\":$t}"; fi
}
cgi_session() {
    tok=$(printf '%s' "${HTTP_COOKIE:-}" | tr ';' '\n' | sed -n 's/^ *xec_s=\([0-9a-f]\{32\}\)$/\1/p' | head -n 1)
    [ -n "$tok" ] && [ -f "$RUN/sess/$tok" ] || return 1
    # 12 h lifetime
    [ -n "$(find "$RUN/sess/$tok" -mmin -720 2>/dev/null)" ] || { rm -f "$RUN/sess/$tok"; return 1; }
    CSRF=$(cat "$RUN/sess/$tok")
    return 0
}
cgi_status() {
    load_conf; lan_detect
    run=false; is_running && run=true
    up=0 down=0; $run && { set -- $(cmd_stats); up=$1; down=$2; }
    xv=$("$XRAY" version 2>/dev/null | head -n 1 | awk '{print $2}')
    ps=''
    for n in $(prof_list); do
        load_prof "$n" >/dev/null 2>&1 || continue
        haspw=false; [ -s "$PROF/$n.pass" ] && haspw=true
        ps="$ps${ps:+,}{\"name\":$(js "$n"),\"type\":$(js "$P_TYPE"),\"addr\":$(js "$P_ADDR"),\"port\":$(js "$P_PORT"),\"sec\":$(js "$P_SEC"),\"net\":$(js "$P_NET"),\"sni\":$(js "$P_SNI"),\"flow\":$(js "$P_FLOW"),\"pq_sig\":$([ -n "$P_PQV" ] && echo true || echo false),\"pq_enc\":$([ -n "$P_ENC" ] && [ "$P_ENC" != none ] && echo true || echo false),\"trans\":$(js "$P_TRANS"),\"user\":$(js "$P_USER"),\"auth\":$(js "$P_AUTH"),\"wshost\":$(js "$P_WSHOST"),\"wspath\":$(js "$P_WSPATH"),\"payload\":$(js "$P_PAYLOAD"),\"haspw\":$haspw,\"remark\":$(js "$P_REMARK")}"
    done
    st=''
    for k in $SKEYS; do eval "v=\$$k"; st="$st${st:+,}\"$k\":$(js "$v")"; done
    pub=''; [ -f "$ETC/id_ed25519.pub" ] && pub=$(cat "$ETC/id_ed25519.pub")
    reply "{\"ok\":true,\"version\":\"$XEC_VERSION\",\"xray\":$(js "$xv"),\"running\":$run,\"active\":$(js "$ACTIVE"),\"suspended\":$([ -f "$RUN/fw-suspended" ] && echo true || echo false),\"lan_ip\":$(js "$LAN_IP"),\"lan_if\":$(js "$LAN_IF"),\"up\":$up,\"down\":$down,\"uptime\":$(js "$(uptime | sed 's/.*up *//;s/, *load.*//')"),\"sshkey\":$(js "$pub"),\"profiles\":[$ps],\"settings\":{$st}}"
}
cgi_exitinfo() {
    load_conf
    is_running || reply_err "tunnel is not running"
    t=$(env -u no_proxy -u NO_PROXY curl -s --max-time 15 -x "socks5h://127.0.0.1:$SOCKS_PORT" "$TRACE_URL" 2>/dev/null)
    r=$(curl_socks "$SOCKS_PORT" "$CHECK_URL")
    ms=$(printf '%s' "${r#* }" | awk '{printf "%d", $1*1000}')
    code_ok "${r%% *}" || reply "{\"ok\":false,\"msg\":\"no answer through the tunnel\"}"
    reply "{\"ok\":true,\"ms\":$ms,\"ip\":$(js "$(printf '%s\n' "$t" | sed -n 's/^ip=//p')"),\"loc\":$(js "$(printf '%s\n' "$t" | sed -n 's/^loc=//p')"),\"colo\":$(js "$(printf '%s\n' "$t" | sed -n 's/^colo=//p')")}"
}
cgi_add_ssh() {
    n=$(fv name)
    set -- "$n" --host "$(fv host)" --port "$(fv port)" --user "$(fv user)" --transport "$(fv trans)"
    [ -n "$(fv sni)" ] && set -- "$@" --sni "$(fv sni)"
    [ -n "$(fv wshost)" ] && set -- "$@" --ws-host "$(fv wshost)"
    [ -n "$(fv wspath)" ] && set -- "$@" --ws-path "$(fv wspath)"
    [ -n "$(fv payload)" ] && set -- "$@" --payload "$(fv payload)"
    [ -n "$(fv remark)" ] && set -- "$@" --remark "$(fv remark)"
    if [ "$(fv auth)" = key ]; then set -- "$@" --key; fi
    pw=$(fv pass)
    if [ -n "$pw" ]; then printf '%s\n' "$pw" | run_json cmd_add_ssh "$@" --pass-stdin; exit 0; fi
    [ "$(fv auth)" = pass ] && [ ! -s "$PROF/$n.pass" ] && reply_err "password required"
    run_json cmd_add_ssh "$@"
}
cmd_cgi() {
    load_conf
    mkdir -p "$RUN/sess" "$LOGD"; chmod 700 "$RUN/sess"
    if [ "${REQUEST_METHOD:-GET}" = POST ]; then
        len=${CONTENT_LENGTH:-0}; match '[0-9]{1,6}' "$len" || len=0
        [ "$len" -le 200000 ] || reply_err "request too large"
        FORM=$(head -c "$len")
    fi
    a=$(fv a)
    if [ "$a" = login ]; then
        [ "${REQUEST_METHOD:-}" = POST ] || reply_err "POST only"
        f=$(cat "$RUN/web-fails" 2>/dev/null || echo 0)
        if [ "$f" -ge 5 ] && [ -n "$(find "$RUN/web-fails" -mmin -5 2>/dev/null)" ]; then reply_err "too many attempts - wait 5 minutes"; fi
        if web_check "$(fv pass)"; then
            rm -f "$RUN/web-fails"
            find "$RUN/sess" -type f -mmin +720 -exec rm -f {} + 2>/dev/null
            tok=$(rand_hex 16); cs=$(rand_hex 16)
            printf '%s' "$cs" >"$RUN/sess/$tok"
            log "web: login from ${REMOTE_ADDR:-?}"
            printf 'Status: 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nSet-Cookie: xec_s=%s; Path=/; HttpOnly; SameSite=Strict\r\n\r\n{"ok":true,"csrf":"%s"}\n' "$tok" "$cs"
            exit 0
        fi
        echo $((f + 1)) >"$RUN/web-fails"
        log "web: bad password from ${REMOTE_ADDR:-?}"
        reply_err "wrong password"
    fi
    cgi_session || { printf 'Status: 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"ok":false,"auth":false}\n'; exit 0; }
    if [ "${REQUEST_METHOD:-}" = POST ]; then
        [ "$(fv csrf)" = "$CSRF" ] || reply_err "bad CSRF token - reload the page"
    elif [ "$a" != status ] && [ "$a" != logs ] && [ "$a" != csrf ] && [ "$a" != export ]; then
        reply_err "POST only"
    fi
    case $a in
        csrf) reply "{\"ok\":true,\"csrf\":$(js "$CSRF")}" ;;
        status) cgi_status ;;
        logs)
            t=$( { tail -n 60 "$LOGF" 2>/dev/null; echo '--- xray ---'; tail -n 40 "$LOGD/xray.log" 2>/dev/null; echo '--- system ---'; logread -e xe-client 2>/dev/null | tail -n 30; } | jtext)
            reply "{\"ok\":true,\"msg\":$t}" ;;
        export)
            printf 'Status: 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename="xe-client-backup.txt"\r\nCache-Control: no-store\r\n\r\n'
            cmd_export; exit 0 ;;
        exitinfo) cgi_exitinfo ;;
        start) run_json cmd_start ;;
        stop) run_json cmd_stop ;;
        restart) run_json cmd_start ;;
        test) run_json cmd_test ;;
        probe) run_json cmd_test "$(fv name)" ;;
        ping) run_json cmd_ping ;;
        add) n=$(fv name); if [ -n "$n" ]; then run_json cmd_add "$n" "$(fv link)"; else run_json cmd_add "$(fv link)"; fi ;;
        import) fv links | run_json cmd_import; exit 0 ;;
        addssh) cgi_add_ssh ;;
        use) run_json cmd_use "$(fv name)" ;;
        del) run_json cmd_del "$(fv name)" ;;
        set) run_json cmd_set "$(fv key)" "$(fv value)" ;;
        sshkey) run_json ssh_key ;;
        forget) run_json cmd_forget "$(fv name)" ;;
        update) run_json cmd_update_xray ;;
        watchdog) run_json cmd_watchdog ;;
        passwd)
            web_check "$(fv old)" || reply_err "current password is wrong"
            n=$(fv new); [ ${#n} -ge 6 ] || reply_err "new password: 6 characters or more"
            run_json web_setpass "$n" ;;
        logout) rm -f "$RUN/sess/$tok"; reply '{"ok":true}' ;;
        *) reply_err "unknown action" ;;
    esac
}

# ------------------------------------------------------------- backup
cmd_export() {
    say "# xe3000-client backup $(date '+%F %T') - contains passwords, keep it private"
    for f in "$CONF" "$PROF"/*.conf "$PROF"/*.pass; do
        [ -f "$f" ] || continue
        say "@@FILE ${f#$ETC/}"; cat "$f"
    done
    return 0
}
cmd_restore() { # FILE
    [ -f "${1:-}" ] || die "usage: xec restore FILE"
    mkdir -p "$PROF"; chmod 700 "$ETC" "$PROF"
    awk -v d="$ETC" '/^@@FILE /{ f=$2; if (f !~ /^(client\.conf|profiles\/[A-Za-z0-9_-]+\.(conf|pass))$/) { f=""; next } f=d "/" f; printf "" > f; next } f!="" { print >> f }' "$1"
    chmod 600 "$CONF" "$PROF"/* 2>/dev/null
    ok "restored"; cmd_list
}

# ------------------------------------------------------------------- xray
xray_arch() {
    case $(uname -m) in
        aarch64 | arm64) echo arm64-v8a ;;
        x86_64) echo 64 ;;
        armv7* | armv8l) echo arm32-v7a ;;
        mips) echo mips32 ;;
        mipsel) echo mips32le ;;
        i?86) echo 32 ;;
        *) return 1 ;;
    esac
}
# xray_install [ZIP DGST] - official release, SHA2-256 from the .dgst file
xray_install() {
    zip=${1:-} dg=${2:-} ver=${XRAY_VERSION:-}
    tmp=/tmp/xec-dl.$$; rm -rf "$tmp"; mkdir -p "$tmp"
    if [ -z "$zip" ]; then
        a=$(xray_arch) || die "unsupported CPU: $(uname -m)"
        if [ -z "$ver" ]; then
            ver=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$XRAY_REPO/releases/latest" 2>/dev/null | sed 's#.*/tag/##')
        fi
        match 'v[0-9]+(\.[0-9]+){1,3}' "$ver" || die "cannot find the latest Xray release (network?)"
        cur=$("$XRAY" version 2>/dev/null | head -n 1 | awk '{print $2}')
        if [ "v$cur" = "$ver" ] && [ -z "${FORCE:-}" ]; then ok "Xray $ver is already installed"; rm -rf "$tmp"; return 0; fi
        say "downloading Xray $ver ($a) from $XRAY_REPO ..."
        u="$XRAY_REPO/releases/download/$ver/Xray-linux-$a.zip"
        curl -fL --retry 3 --connect-timeout 20 -o "$tmp/x.zip" "$u" || die "download failed: $u"
        curl -fsL --retry 3 --connect-timeout 20 -o "$tmp/x.dgst" "$u.dgst" || die "download failed: $u.dgst"
        zip=$tmp/x.zip dg=$tmp/x.dgst
    fi
    want=$(sed -n 's/^SHA2-256= *\([0-9a-fA-F]\{64\}\).*/\1/p' "$dg" | head -n 1 | tr 'A-F' 'a-f')
    got=$(sha256sum "$zip" | cut -d' ' -f1)
    [ -n "$want" ] && [ "$want" = "$got" ] || { rm -rf "$tmp"; die "Xray checksum mismatch - refused"; }
    ok "SHA-256 verified ($got)"
    mkdir -p "$tmp/u"
    unzip -o -q "$zip" xray -d "$tmp/u" || { rm -rf "$tmp"; die "unzip failed"; }
    chmod 755 "$tmp/u/xray"
    nv=$("$tmp/u/xray" version 2>/dev/null | head -n 1) || true
    [ -n "$nv" ] || { rm -rf "$tmp"; die "the downloaded xray does not run on this CPU"; }
    mkdir -p "$OPT/bin"
    [ -x "$XRAY" ] && mv -f "$XRAY" "$XRAY.prev"
    mv -f "$tmp/u/xray" "$XRAY"
    rm -rf "$tmp"
    ok "installed: $nv"
    log "xray installed: $nv"
    return 0
}
cmd_update_xray() {
    xray_install "$@" || return 1
    if is_running && ! restart "$INIT"; then
        warn "restart failed - rolling back"; mv -f "$XRAY.prev" "$XRAY"; restart "$INIT"
    fi
    rm -f "$XRAY.prev"
    return 0
}

# -------------------------------------------------------------- web page
write_www() {
    cat >"$WWW/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XE3000 Client</title>
<style>
:root{--bg:#0f1419;--card:#18212b;--line:#263241;--txt:#e6edf3;--mut:#8b98a5;--acc:#2f81f7;--ok:#2ea043;--bad:#da3633;--warn:#d29922}
@media (prefers-color-scheme:light){:root{--bg:#f4f6f8;--card:#fff;--line:#d8dee4;--txt:#1f2328;--mut:#59636e;--acc:#0969da;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif}
header{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:2}
header b{font-size:17px}header .sp{flex:1}
nav{display:flex;gap:4px;overflow-x:auto;padding:8px 12px;border-bottom:1px solid var(--line)}
nav button{background:none;border:0;color:var(--mut);padding:8px 12px;border-radius:8px;cursor:pointer;font:inherit;white-space:nowrap}
nav button.on{background:var(--acc);color:#fff}
main{max-width:980px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
.card h3{margin:0 0 12px;font-size:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.kv{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:10px}.kv small{color:var(--mut);display:block}.kv span{font-size:17px;font-weight:600;word-break:break-all}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:13px;font-weight:600;color:#fff}
.g{background:var(--ok)}.r{background:var(--bad)}.y{background:var(--warn)}.b{background:var(--acc)}
.chip{display:inline-block;font-size:11px;padding:1px 7px;border-radius:6px;border:1px solid var(--line);margin:0 2px;color:var(--mut)}
button.btn{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer;margin:2px}
button.sec{background:transparent;color:var(--txt);border:1px solid var(--line)}button.dng{background:var(--bad)}
button:disabled{opacity:.5}
label{display:block;margin:8px 0 4px;color:var(--mut);font-size:13px}
input,select,textarea{width:100%;padding:9px 10px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--txt);font:inherit;direction:ltr;text-align:left}
textarea{min-height:90px;font-family:ui-monospace,monospace;font-size:13px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:600px){.row{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse}td,th{padding:8px 6px;border-bottom:1px solid var(--line);text-align:right;vertical-align:top}th{color:var(--mut);font-weight:500;font-size:13px}
td .addr{direction:ltr;display:inline-block;font-family:ui-monospace,monospace;font-size:13px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-all;direction:ltr;text-align:left;font-size:12px;max-height:420px;overflow:auto;margin:8px 0 0}
.tog{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line)}.tog div small{display:block;color:var(--mut);font-size:12px}
.tog input{width:auto;transform:scale(1.3)}
#toast{position:fixed;bottom:16px;left:16px;right:16px;max-width:520px;margin:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;display:none;z-index:9;white-space:pre-wrap;direction:ltr;text-align:left;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.35)}
#login{max-width:360px;margin:12vh auto}.hide{display:none}.mut{color:var(--mut);font-size:13px}
</style>
</head>
<body>
<div id="login" class="card hide"><h3>XE3000 Client</h3><label>كلمة المرور / Password</label><input id="lp" type="password" autocomplete="current-password"><br><br><button class="btn" id="lb">دخول</button><p class="mut">نسيت كلمة المرور؟ عبر SSH: <code>xec web password</code></p></div>
<div id="app" class="hide">
<header><b>XE3000 Client</b><span id="hb" class="badge y">…</span><span class="sp"></span><button class="btn sec" id="lo">خروج</button></header>
<nav id="nav"><button data-t="st" class="on">الحالة</button><button data-t="pr">الخوادم</button><button data-t="ad">إضافة</button><button data-t="se">الإعدادات</button><button data-t="to">الأدوات</button></nav>
<main>
<section id="t-st">
 <div class="card"><h3>الاتصال</h3>
  <div class="grid">
   <div class="kv"><small>الحالة</small><span id="s-run">…</span></div>
   <div class="kv"><small>الخادم النشط</small><span id="s-act">-</span></div>
   <div class="kv"><small>رفع ↑</small><span id="s-up">0</span></div>
   <div class="kv"><small>تنزيل ↓</small><span id="s-dn">0</span></div>
   <div class="kv"><small>Xray</small><span id="s-xv">-</span></div>
   <div class="kv"><small>توجيه الشبكة</small><span id="s-rt">-</span></div>
  </div><br>
  <button class="btn" data-a="start">تشغيل / إعادة تشغيل</button><button class="btn dng" data-a="stop">إيقاف</button><button class="btn sec" id="exb">فحص IP الخروج</button>
  <div id="ex" class="grid hide" style="margin-top:10px">
   <div class="kv"><small>IP الخروج</small><span id="e-ip">-</span></div><div class="kv"><small>الدولة</small><span id="e-loc">-</span></div>
   <div class="kv"><small>محطة Cloudflare</small><span id="e-colo">-</span></div><div class="kv"><small>زمن الاستجابة</small><span id="e-ms">-</span></div>
  </div>
 </div>
 <div class="card"><h3>للأجهزة</h3><p class="mut" id="s-px"></p></div>
</section>
<section id="t-pr" class="hide"><div class="card"><h3>الخوادم المحفوظة</h3>
 <table><thead><tr><th>الاسم</th><th>النوع</th><th>الخادم</th><th></th></tr></thead><tbody id="pl"></tbody></table><br>
 <button class="btn sec" data-a="ping">اختبار كل الخوادم</button></div></section>
<section id="t-ad" class="hide">
 <div class="card"><h3>VLESS REALITY (رابط)</h3>
  <p class="mut">الصق رابطاً أو عدة روابط (سطر لكل رابط): <code>vless://…security=reality&amp;sni=…&amp;pbk=…&amp;sid=…&amp;flow=xtls-rprx-vision</code> — يدعم pqv (ML-DSA-65) و encryption=mlkem768x25519plus و XHTTP و gRPC. يقبل أيضاً <code>ssh://user:pass@host:443?transport=tls&amp;sni=…</code></p>
  <label>الاسم (اختياري لرابط واحد)</label><input id="a-name" placeholder="myserver">
  <label>الرابط / الروابط</label><textarea id="a-link" placeholder="vless://"></textarea><br><br>
  <button class="btn" id="a-go">حفظ</button></div>
 <div class="card"><h3>خادم SSH</h3>
  <div class="row"><div><label>الاسم</label><input id="h-name" placeholder="ssh1"></div><div><label>ملاحظة</label><input id="h-remark"></div></div>
  <div class="row"><div><label>الخادم (دومين أو IP)</label><input id="h-host"></div><div><label>المنفذ</label><input id="h-port" value="22"></div></div>
  <div class="row"><div><label>المستخدم</label><input id="h-user"></div><div><label>المصادقة</label><select id="h-auth"><option value="pass">كلمة مرور</option><option value="key">مفتاح SSH</option></select></div></div>
  <div id="h-pw"><label>كلمة المرور (اتركها فارغة للإبقاء على المحفوظة)</label><input id="h-pass" type="password" autocomplete="new-password"></div>
  <label>طريقة الاتصال</label><select id="h-trans"><option value="direct">مباشر (SSH)</option><option value="tls">SSH عبر TLS مع SNI</option><option value="ws">SSH عبر WebSocket</option><option value="wss">SSH عبر WebSocket + TLS مع SNI</option></select>
  <div id="h-tlsf"><label>SNI (Bug host)</label><input id="h-sni"></div>
  <div id="h-wsf"><div class="row"><div><label>Host header</label><input id="h-wshost"></div><div><label>المسار</label><input id="h-wspath" placeholder="/"></div></div>
   <label>Payload (اختياري: [host] [path] [crlf])</label><textarea id="h-payload" placeholder="GET [path] HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"></textarea></div><br>
  <button class="btn" id="h-go">حفظ</button>
  <div id="h-key" class="hide"><p class="mut">أضف هذا المفتاح في الخادم إلى <code>~/.ssh/authorized_keys</code>:</p><pre id="h-keyv"></pre></div></div>
</section>
<section id="t-se" class="hide"><div class="card"><h3>الإعدادات</h3>
 <div class="tog"><div>توجيه كل أجهزة الشبكة عبر النفق<small>إن أُطفئ: وكيل SOCKS/HTTP فقط</small></div><input type="checkbox" id="c-ROUTE"></div>
 <div class="tog"><div>DNS عبر النفق<small>يمنع تسرب DNS</small></div><input type="checkbox" id="c-DNS_TUNNEL"></div>
 <div class="tog"><div>حظر QUIC (UDP 443)<small>يجبر التطبيقات على TCP عبر النفق</small></div><input type="checkbox" id="c-BLOCK_QUIC"></div>
 <div class="tog"><div>حظر IPv6 للأجهزة<small>يمنع خروج IPv6 خارج النفق</small></div><input type="checkbox" id="c-BLOCK_V6"></div>
 <div class="tog"><div>مفتاح القطع (Kill switch)<small>لا إنترنت إن انقطع النفق</small></div><input type="checkbox" id="c-KILLSWITCH"></div>
 <div class="tog"><div>التبديل التلقائي<small>ينتقل لخادم آخر يعمل عند الانقطاع</small></div><input type="checkbox" id="c-FAILOVER"></div>
 <div class="tog"><div>Sniffing (اسم الموقع)<small>يرسل اسم الموقع للخادم بدل IP</small></div><input type="checkbox" id="c-SNIFF"></div>
 <div class="row"><div><label>خادم DNS</label><input id="v-DNS_SERVER"></div><div><label>مستوى السجل</label><select id="v-LOGLEVEL"><option>none</option><option>error</option><option>warning</option><option>info</option><option>debug</option></select></div></div>
 <label>أجهزة خارج النفق (IP مفصولة بمسافة)</label><input id="v-BYPASS_SRC" placeholder="192.168.8.50 192.168.8.51">
 <label>وجهات مباشرة (IP/CIDR أو domain:example.sa)</label><input id="v-BYPASS_DST" placeholder="domain:gov.sa 1.2.3.0/24">
 <label>رابط فحص الاتصال</label><input id="v-CHECK_URL"><br><br>
 <button class="btn" id="se-go">حفظ الإعدادات</button></div></section>
<section id="t-to" class="hide">
 <div class="card"><h3>الأدوات</h3>
  <button class="btn" data-a="test">اختبار النفق</button><button class="btn sec" data-a="update">تحديث Xray</button><button class="btn sec" data-a="watchdog">تشغيل المراقب الآن</button><button class="btn sec" id="lg">السجلات</button><a class="btn sec" href="cgi-bin/api?a=export" style="text-decoration:none;display:inline-block"><button class="btn sec" type="button">تصدير نسخة احتياطية</button></a>
  <pre id="out" class="hide"></pre></div>
 <div class="card"><h3>كلمة مرور اللوحة</h3><div class="row"><div><label>الحالية</label><input id="p-old" type="password"></div><div><label>الجديدة (6+)</label><input id="p-new" type="password"></div></div><br><button class="btn" id="p-go">تغيير</button></div>
</section>
</main></div>
<div id="toast"></div>
<script>
var CSRF="",S=null,tab="st",timer=null;
function $(i){return document.getElementById(i)}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function hb(b){var u=["B","KB","MB","GB","TB"],i=0;b=+b||0;while(b>=1024&&i<4){b/=1024;i++}return(i?b.toFixed(1):b)+" "+u[i]}
function toast(m,bad){var t=$("toast");t.textContent=m;t.style.borderColor=bad?"var(--bad)":"var(--line)";t.style.display="block";clearTimeout(t._t);t._t=setTimeout(function(){t.style.display="none"},bad?9000:5000)}
function api(a,data){
  var o={credentials:"same-origin"},u="cgi-bin/api";
  if(data){var p=new URLSearchParams();p.append("a",a);p.append("csrf",CSRF);for(var k in data)p.append(k,data[k]);o.method="POST";o.body=p}else u+="?a="+a;
  return fetch(u,o).then(function(r){if(r.status==401){showLogin();throw new Error("auth")}return r.json()})
}
function act(a,data,btn){if(btn)btn.disabled=true;toast("…");return api(a,data||{}).then(function(j){toast(j.msg||(j.ok?"OK":"error"),!j.ok);if(btn)btn.disabled=false;load();return j}).catch(function(e){if(btn)btn.disabled=false;if(e.message!="auth")toast(String(e),true)})}
function showLogin(){$("app").classList.add("hide");$("login").classList.remove("hide");$("lp").focus()}
$("lb").onclick=function(){var p=new URLSearchParams();p.append("a","login");p.append("pass",$("lp").value);fetch("cgi-bin/api",{method:"POST",body:p,credentials:"same-origin"}).then(function(r){return r.json()}).then(function(j){if(j.ok){CSRF=j.csrf;$("lp").value="";start()}else toast(j.msg,true)})};
$("lp").onkeydown=function(e){if(e.key=="Enter")$("lb").onclick()};
$("lo").onclick=function(){api("logout",{}).then(function(){location.reload()})};
function start(){$("login").classList.add("hide");$("app").classList.remove("hide");load();clearInterval(timer);timer=setInterval(function(){if(tab=="st")load()},5000)}
document.querySelectorAll("#nav button").forEach(function(b){b.onclick=function(){tab=b.dataset.t;document.querySelectorAll("#nav button").forEach(function(x){x.classList.toggle("on",x==b)});document.querySelectorAll("main>section").forEach(function(s){s.classList.toggle("hide",s.id!="t-"+tab)});if(tab=="se")fillSettings()}});
document.querySelectorAll("[data-a]").forEach(function(b){b.onclick=function(){act(b.dataset.a,{},b).then(function(j){if(j&&["test","update","watchdog","ping"].indexOf(b.dataset.a)>=0){$("out").textContent=j.msg;$("out").classList.remove("hide")}})}});
function kind(p){if(p.type=="ssh")return'<span class="chip">SSH</span><span class="chip">'+esc(p.trans)+'</span>';var h='<span class="chip">VLESS</span><span class="chip">'+esc(p.net)+'</span><span class="chip">'+esc(p.sec)+'</span>';if(p.flow)h+='<span class="chip">Vision</span>';if(p.pq_sig)h+='<span class="chip">PQ-sig</span>';if(p.pq_enc)h+='<span class="chip">PQ-enc</span>';return h}
function load(){api("status").then(function(j){S=j;
  $("hb").className="badge "+(j.running?(j.suspended?"y":"g"):"r");$("hb").textContent=j.running?(j.suspended?"النفق متوقف مؤقتاً":"متصل"):"متوقف";
  $("s-run").innerHTML=j.running?'<span class="badge g">يعمل</span>':'<span class="badge r">متوقف</span>';
  $("s-act").textContent=j.active||"-";$("s-up").textContent=hb(j.up);$("s-dn").textContent=hb(j.down);$("s-xv").textContent=j.xray||"-";
  $("s-rt").textContent=j.settings.ROUTE=="all"?"كل الأجهزة ("+j.lan_if+")":"وكيل فقط";
  $("s-px").innerHTML='SOCKS5: <code>'+esc(j.lan_ip)+':'+esc(j.settings.SOCKS_PORT)+'</code> — HTTP: <code>'+esc(j.lan_ip)+':'+esc(j.settings.HTTP_PORT)+'</code><br>عند تفعيل "توجيه كل الأجهزة" لا تحتاج الأجهزة لأي إعداد.';
  var h="";j.profiles.forEach(function(p){h+="<tr><td>"+(p.name==j.active?'<span class="badge b">●</span> ':"")+esc(p.name)+(p.remark?'<br><small class="mut">'+esc(p.remark)+"</small>":"")+"</td><td>"+kind(p)+"</td><td><span class=addr>"+esc(p.addr)+":"+esc(p.port)+"</span>"+(p.sni?'<br><small class="mut">SNI: '+esc(p.sni)+"</small>":"")+'</td><td><button class="btn" data-u="'+esc(p.name)+'">استخدام</button><button class="btn sec" data-p="'+esc(p.name)+'">اختبار</button>'+(p.type=="ssh"?'<button class="btn sec" data-e="'+esc(p.name)+'">تعديل</button>':"")+'<button class="btn dng" data-d="'+esc(p.name)+'">حذف</button></td></tr>'});
  $("pl").innerHTML=h||'<tr><td colspan=4 class="mut">لا توجد خوادم بعد — من "إضافة"</td></tr>';
  $("pl").querySelectorAll("[data-u]").forEach(function(b){b.onclick=function(){act("use",{name:b.dataset.u},b)}});
  $("pl").querySelectorAll("[data-p]").forEach(function(b){b.onclick=function(){act("probe",{name:b.dataset.p},b)}});
  $("pl").querySelectorAll("[data-d]").forEach(function(b){b.onclick=function(){if(confirm("حذف "+b.dataset.d+"؟"))act("del",{name:b.dataset.d},b)}});
  $("pl").querySelectorAll("[data-e]").forEach(function(b){b.onclick=function(){editSsh(b.dataset.e)}});
}).catch(function(){})}
$("exb").onclick=function(){var b=this;b.disabled=true;api("exitinfo",{}).then(function(j){b.disabled=false;if(!j.ok)return toast(j.msg,true);$("ex").classList.remove("hide");$("e-ip").textContent=j.ip||"-";$("e-loc").textContent=j.loc||"-";$("e-colo").textContent=j.colo||"-";$("e-ms").textContent=j.ms+" ms"}).catch(function(){b.disabled=false})};
$("a-go").onclick=function(){var l=$("a-link").value.trim();if(!l)return;var many=l.split(/\n/).filter(function(x){return x.trim()}).length>1;(many?act("import",{links:l},this):act("add",{name:$("a-name").value.trim(),link:l},this)).then(function(j){if(j&&j.ok){$("a-link").value="";$("a-name").value=""}})};
function sshFields(){var t=$("h-trans").value;$("h-tlsf").classList.toggle("hide",!(t=="tls"||t=="wss"));$("h-wsf").classList.toggle("hide",!(t=="ws"||t=="wss"));$("h-pw").classList.toggle("hide",$("h-auth").value!="pass")}
$("h-trans").onchange=sshFields;$("h-auth").onchange=sshFields;sshFields();
function editSsh(n){var p=S.profiles.filter(function(x){return x.name==n})[0];if(!p)return;$("h-name").value=p.name;$("h-remark").value=p.remark;$("h-host").value=p.addr;$("h-port").value=p.port;$("h-user").value=p.user;$("h-auth").value=p.auth||"pass";$("h-trans").value=p.trans||"direct";$("h-sni").value=p.sni;$("h-wshost").value=p.wshost;$("h-wspath").value=p.wspath;$("h-payload").value=p.payload;$("h-pass").value="";sshFields();document.querySelector('#nav [data-t="ad"]').click()}
$("h-go").onclick=function(){var d={name:$("h-name").value.trim(),remark:$("h-remark").value.trim(),host:$("h-host").value.trim(),port:$("h-port").value.trim(),user:$("h-user").value.trim(),auth:$("h-auth").value,pass:$("h-pass").value,trans:$("h-trans").value,sni:$("h-sni").value.trim(),wshost:$("h-wshost").value.trim(),wspath:$("h-wspath").value.trim(),payload:$("h-payload").value.replace(/\r?\n/g,"[crlf]")};
  act("addssh",d,this).then(function(j){if(j&&j.ok){$("h-pass").value="";if(d.auth=="key")api("sshkey",{}).then(function(k){$("h-keyv").textContent=k.msg;$("h-key").classList.remove("hide")})}})};
var TOG=["DNS_TUNNEL","BLOCK_QUIC","BLOCK_V6","KILLSWITCH","FAILOVER","SNIFF"],VAL=["DNS_SERVER","LOGLEVEL","BYPASS_SRC","BYPASS_DST","CHECK_URL"];
function fillSettings(){if(!S)return;var s=S.settings;$("c-ROUTE").checked=s.ROUTE=="all";TOG.forEach(function(k){$("c-"+k).checked=s[k]=="1"});VAL.forEach(function(k){$("v-"+k).value=s[k]})}
$("se-go").onclick=function(){var s=S.settings,ch=[],b=this;var r=$("c-ROUTE").checked?"all":"proxy";if(r!=s.ROUTE)ch.push(["ROUTE",r]);
  TOG.forEach(function(k){var v=$("c-"+k).checked?"1":"0";if(v!=s[k])ch.push([k,v])});VAL.forEach(function(k){var v=$("v-"+k).value.trim();if(v!=s[k])ch.push([k,v])});
  if(!ch.length)return toast("لا تغييرات");b.disabled=true;var msgs=[];(function nx(){if(!ch.length){b.disabled=false;toast(msgs.join("\n"));load();return}var c=ch.shift();api("set",{key:c[0],value:c[1]}).then(function(j){msgs.push(j.msg.trim());nx()}).catch(function(){b.disabled=false})})()};
$("lg").onclick=function(){api("logs").then(function(j){$("out").textContent=j.msg;$("out").classList.remove("hide")})};
$("p-go").onclick=function(){act("passwd",{old:$("p-old").value,new:$("p-new").value},this).then(function(j){if(j&&j.ok){$("p-old").value="";$("p-new").value=""}})};
fetch("cgi-bin/api?a=csrf",{credentials:"same-origin"}).then(function(r){if(r.status==401){showLogin();return null}return r.json()}).then(function(j){if(j&&j.ok){CSRF=j.csrf;start()}}).catch(showLogin);
</script>
</body>
</html>
EOF
}

# --------------------------------------------------------------- install
pkg_ok() { opkg status "$1" 2>/dev/null | grep -q '^Status:.* installed'; }
write_files() {
    mkdir -p "$ETC" "$PROF" "$OPT/bin" "$WWW/cgi-bin"
    chmod 700 "$ETC" "$PROF"
    cat >"$INIT" <<'EOF'
#!/bin/sh /etc/rc.common
# XE3000 client tunnel (installed by xec)
START=99
STOP=10
USE_PROCD=1

start_service() {
	/usr/bin/xec _prepare || return 0
	. /var/run/xe-client/procd.env
	procd_open_instance xray
	procd_set_param command /opt/xe-client/bin/xray run -c /var/run/xe-client/xray.json
	procd_set_param respawn 3600 5 0
	procd_set_param limits nofile="16384 16384"
	procd_set_param stderr 1
	procd_close_instance
	if [ "$XEC_TYPE" = ssh ]; then
		procd_open_instance ssh
		procd_set_param command /usr/bin/xec _ssh
		procd_set_param respawn 3600 5 0
		procd_set_param stderr 1
		procd_close_instance
	fi
}

stop_service() {
	/usr/bin/xec _fw off
}
EOF
    cat >"$INIT_WEB" <<'EOF'
#!/bin/sh /etc/rc.common
# XE3000 client web panel (own uhttpd instance, LAN only)
START=99
USE_PROCD=1

start_service() {
	eval "$(/usr/bin/xec _webenv)"
	[ "$WEB_ON" = 1 ] || return 0
	procd_open_instance web
	procd_set_param command /usr/sbin/uhttpd -f -h /opt/xe-client/www -x /cgi-bin -t 300 -T 30 -k 20 -n 8 -N 50
	for l in $WEB_LISTEN; do procd_append_param command -p "$l"; done
	procd_set_param respawn
	procd_close_instance
}
EOF
    chmod 755 "$INIT" "$INIT_WEB"
    printf '#!/bin/sh\nexec /usr/bin/xec _cgi\n' >"$WWW/cgi-bin/api"
    chmod 755 "$WWW/cgi-bin/api"
    write_www
    # firewall reload hook (fw3 include)
    printf '#!/bin/sh\n[ -x /usr/bin/xec ] && /usr/bin/xec _fw auto\nexit 0\n' >"$OPT/firewall.sh"
    chmod 755 "$OPT/firewall.sh"
    uci -q delete firewall.xe_client
    uci set firewall.xe_client=include
    uci set firewall.xe_client.type=script
    uci set firewall.xe_client.path="$OPT/firewall.sh"
    uci set firewall.xe_client.reload=1
    uci commit firewall
    # watchdog every 2 minutes
    touch /etc/crontabs/root
    grep -v '/usr/bin/xec watchdog' /etc/crontabs/root >/etc/crontabs/root.new
    echo '*/2 * * * * /usr/bin/xec watchdog >/dev/null 2>&1' >>/etc/crontabs/root.new
    mv -f /etc/crontabs/root.new /etc/crontabs/root
    /etc/init.d/cron enable 2>/dev/null; /etc/init.d/cron restart 2>/dev/null
    # keep the settings across firmware upgrades
    grep -qx "$ETC/" /etc/sysupgrade.conf 2>/dev/null || echo "$ETC/" >>/etc/sysupgrade.conf
}
cmd_install() {
    [ "$(id -u)" = 0 ] || die "run as root"
    [ -f /etc/openwrt_release ] || die "this script is for OpenWrt / GL.iNet routers"
    . /etc/openwrt_release
    say "== XE3000 CLIENT $XEC_VERSION - $DISTRIB_DESCRIPTION ($(uname -m)) =="
    zip='' dg='' web=1 ssh=1 link='' offline=0
    while [ $# -gt 0 ]; do
        case $1 in
            --xray-zip) zip=$2; shift ;;
            --xray-dgst) dg=$2; shift ;;
            --xray-version) XRAY_VERSION=$2; shift ;;
            --no-web) web=0 ;;
            --no-ssh) ssh=0 ;;
            --offline) offline=1 ;;
            --link) link=$2; shift ;;
            --web-password) WEBPW=$2; shift ;;
            *) die "unknown option: $1" ;;
        esac
        shift
    done
    [ -z "$zip" ] || [ -n "$dg" ] || die "--xray-zip needs --xray-dgst"
    src=$0
    [ -f "$src" ] && head -n 20 "$src" | grep -q 'XE3000 CLIENT' || die "run the saved file: sh /tmp/xec.sh install"
    need='curl ca-bundle unzip'
    [ $web = 1 ] && need="$need uhttpd"
    [ $ssh = 1 ] && need="$need openssh-client openssh-keygen sshpass openssl-util"
    miss=''
    for p in $need; do
        case $p in
            unzip) command -v unzip >/dev/null 2>&1 && continue ;;
            curl) command -v curl >/dev/null 2>&1 && continue ;;
            uhttpd) [ -x /usr/sbin/uhttpd ] && continue ;;
        esac
        pkg_ok "$p" || miss="$miss $p"
    done
    if [ -n "$miss" ]; then
        [ $offline = 1 ] && die "missing packages:$miss"
        say "installing packages:$miss"
        opkg update >/tmp/xec-opkg.log 2>&1 || { tail -n 5 /tmp/xec-opkg.log; die "opkg update failed (internet?)"; }
        opkg install $miss >>/tmp/xec-opkg.log 2>&1 || { tail -n 10 /tmp/xec-opkg.log; die "opkg install failed"; }
        ok "packages installed"
    fi
    [ $ssh = 0 ] || ssh_bin >/dev/null || die "OpenSSH client not usable"
    was=0; is_running && was=1
    if [ -n "$zip" ] || [ ! -x "$XRAY" ]; then xray_install "$zip" "$dg"; else ok "Xray present: $("$XRAY" version | head -n 1)"; fi
    mkdir -p /usr/bin
    if [ "$(readlink -f "$src")" != "$SELF" ]; then cp -f "$src" "$SELF.new" && mv -f "$SELF.new" "$SELF"; fi
    chmod 755 "$SELF"
    printf '#!/bin/sh\n# XE3000 CLIENT menu\nexec /usr/bin/xec menu "$@"\n' >"$MENU_CMD"
    chmod 755 "$MENU_CMD"
    write_files
    [ -f "$CONF" ] || { : >"$CONF"; chmod 600 "$CONF"; }
    load_conf; lan_detect
    [ $web = 1 ] || conf_set "$CONF" WEB 0
    genpw=''
    if [ -n "${WEBPW:-}" ]; then web_setpass "$WEBPW" >/dev/null
    elif [ ! -s "$ETC/web.pass" ]; then genpw=$(web_setpass | sed -n 's/^web password: //p'); fi
    "$INIT_WEB" enable; restart "$INIT_WEB"
    /etc/init.d/firewall reload >/dev/null 2>&1
    [ -n "$link" ] && "$SELF" add "$link"
    load_conf; lan_detect
    if [ -n "$ACTIVE" ] && { [ $was = 1 ] || [ -n "$link" ]; }; then "$SELF" start; fi
    say ""
    ok "installed. menu: menu1   commands: xec help"
    [ $web = 1 ] && say "web panel : http://$LAN_IP:$WEB_PORT/"
    [ -n "$genpw" ] && say "password  : $genpw   (shown once - change: xec web password)"
    [ -n "$ACTIVE" ] || say "next      : xec add NAME 'vless://...'   then   xec start"
    return 0
}
cmd_uninstall() {
    [ -x "$INIT" ] && { "$INIT" stop; "$INIT" disable; }
    [ -x "$INIT_WEB" ] && { "$INIT_WEB" stop; "$INIT_WEB" disable; }
    load_conf; lan_detect; fw_off
    uci -q delete firewall.xe_client && uci commit firewall
    if [ -f /etc/crontabs/root ]; then
        grep -v '/usr/bin/xec' /etc/crontabs/root >/etc/crontabs/root.new
        mv -f /etc/crontabs/root.new /etc/crontabs/root
    fi
    /etc/init.d/cron restart 2>/dev/null
    rm -rf "$OPT" "$RUN" "$LOGD" "$INIT" "$INIT_WEB"
    if [ "${1:-}" = --purge ]; then
        rm -rf "$ETC"; sed -i "\#^$ETC/\$#d" /etc/sysupgrade.conf 2>/dev/null
        ok "removed (settings deleted)"
    else
        ok "removed (settings kept in $ETC - delete with: rm -rf $ETC)"
    fi
    rm -f "$SELF" "$MENU_CMD"
}

# ------------------------------------------------------------------- menu
ask() { printf '%s' "$1" >&2; IFS= read -r REPLY || return 1; }
cmd_status() {
    load_conf; lan_detect
    if is_running; then printf "tunnel : ${C_G}RUNNING${C_0} (%s)\n" "$ACTIVE"; else printf "tunnel : ${C_R}STOPPED${C_0}\n"; fi
    [ -f "$RUN/fw-suspended" ] && say "         (kill switch off: LAN on normal internet until the tunnel is back)"
    say "xray   : $("$XRAY" version 2>/dev/null | head -n 1 | awk '{print $2}')"
    say "routing: $([ "$ROUTE" = all ] && echo "whole LAN ($LAN_IF)" || echo "proxy only") | DNS tunnel=$DNS_TUNNEL QUIC block=$BLOCK_QUIC IPv6 block=$BLOCK_V6 kill switch=$KILLSWITCH failover=$FAILOVER"
    say "proxy  : socks5://$LAN_IP:$SOCKS_PORT  http://$LAN_IP:$HTTP_PORT"
    [ "$WEB" = 1 ] && say "web    : http://$LAN_IP:$WEB_PORT/"
    if is_running; then set -- $(cmd_stats); say "traffic: up $(human "$1")  down $(human "$2")"; fi
    say "profiles:"; cmd_list
}
cmd_menu() {
    while true; do
        say ""
        say "=========== XE3000 CLIENT $XEC_VERSION ==========="
        cmd_status
        say "---------------------------------------------"
        say " 1) add VLESS REALITY link      2) add SSH server"
        say " 3) choose active profile       4) test all profiles"
        say " 5) start / restart tunnel      6) stop tunnel"
        say " 7) test tunnel + exit IP       8) settings"
        say " 9) web panel password         10) update Xray"
        say "11) show logs                  12) SSH public key"
        say " 0) exit"
        ask "choice: " || return 0
        case $REPLY in
            1) ask "name (empty = auto): " || return 0; n=$REPLY; ask "link (vless://...): " || return 0
               if [ -n "$n" ]; then (cmd_add "$n" "$REPLY"); else (cmd_add "$REPLY"); fi ;;
            2) ask "name: " || return 0; n=$REPLY; ask "server host/IP: " || return 0; h=$REPLY
               ask "port [22, 443 for TLS]: " || return 0; p=${REPLY:-22}; ask "user: " || return 0; u=$REPLY
               ask "transport direct|tls|ws|wss [direct]: " || return 0; t=${REPLY:-direct}; s=''; wh=''
               case $t in tls | wss) ask "SNI (bug host) [$h]: " || return 0; s=$REPLY ;; esac
               case $t in ws | wss) ask "WebSocket Host header [$h]: " || return 0; wh=$REPLY ;; esac
               ask "password (empty = use SSH key): " || return 0
               set -- "$n" --host "$h" --port "$p" --user "$u" --transport "$t"
               [ -n "$s" ] && set -- "$@" --sni "$s"; [ -n "$wh" ] && set -- "$@" --ws-host "$wh"
               if [ -n "$REPLY" ]; then printf '%s\n' "$REPLY" | (cmd_add_ssh "$@" --pass-stdin); else (cmd_add_ssh "$@" --key) && ssh_key; fi ;;
            3) cmd_list; ask "profile name: " || return 0; (cmd_use "$REPLY") ;;
            4) cmd_ping ;;
            5) (cmd_start) ;;
            6) (cmd_stop) ;;
            7) (cmd_test) ;;
            8) cmd_set; ask "KEY VALUE (empty = back): " || return 0
               [ -n "$REPLY" ] && (cmd_set ${REPLY%% *} "${REPLY#* }") ;;
            9) ask "new password (empty = random): " || return 0; (web_setpass "$REPLY") ;;
            10) (cmd_update_xray) ;;
            11) tail -n 30 "$LOGF" 2>/dev/null; tail -n 15 "$LOGD/xray.log" 2>/dev/null ;;
            12) (ssh_key) ;;
            0 | q | x) return 0 ;;
            *) err "invalid option" ;;
        esac
    done
}

usage() {
    cat <<EOF
XE3000 CLIENT $XEC_VERSION - router -> your server (VLESS REALITY / SSH)

  sh xe3000-client.sh install [--link URL] [--no-web] [--no-ssh] [--web-password P]
                                [--xray-version vX.Y.Z | --xray-zip F --xray-dgst F]
  menu1  (or: xec menu)      interactive menu
  xec status | start | stop | restart | test [NAME] | ping
  xec add [NAME] 'vless://UUID@HOST:443?security=reality&sni=...&pbk=...&sid=...&flow=xtls-rprx-vision&fp=chrome[&pqv=...]'
  xec add [NAME] 'ssh://USER:PASS@HOST:443?transport=tls&sni=BUGHOST'
  xec add-ssh NAME --host H --user U [--port 22] [--pass P | --pass-stdin | --key]
              [--transport direct|tls|ws|wss] [--sni S] [--ws-host H] [--ws-path /] [--payload STR]
  xec import < links.txt     xec list | use NAME | del NAME | show NAME
  xec ssh-key                xec forget NAME (reset SSH host key)
  xec set [KEY VALUE]        ROUTE all|proxy, DNS_TUNNEL, BLOCK_QUIC, BLOCK_V6, KILLSWITCH, FAILOVER 0|1 ...
  xec route on|off           xec bypass add|del LAN_IP
  xec web on|off|url|password [NEW]
  xec stats | logs | update-xray | export > file | restore FILE | uninstall [--purge]
EOF
}

# ------------------------------------------------------------------- main
cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
    install) cmd_install "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    add) cmd_add "$@" ;;
    add-ssh) cmd_add_ssh "$@" ;;
    import) cmd_import ;;
    list | ls) cmd_list ;;
    use) cmd_use "$@" ;;
    del | rm) cmd_del "$@" ;;
    show) cmd_show "$@" ;;
    start | restart) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    test) cmd_test "$@" ;;
    ping) cmd_ping ;;
    set) cmd_set "$@" ;;
    route) cmd_route "$@" ;;
    bypass) cmd_bypass "$@" ;;
    web) cmd_web "$@" ;;
    stats) set -- $(cmd_stats); say "up $(human "$1")  down $(human "$2")" ;;
    logs) tail -n "${1:-50}" "$LOGF" 2>/dev/null; tail -n 20 "$LOGD/xray.log" 2>/dev/null ;;
    update-xray) FORCE=${FORCE:-} cmd_update_xray "$@" ;;
    ssh-key) ssh_key ;;
    forget) cmd_forget "$@" ;;
    export) cmd_export ;;
    restore) cmd_restore "$@" ;;
    watchdog) cmd_watchdog ;;
    version) say "$XEC_VERSION" ;;
    menu) cmd_menu ;;
    help | -h | --help) usage ;;
    '') if [ -t 0 ]; then cmd_menu; else usage; fi ;;
    # internal
    _prepare) cmd_prepare ;;
    _ssh) load_conf; ssh_exec "$ACTIVE" "$SSH_SOCKS" ;;
    _ssh_probe) ssh_exec "$1" "$2" ;;
    _pc) proxy_cmd "$1" ;;
    _fw) case ${1:-} in on) fw_on ;; off) load_conf; lan_detect; fw_off ;; *) fw_auto ;; esac ;;
    _cgi) cmd_cgi ;;
    _webenv) load_conf; lan_detect
        l="127.0.0.1:$WEB_PORT"; [ "$LAN_IP" != 127.0.0.1 ] && l="$LAN_IP:$WEB_PORT $l"
        printf 'WEB_ON=%s\nWEB_LISTEN=%s\n' "$WEB" "$(shq "$l")" ;;
    _gen) gen_xray "$1" "${2:-/dev/stdout}" ;;
    *) usage; exit 1 ;;
esac
