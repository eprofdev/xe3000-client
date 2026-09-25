#!/usr/bin/env python3
"""Tiny HTTP proxy for the OpenWrt test container.

Runs in the HOST network namespace and listens on a UNIX socket. Inside the
container's private network namespace a `socat TCP-LISTEN:3128 UNIX-CONNECT:`
bridge exposes it as http://127.0.0.1:3128, so opkg / curl in the chroot get
Internet access without any veth/NAT change on the host:

  * CONNECT host:port  -> forwarded to the host's upstream HTTPS proxy
                          ($HTTPS_PROXY, TLS is re-terminated there; the test
                          copies its CA bundle into the chroot)
  * GET http://...     -> fetched directly (plain HTTP works from the host)

usage: netproxy.py /path/to/socket
"""
import os
import socket
import sys
import threading
from urllib.parse import urlsplit


def upstream():
    p = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    if not p:
        return None
    u = urlsplit(p if "://" in p else "http://" + p)
    return (u.hostname or "127.0.0.1", u.port or 3128)


UP = upstream()


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass


def relay(c, u):
    t = threading.Thread(target=pipe, args=(u, c), daemon=True)
    t.start()
    pipe(c, u)
    t.join(600)
    c.close()
    u.close()


def handle(c):
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d:
                c.close()
                return
            buf += d
            if len(buf) > 65536:
                c.close()
                return
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        method, target, ver = lines[0].split(b" ", 2)
        if method == b"CONNECT":
            if UP:
                u = socket.create_connection(UP, timeout=30)
                u.settimeout(None)
                u.sendall(buf)
            else:
                host, _, port = target.decode().rpartition(":")
                u = socket.create_connection((host, int(port)), timeout=30)
                u.settimeout(None)
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if rest:
                    u.sendall(rest)
            relay(c, u)
            return
        url = urlsplit(target.decode())
        if url.scheme != "http":
            c.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            c.close()
            return
        u = socket.create_connection((url.hostname, url.port or 80), timeout=30)
        u.settimeout(None)
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        out = [method + b" " + path.encode() + b" " + ver]
        for line in lines[1:]:
            k = line.split(b":", 1)[0].strip().lower()
            if k in (b"proxy-connection", b"connection", b"keep-alive", b"proxy-authorization"):
                continue
            out.append(line)
        out.append(b"Connection: close")
        u.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)
        relay(c, u)
    except Exception as e:  # noqa: BLE001 - test helper, never crash the server
        try:
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n" + str(e).encode())
        except OSError:
            pass
        c.close()


def main():
    path = sys.argv[1]
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
