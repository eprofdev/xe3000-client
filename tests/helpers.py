#!/usr/bin/env python3
"""Fake "internet" + server-side helpers for the XE3000 client system test.

  helpers.py http   IP PORT LOG         web target: /hello, /generate_204, /cdn-cgi/trace
                                        (logs the peer address of every request)
  helpers.py dns    IP LOG              DNS on UDP+TCP 53: every A query -> 203.0.113.99
  helpers.py tls    LISTEN TARGET CERT KEY LOG
                                        TLS front (SSH-SSL / stunnel style): logs SNI,
                                        relays the decrypted stream to TARGET
  helpers.py ws     LISTEN TARGET LOG   WebSocket upgrade relay (ws-epro style): answers
                                        101, logs the Host header, relays raw bytes
"""
import socket
import ssl
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def log(path, line):
    with open(path, "a") as f:
        f.write(line + "\n")


def hp(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def relay(a, b):
    def pump(x, y):
        try:
            while True:
                d = x.recv(65536)
                if not d:
                    break
                y.sendall(d)
        except OSError:
            pass
        for s in (x, y):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join()
    a.close()
    b.close()


def serve(listen, handler):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(hp(listen))
    s.listen(64)
    while True:
        c, addr = s.accept()
        threading.Thread(target=handler, args=(c, addr), daemon=True).start()


def http_main(ip, port, logf):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            log(logf, "%s %s" % (self.client_address[0], self.path))
            if self.path.startswith("/generate_204"):
                self.send_response(204)
                self.end_headers()
                return
            if self.path.startswith("/cdn-cgi/trace"):
                body = ("ip=%s\nloc=SA\ncolo=JED\n" % self.client_address[0]).encode()
            else:
                body = b"HELLO-XE3000\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    ThreadingHTTPServer((ip, int(port)), H).serve_forever()


def dns_answer(q):
    tid = q[:2]
    i = 12
    while q[i]:
        i += 1 + q[i]
    question = q[12:i + 5]
    name = []
    j = 12
    while q[j]:
        name.append(q[j + 1:j + 1 + q[j]].decode())
        j += 1 + q[j]
    qtype = struct.unpack(">H", q[i + 1:i + 3])[0]
    if qtype == 1:
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.99")
        return tid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0) + question + ans, ".".join(name)
    return tid + b"\x81\x80" + struct.pack(">HHHH", 1, 0, 0, 0) + question, ".".join(name)


def dns_main(ip, logf):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind((ip, 53))

    def udp():
        while True:
            q, addr = u.recvfrom(4096)
            r, n = dns_answer(q)
            log(logf, "udp %s %s" % (addr[0], n))
            u.sendto(r, addr)
    threading.Thread(target=udp, daemon=True).start()

    def tcp(c, addr):
        try:
            while True:
                h = c.recv(2)
                if len(h) < 2:
                    break
                q = b""
                ln = struct.unpack(">H", h)[0]
                while len(q) < ln:
                    q += c.recv(ln - len(q))
                r, n = dns_answer(q)
                log(logf, "tcp %s %s" % (addr[0], n))
                c.sendall(struct.pack(">H", len(r)) + r)
        finally:
            c.close()
    serve("%s:53" % ip, tcp)


def tls_main(listen, target, cert, key, logf):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sni = {}

    def cb(sock, name, _ctx):
        sni[id(sock)] = name
    ctx.sni_callback = cb

    def h(c, addr):
        try:
            t = ctx.wrap_socket(c, server_side=True)
        except (ssl.SSLError, OSError) as e:
            log(logf, "handshake-failed %s %s" % (addr[0], e))
            return
        log(logf, "sni=%s from %s" % (sni.get(id(t)), addr[0]))
        u = socket.create_connection(hp(target))
        relay(t, u)
    serve(listen, h)


def ws_main(listen, target, logf):
    def h(c, addr):
        data = b""
        while b"\r\n\r\n" not in data:
            d = c.recv(4096)
            if not d:
                c.close()
                return
            data += d
        head, rest = data.split(b"\r\n\r\n", 1)
        host = ""
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip().decode()
        log(logf, "ws host=%s first=%s" % (host, head.split(b"\r\n")[0].decode()))
        c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        u = socket.create_connection(hp(target))
        if rest:
            u.sendall(rest)
        relay(c, u)
    serve(listen, h)


if __name__ == "__main__":
    m, a = sys.argv[1], sys.argv[2:]
    {"http": http_main, "dns": dns_main, "tls": tls_main, "ws": ws_main}[m](*a)
