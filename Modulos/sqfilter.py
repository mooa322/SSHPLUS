#!/usr/bin/env python3
# encoding: utf-8
#
# Filter in front of the SSHPLUS Squid Proxy.
#
# Apps like HTTP Injector, NPV Tunnel, etc send payloads with a "noise"
# line that isn't a valid HTTP header (no ':', like separators
# "===FORCE===") before the real request (usually a CONNECT), to
# confuse the carrier's DPI. Modern Squid (6.x, the only one available
# on Ubuntu 24.04) rejects any such line with "400 Bad Request" and
# CLOSES the connection -- breaking the whole payload before the real
# request (the CONNECT) is even read, even though it is itself valid.
#
# This filter listens on the public ports the user configured (the
# same ones they type into the app), and the real Squid now listens
# only on 127.0.0.1:SQUID_PORT (not exposed). The filter reads the
# payload line by line; any line that doesn't look like a valid header
# (neither a request-line nor blank) is rewritten as a harmless header
# before being forwarded to Squid -- without requiring any edit to the
# user's app payload. Once the CONNECT request (and the end of its
# headers) is seen, it stops parsing line by line and becomes a raw
# two-way relay (from that point on it's tunnel traffic).
import socket
import threading
import select
import sys
import re

LISTEN_PORTS = [int(p) for p in sys.argv[1].split()] if len(sys.argv) > 1 else [8080]
SQUID_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31280
BUFLEN = 8192
IDLE_TIMEOUT = 8

HEADER_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+:")
REQLINE_RE = re.compile(rb'^[A-Za-z]+ \S+ HTTP/\d\.\d$')


def sanitize_line(line):
    if line == b'' or HEADER_RE.match(line) or REQLINE_RE.match(line):
        return line
    # Doesn't look like an HTTP header or a request line: turn it into a
    # harmless header (Squid ignores headers it doesn't know) instead of
    # breaking its parser.
    return b'X-Ignore: ' + line.replace(b'\r', b'').replace(b'\n', b' ')


def relay(a, b):
    socs = [a, b]
    try:
        while True:
            r, _, x = select.select(socs, [], socs, 60)
            if x or not r:
                break
            closed = False
            for s in r:
                try:
                    data = s.recv(BUFLEN)
                except Exception:
                    closed = True
                    break
                if not data:
                    closed = True
                    break
                (b if s is a else a).sendall(data)
            if closed:
                break
    except Exception:
        pass
    for s in (a, b):
        try:
            s.close()
        except Exception:
            pass


def handle(client, squid_port):
    try:
        target = socket.create_connection(('127.0.0.1', squid_port), timeout=8)
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return

    client.settimeout(IDLE_TIMEOUT)
    pending = b''
    in_connect_headers = False
    done = False
    try:
        while not done:
            try:
                chunk = client.recv(BUFLEN)
            except socket.timeout:
                break
            if not chunk:
                break
            pending += chunk
            while True:
                idx = pending.find(b'\r\n')
                if idx == -1:
                    break
                line = pending[:idx]
                pending = pending[idx + 2:]
                out = sanitize_line(line)
                target.sendall(out + b'\r\n')
                if REQLINE_RE.match(line) and line.startswith(b'CONNECT '):
                    in_connect_headers = True
                elif in_connect_headers and line == b'':
                    done = True
                    break
        if pending:
            target.sendall(pending)
        client.settimeout(None)
    except Exception:
        try:
            target.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass
        return

    relay(client, target)


def serve(port, squid_port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(100)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, squid_port), daemon=True).start()


if __name__ == '__main__':
    threads = []
    for p in LISTEN_PORTS:
        t = threading.Thread(target=serve, args=(p, SQUID_PORT), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
