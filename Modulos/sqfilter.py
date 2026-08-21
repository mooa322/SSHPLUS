#!/usr/bin/env python3
# encoding: utf-8
#
# Filtro na frente do Squid Proxy do SSHPLUS.
#
# Apps como HTTP Injector, NPV Tunnel, etc mandam payloads com uma linha
# de "ruido" que nao e um header HTTP valido (sem ':', tipo separadores
# "===FORCE===") antes do pedido real (normalmente um CONNECT), pra
# confundir o DPI da operadora. O Squid moderno (6.x, o unico disponivel
# no Ubuntu 24.04) rejeita qualquer linha assim com "400 Bad Request" e
# FECHA a conexao -- quebrando o payload inteiro antes do pedido real
# (o CONNECT) ser lido, mesmo que ele mesmo seja valido.
#
# Este filtro escuta nas portas publicas que o usuario configurou (as
# mesmas que ele digita no app) e o Squid de verdade passa a escutar so
# em 127.0.0.1:SQUID_PORT (nao exposto). O filtro le o payload linha a
# linha; qualquer linha que nao pareca um header valido (nem uma
# request-line, nem em branco) e reescrita como um header inofensivo
# antes de ser repassada pro Squid -- sem exigir nenhuma edicao no
# payload do app do usuario. Depois que o pedido CONNECT (e o fim dos
# headers dele) e visto, para de analisar linha a linha e vira um
# repasse bruto nos dois sentidos (a partir dai e trafego do tunel).
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
    # Nao parece um header HTTP nem uma linha de pedido: vira um header
    # inofensivo (o Squid ignora headers que nao conhece) em vez de
    # quebrar o parser dele.
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
