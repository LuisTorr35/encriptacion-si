#!/usr/bin/env python3
"""Proxy TLS transparente: termina HTTPS en 0.0.0.0:8443 y reenvia el trafico
en texto plano a la app Laravel (php artisan serve) en 127.0.0.1:8001.

Asi `crypto.subtle` (Web Crypto API) queda disponible en los dispositivos de la
red, porque acceden por https:// (contexto seguro). El backend sigue siendo el
servidor HTTP normal de Laravel; este proxy solo anade/quita la capa TLS.

Uso:  python3 storage/tls/proxy.py
"""

import os
import socket
import ssl
import threading

HERE = os.path.dirname(os.path.abspath(__file__))

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8001
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")


def pipe(src, dst):
    """Reenvia bytes de un socket a otro hasta que se cierre la conexion."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client):
    """Abre una conexion al backend y conecta ambos extremos (cliente <-> Laravel)."""
    try:
        backend = socket.create_connection((BACKEND_HOST, BACKEND_PORT))
    except OSError as e:
        client.close()
        print(f"[proxy] no se pudo conectar al backend {BACKEND_HOST}:{BACKEND_PORT}: {e}")
        return
    threading.Thread(target=pipe, args=(client, backend), daemon=True).start()
    threading.Thread(target=pipe, args=(backend, client), daemon=True).start()


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    # Forzamos HTTP/1.1 (el servidor embebido de PHP no habla HTTP/2).
    ctx.set_alpn_protocols(["http/1.1"])

    bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind.bind((LISTEN_HOST, LISTEN_PORT))
    bind.listen(128)
    print(f"[proxy] HTTPS en https://{LISTEN_HOST}:{LISTEN_PORT}  ->  http://{BACKEND_HOST}:{BACKEND_PORT}")

    while True:
        raw, addr = bind.accept()
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            continue
        threading.Thread(target=handle, args=(tls,), daemon=True).start()


if __name__ == "__main__":
    main()
