"""A tiny TLS server for testing without Docker: same settings as nginx.conf
(TLS 1.2 only, RSA-2048 certificate, ECDHE-RSA-AES128-GCM-SHA256).

    python evaluation/tls-testserver/python_server.py      # listens on localhost:8444
"""
import os
import socket
import ssl
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))


def make_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    ctx.load_cert_chain(os.path.join(HERE, "certs", "server.crt"),
                        os.path.join(HERE, "certs", "server.key"))
    return ctx


def serve(port=8444, ready=None):
    ctx = make_context()
    with socket.create_server(("127.0.0.1", port)) as sock:
        if ready:
            ready.set()
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handle, args=(ctx, conn), daemon=True).start()


def handle(ctx, conn):
    try:
        with ctx.wrap_socket(conn, server_side=True) as tls:
            tls.recv(1024)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
    except (ssl.SSLError, OSError):
        pass


def start_in_background(port=8444):
    ready = threading.Event()
    threading.Thread(target=serve, args=(port, ready), daemon=True).start()
    ready.wait(5)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8444
    print(f"TLS 1.2 test server on localhost:{port}  (Ctrl+C to stop)")
    serve(port)
