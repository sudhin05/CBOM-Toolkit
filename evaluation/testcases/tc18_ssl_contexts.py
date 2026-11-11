"""TLS client contexts."""
import socket
import ssl

legacy = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # expect: TLS 1.0
modern = ssl.create_default_context()  # expect: TLS

with socket.create_connection(("example.com", 443)) as sock:
    with modern.wrap_socket(sock, server_hostname="example.com") as tls:
        print(tls.version())
