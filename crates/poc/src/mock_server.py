#!/usr/bin/env python3
"""Mock HTTPS server for the integration PoC.

Simulates an LLM API (api.openai.com) so the integration test is fully
self-contained — no real API keys needed.

The server:
  - Listens on HTTPS with a self-signed cert (CN=api.openai.com)
  - /v1/models — returns a JSON list if the Authorization header is present
    and NOT "PLACEHOLDER"
  - /v1/chat/completions — streams SSE chunks if auth is correct
  - Logs the received Authorization header so we can verify the proxy
    injected the real key (sk-INJECTED-BY-PROXY)
"""
import http.server
import ssl
import subprocess
import sys
import time
import os
import tempfile
import socket


def generate_self_signed_cert():
    """Generate a self-signed cert for the mock server."""
    tmpdir = tempfile.mkdtemp()
    cert_path = os.path.join(tmpdir, "server.pem")
    key_path = os.path.join(tmpdir, "server.key")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "1", "-nodes", "-subj",
        "/CN=api.openai.com",
        "-addext", "subjectAltName=DNS:api.openai.com",
    ], check=True, capture_output=True)
    return cert_path, key_path


class APIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            auth = self.headers.get("Authorization", "")
            if "PLACEHOLDER" in auth or not auth:
                sys.stderr.write(f"ERROR: Bad auth header: {auth}\n")
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"invalid auth"}')
                return

            sys.stderr.write(f"OK: GET /v1/models — auth: {auth}\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":[{"id":"gpt-4o"}]}')
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return

        auth = self.headers.get("Authorization", "")
        if "PLACEHOLDER" in auth or not auth:
            sys.stderr.write(f"ERROR: Bad auth header: {auth}\n")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid auth"}')
            return

        sys.stderr.write(f"OK: POST /v1/chat/completions — auth: {auth}\n")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        for i in range(5):
            chunk = f'data: {{"id":"chatcmpl-test","choices":[{{"delta":{{"content":"chunk-{i}"}}}}]}}\n\n'
            self.wfile.write(chunk.encode())
            self.wfile.flush()
            sys.stderr.write(f"SENT chunk {i}\n")
            sys.stderr.flush()
            time.sleep(0.5)

        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        sys.stderr.write("SENT [DONE]\n")

    def log_message(self, format, *args):
        sys.stderr.write(f"[mock-api] {format % args}\n")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9443
    cert_path, key_path = generate_self_signed_cert()

    server = http.server.HTTPServer(("127.0.0.1", port), APIHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    sys.stderr.write(f"[mock-api] listening on https://127.0.0.1:{port}\n")
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()