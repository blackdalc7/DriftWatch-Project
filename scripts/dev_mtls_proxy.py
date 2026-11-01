"""A small mTLS reverse proxy that behaves like deploy/nginx for local development and the end-to-end test.

It terminates TLS with the server certificate, asks for (but does not require) a client certificate
signed by the Driftwatch CA, and forwards to the FastAPI server with the same headers nginx sets:
X-Driftwatch-Proxy, X-Client-Verify and X-Client-Cert (URL-escaped PEM). Only agent routes are proxied.

    python scripts/dev_mtls_proxy.py --pki deploy/pki --upstream http://127.0.0.1:8000 --port 8443

Use nginx (docker compose) for anything beyond a laptop.
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

import httpx

AGENT_PREFIX = "/api/v1/agent/"
ENROLL = "/api/v1/enroll"


def make_handler(upstream: str, secret: str) -> type[BaseHTTPRequestHandler]:
    client = httpx.Client(base_url=upstream, timeout=60)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _forward(self) -> None:
            path = self.path.split("?", 1)[0]
            if path != ENROLL and not path.startswith(AGENT_PREFIX):
                self._reply(404, b'{"detail":"not found"}')
                return
            der = self.connection.getpeercert(binary_form=True)  # type: ignore[attr-defined]
            if path.startswith(AGENT_PREFIX) and not der:
                self._reply(403, b'{"detail":"client certificate required"}')
                return
            headers = {"X-Driftwatch-Proxy": secret, "Content-Type": self.headers.get("Content-Type", "")}
            if der and path != ENROLL:
                pem = ssl.DER_cert_to_PEM_cert(der)
                headers.update({"X-Client-Verify": "SUCCESS", "X-Client-Cert": quote(pem, safe="")})
            else:
                headers["X-Client-Verify"] = "NONE"
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            resp = client.request(self.command, self.path, content=body, headers=headers)
            self._reply(resp.status_code, resp.content, resp.headers.get("content-type", "application/json"))

        def _reply(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _forward
        do_POST = _forward

        def log_message(self, fmt: str, *args: object) -> None:
            sys.stderr.write("proxy: " + fmt % args + "\n")

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pki", default="deploy/pki")
    ap.add_argument("--upstream", default="http://127.0.0.1:8000")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()
    secret = os.environ.get("DRIFTWATCH_PROXY_SECRET", "")
    if len(secret) < 24:
        print("set DRIFTWATCH_PROXY_SECRET (same value as the server)", file=sys.stderr)
        return 2
    pki = Path(args.pki)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pki / "server.crt", pki / "server.key")
    ctx.load_verify_locations(pki / "ca.crt")
    ctx.verify_mode = ssl.CERT_OPTIONAL
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(args.upstream, secret))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"mTLS proxy on https://{args.host}:{args.port} -> {args.upstream}", file=sys.stderr)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
