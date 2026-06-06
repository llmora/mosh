from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/robots.txt":
            self._send(
                "text/plain",
                f"User-agent: *\nDisallow: /admin\nSitemap: http://{self.headers['Host']}/sitemap.xml\n",
            )
        elif self.path == "/":
            self._send(
                "text/html; charset=utf-8",
                """
                <html>
                  <head>
                    <title>Fixture Home</title>
                    <script src="/static/jquery-3.7.1.min.js"></script>
                    <link rel="stylesheet" href="https://cdn.example.net/site.css">
                  </head>
                  <body>
                    <a href="/about">About</a>
                    <a href="https://outside.example.org/path">Outside</a>
                    <form action="/search"></form>
                  </body>
                </html>
                """,
            )
        elif self.path == "/about":
            self._send("text/html", "<html><head><title>About</title></head><body>About</body></html>")
        elif self.path == "/search":
            self._send("text/html", "<html><head><title>Search</title></head><body>Search</body></html>")
        elif self.path == "/static/jquery-3.7.1.min.js":
            self._send("application/javascript", "window.jQuery = {};")
        elif self.path == "/redirect-app":
            self.send_response(308)
            self.send_header("Location", "/redirect-app/")
            self.end_headers()
        elif self.path == "/redirect-app/":
            self._send(
                "text/html; charset=utf-8",
                """
                <html>
                  <head>
                    <title>Redirect App</title>
                    <script>
                      window.BACKOFFICE_API_BASE = 'https://api.example.test/api/private';
                    </script>
                    <script type="module" src="./shell.js"></script>
                  </head>
                  <body>Redirect app</body>
                </html>
                """,
            )
        elif self.path == "/redirect-app/shell.js":
            self._send(
                "application/javascript",
                "const API_BASE = (window.BACKOFFICE_API_BASE || '/api/private').replace(/\\/$/, '');",
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, content_type: str, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Powered-By", "FixtureFramework")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@contextmanager
def fixture_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
