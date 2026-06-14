from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
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


@contextmanager
def fixture_source_tree() -> Iterator[Path]:
    with TemporaryDirectory() as directory:
        root = Path(directory) / "fixture-app"
        root.mkdir()
        (root / "app.py").write_text(
            "\n".join(
                [
                    "from flask import Flask, request",
                    "",
                    "app = Flask(__name__)",
                    "",
                    "@app.route('/api/users/<user_id>', methods=['GET'])",
                    "def get_user(user_id):",
                    "    return {'id': user_id}",
                    "",
                    "@app.post('/api/users')",
                    "def create_user():",
                    "    return request.json",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "package.json").write_text(
            '{"dependencies":{"express":"^4.18.0"},"devDependencies":{"eslint":"^9.0.0"}}',
            encoding="utf-8",
        )
        (root / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
        (root / "pyproject.toml").write_text(
            "\n".join(
                [
                    "[project]",
                    'dependencies = ["flask>=3.0.0", "sqlalchemy==2.0.0"]',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
        (root / ".env.example").write_text("DATABASE_URL=postgres://example\n", encoding="utf-8")
        api_root = root / "apps" / "api"
        api_src = api_root / "src"
        api_src.mkdir(parents=True)
        (api_root / "package.json").write_text(
            '{"scripts":{"start":"node src/server.ts"},"dependencies":{"express":"^4.18.0"}}',
            encoding="utf-8",
        )
        (api_src / "server.ts").write_text(
            "\n".join(
                [
                    "import express from 'express'",
                    "const app = express()",
                    "const API_VERSION_PREFIXES = ['', '/v1', '/api/v1']",
                    "function registerVersionedRoute(method, path, middleware, handler) {",
                    "  API_VERSION_PREFIXES.forEach(prefix => app[method](prefix + path, middleware, handler))",
                    "}",
                    "const requireAuth = (_req, _res, next) => next()",
                    "const usersRouter = express.Router()",
                    "usersRouter.get('/users', (_req, res) => res.json([]))",
                    "app.use('/api/v1', usersRouter)",
                    "app.post('/admin', requireAuth, (_req, res) => res.json({ ok: true }))",
                    "registerVersionedRoute('POST', '/check-sms', requireAuth, (_req, res) => res.json({ ok: true }))",
                    "const secret = process.env.JWT_SECRET",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (api_src / "server.test.ts").write_text("app.get('/test-only', (_req, res) => res.json({}))\n", encoding="utf-8")
        classifier_root = root / "services" / "classifier"
        classifier_root.mkdir(parents=True)
        (classifier_root / "requirements.txt").write_text("fastapi==0.115.0\nuvicorn>=0.30\n", encoding="utf-8")
        (classifier_root / "main.py").write_text(
            "\n".join(
                [
                    "import os",
                    "from fastapi import FastAPI",
                    "app = FastAPI()",
                    "MODEL_PATH = os.getenv('MODEL_PATH')",
                    "@app.post('/classify')",
                    "def classify():",
                    "    return {'ok': True}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        docker_root = root / "docker"
        docker_root.mkdir()
        (docker_root / "docker-compose.yml").write_text(
            "\n".join(
                [
                    "services:",
                    "  api:",
                    "    build: ../apps/api",
                    "    ports:",
                    "      - '4000:4000'",
                    "    environment:",
                    "      - JWT_SECRET=test",
                    "    depends_on:",
                    "      - classifier",
                    "  classifier:",
                    "    build: ../services/classifier",
                    "    environment:",
                    "      - MODEL_PATH=/models/current",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        android_root = root / "apps" / "android"
        android_src = android_root / "src" / "main"
        (android_src / "java" / "com" / "example").mkdir(parents=True)
        (android_root / "build.gradle.kts").write_text(
            "\n".join(
                [
                    "plugins { id(\"com.android.application\") }",
                    "dependencies {",
                    '  implementation("androidx.core:core-ktx:1.13.1")',
                    "}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (android_src / "AndroidManifest.xml").write_text(
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <application>
                <activity android:name=".MainActivity">
                  <intent-filter>
                    <action android:name="android.intent.action.MAIN" />
                    <category android:name="android.intent.category.LAUNCHER" />
                  </intent-filter>
                </activity>
              </application>
            </manifest>
            """,
            encoding="utf-8",
        )
        (android_src / "java" / "com" / "example" / "MainActivity.kt").write_text(
            "class MainActivity\n",
            encoding="utf-8",
        )
        ios_root = root / "apps" / "ios"
        ios_root.mkdir(parents=True)
        (ios_root / "Podfile").write_text("pod 'Alamofire', '~> 5.9'\n", encoding="utf-8")
        (ios_root / "Info.plist").write_text("<plist><dict></dict></plist>\n", encoding="utf-8")
        (ios_root / "AppDelegate.swift").write_text("import UIKit\nclass AppDelegate {}\n", encoding="utf-8")
        extension_root = root / "apps" / "ios-share"
        extension_root.mkdir(parents=True)
        (extension_root / "Info.plist").write_text("<plist><dict><key>NSExtension</key><dict></dict></dict></plist>\n", encoding="utf-8")
        (extension_root / "ShareViewController.swift").write_text("import UIKit\nclass ShareViewController {}\n", encoding="utf-8")
        github = root / ".github"
        github.mkdir()
        (github / ".DS_Store").write_bytes(b"ignored metadata")
        node_modules = root / "node_modules" / "ignored"
        node_modules.mkdir(parents=True)
        (node_modules / "index.js").write_text("app.get('/ignored')\n", encoding="utf-8")
        gradle_cache = root / ".gradle" / "caches"
        gradle_cache.mkdir(parents=True)
        (gradle_cache / "generated.py").write_text("@app.get('/gradle-cache')\n", encoding="utf-8")
        derived_data = root / ".derivedData" / "Build"
        derived_data.mkdir(parents=True)
        (derived_data / "generated.py").write_text("@app.get('/derived-data')\n", encoding="utf-8")
        build_maestro = root / "build-maestro" / "generated"
        build_maestro.mkdir(parents=True)
        (build_maestro / "generated.py").write_text("@app.get('/build-maestro')\n", encoding="utf-8")
        build_share_flow = root / "build-share-flow" / "generated"
        build_share_flow.mkdir(parents=True)
        (build_share_flow / "generated.py").write_text("@app.get('/build-share-flow')\n", encoding="utf-8")
        yield root
