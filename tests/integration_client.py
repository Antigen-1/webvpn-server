#!/usr/bin/env python3
"""End-to-end test over TLS.

Starts a mock upstream HTTP site, runs `main.py init` to create a real
self-signed certificate and configuration, starts the generated server, and
walks through login, CSRF, session fixation, the portal, rewriting, cookie
namespacing, HEAD, logout and rate limiting.

Run by tests/integration.rkt with the rendered application as argv[1] and the
project root as argv[2].
"""

import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

warnings.filterwarnings("ignore", category=DeprecationWarning)

APP = os.path.abspath(sys.argv[1])
ROOT = os.path.abspath(sys.argv[2])
MAIN = os.path.join(APP, "main.py")
PYTHON = sys.executable


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"


    def log_message(self, *args):
        pass

    def _send(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/":
            html = (
                "<html><head><title>Up</title></head><body>"
                '<a href="/root">root</a>'
                f'<a href="http://127.0.0.1:{port}/root">absolute</a>'
                '<a href="https://example.com/x">external</a>'
                '<img src="/img.png">'
                '<form action="/submit" method="post"></form>'
                '<div style="background:url(/background.png)"></div>'
                '<img srcset="/small.png 1x, http://127.0.0.1:%d/large.png 2x">'
                "</body></html>"
            ) % port
            self._send(200, html, headers=[
                ("Set-Cookie", "sid=upstream; Path=/; HttpOnly; SameSite=Lax"),
            ])
        elif self.path == "/redir":
            self._send(302, b"", headers=[("Location", "/root")])
        elif self.path == "/redirabs":
            self._send(302, b"", headers=[
                ("Location", f"http://127.0.0.1:{port}/root"),
            ])
        elif self.path == "/json":
            self._send(200, b'{"ok":true}', "application/json", headers=[
                ("Access-Control-Allow-Origin", "*"),
            ])
        elif self.path == "/headers":
            data = json.dumps(dict(self.headers.items())).encode("utf-8")
            self._send(200, data, "application/json", headers=[("X-Private", "yes")])
        elif self.path == "/big":
            self._send(200, b"x" * 100000, "text/plain")
        else:
            self._send(200, "cookie=" + (self.headers.get("Cookie") or ""),
                       "text/plain; charset=utf-8")

    def do_HEAD(self):
        port = self.server.server_address[1]
        body = "cookie=" + (self.headers.get("Cookie") or "")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        self._send(200, self.path + "|" + body + "|" + (self.headers.get("Cookie") or ""),
                   "text/plain; charset=utf-8")


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Client:
    def __init__(self, port):
        self.port = port
        self.context = ssl._create_unverified_context()
        self.cookies = {}

    def cookie_header(self):
        return "; ".join(f"{name}={value}" for name, value in self.cookies.items())

    def remember(self, response):
        for name, value in response.getheaders():
            if name.lower() != "set-cookie":
                continue
            pair = value.split(";", 1)[0]
            cookie_name, _, cookie_value = pair.partition("=")
            lower = value.lower()
            if "max-age=0" in lower:
                self.cookies.pop(cookie_name, None)
            else:
                self.cookies[cookie_name] = cookie_value

    def request(self, method, path, body=None, headers=None):
        header_map = dict(headers or {})
        if self.cookies:
            header_map["Cookie"] = self.cookie_header()
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self.context, timeout=10
        )
        connection.request(method, path, body=body, headers=header_map)
        response = connection.getresponse()
        data = response.read()
        version = connection.sock.version() if connection.sock else None
        self.remember(response)
        connection.close()
        return response, data, version


def csrf_of(html):
    match = re.search(rb'name="csrf" value="([0-9a-f]+)"', html)
    if not match:
        raise AssertionError("login/portal page has no CSRF token")
    return match.group(1).decode()


def login(client, password, csrf, next_path="/"):
    body = urllib.parse.urlencode(
        {"csrf": csrf, "username": "admin", "password": password, "next": next_path}
    )
    return client.request(
        "POST", "/login", body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def main():
    upstream = QuietServer(("127.0.0.1", 0), Upstream)
    upstream_port = upstream.server_address[1]
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    work = tempfile.mkdtemp(prefix="webvpn-integration-")
    process = None
    try:
        port = free_port()
        init = subprocess.run(
            [PYTHON, MAIN, "init", work, "--host", "127.0.0.1", "--port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60,
        )
        if init.returncode != 0:
            raise AssertionError("init failed:\n" + init.stdout)
        password = re.search(r"^password:\s+(\S+)\s*$", init.stdout, re.M).group(1)
        config_path = os.path.join(work, "webvpn.json")

        raw = json.load(open(config_path, encoding="utf-8"))
        raw["login_max_attempts"] = 3
        raw["max_body"] = 65536
        raw["max_response"] = 10000
        raw["blocked_request_headers"] = ["x-secret-.*"]
        raw["blocked_response_headers"] = ["x-private"]
        raw["cors_origins"] = ["https://frontend.example"]
        raw["targets"] = [
            {"name": "up", "label": "内部测试站", "url": f"http://127.0.0.1:{upstream_port}"}
        ]
        with open(config_path, "w", encoding="utf-8") as stream:
            json.dump(raw, stream, ensure_ascii=False, indent=2)

        checked = subprocess.run(
            [PYTHON, MAIN, "check", "--config", config_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
        )
        assert checked.returncode == 0, checked.stdout
        assert "ok:" in checked.stdout

        process = subprocess.Popen(
            [PYTHON, MAIN, "serve", "--config", config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        client = Client(port)
        started = False
        for _ in range(80):
            time.sleep(0.1)
            if process.poll() is not None:
                raise AssertionError("server exited:\n" + process.stderr.read())
            try:
                response, data, version = client.request("GET", "/healthz")
                if response.status == 200 and data == b"ok":
                    started = True
                    break
            except Exception:
                continue
        if not started:
            raise AssertionError("server did not answer")

        assert version in ("TLSv1.2", "TLSv1.3"), version
        response, _, _ = client.request("GET", "/healthz")
        assert response.status == 200
        assert response.getheader("server") is None
        assert response.getheader("date") is None

        response, _, _ = client.request(
            "OPTIONS", "/proxy/up/api",
            headers={
                "Origin": "https://frontend.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, x-test",
            },
        )
        assert response.status == 204
        assert response.getheader("access-control-allow-origin") == "https://frontend.example"
        assert response.getheader("access-control-allow-credentials") == "true"
        assert "POST" in response.getheader("access-control-allow-methods")
        allowed = response.getheader("access-control-allow-headers").lower()
        assert "content-type" in allowed and "x-test" in allowed
        assert "origin" in response.getheader("vary").lower()

        response, _, _ = client.request(
            "OPTIONS", "/proxy/up/api",
            headers={"Origin": "https://evil.example",
                     "Access-Control-Request-Method": "POST"},
        )
        assert response.status == 401
        assert response.getheader("access-control-allow-origin") is None

        response, _, _ = client.request(
            "POST", "/proxy/up/api", body=b"x",
            headers={"Origin": "https://frontend.example"},
        )
        assert response.status == 401
        assert response.getheader("access-control-allow-origin") == "https://frontend.example"
        assert response.getheader("access-control-allow-credentials") == "true"

        response, data, _ = client.request("GET", "/")
        assert response.status == 303
        assert response.getheader("location") == "/login?next=/"

        response, data, _ = client.request("GET", "/login")
        assert response.status == 200
        headers = "\n".join(f"{k}: {v}" for k, v in response.getheaders()).lower()
        assert "content-security-policy" in headers
        assert "frame-ancestors 'none'" in headers
        assert "x-frame-options: deny" in headers
        assert "strict-transport-security" in headers
        assert "httponly" in headers and "secure" in headers and "samesite=strict" in headers
        csrf = csrf_of(data)
        assert "webvpn_csrf" in client.cookies

        response, _, _ = client.request(
            "POST", "/login", body="username=admin&password=" + urllib.parse.quote(password),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 403

        response, data, _ = login(client, "wrong-password", csrf)
        assert response.status == 401
        csrf = csrf_of(data)

        response, data, _ = login(client, password, csrf)
        assert response.status == 303
        assert response.getheader("location") == "/"
        assert "webvpn_session" in client.cookies
        session_id = client.cookies["webvpn_session"]
        assert len(session_id) == 64

        response, data, _ = client.request("GET", "/")
        assert response.status == 200
        assert "内部测试站".encode() in data
        portal_csrf = csrf_of(data)

        response, _, _ = client.request("GET", "/login")
        assert response.status == 303 and response.getheader("location") == "/"

        response, _, _ = client.request("OPTIONS", "/")
        assert response.status == 204
        assert "GET" in response.getheader("allow")

        response, _, _ = client.request("GET", "/favicon.ico")
        assert response.status == 204

        response, _, _ = client.request("GET", "/logout")
        assert response.status == 405

        too_big = b"x" * 70000
        response, _, _ = client.request(
            "POST", "/login", body=too_big,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 413

        response, _, _ = client.request("GET", "/proxy/up")
        assert response.status == 308
        assert response.getheader("location") == "/proxy/up/"

        response, _, _ = client.request(
            "GET", "/proxy/up", headers={"Origin": "https://frontend.example"},
        )
        assert response.status == 308
        assert response.getheader("access-control-allow-origin") == "https://frontend.example"
        assert response.getheader("access-control-allow-credentials") == "true"

        response, data, _ = client.request("GET", "/proxy/up/")
        assert response.status == 200
        text = data.decode("utf-8")
        assert 'href="/proxy/up/root"' in text
        assert 'href="https://example.com/x"' in text
        assert 'src="/proxy/up/img.png"' in text
        assert 'action="/proxy/up/submit"' in text
        assert "url(/proxy/up/background.png)" in text
        assert 'srcset="/proxy/up/small.png 1x, /proxy/up/large.png 2x"' in text
        namespace = session_id[:16]
        up_cookie = f"wv_{namespace}_up_sid"
        set_cookie = response.getheader("set-cookie")
        assert set_cookie and set_cookie.startswith(up_cookie + "=upstream")
        assert "Path=/proxy/up/" in set_cookie
        assert "Secure" in set_cookie and "HttpOnly" in set_cookie
        assert up_cookie in client.cookies

        response, data, _ = client.request("GET", "/proxy/up/root")
        assert response.status == 200
        assert data == b"cookie=sid=upstream"

        response, data, _ = client.request("GET", "/proxy/up/redir")
        assert response.status == 302
        assert response.getheader("location") == "/proxy/up/root"

        response, data, _ = client.request("GET", "/proxy/up/redirabs")
        assert response.status == 302
        assert response.getheader("location") == "/proxy/up/root"

        response, data, _ = client.request("GET", "/proxy/up/json")
        assert response.status == 200
        assert response.getheader("content-type") == "application/json"
        assert data == b'{"ok":true}'

        cross_origin = {"Origin": "https://frontend.example"}
        response, _, _ = client.request("GET", "/proxy/up/root", headers=cross_origin)
        assert response.status == 200
        assert response.getheader("access-control-allow-origin") == "https://frontend.example"
        assert response.getheader("access-control-allow-credentials") == "true"
        assert "origin" in response.getheader("vary").lower()

        response, _, _ = client.request("GET", "/proxy/up/json", headers=cross_origin)
        assert response.status == 200
        origins = [value for name, value in response.getheaders()
                   if name.lower() == "access-control-allow-origin"]
        assert origins == ["https://frontend.example"]

        response, _, _ = client.request(
            "GET", "/proxy/up/json", headers={"Origin": "https://other.example"},
        )
        assert response.status == 200
        assert response.getheader("access-control-allow-origin") is None
        assert response.getheader("vary") is not None

        response, _, _ = client.request("GET", "/proxy/up/../etc", headers=cross_origin)
        assert response.status == 400
        assert response.getheader("access-control-allow-origin") == "https://frontend.example"

        response, _, _ = client.request("GET", "/proxy/nope/", headers=cross_origin)
        assert response.status == 404
        assert response.getheader("access-control-allow-origin") == "https://frontend.example"

        response, data, _ = client.request(
            "GET", "/proxy/up/headers",
            headers={
                "X-Custom-Header": "kept",
                "X-Secret-Token": "drop",
                "X-Forwarded-For": "6.6.6.6",
                "Connection": "X-Hop-Header",
                "X-Hop-Header": "drop",
            },
        )
        assert response.status == 200
        seen = {key.lower(): value for key, value in json.loads(data).items()}
        assert seen["x-custom-header"] == "kept"
        assert "x-secret-token" not in seen
        assert "x-forwarded-for" not in seen
        assert "x-hop-header" not in seen
        assert seen["accept-encoding"] == "identity"
        assert seen["host"] == f"127.0.0.1:{upstream_port}"
        assert seen["cookie"] == "sid=upstream"
        assert response.getheader("x-private") is None

        response, data, _ = client.request("GET", "/proxy/up/big")
        assert response.status == 502

        response, _, _ = client.request("GET", "/proxy/up/../etc")
        assert response.status == 400

        response, _, _ = client.request("GET", "/proxy/nope/")
        assert response.status == 404

        response, data, _ = client.request("HEAD", "/")
        assert response.status == 200
        assert data == b""
        assert int(response.getheader("content-length")) > 0

        response, get_body, _ = client.request("GET", "/proxy/up/root")
        response, data, _ = client.request("HEAD", "/proxy/up/root")
        assert response.status == 200
        assert data == b""
        assert int(response.getheader("content-length")) == len(get_body)

        response, _, _ = client.request(
            "POST", "/logout", body="csrf=bad",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 403

        response, _, _ = client.request(
            "POST", "/logout", body="csrf=" + portal_csrf,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 303
        assert response.getheader("location") == "/login"
        response, _, _ = client.request("GET", "/")
        assert response.status == 303

        # a fresh login must not keep the old identifier
        response, data, _ = client.request("GET", "/login")
        csrf = csrf_of(data)
        response, _, _ = login(client, password, csrf)
        assert response.status == 303
        second_session = client.cookies["webvpn_session"]
        assert second_session != session_id
        response, data, _ = client.request("GET", "/")
        portal_csrf = csrf_of(data)
        response, _, _ = client.request(
            "POST", "/logout", body="csrf=" + portal_csrf,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 303

        # an off-site next is discarded, not followed
        response, data, _ = client.request("GET", "/login?next=//evil.example")
        assert b'name="next" value="/"' in data
        csrf = csrf_of(data)
        response, _, _ = login(client, password, csrf, "//evil.example")
        assert response.status == 303
        assert response.getheader("location") == "/"
        response, data, _ = client.request("GET", "/")
        portal_csrf = csrf_of(data)
        response, _, _ = client.request(
            "POST", "/logout", body="csrf=" + portal_csrf,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 303

        response, _, _ = client.request(
            "POST", "/login", body="{}",
            headers={"Content-Type": "application/json"},
        )
        assert response.status == 415

        response, _, _ = client.request("GET", "/proxy/up/root")
        assert response.status == 303

        # three failures block the fourth attempt even with the right password
        response, data, _ = client.request("GET", "/login")
        csrf = csrf_of(data)
        for _ in range(3):
            response, data, _ = login(client, "wrong", csrf)
            assert response.status == 401
            csrf = csrf_of(data)
        response, _, _ = login(client, password, csrf)
        assert response.status == 429
        assert int(response.getheader("retry-after")) >= 1

        # TLS 1.1 must not be negotiated
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname = False
        legacy.verify_mode = ssl.CERT_NONE
        try:
            legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        except Exception:
            pass
        try:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", port, context=legacy, timeout=5
            )
            connection.request("GET", "/healthz")
            connection.getresponse().read()
            connection.close()
            raise AssertionError("TLS 1.1 was accepted")
        except AssertionError:
            raise
        except Exception:
            pass

        print("integration ok")
    finally:
        if process is not None:
            process.terminate()
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                out, err = process.communicate()
            if process.returncode not in (0, -15, 143):
                print("server stderr:\n" + (err or ""), file=sys.stderr)
        upstream.shutdown()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
