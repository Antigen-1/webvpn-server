#!/usr/bin/env python3
"""Unit-level checks of the Python the Racket modules render.

The script is run by tests/behavior.rkt with the rendered application as
argv[1] and the project root as argv[2].  It never starts the HTTP server; the
TLS end-to-end test lives in integration_client.py.
"""

import gzip
import json
import re
import os
import shutil
import sys
import tempfile
import time

APP = sys.argv[1]
ROOT = sys.argv[2]
sys.path.insert(0, APP)

import auth  # noqa: E402
import config  # noqa: E402
import proxy  # noqa: E402
import util  # noqa: E402


def raises(function, needle=None):
    try:
        function()
    except Exception as error:
        if needle is not None and needle not in str(error):
            raise AssertionError(f"expected {needle!r} in {error!r}")
        return
    raise AssertionError("expected an exception")


def target(name="wiki", url="http://127.0.0.1:8000"):
    parsed = util.url_split(url)
    return {
        "name": name,
        "label": "Test " + name,
        "url": url,
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "host": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
    }


def test_util():
    assert util.to_text(None) == ""
    assert util.text_join("-", ["a", "b"]) == "a-b"
    assert util.parse_cookies("a=1; b=2") == {"a": "1", "b": "2"}
    assert util.parse_cookies("a=1; a=2")["a"] == "2"
    assert util.b64url_decode(util.b64url_encode(b"hello")) == b"hello"
    assert util.header_name_p("content-type")
    assert not util.header_name_p("bad name")
    assert util.header_safe("a\r\nb") == "ab"
    assert "&lt;" in util.html_escape("<")
    assert util.url_first_param(util.url_parse_qs("a=1&a=2"), "a") == "1"
    assert util.url_first_param(util.url_parse_qs(""), "a") is None
    assert util.url_origin_key("http", "Example.COM:80") == "example.com:80"


def test_auth():
    encoded = auth.hash_password("correct horse", 1000)
    assert encoded.startswith("pbkdf2_sha256$1000$")
    assert auth.verify_password("correct horse", encoded)
    assert not auth.verify_password("wrong", encoded)
    assert not auth.verify_password("correct horse", "not-a-hash")
    assert auth.valid_hash_p(encoded)
    assert not auth.valid_hash_p("pbkdf2_sha256$0$00$00")
    assert not auth.valid_hash_p(None)
    assert auth.constant_equal("abc", "abc")
    assert not auth.constant_equal("abc", "abd")
    assert not auth.constant_equal(None, None)

    store = auth.make_session_store(60, 2)
    sid = auth.create_session(store, "alice")
    assert sid and len(sid) == 64
    session = auth.get_session(store, sid)
    assert session["user"] == "alice"
    assert session["sid"] == sid
    assert auth.session_csrf_p(session, session["csrf"])
    assert not auth.session_csrf_p(session, "0" * 48)
    assert auth.get_session(store, "f" * 64) is None
    assert auth.get_session(store, "not-a-session") is None
    auth.drop_session(store, sid)
    assert auth.get_session(store, sid) is None

    expired = auth.make_session_store(0, 2)
    expired_sid = auth.create_session(expired, "bob")
    assert auth.get_session(expired, expired_sid) is None

    full = auth.make_session_store(60, 1)
    assert auth.create_session(full, "a") is not None
    assert auth.create_session(full, "b") is None

    limiter = auth.make_limiter(2, 60)
    now = time.time()
    assert auth.limiter_check(limiter, "ip", now)
    auth.limiter_fail(limiter, "ip", now)
    auth.limiter_fail(limiter, "ip", now)
    assert not auth.limiter_check(limiter, "ip", now)
    assert auth.limiter_retry_after(limiter, "ip", now) >= 0
    auth.limiter_clear(limiter, "ip")
    assert auth.limiter_check(limiter, "ip", now)

    cookie = auth.session_cookie(sid, 100)
    assert cookie.startswith("webvpn_session=")
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    csrf = auth.csrf_cookie("x" * 48)
    assert "SameSite=Strict" in csrf
    assert "Max-Age=0" in auth.clear_session_cookie()


def test_proxy():
    wiki = target("wiki")
    other = target("other", "https://10.0.0.2:8443")
    index = proxy.target_index([wiki, other])

    assert proxy.rewrite_url("/a", wiki, index) == "/proxy/wiki/a"
    assert proxy.rewrite_url("/a?x=1", wiki, index) == "/proxy/wiki/a?x=1"
    assert proxy.rewrite_url("http://127.0.0.1:8000/b", wiki, index) == "/proxy/wiki/b"
    assert proxy.rewrite_url("https://10.0.0.2:8443/c", wiki, index) == "/proxy/other/c"
    assert proxy.rewrite_url("https://example.com/c", wiki, index) == "https://example.com/c"
    assert proxy.rewrite_url("//127.0.0.1:8000/d", wiki, index) == "/proxy/wiki/d"
    assert proxy.rewrite_url("relative/path", wiki, index) == "relative/path"
    assert proxy.rewrite_url("#anchor", wiki, index) == "#anchor"
    assert proxy.rewrite_url("mailto:a@example.com", wiki, index) == "mailto:a@example.com"
    assert proxy.rewrite_url("/a/../b", wiki, index) == "/proxy/wiki/b"
    assert proxy.rewrite_url("/proxy/wiki/a", wiki, index) == "/proxy/wiki/a"

    html = (
        '<a href="/a">A</a>'
        '<img src="http://127.0.0.1:8000/b">'
        '<a href="https://example.com/c">C</a>'
        '<form action="/login" method="post"></form>'
        '<div style="background:url(/img.png)"></div>'
        '<img srcset="/x.png 1x, http://127.0.0.1:8000/y.png 2x">'
    )
    out = proxy.rewrite_html(html, wiki, index)
    assert 'href="/proxy/wiki/a"' in out
    assert 'src="/proxy/wiki/b"' in out
    assert 'href="https://example.com/c"' in out
    assert 'action="/proxy/wiki/login"' in out
    assert "url(/proxy/wiki/img.png)" in out
    assert 'srcset="/proxy/wiki/x.png 1x, /proxy/wiki/y.png 2x"' in out

    css = "body{background:url('/img.png')} @import url(/x.css); @import \"/y.css\";"
    out = proxy.rewrite_css(css, wiki, index)
    assert "url('/proxy/wiki/img.png')" in out
    assert "url(/proxy/wiki/x.css)" in out
    assert '@import "/proxy/wiki/y.css"' in out

    assert proxy.rewrite_location("/a", wiki, index) == "/proxy/wiki/a"
    assert proxy.rewrite_location("https://10.0.0.2:8443/c", wiki, index) == "/proxy/other/c"
    assert proxy.rewrite_location("https://example.com/c", wiki, index) == "https://example.com/c"

    namespace = "abcd1234"
    cookie = proxy.rewrite_set_cookie("sid=abc; Path=/; HttpOnly; SameSite=Strict; Max-Age=60", wiki, namespace)
    assert cookie.startswith("wv_abcd1234_wiki_sid=abc")
    assert "Path=/proxy/wiki/" in cookie
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Max-Age=60" in cookie
    assert proxy.rewrite_set_cookie("sid=abc; Domain=.example.com; Path=/", wiki, namespace).find("Domain") == -1
    assert proxy.request_cookie_header(
        "wv_abcd1234_wiki_sid=abc; other=1; wv_abcd1234_wiki_x=2", wiki, namespace
    ) == "sid=abc; x=2"
    assert proxy.request_cookie_header("other=1", wiki, namespace) is None

    assert proxy.request_target(wiki, "a/b", "q=1") == "/a/b?q=1"
    assert proxy.request_target(wiki, "", "") == "/"
    raises(lambda: proxy.request_target(wiki, "..", ""), "路径")
    raises(lambda: proxy.request_target(wiki, "%2e%2e/x", ""), "路径")
    raises(lambda: proxy.request_target(wiki, "a/../b", ""), "路径")
    raises(lambda: proxy.request_target(wiki, "a\\b", ""), "路径")

    result = {
        "status": 200,
        "reason": "OK",
        "headers": [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Location", "/next"),
            ("Set-Cookie", "sid=1; Path=/; HttpOnly"),
            ("X-Test", "yes"),
        ],
        "body": b'<a href="/x">x</a>',
    }
    rewritten = proxy.rewrite_response(result, wiki, index, False, namespace, [])
    assert rewritten["body"] == b'<a href="/proxy/wiki/x">x</a>'
    headers = dict(rewritten["headers"])
    assert headers["location"] == "/proxy/wiki/next"
    assert "wv_abcd1234_wiki_sid" in headers["set-cookie"]
    assert headers["x-test"] == "yes"

    gz = dict(result)
    gz["body"] = gzip.compress(b'<a href="/gzip">g</a>')
    gz["headers"] = [("Content-Type", "text/html"), ("Content-Encoding", "gzip")]
    rewritten = proxy.rewrite_response(gz, wiki, index, False, namespace, [])
    assert b"/proxy/wiki/gzip" in rewritten["body"]
    assert "content-encoding" not in dict(rewritten["headers"])


def test_headers():
    wiki = target("wiki")
    namespace = "abcd1234"
    patterns = [re.compile("x-secret-.*", re.IGNORECASE)]
    incoming = [
        ("Accept", "text/html"),
        ("X-Custom-Header", "kept"),
        ("X-Secret-Token", "drop"),
        ("Host", "evil.example"),
        ("Cookie", "wv_abcd1234_wiki_sid=abc"),
        ("Connection", "X-Hop-Header"),
        ("X-Hop-Header", "drop"),
        ("X-Forwarded-For", "6.6.6.6"),
        ("X-Forwarded-Custom", "6.6.6.6"),
        ("Content-Length", "999"),
        ("Accept-Encoding", "gzip"),
    ]
    headers = proxy.filter_request_headers(incoming, wiki, namespace, patterns)
    assert headers["accept"] == "text/html"
    assert headers["x-custom-header"] == "kept"
    assert headers["Host"] == wiki["netloc"]
    assert headers["Accept-Encoding"] == "identity"
    assert headers["Cookie"] == "sid=abc"
    for blocked in [
        "x-secret-token",
        "host",
        "cookie",
        "x-hop-header",
        "x-forwarded-for",
        "x-forwarded-custom",
        "content-length",
        "accept-encoding",
        "connection",
    ]:
        assert blocked not in headers

    result = {
        "status": 200,
        "reason": "OK",
        "headers": [("Content-Type", "text/plain"), ("X-Private", "yes")],
        "body": b"ok",
    }
    rewritten = proxy.rewrite_response(
        result, wiki, proxy.target_index([wiki]), False, namespace,
        [re.compile("x-private", re.IGNORECASE)],
    )
    assert "x-private" not in dict(rewritten["headers"])
    assert dict(rewritten["headers"])["content-type"] == "text/plain"


def test_config():
    encoded = auth.hash_password("pw", 1000)
    directory = tempfile.mkdtemp(prefix="webvpn-config-")
    try:
        cert = os.path.join(directory, "cert.pem")
        key = os.path.join(directory, "key.pem")
        open(cert, "w").write("cert")
        open(key, "w").write("key")
        os.chmod(key, 0o600)
        raw = {
            "host": "127.0.0.1",
            "port": 8443,
            "cert_file": "cert.pem",
            "key_file": "key.pem",
            "blocked_request_headers": ["x-secret-.*"],
            "blocked_response_headers": ["x-private"],
            "users": {"admin": encoded},
            "targets": [{"name": "wiki", "label": "Wiki", "url": "http://127.0.0.1:8000"}],
        }
        path = os.path.join(directory, "webvpn.json")
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(raw, stream)
        loaded = config.load_config(path)
        assert loaded["cert_file"] == cert
        assert loaded["key_file"] == key
        assert loaded["targets"][0]["name"] == "wiki"
        assert loaded["blocked_request_headers"] == ["x-secret-.*"]
        assert loaded["blocked_response_headers"] == ["x-private"]
        assert len(loaded["blocked_request_header_patterns"]) == 1
        assert loaded["blocked_request_header_patterns"][0].fullmatch("X-SECRET-TOKEN")
        config.check_config(loaded)

        config.apply_overrides(loaded, "0.0.0.0", 9443, None, None)
        assert loaded["host"] == "0.0.0.0" and loaded["port"] == 9443

        if os.name != "nt":
            os.chmod(key, 0o644)
            raises(lambda: config.check_config(loaded), "权限")
            os.chmod(key, 0o600)

        bad = dict(raw)
        bad["blocked_request_headers"] = ["("]
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(bad, stream)
        raises(lambda: config.load_config(path), "正则")

        bad = dict(raw)
        bad["targets"] = [{"name": "bad name", "label": "x", "url": "http://127.0.0.1"}]
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(bad, stream)
        raises(lambda: config.load_config(path), "name")

        bad = dict(raw)
        bad["targets"] = [{"name": "wiki", "label": "x", "url": "http://127.0.0.1/path"}]
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(bad, stream)
        raises(lambda: config.load_config(path), "origin")

        bad = dict(raw)
        bad["users"] = {}
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(bad, stream)
        loaded = config.load_config(path)
        raises(lambda: config.check_config(loaded), "没有用户")

        # the default is beside a frozen executable, and in the current
        # directory for a source run
        old_frozen = getattr(sys, "frozen", None)
        old_executable = sys.executable
        sys.frozen = True
        sys.executable = os.path.join(directory, "webvpn-server")
        assert config.default_config_path() == os.path.join(directory, "webvpn.json")
        assert config.default_init_directory() == directory
        if old_frozen is None:
            del sys.frozen
        else:
            sys.frozen = old_frozen
        sys.executable = old_executable
    finally:
        shutil.rmtree(directory)

    example = os.path.join(ROOT, "webvpn.example.json")
    data = json.load(open(example, encoding="utf-8"))
    assert data["users"] and data["targets"]
    assert "REPLACE" in next(iter(data["users"].values()))
    raises(lambda: config.load_config(example), "pbkdf2")


def main():
    test_util()
    test_auth()
    test_headers()
    test_proxy()
    test_config()
    print("behavior ok")


if __name__ == "__main__":
    main()
