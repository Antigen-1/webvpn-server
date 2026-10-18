"""The one Python module that imports Python libraries.

Everything the rest of the program needs from Python is imported here, at
module import time, so PyInstaller's static analysis sees it.  The Racket
modules get these modules with ``(import pyimports)`` and ``getattr``; they
never import a library themselves.  That keeps the frozen executable's
dependency set in one file instead of a hand-maintained hidden-import list.

The module also holds the thin FastAPI/Starlette adapter.  The routes, the
authentication, the sessions and the reverse proxy stay in Racket; this file
only turns an ASGI request into a call of a Racket function and turns the
returned object back into a response.
"""

# ---- the standard library the program uses

import argparse
import base64
import builtins
import getpass
import gzip
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import os.path
import posixpath
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import zlib

# ---- the third-party libraries, and every module Uvicorn loads by name

import fastapi
import starlette.concurrency
import starlette.requests
import starlette.responses
import uvicorn

import uvicorn.logging
import uvicorn.loops.auto
import uvicorn.loops.asyncio
import uvicorn.protocols.http.auto
import uvicorn.protocols.http.h11_impl
import uvicorn.protocols.websockets.auto
import uvicorn.lifespan.on
import uvicorn.lifespan.off

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

# aliases the Racket side asks for by name
os_path = os.path
posix_path = posixpath
urllib_parse = urllib.parse
http_client = http.client
starlette_responses = starlette.responses
starlette_concurrency = starlette.concurrency

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

TEXT = "text/plain; charset=utf-8"
HTML = "text/html; charset=utf-8"


def safe_header(value):
    return str(value).replace("\r", "").replace("\n", "")


def response(content=b"", status=200, headers=None, cookies=None, content_length=None):
    """A Starlette response with possibly repeated Set-Cookie headers."""
    result = Response(content=content, status_code=status)
    if content_length is not None:
        result.raw_headers = [
            (name, value)
            for name, value in result.raw_headers
            if name.lower() != b"content-length"
        ]
        result.raw_headers.append(
            (b"content-length", str(content_length).encode("latin-1"))
        )
    for name, value in headers or []:
        result.raw_headers.append(
            (
                safe_header(name).lower().encode("latin-1", "replace"),
                safe_header(value).encode("latin-1", "replace"),
            )
        )
    for cookie in cookies or []:
        result.raw_headers.append((b"set-cookie", safe_header(cookie).encode("latin-1", "replace")))
    return result


def text_response(text, status=200, headers=None, cookies=None):
    return response(
        text.encode("utf-8"), status, [("content-type", TEXT)] + list(headers or []), cookies
    )


def html_response(text, status=200, headers=None, cookies=None):
    return response(
        text.encode("utf-8"), status, [("content-type", HTML)] + list(headers or []), cookies
    )


def redirect(location, status=303, cookies=None, headers=None):
    result = RedirectResponse(safe_header(location), status_code=status)
    for name, value in headers or []:
        result.raw_headers.append(
            (
                safe_header(name).lower().encode("latin-1", "replace"),
                safe_header(value).encode("latin-1", "replace"),
            )
        )
    for cookie in cookies or []:
        result.raw_headers.append((b"set-cookie", safe_header(cookie).encode("latin-1", "replace")))
    return result


def request_info(request):
    """The parts of an ASGI request the Racket handler works with."""
    raw_path = request.scope.get("raw_path", b"")
    try:
        raw_text = raw_path.decode("latin-1")
    except Exception:
        raw_text = request.url.path
    client = request.client
    return {
        "method": request.method,
        "path": request.url.path,
        "raw_path": raw_text,
        "query": request.url.query,
        "headers": list(request.headers.items()),
        "client_ip": client.host if client is not None else "",
        "forwarded_for": request.headers.get("x-forwarded-for", ""),
        "scheme": request.url.scheme,
    }


def make_endpoint(handler, max_body):
    """An ASGI endpoint that hands a request to a synchronous Racket function."""

    async def endpoint(request: Request):
        length = request.headers.get("content-length")
        if length is not None:
            try:
                size = int(length)
            except ValueError:
                return text_response("bad request", 400)
            if size < 0:
                return text_response("bad request", 400)
            if size > max_body:
                return text_response("request too large", 413)
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > max_body:
                return text_response("request too large", 413)
        body = bytes(chunks)
        info = request_info(request)
        answer = await run_in_threadpool(handler, info, body)
        if not isinstance(answer, Response):
            return text_response("internal server error", 500)
        if request.method == "HEAD":
            answer.body = b""
        return answer

    return endpoint


def make_app(handler, max_body):
    """The FastAPI application: one catch-all route, no docs, no OpenAPI."""
    app = fastapi.FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    endpoint = make_endpoint(handler, max_body)
    app.add_api_route("/", endpoint, methods=HTTP_METHODS, include_in_schema=False)
    app.add_api_route("/{path:path}", endpoint, methods=HTTP_METHODS, include_in_schema=False)
    return app


def secure_ssl_context_factory(config, default_factory):
    """Uvicorn's SSL context, raised to TLS 1.2 and HTTP/1.1 only."""
    context = default_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.set_alpn_protocols(["http/1.1"])
    return context


def run(app, host, port, certfile, keyfile, max_body=16 * 1024 * 1024):
    """Run the ASGI application over TLS until the process is stopped."""
    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        ssl_context_factory=secure_ssl_context_factory,
        proxy_headers=False,
        server_header=False,
        date_header=False,
        access_log=False,
        log_level="warning",
        timeout_keep_alive=5,
        timeout_graceful_shutdown=5,
        limit_concurrency=256,
        h11_max_incomplete_event_size=32 * 1024,
    )
