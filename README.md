# webvpn-server

A school-style WebVPN: TLS entry, password login, a portal of configured
intranet Web sites, an authenticated reverse proxy that rewrites links and
namespaces cookies, and a one-file PyInstaller build.

The server logic is written in Racket's LE and compiled to Python by
[rkt-pythonize](https://pkgs.racket-lang.org/package/rkt-pythonize).
`src/pyimports.py` is the only file that imports Python libraries statically
(FastAPI, Uvicorn, the standard library); FastAPI/Uvicorn are a thin ASGI/TLS
adapter, while authentication, sessions, the portal and the proxy stay in Racket.

Request and response headers use a default-forward blacklist: built-in
hop-by-hop/security names always apply, and `blocked_request_headers` /
`blocked_response_headers` add case-insensitive regular expressions matched
against the whole header name.

## Quick start

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# create webvpn.json, cert.pem, key.pem and a random admin password
racket run-dev.rkt init ./deploy
# edit deploy/webvpn.json: add targets
racket run-dev.rkt serve --config ./deploy/webvpn.json
```

Open <https://127.0.0.1:8443/>. The self-signed certificate produces a browser
warning; use a CA certificate for a real deployment.

The runtime configuration is `webvpn.json` **beside the executable** (for a
source run, the current directory). `init` with no directory writes it there.
The repository root contains `webvpn.example.json`; its user hash is a
deliberate placeholder, so generate a real one with `hash-password` or use
`init`.

## Build the executable

```sh
racket build.rkt
```

The first build installs `requirements.txt` and PyInstaller 6.22.3 into
`build/venv` (network required), renders `src/` to `build/python`, and writes
`build/bin/webvpn-server` (`webvpn-server.exe` on Windows). Config and
certificates are not packed; they stay next to the executable. Run the script
when you need the artifact.

## Tests

```sh
mkdir -p .tmp
TMPDIR="$PWD/.tmp" raco test -x tests/
```

The suite renders the Python, checks the generated sources, tests auth/proxy
policy, and runs a real TLS login/proxy/logout integration test. It needs
`openssl` and the project `.venv`; it does not need PyInstaller.

## Documentation

The manual is Scribble, in `scribblings/webvpn-server.scrbl`:

```sh
raco scribble --htmls --dest doc scribblings/webvpn-server.scrbl
```

It covers configuration, endpoints, the security model and its limits, the
build, tests, and the code layout.

## License

Apache-2.0 OR MIT.
