#lang racket/base

;; Build the one-file executable with rkt-pythonize/builder.
;;
;;   racket build.rkt
;;
;; The first build creates build/venv, installs requirements.txt and
;; PyInstaller, renders src/ to build/python, and writes build/bin/webvpn-server
;; (webvpn-server.exe on Windows).  It needs network access for pip the first
;; time.  The configuration is not packed: it lives beside the executable, and
;; `webvpn-server init` writes it there.

(require racket/runtime-path
         rkt-pythonize/builder)

(define-runtime-path here ".")

(define artifact
  (build-executable here
                    #:name "webvpn-server"
                    #:entry "main"
                    #:onefile? #t
                    ;; pyimports.py imports Uvicorn's protocol and loop
                    ;; implementations statically.  Naming them again here is
                    ;; harmless and keeps a PyInstaller upgrade from losing
                    ;; one of the modules Uvicorn loads by name.
                    #:hidden-imports
                    '("anyio._backends._asyncio"
                      "uvicorn.logging"
                      "uvicorn.loops.auto"
                      "uvicorn.loops.asyncio"
                      "uvicorn.protocols.http.auto"
                      "uvicorn.protocols.http.h11_impl"
                      "uvicorn.protocols.websockets.auto"
                      "uvicorn.lifespan.on"
                      "uvicorn.lifespan.off")))

(printf "built: ~a\n" (path->string artifact))
