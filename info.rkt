#lang info
(define collection "webvpn-server")
(define deps '("base" "rkt-pythonize"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib"))
(define scribblings '(("scribblings/webvpn-server.scrbl" ())))
(define pkg-desc "A TLS WebVPN portal and authenticated reverse proxy, compiled from LE by rkt-pythonize")
(define version "0.0.1")
(define pkg-authors '(zhanghao))
(define license '(Apache-2.0 OR MIT))
