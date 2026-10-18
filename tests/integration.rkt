#lang racket/base

(require racket/path
         racket/system
         rackunit
         "support.rkt")

(module+ test
  (test-case "TLS login, portal, proxy rewriting and logout"
    (if (not (find-executable-path "openssl"))
        (void)
        (with-rendered-app
         (lambda (app)
           (define output
             (run-python-script (build-path project-root "tests" "integration_client.py")
                                app (path->string project-root)))
           (check-regexp-match #rx"integration ok" output))))))
