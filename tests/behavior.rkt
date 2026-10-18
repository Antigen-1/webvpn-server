#lang racket/base

(require racket/path
         rackunit
         "support.rkt")

(module+ test
  (test-case "the rendered helpers and rewriting policy behave"
    (with-rendered-app
     (lambda (app)
       (define output
         (run-python-script (build-path project-root "tests" "behavior_client.py")
                            app (path->string project-root)))
       (check-regexp-match #rx"behavior ok" output)))))
