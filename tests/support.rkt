#lang racket/base

;; Shared test support: render src/ to a temporary directory of Python, find
;; the project venv's interpreter, and run a Python test script.

(require racket/file
         racket/runtime-path
         racket/list
         racket/path
         racket/port
         racket/string
         racket/system
         rackunit)

(provide project-root
         find-python
         render-app
         with-rendered-app
         run-python-script
         rkt-sources)

(define-runtime-path here ".")
(define project-root (simplify-path (path->complete-path (build-path here ".."))))

(define (source-directory) (build-path project-root "src"))

(define (rkt-sources)
  (sort (for/list ([name (in-list (directory-list (source-directory)))]
                   #:when (and (file-exists? (build-path (source-directory) name))
                               (equal? (path-get-extension name) #".rkt")))
          (build-path (source-directory) name))
        string<? #:key path->string))

(define (find-python)
  (or (let ([configured (getenv "PYTHON_EXE")])
        (and configured (find-executable-path configured)))
      (let* ([windows? (eq? (system-type 'os) 'windows)]
             [venv (build-path project-root ".venv"
                               (if windows? "Scripts" "bin")
                               (if windows? "python.exe" "python"))])
        (and (file-exists? venv) venv))
      (find-executable-path "python3")
      (find-executable-path "python")
      (error 'test "no Python found: create .venv and install requirements.txt, or set PYTHON_EXE")))

(define (render-app)
  (define temp-root (build-path project-root ".tmp"))
  (make-directory* temp-root)
  (define directory (make-temporary-file "webvpn-render-~a" 'directory temp-root))
  (for ([file (in-list (rkt-sources))])
    (define code
      (parameterize ([use-compiled-file-paths '()])
        (dynamic-require `(file ,(path->string file)) 'python)))
    (unless (string? code)
      (delete-directory/files directory)
      (error 'test "~a does not provide python" (path->string file)))
    (display-to-file code
                     (build-path directory
                                 (path-replace-extension (file-name-from-path file) #".py"))
                     #:exists 'replace))
  (copy-file (build-path (source-directory) "pyimports.py")
             (build-path directory "pyimports.py") #t)
  directory)

(define (with-rendered-app thunk)
  (define directory (render-app))
  (dynamic-wind
   void
   (lambda () (thunk directory))
   (lambda ()
     (when (directory-exists? directory)
       (delete-directory/files directory)))))

(define (run-python-script script . arguments)
  (define python (path->string (find-python)))
  (define-values (process stdout stdin stderr)
    (apply subprocess #f #f (current-error-port) python "-u"
           (path->string script) arguments))
  (close-output-port stdin)
  (define output (port->string stdout))
  (subprocess-wait process)
  (define status (subprocess-status process))
  (unless (equal? status 0)
    (error 'test "~a exited with ~s~a"
           (path->string script) status
           (if (string=? output "") "" (format "\noutput:\n~a" output))))
  output)
