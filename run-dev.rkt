#lang racket/base

;; Render src/ to build/python and run it with the project venv, without
;; PyInstaller.  This is the development path; the shipped artifact is made by
;; build.rkt.
;;
;;   racket run-dev.rkt init ./deploy
;;   racket run-dev.rkt serve --config ./deploy/webvpn.json

(require racket/file
         racket/runtime-path
         racket/list
         racket/path
         racket/string
         racket/system)

(define-runtime-path here ".")
(define root (simplify-path (path->complete-path here)))
(define source-directory (build-path root "src"))
(define output-directory (build-path root "build" "python"))

(define (rkt-source? path)
  (equal? (path-get-extension path) #".rkt"))

(define (sources)
  (sort (for/list ([name (in-list (directory-list source-directory))]
                   #:when (and (file-exists? (build-path source-directory name))
                               (rkt-source? name)))
          (build-path source-directory name))
        string<? #:key path->string))

(define (python-executable)
  (or (let ([configured (getenv "PYTHON_EXE")])
        (and configured (find-executable-path configured)))
      (let* ([windows? (eq? (system-type 'os) 'windows)]
             [venv (build-path root ".venv"
                               (if windows? "Scripts" "bin")
                               (if windows? "python.exe" "python"))])
        (and (file-exists? venv) venv))
      (find-executable-path "python3")
      (find-executable-path "python")
      (error 'run-dev "no Python found: create .venv or set PYTHON_EXE")))

(define (render! file)
  (define code
    (parameterize ([use-compiled-file-paths '()])
      (dynamic-require `(file ,(path->string file)) 'python)))
  (define target (build-path output-directory
                             (path-replace-extension (file-name-from-path file) #".py")))
  (display-to-file code target #:exists 'replace)
  (printf "rendered ~a -> ~a\n" (path->string file) (path->string target)))

(unless (directory-exists? source-directory)
  (error 'run-dev "run this from the webvpn-server project root"))

(when (directory-exists? output-directory)
  (delete-directory/files output-directory))
(make-directory* output-directory)

(for ([file (in-list (sources))])
  (render! file))

(copy-file (build-path source-directory "pyimports.py")
           (build-path output-directory "pyimports.py") #t)

(define arguments (vector->list (current-command-line-arguments)))
(define status
  (apply system* (python-executable)
         (path->string (build-path output-directory "main.py"))
         arguments))
(exit (if status 0 1))
