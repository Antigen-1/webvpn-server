#lang racket/base

;; Small, dependency-free helpers shared by the generated Python modules.
;;
;; Every function here is written in LE and compiled by rkt-pythonize.  The
;; module is the only place that knows how to call a Python method, how to
;; join a list of strings, or how to turn an exception into a log line, so the
;; rest of the server reads as ordinary Python-shaped code.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define bridge (import pyimports))
    (define sys (object-get-attr bridge "sys"))
    (define os (object-get-attr bridge "os"))
    (define re (object-get-attr bridge "re"))
    (define json (object-get-attr bridge "json"))
    (define time (object-get-attr bridge "time"))
    (define html (object-get-attr bridge "html"))
    (define base64 (object-get-attr bridge "base64"))
    (define builtins (object-get-attr bridge "builtins"))
    (define secrets (object-get-attr bridge "secrets"))
    (define urllib-parse (object-get-attr bridge "urllib_parse"))
    (define os-path (object-get-attr os "path"))

    ;; `list` is a runtime piece in LE, so the Python builtin is named once
    ;; here and used where a type object (not a constructor call) is needed.
    (define py-list (object-get-attr builtins "list"))

    ;; ---- values and text

    (define (none? value) (eq? value None))
    (define (some? value) (not (eq? value None)))
    (define (list? value) (isinstance value py-list))
    (define (dict? value) (isinstance value dict))
    (define (bool? value) (isinstance value bool))
    (define (text? value) (isinstance value str))
    (define (integer? value) (isinstance value int))
    (define (bytes? value) (isinstance value bytes))

    (define (to-text value)
      (if (eq? value None) "" (str value)))

    (define (text-join separator items)
      ((object-get-attr separator "join") items))

    (define (text-split text separator)
      ((object-get-attr text "split") separator))

    (define (text-lines text)
      ((object-get-attr text "splitlines")))

    (define (text-replace text old new)
      ((object-get-attr text "replace") old new))

    (define (text-strip text)
      ((object-get-attr text "strip")))

    (define (text-lower text)
      ((object-get-attr text "lower")))

    (define (text-upper text)
      ((object-get-attr text "upper")))

    (define (text-startswith? text prefix)
      ((object-get-attr text "startswith") prefix))

    (define (text-endswith? text suffix)
      ((object-get-attr text "endswith") suffix))

    (define (text-contains? text needle)
      (in needle text))

    (define (text-find text needle)
      ((object-get-attr text "find") needle))

    (define (text-substr text start end)
      (object-ref text (slice start end)))

    (define (text-format template values)
      (apply (object-get-attr template "format") values))

    (define (repeat-text text count)
      (* text count))

    (define (encode-utf8 text)
      ((object-get-attr text "encode") "utf-8"))

    (define (decode-utf8 data)
      ((object-get-attr data "decode") "utf-8" "replace"))

    (define (decode-bytes data charset)
      (with-handler (lambda (e) ((object-get-attr data "decode") "utf-8" "replace"))
                    ((object-get-attr data "decode") charset "replace")))

    (define (encode-charset text charset)
      (with-handler (lambda (e) ((object-get-attr text "encode") "utf-8"))
                    ((object-get-attr text "encode") charset "replace")))

    (define (safe-int value default)
      (with-handler (lambda (e) default) (int value)))

    (define (safe-float value default)
      (with-handler (lambda (e) default) (float value)))

    ;; ---- bytes, base64 and JSON

    (define (bytes-join chunks)
      ((object-get-attr (bytes) "join") chunks))

    (define (b64url-encode data)
      (define encoded ((object-get-attr base64 "urlsafe_b64encode") data))
      (define text ((object-get-attr encoded "decode") "ascii"))
      ((object-get-attr text "rstrip") "="))

    (define (b64url-decode text)
      (define remainder (modulo (len text) 4))
      (define padded (if (= remainder 0) text (+ text (repeat-text "=" (- 4 remainder)))))
      ((object-get-attr base64 "urlsafe_b64decode") padded))

    (define (json-dumps value)
      ((object-get-attr json "dumps") value #:ensure_ascii #f #:sort_keys #t #:indent 2))

    (define (json-loads text)
      ((object-get-attr json "loads") text))

    ;; ---- files and paths

    (define (path-join parts)
      (apply (object-get-attr os-path "join") parts))

    (define (path-abspath path)
      ((object-get-attr os-path "abspath") path))

    (define (path-dirname path)
      ((object-get-attr os-path "dirname") path))

    (define (path-basename path)
      ((object-get-attr os-path "basename") path))

    (define (path-exists? path)
      ((object-get-attr os-path "exists") path))

    (define (file-exists? path)
      ((object-get-attr os-path "isfile") path))

    (define (dir-exists? path)
      ((object-get-attr os-path "isdir") path))

    (define (absolute-path? path)
      ((object-get-attr os-path "isabs") path))

    (define (ensure-dir path)
      ((object-get-attr os "makedirs") path #:exist_ok #t))

    (define (chmod path mode)
      ((object-get-attr os "chmod") path mode))

    (define (file-mode path)
      (object-get-attr ((object-get-attr os "stat") path) "st_mode"))

    (define (replace-file source dest)
      ((object-get-attr os "replace") source dest))

    (define (remove-file path)
      (if (path-exists? path) ((object-get-attr os "unlink") path) None))

    (define (read-text path)
      (define stream (open path "r" #:encoding "utf-8"))
      (define text ((object-get-attr stream "read")))
      ((object-get-attr stream "close"))
      text)

    (define (write-text path text)
      (define stream (open path "w" #:encoding "utf-8"))
      ((object-get-attr stream "write") text)
      ((object-get-attr stream "close"))
      None)

    (define (write-bytes path data)
      (define stream (open path "wb"))
      ((object-get-attr stream "write") data)
      ((object-get-attr stream "close"))
      None)

    (define (temp-name directory prefix)
      (path-join (list directory (+ prefix ((object-get-attr secrets "token_hex") 8)))))

    ;; ---- time and logging

    (define (now)
      ((object-get-attr time "time")))

    (define (utc-stamp)
      ((object-get-attr time "strftime") "%Y-%m-%dT%H:%M:%SZ" ((object-get-attr time "gmtime"))))

    (define (stderr-write-both stream text)
      (with-handler (lambda (e) None)
                    ((object-get-attr stream "write") text))
      (with-handler (lambda (e) None)
                    ((object-get-attr stream "flush"))))

    (define (stderr-write text)
      (define stream (object-get-attr sys "stderr"))
      (if (eq? stream None)
          None
          (stderr-write-both stream text)))

    (define (log-line level message)
      (define safe-message
        (text-replace (text-replace message (chr 13) " ") (chr 10) " "))
      (stderr-write (+ (utc-stamp) " " level " " safe-message "\n")))

    (define (log-info message) (log-line "INFO" message))
    (define (log-warn message) (log-line "WARN" message))
    (define (log-error message) (log-line "ERROR" message))

    (define (error-text-exception error)
      (define value (with-handler (lambda (e) None) (getattr error "value" None)))
      (cond
        [(text? value) value]
        [(isinstance value Exception) (error-text value)]
        [else (+ (object-get-attr (type error) "__name__") ": " (str error))]))

    (define (error-text error)
      (if (isinstance error Exception)
          (error-text-exception error)
          (str error)))

    ;; ---- HTTP text

    (define header-token
      ((object-get-attr re "compile") "^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$"))

    (define (header-name? name)
      (and (text? name)
           (some? ((object-get-attr header-token "fullmatch") name))))

    (define (header-safe value)
      (text-replace (text-replace (to_text value) (chr 13) "") (chr 10) ""))

    (define (html-escape text)
      ((object-get-attr html "escape") (to-text text)))

    ;; ---- URLs

    (define (url-split url)
      ((object-get-attr urllib-parse "urlsplit") url))

    (define (url-unsplit parts)
      ((object-get-attr urllib-parse "urlunsplit") parts))

    (define (url-join base relative)
      ((object-get-attr urllib-parse "urljoin") base relative))

    (define (url-quote text)
      ((object-get-attr urllib-parse "quote") text #:safe "/"))

    (define (url-quote-plus text)
      ((object-get-attr urllib-parse "quote_plus") text))

    (define (url-unquote text)
      ((object-get-attr urllib-parse "unquote") text))

    (define (url-encode fields)
      ((object-get-attr urllib-parse "urlencode") fields))

    (define (url-parse-qs query)
      ((object-get-attr urllib-parse "parse_qs") query #:keep_blank_values #t))

    (define (url-first-param params name)
      (define values ((object-get-attr params "get") name))
      (if (and (some? values) (> (len values) 0))
          (object-ref values 0)
          None))

    (define (url-default-port scheme)
      (if (= scheme "https") 443 80))

    ;; the host and port a URL names, with the default port filled in, for
    ;; comparing two URLs' origins without caring how they were spelled
    (define (url-origin-key scheme netloc)
      (define parsed (url-split (+ scheme "://" netloc)))
      (define host (with-handler (lambda (e) "")
                                 (object-get-attr parsed "hostname")))
      (define port (with-handler (lambda (e) None)
                                 (object-get-attr parsed "port")))
      (define effective (if (eq? port None) (url-default-port scheme) port))
      (+ (text-lower (to-text host)) ":" (str effective)))

    ;; ---- cookies

    (define (parse-cookie-piece result trimmed)
      (define piece ((object-get-attr trimmed "partition") "="))
      (define name (text-strip (object-ref piece 0)))
      (define value (text-strip (object-ref piece 2)))
      (if (> (len name) 0)
          (object-set! result name value)
          None))

    (define (parse-cookie-part result part)
      (define trimmed (text-strip part))
      (if (> (len trimmed) 0)
          (parse-cookie-piece result trimmed)
          None))

    (define (parse-cookies header)
      (define result (dict))
      (define parts (if (or (eq? header None) (= (len header) 0))
                        (list)
                        (text-split header ";")))
      (tuple (map (lambda (part) (parse-cookie-part result part)) parts))
      result)

    (define (cookie-header-value cookies name)
      ((object-get-attr cookies "get") name))

    (define (build-cookie name value path max-age same-site)
      (+ name "=" value
         "; Path=" path
         "; Max-Age=" (str max-age)
         "; Secure; HttpOnly; SameSite=" same-site))

    (define (clear-cookie name path same-site)
      (+ name "=; Path=" path
         "; Max-Age=0; Secure; HttpOnly; SameSite=" same-site))

    ;; ---- misc

    (define (for-each-item items function)
      (tuple (map function items)))
    ))

(provide python)
