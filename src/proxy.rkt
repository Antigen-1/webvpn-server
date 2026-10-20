#lang racket/base

;; The reverse proxy's policy, kept away from HTTP plumbing: which upstream a
;; target names, how a URL in a page becomes a URL under /proxy/<target>/, how
;; cookies are namespaced, and how a request is made with http.client.
;;
;; Redirects are never followed here.  They are rewritten and handed to the
;; browser, so the browser stays the only thing that decides where to go.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define bridge (import pyimports))
    (define util (import util))
    (define re (object-get-attr bridge "re"))
    (define gzip (object-get-attr bridge "gzip"))
    (define zlib (object-get-attr bridge "zlib"))
    (define ssl (object-get-attr bridge "ssl"))
    (define http-client (object-get-attr bridge "http_client"))
    (define posixpath (object-get-attr bridge "posix_path"))

    (define text-value? (object-get-attr util "text_p"))
    (define some? (object-get-attr util "some_p"))
    (define none? (object-get-attr util "none_p"))
    (define to-text (object-get-attr util "to_text"))
    (define text-split (object-get-attr util "text_split"))
    (define text-join (object-get-attr util "text_join"))
    (define text-strip (object-get-attr util "text_strip"))
    (define text-lower (object-get-attr util "text_lower"))
    (define text-startswith? (object-get-attr util "text_startswith_p"))
    (define text-contains? (object-get-attr util "text_contains_p"))
    (define text-find (object-get-attr util "text_find"))
    (define text-substr (object-get-attr util "text_substr"))
    (define text-replace (object-get-attr util "text_replace"))
    (define header-name? (object-get-attr util "header_name_p"))
    (define header-safe (object-get-attr util "header_safe"))
    (define parse-cookies (object-get-attr util "parse_cookies"))
    (define url-split (object-get-attr util "url_split"))
    (define url-origin-key (object-get-attr util "url_origin_key"))
    (define url-unquote (object-get-attr util "url_unquote"))
    (define decode-bytes (object-get-attr util "decode_bytes"))
    (define encode-charset (object-get-attr util "encode_charset"))

    (define ignore-case (object-get-attr re "IGNORECASE"))
    (define dot-all (object-get-attr re "DOTALL"))
    (define regex-flags (\| ignore-case dot-all))
    (define attr-pattern
      ((object-get-attr re "compile")
       "(\\b(?:href|src|action|formaction|poster|data|cite)\\s*=\\s*)([\"'])(.*?)\\2"
       regex-flags))
    (define srcset-pattern
      ((object-get-attr re "compile") "(\\bsrcset\\s*=\\s*)([\"'])(.*?)\\2" regex-flags))
    (define css-url-pattern
      ((object-get-attr re "compile") "(?i)url\\(\\s*(['\"]?)(.*?)\\1\\s*\\)" regex-flags))
    (define css-import-pattern
      ((object-get-attr re "compile") "(?i)(@import\\s+)([\"'])(.*?)\\2" regex-flags))
    (define scheme-pattern
      ((object-get-attr re "compile") "^[A-Za-z][A-Za-z0-9+.-]*:"))

    ;; Always blocked on the request path, before the extensible patterns.
    ;; Hop-by-hop headers, headers this proxy owns, and headers a client must
    ;; not be able to forge towards an upstream.
    (define builtin-blocked-request-headers
      (list "host" "cookie" "content-length" "accept-encoding"
            "connection" "keep-alive" "proxy-authenticate" "proxy-authorization"
            "proxy-connection" "te" "trailer" "transfer-encoding" "upgrade"
            "expect" "forwarded" "via"
            "x-forwarded-for" "x-forwarded-host" "x-forwarded-proto"
            "x-forwarded-port" "x-forwarded-server" "x-real-ip"))

    (define (builtin-blocked-request-header? name)
      (or (in name builtin-blocked-request-headers)
          (text-startswith? name "x-forwarded-")))

    (define (header-blocked-by-pattern? name patterns)
      (header-blocked-by-pattern-loop name patterns 0))

    (define (header-blocked-by-pattern-loop name patterns index)
      (if (>= index (len patterns))
          #f
          (if (some? ((object-get-attr (object-ref patterns index) "fullmatch") name))
              #t
              (header-blocked-by-pattern-loop name patterns (+ index 1)))))

    ;; ---- target index

    (define (target-prefix target namespace)
      (+ "wv_" namespace "_" (object-ref target "name") "_"))

    (define (index-target by-name by-origin target)
      (define name (object-ref target "name"))
      (define key (url-origin-key (object-ref target "scheme") (object-ref target "netloc")))
      (object-set! by-name name target)
      (object-set! by-origin key target)
      None)

    (define (target-index targets)
      (define by-name (dict))
      (define by-origin (dict))
      (tuple (map (lambda (target) (index-target by-name by-origin target)) targets))
      (define index (dict))
      (object-set! index "targets" targets)
      (object-set! index "by_name" by-name)
      (object-set! index "by_origin" by-origin)
      index)

    (define (target-by-name index name)
      ((object-get-attr (object-ref index "by_name") "get") name None))

    (define (target-by-origin index key)
      ((object-get-attr (object-ref index "by_origin") "get") key None))

    ;; ---- what the browser asks for, and what the upstream sees

    (define (bad-path message)
      (raise (+ "路径不合法: " message)))

    (define (check-upstream-path rest)
      (define raw (text-strip rest))
      (define relative ((object-get-attr raw "lstrip") "/"))
      (define decoded (url-unquote relative))
      (if (> (len relative) 8192)
          (bad-path "太长")
          (check-upstream-segments decoded relative)))

    (define (check-upstream-segments decoded relative)
      (define parts (text-split decoded "/"))
      (if (or (text-contains? relative (chr 92))
              (text-contains? relative (chr 0))
              (text-contains? relative (chr 10))
              (text-contains? relative (chr 13))
              (text-contains? decoded (chr 0))
              (text-contains? decoded (chr 10))
              (text-contains? decoded (chr 13))
              (in ".." parts)
              (in "." parts))
          (bad-path "包含 ..、控制字符或反斜杠")
          relative))

    (define (request-target target rest query)
      (define relative (check-upstream-path rest))
      (define raw-query (if (none? query) "" query))
      (if (or (text-contains? raw-query (chr 0))
              (text-contains? raw-query (chr 10))
              (text-contains? raw-query (chr 13)))
          (bad-path "查询字符串包含控制字符")
          (+ "/" relative (if (> (len raw-query) 0) (+ "?" raw-query) ""))))

    ;; ---- rewriting URLs in pages

    (define (proxy-url target path query fragment)
      (define safe-path (if (> (len path) 0) path "/"))
      (+ "/proxy/" (object-ref target "name") safe-path
         (if (> (len query) 0) (+ "?" query) "")
         (if (> (len fragment) 0) (+ "#" fragment) "")))

    (define (absolute-proxy-url value target index)
      (define parsed (url-split value))
      (define scheme (text-lower (object-get-attr parsed "scheme")))
      (if (not (or (= scheme "http") (= scheme "https")))
          value
          (absolute-proxy-url-scheme parsed scheme target index value)))

    (define (absolute-proxy-url-scheme parsed scheme target index value)
      (define netloc (object-get-attr parsed "netloc"))
      (if (= (len netloc) 0)
          value
          (absolute-proxy-url-owner parsed scheme netloc target index value)))

    (define (absolute-proxy-url-owner parsed scheme netloc target index value)
      (define match (target-by-origin index (url-origin-key scheme netloc)))
      (if (none? match)
          value
          (absolute-proxy-url-match parsed match)))

    (define (absolute-proxy-url-match parsed match)
      (define path (object-get-attr parsed "path"))
      (define safe-path (if (text-startswith? path "/") path (+ "/" path)))
      (proxy-url match safe-path (object-get-attr parsed "query") (object-get-attr parsed "fragment")))

    (define (normalized-root-path path)
      (define normalized ((object-get-attr posixpath "normpath") path))
      (define absolute (if (text-startswith? normalized "/") normalized (+ "/" normalized)))
      (if (text-startswith? absolute "//")
          (+ "/" ((object-get-attr absolute "lstrip") "/"))
          absolute))

    (define (root-relative-proxy-url value target)
      (define parsed (url-split value))
      (define path (normalized-root-path (object-get-attr parsed "path")))
      (proxy-url target path (object-get-attr parsed "query") (object-get-attr parsed "fragment")))

    (define (rewrite-url value target index)
      (define trimmed (text-strip value))
      (cond
        [(= (len trimmed) 0) value]
        [(text-startswith? trimmed "#") value]
        [(text-startswith? trimmed "//") (rewrite-scheme-relative value target index)]
        [(text-startswith? trimmed "/")
         (if (text-startswith? trimmed "/proxy/")
             value
             (root-relative-proxy-url trimmed target))]
        [(some? ((object-get-attr scheme-pattern "match") trimmed))
         (absolute-proxy-url trimmed target index)]
        [else value]))

    (define (rewrite-scheme-relative value target index)
      (define absolute (+ "https:" value))
      (define rewritten (absolute-proxy-url absolute target index))
      (if (equal? rewritten absolute) value rewritten))

    (define (rewrite-location value target index)
      (rewrite-url value target index))

    (define (rewrite-refresh value target index)
      (define position (text-find value "url="))
      (if (< position 0)
          value
          (+ (text-substr value 0 (+ position 4))
             (rewrite-url (text-substr value (+ position 4) None) target index))))

    (define (group match number)
      ((object-get-attr match "group") number))

    (define (rewrite-attr-match match target index)
      (+ (group match 1) (group match 2)
         (rewrite-url (group match 3) target index)
         (group match 2)))

    (define (rewrite-srcset-candidate candidate target index)
      (define stripped (text-strip candidate))
      (if (= (len stripped) 0)
          stripped
          (rewrite-srcset-parts stripped target index)))

    (define (rewrite-srcset-parts stripped target index)
      (define parts ((object-get-attr stripped "split")))
      (define first-url (rewrite-url (object-ref parts 0) target index))
      (define descriptor (text-join " " (object-ref parts (slice 1 None))))
      (if (> (len descriptor) 0)
          (+ first-url " " descriptor)
          first-url))

    (define (rewrite-srcset-value value target index)
      (text-join ", "
                 (tuple (map (lambda (candidate)
                               (rewrite-srcset-candidate candidate target index))
                             (text-split value ",")))))

    (define (rewrite-srcset-match match target index)
      (+ (group match 1) (group match 2)
         (rewrite-srcset-value (group match 3) target index)
         (group match 2)))

    (define (rewrite-css-match match target index)
      (+ "url(" (group match 1)
         (rewrite-url (group match 2) target index)
         (group match 1) ")"))

    (define (rewrite-import-match match target index)
      (+ (group match 1) (group match 2)
         (rewrite-url (group match 3) target index)
         (group match 2)))

    (define (rewrite-html text target index)
      (define attributes
        ((object-get-attr attr-pattern "sub")
         (lambda (match) (rewrite-attr-match match target index)) text))
      (define srcsets
        ((object-get-attr srcset-pattern "sub")
         (lambda (match) (rewrite-srcset-match match target index)) attributes))
      (define urls
        ((object-get-attr css-url-pattern "sub")
         (lambda (match) (rewrite-css-match match target index)) srcsets))
      ((object-get-attr css-import-pattern "sub")
       (lambda (match) (rewrite-import-match match target index)) urls))

    (define (rewrite-css text target index)
      (define urls
        ((object-get-attr css-url-pattern "sub")
         (lambda (match) (rewrite-css-match match target index)) text))
      ((object-get-attr css-import-pattern "sub")
       (lambda (match) (rewrite-import-match match target index)) urls))

    ;; ---- cookies: one namespace per target

    (define (cookie-flag flags key default)
      ((object-get-attr flags "get") key default))

    (define (cookie-attribute-scan parts index extras flags)
      (if (>= index (len parts))
          extras
          (cookie-attribute-scan-one parts index extras flags)))

    (define (cookie-attribute-scan-one parts index extras flags)
      (define attribute (text-strip (object-ref parts index)))
      (define lower (text-lower attribute))
      (cond
        [(= (len attribute) 0)
         (cookie-attribute-scan parts (+ index 1) extras flags)]
        [(text-startswith? lower "domain=")
         (cookie-attribute-scan parts (+ index 1) extras flags)]
        [(text-startswith? lower "path=")
         (cookie-attribute-scan parts (+ index 1) extras flags)]
        [(= lower "secure")
         (cookie-attribute-scan parts (+ index 1) extras flags)]
        [(= lower "httponly")
         (scan-httponly parts index extras flags)]
        [(text-startswith? lower "samesite=")
         (scan-samesite parts index extras flags attribute)]
        [else
         (cookie-attribute-scan parts (+ index 1) (+ extras (list attribute)) flags)]))

    (define (scan-httponly parts index extras flags)
      (object-set! flags "httponly" #t)
      (cookie-attribute-scan parts (+ index 1) extras flags))

    (define (scan-samesite parts index extras flags attribute)
      (object-set! flags "samesite" (text-substr attribute 9 None))
      (cookie-attribute-scan parts (+ index 1) extras flags))

    (define (valid-same-site value)
      (if (in value (list "Strict" "Lax" "None")) value "Lax"))

    (define (cookie-attribute-list target extras flags)
      (define path (+ "Path=/proxy/" (object-ref target "name") "/"))
      (+ (list path "Secure")
         (if (cookie-flag flags "httponly" #f) (list "HttpOnly") (list))
         (list (+ "SameSite=" (valid-same-site (cookie-flag flags "samesite" "Lax"))))
         extras))

    (define (rewrite-set-cookie header target namespace)
      (define parts (text-split header ";"))
      (define first (object-ref parts 0))
      (define pair ((object-get-attr first "partition") "="))
      (define name (text-strip (object-ref pair 0)))
      (define value (object-ref pair 2))
      (if (or (= (len name) 0) (not (header-name? name)))
          None
          (rewrite-set-cookie-parts parts target name value namespace)))

    (define (rewrite-set-cookie-parts parts target name value namespace)
      (define new-name (+ (target-prefix target namespace) name))
      (if (not (header-name? new-name))
          None
          (rewrite-set-cookie-build parts target new-name value)))

    (define (rewrite-set-cookie-build parts target new-name value)
      (define flags (dict))
      (define extras (cookie-attribute-scan parts 1 (list) flags))
      (define attributes (cookie-attribute-list target extras flags))
      (define result (+ new-name "=" value "; " (text-join "; " attributes)))
      (if (> (len result) 4096) None result))

    (define (cookie-entry entry prefix)
      (define name (object-ref entry 0))
      (define value (object-ref entry 1))
      (if (text-startswith? name prefix)
          (+ (text-substr name (len prefix) None) "=" value)
          None))

    (define (request-cookie-header header target namespace)
      (define cookies (parse-cookies header))
      (define entries (tuple ((object-get-attr cookies "items"))))
      (define prefix (target-prefix target namespace))
      (define pieces
        (tuple (filter (lambda (piece) (some? piece))
                       (tuple (map (lambda (entry) (cookie-entry entry prefix)) entries)))))
      (if (= (len pieces) 0)
          None
          (text-join "; " pieces)))

    ;; ---- the request the upstream receives

    (define (incoming-header result pair)
      (define name (text-lower (to-text (object-ref pair 0))))
      (define value (to-text (object-ref pair 1)))
      (if (header-name? name)
          (object-set! result name value)
          None))

    (define (header-list-to-dict headers)
      (define result (dict))
      (tuple (map (lambda (pair) (incoming-header result pair)) headers))
      result)

    (define (add-connection-token result token)
      (define name (text-strip (text-lower token)))
      (if (> (len name) 0)
          (object-set! result name #t)
          None))

    ;; RFC 7230: Connection lists headers that are hop-by-hop for this hop,
    ;; even if their names are not in the fixed list above.
    (define (connection-blocked-headers incoming)
      (define result (dict))
      (define value ((object-get-attr incoming "get") "connection" None))
      (if (some? value)
          (tuple (map (lambda (token) (add-connection-token result token))
                      (text-split value ",")))
          None)
      result)

    (define (forward-incoming-header incoming result name connection-blocked patterns)
      (if (or (builtin-blocked-request-header? name)
              (in name connection-blocked)
              (header-blocked-by-pattern? name patterns))
          None
          (object-set! result name (object-ref incoming name))))

    (define (filter-request-headers headers target namespace blocked-patterns)
      (define incoming (header-list-to-dict headers))
      (define result (dict))
      (define connection-blocked (connection-blocked-headers incoming))
      (define names (tuple ((object-get-attr incoming "keys"))))
      (tuple (map (lambda (name)
                    (forward-incoming-header incoming result name
                                             connection-blocked blocked-patterns))
                  names))
      (object-set! result "Host" (object-ref target "netloc"))
      (object-set! result "Accept-Encoding" "identity")
      (define cookie (request-cookie-header ((object-get-attr incoming "get") "cookie" None)
                                            target namespace))
      (if (some? cookie)
          (object-set! result "Cookie" cookie)
          None)
      result)

    ;; ---- http.client

    (define (close-connection connection)
      (with-handler (lambda (e) None)
                    ((object-get-attr connection "close"))))

    (define (close-and-raise connection error)
      (close-connection connection)
      (raise error))

    (define (ssl-context verify-tls)
      (if verify-tls
          ((object-get-attr ssl "create_default_context"))
          ((object-get-attr ssl "_create_unverified_context"))))

    (define (open-connection target verify-tls timeout)
      (define host (object-ref target "host"))
      (define port (object-ref target "port"))
      (if (= (object-ref target "scheme") "https")
          ((object-get-attr http-client "HTTPSConnection")
           host port #:timeout timeout #:context (ssl-context verify-tls))
          ((object-get-attr http-client "HTTPConnection") host port #:timeout timeout)))

    (define (fetch-upstream target method request-target headers body
                            verify-tls timeout max-response)
      (define connection (open-connection target verify-tls timeout))
      (with-handler
       (lambda (e) (close-and-raise connection e))
       (fetch-upstream-read connection method request-target headers body max-response)))

    (define (fetch-upstream-read connection method request-target headers body max-response)
      ((object-get-attr connection "request") method request-target
                                                #:body body #:headers headers)
      (define response ((object-get-attr connection "getresponse")))
      (define answer-body ((object-get-attr response "read") (+ max-response 1)))
      (if (> (len answer-body) max-response)
          (raise "上游响应超过 max_response")
          #t)
      (define result (dict))
      (object-set! result "status" (object-get-attr response "status"))
      (object-set! result "reason" (object-get-attr response "reason"))
      (object-set! result "headers" (tuple ((object-get-attr response "getheaders"))))
      (object-set! result "body" answer-body)
      (close-connection connection)
      result)

    ;; ---- response rewriting

    (define (header-value headers name)
      (header-value-loop headers (text-lower name) 0))

    (define (header-value-loop headers name index)
      (if (>= index (len headers))
          None
          (header-value-one headers name index)))

    (define (header-value-one headers name index)
      (define pair (object-ref headers index))
      (if (= (text-lower (object-ref pair 0)) name)
          (object-ref pair 1)
          (header-value-loop headers name (+ index 1))))

    (define (media-kind headers)
      (define content-type (header-value headers "content-type"))
      (if (none? content-type)
          None
          (media-kind-text content-type)))

    (define (media-kind-text content-type)
      (define parts (text-split content-type ";"))
      (define base (text-lower (text-strip (object-ref parts 0))))
      (cond
        [(= base "text/html") "html"]
        [(= base "application/xhtml+xml") "html"]
        [(= base "text/css") "css"]
        [else None]))

    (define (content-charset headers)
      (define content-type (header-value headers "content-type"))
      (if (none? content-type)
          "utf-8"
          (content-charset-text content-type)))

    (define (content-charset-text content-type)
      (content-charset-parts (text-split content-type ";") 1 "utf-8"))

    (define (content-charset-parts parts index default)
      (if (>= index (len parts))
          default
          (content-charset-one parts index default)))

    (define (content-charset-one parts index default)
      (define parameter (text-strip (object-ref parts index)))
      (if (text-startswith? (text-lower parameter) "charset=")
          (text-strip (text-replace (text-substr parameter 8 None) "\"" ""))
          (content-charset-parts parts (+ index 1) default)))

    (define (decompress-body headers body)
      (define encoding (header-value headers "content-encoding"))
      (if (or (none? encoding) (= (len body) 0))
          body
          (decompress-body-encoding (text-lower (text-strip encoding)) body)))

    (define (decompress-body-encoding encoding body)
      (cond
        [(or (= encoding "") (= encoding "identity")) body]
        [(= encoding "gzip") (decompress-gzip body)]
        [(= encoding "deflate") (decompress-deflate body)]
        [else (raise (+ "不支持的上游压缩编码: " encoding))]))

    (define (decompress-gzip body)
      (with-handler (lambda (e) (raise "无法解压上游 gzip 响应"))
                    ((object-get-attr gzip "decompress") body)))

    (define (decompress-deflate body)
      (with-handler (lambda (e) (raise "无法解压上游 deflate 响应"))
                    ((object-get-attr zlib "decompress") body)))

    (define (drop-header? name)
      (in name (list "connection" "keep-alive" "transfer-encoding" "upgrade"
                     "trailer" "te" "proxy-authenticate" "proxy-authorization"
                     "server" "date" "alt-svc" "via"
                     "strict-transport-security"
                     "x-content-type-options" "referrer-policy"
                     "content-security-policy" "content-security-policy-report-only")))

    (define (rewrite-set-cookie-header value target namespace)
      (define rewritten (rewrite-set-cookie value target namespace))
      (if (none? rewritten) (list) (list (list "set-cookie" (header-safe rewritten)))))

    (define (rewrite-one-header header target index head? namespace blocked-patterns)
      (define name (text-lower (object-ref header 0)))
      (define value (object-ref header 1))
      (cond
        [(header-blocked-by-pattern? name blocked-patterns) (list)]
        [(= name "set-cookie") (rewrite-set-cookie-header value target namespace)]
        [(= name "location")
         (list (list "location" (header-safe (rewrite-location value target index))))]
        [(= name "refresh")
         (list (list "refresh" (header-safe (rewrite-refresh value target index))))]
        [(= name "content-length")
         (if head? (list (list "content-length" (header-safe value))) (list))]
        [(= name "content-encoding") (list)]
        [(drop-header? name) (list)]
        [(header-name? name) (list (list name (header-safe value)))]
        [else (list)]))

    (define (rewrite-headers headers index target target-index head? namespace blocked-patterns)
      (if (>= index (len headers))
          (list)
          (+ (rewrite-one-header (object-ref headers index) target target-index head? namespace
                                 blocked-patterns)
             (rewrite-headers headers (+ index 1) target target-index head? namespace
                              blocked-patterns))))

    (define (rewrite-body body headers target index head? status)
      (define kind (media-kind headers))
      (if (or head? (none? kind) (= (len body) 0) (in status (list 204 304)))
          body
          (rewrite-body-text body kind (content-charset headers) target index)))

    (define (rewrite-body-text body kind charset target index)
      (define text (decode-bytes body charset))
      (define rewritten (if (= kind "html")
                            (rewrite-html text target index)
                            (rewrite-css text target index)))
      (encode-charset rewritten charset))

    (define (rewrite-response result target index head? namespace blocked-patterns)
      (define status (object-ref result "status"))
      (define headers (object-ref result "headers"))
      (define body (if head?
                       (object-ref result "body")
                       (decompress-body headers (object-ref result "body"))))
      (define rewritten-body (rewrite-body body headers target index head? status))
      (define answer (dict))
      (object-set! answer "status" status)
      (object-set! answer "reason" (object-ref result "reason"))
      (object-set! answer "headers"
                   (rewrite-headers headers 0 target index head? namespace blocked-patterns))
      (object-set! answer "body" rewritten-body)
      answer)
    ))

(provide python)
