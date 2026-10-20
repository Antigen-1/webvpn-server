#lang racket/base

;; The HTTP layer on top of FastAPI: routes, sessions, CSRF, login rate
;; limiting, the portal and the authenticated proxy.  FastAPI only carries the
;; ASGI request into handle-request and the returned Starlette response back;
;; every decision below is Racket code compiled by rkt-pythonize.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define bridge (import pyimports))
    (define util (import util))
    (define auth (import auth))
    (define pages (import pages))
    (define proxy (import proxy))
    (define sys (object-get-attr bridge "sys"))
    (define ipaddress (object-get-attr bridge "ipaddress"))

    (define text-lower (object-get-attr util "text_lower"))
    (define text-strip (object-get-attr util "text_strip"))
    (define text-join (object-get-attr util "text_join"))
    (define text-split (object-get-attr util "text_split"))
    (define text-contains? (object-get-attr util "text_contains_p"))
    (define text-startswith? (object-get-attr util "text_startswith_p"))
    (define text-substr (object-get-attr util "text_substr"))
    (define text-find (object-get-attr util "text_find"))
    (define to-text (object-get-attr util "to_text"))
    (define some? (object-get-attr util "some_p"))
    (define none? (object-get-attr util "none_p"))
    (define parse-cookies (object-get-attr util "parse_cookies"))
    (define decode-bytes (object-get-attr util "decode_bytes"))
    (define url-parse-qs (object-get-attr util "url_parse_qs"))
    (define url-first-param (object-get-attr util "url_first_param"))
    (define url-quote (object-get-attr util "url_quote"))
    (define url-unquote (object-get-attr util "url_unquote"))
    (define safe-int (object-get-attr util "safe_int"))
    (define now (object-get-attr util "now"))
    (define log-info (object-get-attr util "log_info"))
    (define log-warn (object-get-attr util "log_warn"))
    (define log-error (object-get-attr util "log_error"))
    (define error-text (object-get-attr util "error_text"))

    (define content-security-policy
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    (define proxy-methods (list "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" "OPTIONS"))
    (define max-form-body 8192)
    (define max-sessions 1024)
    (define session-cookie-name "webvpn_session")
    (define csrf-cookie-name "webvpn_csrf")

    (define app-state None)

    ;; ---- headers and responses

    (define (fallback-config)
      (define config (dict))
      (object-set! config "hsts" #f)
      config)

    (define (base-headers config csp?)
      (define security
        (list (list "X-Content-Type-Options" "nosniff")
              (list "Referrer-Policy" "no-referrer")))
      (define hsts
        (if (object-ref config "hsts")
            (list (list "Strict-Transport-Security" "max-age=31536000"))
            (list)))
      (define page
        (if csp?
            (list (list "Content-Security-Policy" content-security-policy)
                  (list "X-Frame-Options" "DENY")
                  (list "Cache-Control" "no-store"))
            (list)))
      (+ security hsts page))

    (define (html-answer config status text csp? cookies)
      ((object-get-attr bridge "html_response") text status
                                                  (base-headers config csp?) cookies))

    (define (text-response-body config status text extra cookies)
      ((object-get-attr bridge "text_response") text status
                                                   (+ (base-headers config #f) extra)
                                                   cookies))

    (define (redirect-answer-status config location status cookies)
      ((object-get-attr bridge "redirect") location status cookies (base-headers config #t)))

    (define (redirect-answer config location cookies)
      (redirect-answer-status config location 303 cookies))

    (define (empty-answer config status extra)
      ((object-get-attr bridge "response") (bytes) status
                                            (+ (base-headers config #f) extra) (list)))

    (define (error-answer config status message)
      (html-answer config status ((object-get-attr pages "error_page") status message)
                   #t (list)))

    (define (method-not-allowed config allow)
      ((object-get-attr bridge "text_response")
       "method not allowed" 405
       (+ (base-headers config #f) (list (list "Allow" allow))) (list)))

    ;; ---- request helpers

    (define (header-values headers name)
      (header-values-loop headers (text-lower name) 0 (list)))

    (define (header-values-loop headers name index result)
      (if (>= index (len headers))
          result
          (header-values-one headers name index result)))

    (define (header-values-one headers name index result)
      (define pair (object-ref headers index))
      (if (= (text-lower (object-ref pair 0)) name)
          (header-values-loop headers name (+ index 1)
                              (+ result (list (object-ref pair 1))))
          (header-values-loop headers name (+ index 1) result)))

    (define (header-value headers name)
      (define values (header-values headers name))
      (if (= (len values) 0) None (object-ref values 0)))

    (define (header-int headers name)
      (define value (header-value headers name))
      (if (none? value) None (safe-int value None)))

    (define (request-header info name)
      (header-value (object-ref info "headers") name))

    (define (request-cookie-string info)
      (text-join "; " (header-values (object-ref info "headers") "cookie")))

    (define (request-cookies info)
      (parse-cookies (request-cookie-string info)))

    (define (cookie-value cookies name)
      ((object-get-attr cookies "get") name None))

    (define (session-from-request app info)
      (define cookies (request-cookies info))
      (define sid (cookie-value cookies session-cookie-name))
      (if (none? sid)
          None
          (auth.get-session (object-ref app "sessions") sid)))

    (define (valid-ip? value)
      (some? (with-handler (lambda (e) None)
                           ((object-get-attr ipaddress "ip_address") value))))

    (define (client-ip app info)
      (define config (object-ref app "config"))
      (define direct (to-text (object-ref info "client_ip")))
      (if (object-ref config "trust_proxy")
          (client-ip-forwarded (to-text (object-ref info "forwarded_for")) direct)
          (if (> (len direct) 0) direct "unknown")))

    (define (client-ip-forwarded forwarded direct)
      (if (= (len forwarded) 0)
          (if (> (len direct) 0) direct "unknown")
          (client-ip-first (text-strip (object-ref (text-split forwarded ",") 0)) direct)))

    (define (client-ip-first candidate direct)
      (if (valid-ip? candidate)
          candidate
          (if (> (len direct) 0) direct "unknown")))

    (define (safe-next value)
      (if (none? value)
          "/"
          (safe-next-text (to-text value))))

    (define (safe-next-text value)
      (define decoded (url-unquote value))
      (if (or (= (len value) 0)
              (> (len value) 2048)
              (not (text-startswith? value "/"))
              (text-startswith? value "//")
              (text-contains? value (chr 92))
              (text-contains? value (chr 10))
              (text-contains? value (chr 13))
              (not (text-startswith? decoded "/"))
              (text-startswith? decoded "//")
              (text-contains? decoded (chr 92))
              (text-contains? decoded (chr 10))
              (text-contains? decoded (chr 13)))
          "/"
          value))

    (define (login-location info)
      (define query (to-text (object-ref info "query")))
      (define path (to-text (object-ref info "path")))
      (define target (+ path (if (> (len query) 0) (+ "?" query) "")))
      (+ "/login?next=" (url-quote target)))

    (define (form-content-type? info)
      (define value (request-header info "content-type"))
      (if (none? value)
          #f
          (text-startswith? (text-lower value) "application/x-www-form-urlencoded")))

    (define (form-from-body body)
      (url-parse-qs (decode-bytes body "utf-8")))

    (define (form-value form name)
      (define value (url-first-param form name))
      (if (none? value) "" value))

    ;; ---- pages and the portal

    (define (portal-answer app info session)
      (define config (object-ref app "config"))
      (define body ((object-get-attr pages "portal_page")
                    (object-ref session "user") (object-ref app "targets")
                    (object-ref session "csrf")))
      (html-answer config 200 body #t (list)))

    (define (handle-portal app info)
      (define session (session-from-request app info))
      (if (none? session)
          (redirect-answer (object-ref app "config") (login-location info) (list))
          (portal-answer app info session)))

    (define (login-page-answer config status message next extra)
      (define token (auth.new-csrf-token))
      (define body ((object-get-attr pages "login_page") token next message))
      ((object-get-attr bridge "html_response")
       body status (+ (base-headers config #t) extra)
       (list (auth.csrf-cookie token))))

    (define (handle-login-get app info)
      (define session (session-from-request app info))
      (if (some? session)
          (redirect-answer (object-ref app "config") "/" (list))
          (handle-login-form app info)))

    (define (handle-login-form app info)
      (define config (object-ref app "config"))
      (define next (safe-next (url-first-param
                               (url-parse-qs (to-text (object-ref info "query")))
                               "next")))
      (login-page-answer config 200 "" next (list)))

    (define (handle-login-post app info body)
      (define session (session-from-request app info))
      (if (some? session)
          (redirect-answer (object-ref app "config") "/" (list))
          (handle-login-post-valid app info body)))

    (define (handle-login-post-valid app info body)
      (define config (object-ref app "config"))
      (if (not (form-content-type? info))
          (error-answer config 415 "登录请求必须使用 application/x-www-form-urlencoded")
          (if (> (len body) max-form-body)
              (error-answer config 413 "登录请求过大")
              (handle-login-fields app info body))))

    (define (handle-login-fields app info body)
      (define config (object-ref app "config"))
      (define form (form-from-body body))
      (define cookies (request-cookies info))
      (define csrf-cookie-value (cookie-value cookies csrf-cookie-name))
      (define csrf-form-value (form-value form "csrf"))
      (if (not (auth.constant-equal csrf-cookie-value csrf-form-value))
          (error-answer config 403 "登录表单已失效，请刷新页面后重试")
          (handle-login-rate app info form)))

    (define (handle-login-rate app info form)
      (define ip (client-ip app info))
      (define limiter (object-ref app "limiter"))
      (define current (now))
      (define next (safe-next (form-value form "next")))
      (if (not (auth.limiter-check limiter ip current))
          (handle-login-throttled app info ip limiter current next)
          (handle-login-credentials app info form ip limiter current next)))

    (define (handle-login-throttled app info ip limiter current next)
      (define config (object-ref app "config"))
      (define retry (auth.limiter-retry-after limiter ip current))
      (log-warn (+ "login throttled for " ip))
      (login-page-answer config 429 "尝试次数过多，请稍后再试" next
                         (list (list "Retry-After" (str retry)))))

    (define (handle-login-credentials app info form ip limiter current next)
      (define username (form-value form "username"))
      (define password (form-value form "password"))
      (if (auth.verify-user-password password (object-ref app "users") username)
          (handle-login-success app info username next ip limiter)
          (handle-login-failure app info username next ip limiter)))

    (define (handle-login-success app info username next ip limiter)
      (define config (object-ref app "config"))
      (auth.limiter-clear limiter ip)
      (define sid (auth.create-session (object-ref app "sessions") username))
      (if (none? sid)
          (error-answer config 503 "会话数量已达上限，请稍后再试")
          (handle-login-session app info sid username next ip)))

    (define (handle-login-session app info sid username next ip)
      (define config (object-ref app "config"))
      (define ttl (object-ref config "session_ttl"))
      (log-info (+ "login ok user=" username " ip=" ip))
      (redirect-answer config next
                       (list (auth.session-cookie sid ttl)
                             (auth.clear-csrf-cookie))))

    (define (handle-login-failure app info username next ip limiter)
      (define config (object-ref app "config"))
      (auth.limiter-fail limiter ip (now))
      (log-warn (+ "login failed ip=" ip))
      (login-page-answer config 401 "用户名或密码错误" next (list)))

    (define (handle-logout app info body)
      (define config (object-ref app "config"))
      (define session (session-from-request app info))
      (if (none? session)
          (redirect-answer config "/login" (list))
          (handle-logout-valid app info body session)))

    (define (handle-logout-valid app info body session)
      (define config (object-ref app "config"))
      (if (not (form-content-type? info))
          (error-answer config 415 "退出请求必须使用 application/x-www-form-urlencoded")
          (if (> (len body) max-form-body)
              (error-answer config 413 "退出请求过大")
              (handle-logout-csrf app info body session))))

    (define (handle-logout-csrf app info body session)
      (define config (object-ref app "config"))
      (define token (form-value (form-from-body body) "csrf"))
      (if (not (auth.session-csrf? session token))
          (error-answer config 403 "退出表单已失效，请刷新页面后重试")
          (handle-logout-commit app info session)))

    (define (handle-logout-commit app info session)
      (define config (object-ref app "config"))
      (auth.drop-session (object-ref app "sessions") (object-ref session "sid"))
      (log-info (+ "logout user=" (object-ref session "user")
                   " ip=" (client-ip app info)))
      (redirect-answer config "/login" (list (auth.clear-session-cookie))))

    ;; ---- health and CORS-free options

    (define (handle-health app info)
      (text-response-body (object-ref app "config") 200 "ok"
                          (list (list "Cache-Control" "no-store")) (list)))

    (define (handle-options app info)
      (empty-answer (object-ref app "config") 204
                    (list (list "Allow" "GET, HEAD, POST, OPTIONS"))))

    ;; ---- the proxy

    (define (capture-error info error)
      (log-error (+ "proxy failed " (to-text (object-ref info "method")) " "
                    (to-text (object-ref info "path")) ": " (error-text error)))
      (define original (if (isinstance error Exception)
                           (getattr error "value" error)
                           error))
      (define result (dict))
      (object-set! result "error" (error-text error))
      (object-set! result "timeout"
                   (or (isinstance error TimeoutError)
                       (isinstance original TimeoutError)))
      result)

    (define (proxy-error-answer config info failure)
      (define message (object-ref failure "error"))
      (cond
        [(text-contains? message "路径") (error-answer config 400 "请求路径不合法")]
        [(object-ref failure "timeout") (error-answer config 504 "上游站点响应超时")]
        [(text-contains? message "max_response") (error-answer config 502 "上游站点响应过大")]
        [else (error-answer config 502 "无法访问上游站点")]))

    (define (proxy-answer config rewritten head?)
      (define body (object-ref rewritten "body"))
      (define status (object-ref rewritten "status"))
      (define headers (+ (base-headers config #f) (object-ref rewritten "headers")))
      (define head-length
        (if head?
            (header-int (object-ref rewritten "headers") "content-length")
            None))
      (if (some? head-length)
          ((object-get-attr bridge "response") body status headers (list)
                                              #:content_length head-length)
          ((object-get-attr bridge "response") body status headers (list))))

    (define (handle-proxy app info body)
      (define session (session-from-request app info))
      (if (none? session)
          (handle-proxy-unauthenticated app info)
          (handle-proxy-authenticated app info body session)))

    (define (handle-proxy-unauthenticated app info)
      (define config (object-ref app "config"))
      (define method (to-text (object-ref info "method")))
      (if (or (= method "GET") (= method "HEAD"))
          (redirect-answer config (login-location info) (list))
          (text-response-body config 401 "authentication required"
                              (list (list "WWW-Authenticate" "WebVPN")) (list))))

    (define (handle-proxy-authenticated app info body session)
      (define config (object-ref app "config"))
      (define raw-path (to-text (object-ref info "raw_path")))
      (define after-prefix (substring-after raw-path "/proxy/"))
      (define slash (text-find after-prefix "/"))
      (define name (if (= slash -1) after-prefix (text-substr after-prefix 0 slash)))
      (define rest (if (= slash -1) "" (text-substr after-prefix slash None)))
      (define target (proxy.target-by-name (object-ref app "index") name))
      (if (none? target)
          (error-answer config 404 "没有这个内网站点")
          (if (= slash -1)
              (proxy-canonical-redirect config name (to-text (object-ref info "query")))
              (handle-proxy-target app info body target rest
                               (object-ref session "namespace")))))

    (define (proxy-canonical-redirect config name query)
      (redirect-answer-status config
                              (+ "/proxy/" name "/"
                                 (if (> (len query) 0) (+ "?" query) ""))
                              308 (list)))

    (define (substring-after text prefix)
      (if (text-startswith? text prefix)
          (text-substr text (len prefix) None)
          text))

    (define (handle-proxy-target app info body target rest namespace)
      (define config (object-ref app "config"))
      (define request-target
        (with-handler (lambda (e) None)
                      (proxy.request-target target rest (to-text (object-ref info "query")))))
      (if (none? request-target)
          (error-answer config 400 "请求路径不合法")
          (handle-proxy-fetch app info body target request-target namespace)))

    (define (handle-proxy-fetch app info body target request-target namespace)
      (define config (object-ref app "config"))
      (define method (to-text (object-ref info "method")))
      (define head? (= method "HEAD"))
      (define headers
        (proxy.filter-request-headers (object-ref info "headers") target namespace
                                      (object-ref config "blocked_request_header_patterns")))
      (define result
        (with-handler (lambda (e) (capture-error info e))
                      (proxy.fetch-upstream target method request-target headers body
                                            (object-ref config "verify_upstream_tls")
                                            (object-ref config "upstream_timeout")
                                            (object-ref config "max_response"))))
      (if (in "error" result)
          (proxy-error-answer config info result)
          (handle-proxy-rewrite app info target result head? namespace)))

    (define (handle-proxy-rewrite app info target result head? namespace)
      (define config (object-ref app "config"))
      (define rewritten
        (with-handler (lambda (e) (capture-error info e))
                      (proxy.rewrite-response result target
                                              (object-ref app "index") head? namespace
                                              (object-ref config "blocked_response_header_patterns"))))
      (if (in "error" rewritten)
          (proxy-error-answer config info rewritten)
          (proxy-answer config rewritten head?)))

    ;; ---- routing

    (define (dispatch app info body)
      (define method (to-text (object-ref info "method")))
      (define path (to-text (object-ref info "path")))
      (define config (object-ref app "config"))
      (cond
        [(and (= path "/") (or (= method "GET") (= method "HEAD")))
         (handle-portal app info)]
        [(and (= path "/login") (or (= method "GET") (= method "HEAD")))
         (handle-login-get app info)]
        [(and (= path "/login") (= method "POST"))
         (handle-login-post app info body)]
        [(and (= path "/logout") (= method "POST"))
         (handle-logout app info body)]
        [(and (= path "/healthz") (or (= method "GET") (= method "HEAD")))
         (handle-health app info)]
        [(= path "/favicon.ico")
         (empty-answer config 204 (list))]
        [(text-startswith? path "/proxy/")
         (if (in method proxy-methods)
             (handle-proxy app info body)
             (method-not-allowed config "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"))]
        [(= method "OPTIONS")
         (handle-options app info)]
        [(or (= path "/") (= path "/login") (= path "/healthz"))
         (method-not-allowed config "GET, HEAD, POST, OPTIONS")]
        [(= path "/logout")
         (method-not-allowed config "POST, OPTIONS")]
        [else (error-answer config 404 "页面不存在")]))

    (define (unexpected-error app info error)
      (log-error (+ "request failed " (to-text (object-ref info "method")) " "
                    (to-text (object-ref info "path")) ": " (error-text error)))
      (error-answer (object-ref app "config") 500 "服务器内部错误"))

    (define (handle-request info body)
      (define app app-state)
      (if (none? app)
          (error-answer (fallback-config) 500 "服务器尚未初始化")
          (with-handler (lambda (e) (unexpected-error app info e))
                        (dispatch app info body))))

    ;; ---- starting up

    (define (make-app config)
      (define app (dict))
      (object-set! app "config" config)
      (object-set! app "users" (object-ref config "users"))
      (object-set! app "targets" (object-ref config "targets"))
      (object-set! app "index" (proxy.target-index (object-ref config "targets")))
      (object-set! app "sessions"
                   (auth.make-session-store (object-ref config "session_ttl")
                                            max-sessions))
      (object-set! app "limiter"
                   (auth.make-limiter (object-ref config "login_max_attempts")
                                      (object-ref config "login_window")))
      (set! app-state app)
      ((object-get-attr bridge "make_app") handle-request (object-ref config "max_body")))

    (define (serve config)
      (define app (make-app config))
      (define out (object-get-attr sys "stdout"))
      ((object-get-attr out "write")
       (+ "webvpn-server listening on https://"
          (object-ref config "host") ":" (str (object-ref config "port")) "\n"))
      ((object-get-attr out "flush"))
      ((object-get-attr bridge "run") app
                                      (object-ref config "host")
                                      (object-ref config "port")
                                      (object-ref config "cert_file")
                                      (object-ref config "key_file")
                                      (object-ref config "max_body"))
      None)
    ))

(provide python)
