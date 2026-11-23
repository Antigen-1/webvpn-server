#lang racket/base

;; The configuration file: defaults, validation, the sample a new deployment
;; starts with, and the self-signed certificate `init` asks openssl to make.
;;
;; A path in the file is relative to the directory the file itself is in, so a
;; deployment can be moved as one directory.  Validation refuses a target that
;; is not an http(s) origin, a password hash that is not PBKDF2, and a key file
;; other users can read.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define bridge (import pyimports))
    (define util (import util))
    (define auth (import auth))
    (define json (object-get-attr bridge "json"))
    (define os (object-get-attr bridge "os"))
    (define sys (object-get-attr bridge "sys"))
    (define re (object-get-attr bridge "re"))
    (define subprocess (object-get-attr bridge "subprocess"))
    (define secrets (object-get-attr bridge "secrets"))

    (define text-value? (object-get-attr util "text_p"))
    (define some? (object-get-attr util "some_p"))
    (define dict-value? (object-get-attr util "dict_p"))
    (define list-value? (object-get-attr util "list_p"))
    (define bool-value? (object-get-attr util "bool_p"))
    (define integer-value? (object-get-attr util "integer_p"))
    (define text-strip (object-get-attr util "text_strip"))
    (define text-lower (object-get-attr util "text_lower"))
    (define text-join (object-get-attr util "text_join"))
    (define text-contains? (object-get-attr util "text_contains_p"))
    (define to-text (object-get-attr util "to_text"))
    (define json-loads (object-get-attr util "json_loads"))
    (define json-dumps (object-get-attr util "json_dumps"))
    (define read-text (object-get-attr util "read_text"))
    (define write-text (object-get-attr util "write_text"))
    (define ensure-dir (object-get-attr util "ensure_dir"))
    (define chmod (object-get-attr util "chmod"))
    (define file-mode (object-get-attr util "file_mode"))
    (define file-exists? (object-get-attr util "file_exists_p"))
    (define dir-exists? (object-get-attr util "dir_exists_p"))
    (define path-exists? (object-get-attr util "path_exists_p"))
    (define path-join (object-get-attr util "path_join"))
    (define path-abspath (object-get-attr util "path_abspath"))
    (define path-dirname (object-get-attr util "path_dirname"))
    (define absolute-path? (object-get-attr util "absolute_path_p"))
    (define temp-name (object-get-attr util "temp_name"))
    (define replace-file (object-get-attr util "replace_file"))
    (define remove-file (object-get-attr util "remove_file"))
    (define url-split (object-get-attr util "url_split"))
    (define html-escape (object-get-attr util "html_escape"))
    (define error-text (object-get-attr util "error_text"))
    (define hash-password (object-get-attr auth "hash_password"))
    (define valid-hash? (object-get-attr auth "valid_hash_p"))

    (define target-name-pattern
      ((object-get-attr re "compile") "^[A-Za-z][A-Za-z0-9_-]{0,31}$"))
    (define host-pattern
      ((object-get-attr re "compile") "^[A-Za-z0-9_.:-]+$"))
    (define ipv4-pattern
      ((object-get-attr re "compile") "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))

    (define default-host "127.0.0.1")
    (define default-port 8443)
    (define default-session-ttl 28800)
    (define default-login-attempts 5)
    (define default-login-window 300)
    (define default-max-body 16777216)
    (define default-max-response 33554432)
    (define default-upstream-timeout 30)
    (define default-config-name "webvpn.json")

    ;; The configuration lives beside the executable.  PyInstaller sets
    ;; sys.frozen and leaves sys.executable pointing at the launcher, so a
    ;; one-file build finds the file next to the .exe, not in its temporary
    ;; unpack directory.  A source run uses the current directory.
    (define (default-config-path)
      (if (getattr sys "frozen" #f)
          (path-join (list (path-dirname (path-abspath (getattr sys "executable")))
                           default-config-name))
          (path-join (list ((object-get-attr os "getcwd")) default-config-name))))

    (define (default-init-directory)
      (path-dirname (default-config-path)))
    (define default-cert-name "cert.pem")
    (define default-key-name "key.pem")
    (define max-targets 64)
    (define max-header-patterns 64)
    (define max-header-pattern-length 256)
    (define max-cors-origins 32)
    (define max-cors-origin-length 255)

    (define (config-error message)
      (raise (+ "配置错误: " message)))

    (define (raw-value raw key default)
      ((object-get-attr raw "get") key default))

    (define (integer-field raw key default low high label)
      (define value (raw-value raw key default))
      (if (and (integer-value? value)
               (not (bool-value? value))
               (>= value low)
               (<= value high))
          value
          (config-error (+ label " 必须是 " (str low) " 到 " (str high) " 之间的整数"))))

    (define (bool-field raw key default label)
      (define value (raw-value raw key default))
      (if (bool-value? value)
          value
          (config-error (+ label " 必须是 true 或 false"))))

    (define (text-field raw key default label max-length)
      (define value (raw-value raw key default))
      (if (and (text-value? value)
               (> (len value) 0)
               (<= (len value) max-length)
               (equal? (text-strip value) value))
          value
          (config-error (+ label " 必须是非空字符串（最多 " (str max-length) " 个字符）"))))

    (define (safe-file-name value)
      (and (text-value? value)
           (> (len value) 0)
           (not (text-contains? value (chr 0)))
           (not (text-contains? value (chr 10)))
           (not (text-contains? value (chr 13)))
           (not (text-contains? value " "))))

    (define (resolve-path base value)
      (if (absolute-path? value)
          value
          (path-join (list base value))))

    (define (printable-name? value)
      (and (text-value? value)
           (> (len value) 0)
           (<= (len value) 128)
           ((object-get-attr value "isprintable"))
           (equal? (text-strip value) value)))

    ;; ---- users

    (define (validate-user users entry)
      (define name (object-ref entry 0))
      (define encoded (object-ref entry 1))
      (if (not (and (printable-name? name) (<= (len name) 64)))
          (config-error "用户名必须是可打印的、长度不超过 64 的字符串")
          (if (not (valid-hash? encoded))
              (config-error (+ "用户 " (html-escape name) " 的密码不是有效的 pbkdf2_sha256 哈希"))
              (object-set! users name encoded)))
      None)

    (define (normalize-users raw)
      (if (not (dict-value? raw))
          (config-error "users 必须是一个对象，键是用户名，值是密码哈希")
          (normalize-users-dict raw)))

    (define (normalize-users-dict raw)
      (define users (dict))
      (tuple (map (lambda (entry) (validate-user users entry))
                  (tuple ((object-get-attr raw "items")))))
      users)

    ;; ---- targets

    (define (target-host-san host)
      (if (or (some? ((object-get-attr ipv4-pattern "fullmatch") host))
              (text-contains? host ":"))
          (+ "IP:" host)
          (+ "DNS:" host)))

    (define (normalize-target raw index)
      (if (not (dict-value? raw))
          (config-error (+ "targets[" (str index) "] 必须是一个对象"))
          (normalize-target-dict raw index)))

    (define (normalize-target-dict raw index)
      (define name (raw-value raw "name" ""))
      (define label (raw-value raw "label" name))
      (define url (raw-value raw "url" ""))
      (define prefix (+ "targets[" (str index) "]"))
      (if (not (and (text-value? name)
                    (some? ((object-get-attr target-name-pattern "fullmatch") name))))
          (config-error (+ prefix ": name 必须匹配 [A-Za-z][A-Za-z0-9_-]{0,31}"))
          (normalize-target-fields name label url prefix)))

    (define (normalize-target-fields name label url prefix)
      (if (not (printable-name? label))
          (config-error (+ prefix ": label 必须是非空的可打印字符串"))
          (if (not (safe-file-name url))
              (config-error (+ prefix ": url 不合法"))
              (normalize-target-url name label url prefix))))

    (define (normalize-target-url name label url prefix)
      (if (> (len url) 2048)
          (config-error (+ prefix ": url 太长"))
          (normalize-target-parsed name label url prefix (url-split url))))

    (define (normalize-target-parsed name label url prefix parsed)
      (define scheme (text-lower (to-text (object-get-attr parsed "scheme"))))
      (define netloc (to-text (object-get-attr parsed "netloc")))
      (define path (to-text (object-get-attr parsed "path")))
      (define query (to-text (object-get-attr parsed "query")))
      (define fragment (to-text (object-get-attr parsed "fragment")))
      (if (not (or (= scheme "http") (= scheme "https")))
          (config-error (+ prefix ": url 必须以 http:// 或 https:// 开头"))
          (normalize-target-origin name label url prefix scheme netloc path query fragment)))

    (define (normalize-target-origin name label url prefix scheme netloc path query fragment)
      (define invalid-port (list))
      (define raw-host (with-handler (lambda (e) None)
                                     (object-get-attr (url-split url) "hostname")))
      (define raw-port (with-handler (lambda (e) invalid-port)
                                     (object-get-attr (url-split url) "port")))
      (if (or (not (text-value? raw-host))
              (= (len netloc) 0)
              (text-contains? netloc "@")
              (not (or (= path "") (= path "/")))
              (> (len query) 0)
              (> (len fragment) 0)
              (eq? raw-port invalid-port))
          (config-error (+ prefix ": url 必须是 http(s) 的 origin，不能带路径、查询、片段或账号"))
          (normalize-target-port name label url prefix scheme netloc path raw-host raw-port)))

    (define (normalize-target-port name label url prefix scheme netloc path raw-host raw-port)
      (define port (if (eq? raw-port None)
                       (if (= scheme "https") 443 80)
                       raw-port))
      (if (or (not (integer-value? port)) (< port 1) (> port 65535))
          (config-error (+ prefix ": 端口不合法"))
          (normalize-target-build name label url prefix scheme netloc path raw-host port)))

    (define (normalize-target-build name label url prefix scheme netloc path raw-host port)
      (define target (dict))
      (define origin (+ scheme "://" netloc))
      (object-set! target "name" name)
      (object-set! target "label" label)
      (object-set! target "url" origin)
      (object-set! target "scheme" scheme)
      (object-set! target "netloc" netloc)
      (object-set! target "host" raw-host)
      (object-set! target "port" port)
      target)

    (define (normalize-targets raw)
      (if (not (list-value? raw))
          (config-error "targets 必须是一个数组")
          (normalize-targets-list raw)))

    (define (normalize-targets-list raw)
      (if (> (len raw) max-targets)
          (config-error (+ "targets 最多 " (str max-targets) " 个"))
          (normalize-targets-entries raw (dict) (list) 0)))

    (define (normalize-targets-entries raw seen result index)
      (if (>= index (len raw))
          result
          (normalize-targets-one raw seen result index)))

    (define (normalize-targets-one raw seen result index)
      (define target (normalize-target (object-ref raw index) index))
      (define name (object-ref target "name"))
      (if (in name seen)
          (config-error (+ "targets 里有重复的 name: " name))
          (register-target raw seen result index target)))

    (define (register-target raw seen result index target)
      (define name (object-ref target "name"))
      (object-set! seen name #t)
      (normalize-targets-entries raw seen (+ result (list target)) (+ index 1)))

    ;; ---- extensible header blacklists
    ;;
    ;; Both lists are arrays of regular expressions, matched against the whole
    ;; lower-cased header name.  The built-in hop-by-hop and security list in
    ;; proxy.rkt always applies; these only add to it.

    (define (normalize-header-patterns raw key)
      (define value (raw-value raw key (list)))
      (if (not (list-value? value))
          (config-error (+ key " 必须是正则表达式字符串数组"))
          (if (> (len value) max-header-patterns)
              (config-error (+ key " 最多 " (str max-header-patterns) " 项"))
              (normalize-header-patterns-list value key 0 (list) (list)))))

    (define (normalize-header-patterns-list value key index strings compiled)
      (if (>= index (len value))
          (list strings compiled)
          (normalize-header-pattern-one value key index strings compiled)))

    (define (normalize-header-pattern-one value key index strings compiled)
      (define pattern (object-ref value index))
      (if (or (not (text-value? pattern))
              (= (len pattern) 0)
              (> (len pattern) max-header-pattern-length))
          (config-error (+ key " 第 " (str (+ index 1))
                           " 项必须是非空字符串（最多 "
                           (str max-header-pattern-length) " 个字符）"))
          (normalize-header-pattern-compile value key index strings compiled pattern)))

    (define (normalize-header-pattern-compile value key index strings compiled pattern)
      (define compiled-pattern
        (with-handler
         (lambda (e)
           (config-error (+ key " 第 " (str (+ index 1)) " 项不是合法正则")))
         ((object-get-attr re "compile") pattern (object-get-attr re "IGNORECASE"))))
      (normalize-header-patterns-list value key (+ index 1)
                                      (+ strings (list pattern))
                                      (+ compiled (list compiled-pattern))))

    ;; ---- origins allowed to call the proxy cross-origin
    ;;
    ;; A CORS preflight carries no session cookie, so a listed origin must be
    ;; answered before the session check.  The session is still required for
    ;; every actual request; the list only grants permission to read the reply.
    ;; "null" is the opaque origin of a file:// page or a sandboxed iframe.

    (define (default-scheme-port scheme)
      (if (= scheme "https") 443 80))

    (define (normalize-cors-origins raw)
      (define value (raw-value raw "cors_origins" (list)))
      (if (not (list-value? value))
          (config-error "cors_origins 必须是 origin 字符串数组")
          (if (> (len value) max-cors-origins)
              (config-error (+ "cors_origins 最多 " (str max-cors-origins) " 项"))
              (normalize-cors-origins-list value 0 (list) (dict)))))

    (define (normalize-cors-origins-list value index result seen)
      (if (>= index (len value))
          result
          (normalize-cors-origin-one value index result seen)))

    (define (normalize-cors-origin-one value index result seen)
      (define origin (normalize-cors-origin (object-ref value index) index))
      (if (in origin seen)
          (config-error (+ "cors_origins 第 " (str (+ index 1)) " 项重复: " origin))
          (register-cors-origin value index result seen origin)))

    (define (register-cors-origin value index result seen origin)
      (object-set! seen origin #t)
      (normalize-cors-origins-list value (+ index 1) (+ result (list origin)) seen))

    (define (normalize-cors-origin value index)
      (define prefix (+ "cors_origins[" (str index) "]"))
      (if (not (text-value? value))
          (config-error (+ prefix " 必须是字符串"))
          (if (or (= (len value) 0)
                  (not (equal? (text-strip value) value))
                  (> (len value) max-cors-origin-length))
              (config-error (+ prefix " 必须是非空、无首尾空白、最多 "
                               (str max-cors-origin-length) " 个字符的字符串"))
              (if (= value "null")
                  "null"
                  (normalize-cors-origin-url value prefix)))))

    (define (normalize-cors-origin-url value prefix)
      (if (= value "*")
          (config-error "cors_origins 不支持通配符 *；请逐项列出可信 origin")
          (normalize-cors-origin-parsed value prefix
            (with-handler (lambda (e) None) (url-split value)))))

    (define (normalize-cors-origin-parsed value prefix parsed)
      (if (eq? parsed None)
          (config-error (+ prefix " 不是合法的 origin"))
          (normalize-cors-origin-fields value prefix parsed)))

    (define (normalize-cors-origin-fields value prefix parsed)
      (define scheme (text-lower (to-text (object-get-attr parsed "scheme"))))
      (define netloc (to-text (object-get-attr parsed "netloc")))
      (define path (to-text (object-get-attr parsed "path")))
      (define query (to-text (object-get-attr parsed "query")))
      (define fragment (to-text (object-get-attr parsed "fragment")))
      (define raw-host (with-handler (lambda (e) None)
                                     (object-get-attr parsed "hostname")))
      (define invalid-port (list))
      (define raw-port (with-handler (lambda (e) invalid-port)
                                     (object-get-attr parsed "port")))
      (if (or (not (or (= scheme "http") (= scheme "https")))
              (= (len netloc) 0)
              (text-contains? netloc "@")
              (not (or (= path "") (= path "/")))
              (> (len query) 0)
              (> (len fragment) 0)
              (not (text-value? raw-host))
              (eq? raw-port invalid-port))
          (config-error (+ prefix " 必须是 http(s) origin，不能带路径、查询、片段或账号"))
          (normalize-cors-origin-port prefix scheme raw-host raw-port)))

    (define (normalize-cors-origin-port prefix scheme raw-host raw-port)
      (define port (if (eq? raw-port None) (default-scheme-port scheme) raw-port))
      (if (or (not (integer-value? port)) (< port 1) (> port 65535))
          (config-error (+ prefix " 的端口不合法"))
          (cors-origin-text scheme raw-host port)))

    (define (cors-origin-text scheme raw-host port)
      (define host (text-lower raw-host))
      (define host-text (if (text-contains? host ":") (+ "[" host "]") host))
      (if (= port (default-scheme-port scheme))
          (+ scheme "://" host-text)
          (+ scheme "://" host-text ":" (str port))))

    ;; ---- the whole file

    (define (normalize-config raw config-path)
      (if (not (dict-value? raw))
          (config-error "配置的顶层必须是一个 JSON 对象")
          (normalize-config-fields raw config-path)))

    (define (normalize-config-fields raw config-path)
      (define directory (path-dirname config-path))
      (define config (dict))
      (object-set! config "config_path" config-path)
      (object-set! config "directory" directory)
      (object-set! config "host" (text-field raw "host" default-host "host" 255))
      (object-set! config "port" (integer-field raw "port" default-port 1 65535 "port"))
      (object-set! config "cert_file"
                   (resolve-path directory (text-field raw "cert_file" default-cert-name "cert_file" 4096)))
      (object-set! config "key_file"
                   (resolve-path directory (text-field raw "key_file" default-key-name "key_file" 4096)))
      (object-set! config "session_ttl"
                   (integer-field raw "session_ttl" default-session-ttl 60 2592000 "session_ttl"))
      (object-set! config "login_max_attempts"
                   (integer-field raw "login_max_attempts" default-login-attempts 1 100 "login_max_attempts"))
      (object-set! config "login_window"
                   (integer-field raw "login_window" default-login-window 10 86400 "login_window"))
      (object-set! config "max_body"
                   (integer-field raw "max_body" default-max-body 1024 268435456 "max_body"))
      (object-set! config "max_response"
                   (integer-field raw "max_response" default-max-response 1024 268435456 "max_response"))
      (object-set! config "upstream_timeout"
                   (integer-field raw "upstream_timeout" default-upstream-timeout 1 300 "upstream_timeout"))
      (object-set! config "trust_proxy" (bool-field raw "trust_proxy" #f "trust_proxy"))
      (object-set! config "verify_upstream_tls"
                   (bool-field raw "verify_upstream_tls" #t "verify_upstream_tls"))
      (object-set! config "hsts" (bool-field raw "hsts" #t "hsts"))
      (define request-patterns (normalize-header-patterns raw "blocked_request_headers"))
      (define response-patterns (normalize-header-patterns raw "blocked_response_headers"))
      (object-set! config "blocked_request_headers" (object-ref request-patterns 0))
      (object-set! config "blocked_request_header_patterns" (object-ref request-patterns 1))
      (object-set! config "blocked_response_headers" (object-ref response-patterns 0))
      (object-set! config "blocked_response_header_patterns" (object-ref response-patterns 1))
      (object-set! config "cors_origins" (normalize-cors-origins raw))
      (object-set! config "users" (normalize-users (raw-value raw "users" (dict))))
      (object-set! config "targets" (normalize-targets (raw-value raw "targets" (list))))
      (validate-host (object-ref config "host") config))

    (define (validate-host host config)
      (if (some? ((object-get-attr host-pattern "fullmatch") host))
          config
          (config-error "host 只能包含字母、数字、点、短横线、下划线和冒号")))

    (define (load-config path-text)
      (define path (path-abspath path-text))
      (if (not (file-exists? path))
          (raise (+ "配置文件不存在: " path "。请先运行 webvpn-server init <目录>"))
          (load-config-file path)))

    (define (load-config-file path)
      (define text (read-text path))
      (define raw (with-handler (lambda (e) (raise (+ "无法解析配置 JSON: " (error-text e))))
                                (json-loads text)))
      (normalize-config raw path))

    ;; ---- command-line overrides

    (define (set-config-value config key value)
      (object-set! config key value)
      config)

    (define (override-host config value)
      (if (and (text-value? value)
               (<= (len value) 255)
               (some? ((object-get-attr host-pattern "fullmatch") value)))
          (set-config-value config "host" value)
          (config-error "命令行 --host 不合法")))

    (define (override-port config value)
      (if (and (integer-value? value)
               (not (bool-value? value))
               (>= value 1)
               (<= value 65535))
          (set-config-value config "port" value)
          (config-error "命令行 --port 必须是 1 到 65535 之间的整数")))

    (define (override-file config key value)
      (if (safe-file-name value)
          (set-config-value config key (path-abspath value))
          (config-error (+ "命令行 " key " 不合法"))))

    (define (apply-overrides config host port cert key)
      (if (some? host) (override-host config host) config)
      (if (some? port) (override-port config port) config)
      (if (some? cert) (override-file config "cert_file" cert) config)
      (if (some? key) (override-file config "key_file" key) config)
      config)

    (define (check-config config)
      (define cert (object-ref config "cert_file"))
      (define key (object-ref config "key_file"))
      (if (not (file-exists? cert))
          (raise (+ "证书文件不存在: " cert))
          #t)
      (if (not (file-exists? key))
          (raise (+ "私钥文件不存在: " key))
          #t)
      (check-key-permissions key)
      (if (= (len (object-ref config "users")) 0)
          (raise "配置里没有用户；请用 webvpn-server hash-password 生成哈希并加入 users")
          #t)
      config)

    (define (check-key-permissions key)
      (if (not (= (to-text (object-get-attr os "name")) "nt"))
          (if (> (& (file-mode key) 63) 0)
              (raise (+ "私钥文件权限过宽（组或其他用户可读）: " key "；请执行 chmod 600"))
              #t)
          #t))

    ;; ---- writing a new deployment

    (define (write-config path raw)
      (define directory (path-dirname path))
      (ensure-dir directory)
      (define temp (temp-name directory ".webvpn-config-"))
      (define text (json-dumps raw))
      (with-handler (lambda (e) (cleanup-and-raise temp e))
                    (write-text temp text))
      (chmod temp 384)
      (replace-file temp path)
      path)

    (define (cleanup-and-raise temp error)
      (remove-file temp)
      (raise error))

    (define (generate-certificate cert-file key-file host)
      (define directory (path-dirname cert-file))
      (ensure-dir directory)
      (ensure-dir (path-dirname key-file))
      (define cert-temp (temp-name directory ".webvpn-cert-"))
      (define key-temp (temp-name directory ".webvpn-key-"))
      (define cn (if (or (= host "0.0.0.0") (= host "::")) "localhost" host))
      (define sans (+ (list "DNS:localhost" "IP:127.0.0.1")
                      (host-sans host)))
      (define arguments
        (list "openssl" "req" "-x509" "-newkey" "rsa:3072" "-sha256" "-days" "365" "-nodes"
              "-keyout" key-temp "-out" cert-temp
              "-subj" (+ "/CN=" cn)
              "-addext" (+ "subjectAltName=" (text-join "," sans))))
      (define result (with-handler (lambda (e) None)
                                   (subprocess.run arguments #:check #f
                                                   #:capture_output #t #:text #t)))
      (if (eq? result None)
          (cleanup-certificate cert-temp key-temp
                               "找不到 openssl 命令；请安装 openssl，或自己提供 cert.pem 与 key.pem")
          (finish-certificate result cert-temp key-temp cert-file key-file)))

    (define (cleanup-certificate cert-temp key-temp message)
      (remove-file cert-temp)
      (remove-file key-temp)
      (raise message))

    (define (host-sans host)
      (if (or (= host "0.0.0.0")
              (= host "::")
              (= host "localhost")
              (= host "127.0.0.1"))
          (list)
          (list (target-host-san host))))

    (define (finish-certificate result cert-temp key-temp cert-file key-file)
      (if (not (= (object-get-attr result "returncode") 0))
          (cleanup-certificate cert-temp key-temp
                               (+ "openssl 生成证书失败: " (to-text (object-get-attr result "stderr"))))
          (install-certificate cert-temp key-temp cert-file key-file)))

    (define (install-certificate cert-temp key-temp cert-file key-file)
      (chmod key-temp 384)
      (chmod cert-temp 420)
      (replace-file key-temp key-file)
      (replace-file cert-temp cert-file)
      (list cert-file key-file))

    (define (validate-init-values host port)
      (if (or (not (text-value? host))
              (> (len host) 255)
              (not (some? ((object-get-attr host-pattern "fullmatch") host))))
          (config-error "init 的 host 不合法")
          #t)
      (if (or (not (integer-value? port))
              (bool-value? port)
              (< port 1)
              (> port 65535))
          (config-error "init 的 port 不合法")
          #t))

    (define (init-config directory config-name host port force)
      (validate-init-values host port)
      (define base (path-abspath directory))
      (ensure-dir base)
      (define config-path (resolve-path base config-name))
      (if (and (file-exists? config-path) (not force))
          (raise (+ "配置文件已存在: " config-path "（加 --force 覆盖）"))
          (init-config-write base config-path host port force)))

    (define (init-config-write base config-path host port force)
      (define cert-file (path-join (list base default-cert-name)))
      (define key-file (path-join (list base default-key-name)))
      (define password ((object-get-attr secrets "token_urlsafe") 15))
      (define encoded (hash-password password 600000))
      (define raw (dict))
      (object-set! raw "host" host)
      (object-set! raw "port" port)
      (object-set! raw "cert_file" default-cert-name)
      (object-set! raw "key_file" default-key-name)
      (object-set! raw "session_ttl" default-session-ttl)
      (object-set! raw "login_max_attempts" default-login-attempts)
      (object-set! raw "login_window" default-login-window)
      (object-set! raw "max_body" default-max-body)
      (object-set! raw "max_response" default-max-response)
      (object-set! raw "upstream_timeout" default-upstream-timeout)
      (object-set! raw "trust_proxy" #f)
      (object-set! raw "verify_upstream_tls" #t)
      (object-set! raw "hsts" #t)
      (object-set! raw "blocked_request_headers" (list))
      (object-set! raw "blocked_response_headers" (list))
      (object-set! raw "cors_origins" (list))
      (define users (dict))
      (object-set! users "admin" encoded)
      (object-set! raw "users" users)
      (object-set! raw "targets" (list))
      (generate-certificate cert-file key-file host)
      (write-config config-path raw)
      (define result (dict))
      (object-set! result "config" config-path)
      (object-set! result "cert" cert-file)
      (object-set! result "key" key-file)
      (object-set! result "username" "admin")
      (object-set! result "password" password)
      result)

    ;; unused, but keeps the host pattern and a few helpers part of the
    ;; compiled module for tests that read them
    (define (is-ipv4? value)
      (some? ((object-get-attr ipv4-pattern "fullmatch") value)))
    ))

(provide python)
