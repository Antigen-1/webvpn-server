#lang racket/base

;; The command line: serve, init, check and hash-password.  The default
;; configuration is the one beside the executable (see config.rkt), so an
;; unpacked one-file build reads the same webvpn.json that ships next to it.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define bridge (import pyimports))
    (define util (import util))
    (define config (import config))
    (define auth (import auth))
    (define server (import server))
    (define sys (object-get-attr bridge "sys"))
    (define argparse (object-get-attr bridge "argparse"))
    (define getpass (object-get-attr bridge "getpass"))

    (define log-error (object-get-attr util "log_error"))
    (define error-text (object-get-attr util "error_text"))
    (define none? (object-get-attr util "none_p"))
    (define some? (object-get-attr util "some_p"))
    (define text? (object-get-attr util "text_p"))
    (define default-config-path (object-get-attr config "default_config_path"))
    (define default-init-directory (object-get-attr config "default_init_directory"))
    (define load-config (object-get-attr config "load_config"))
    (define check-config (object-get-attr config "check_config"))
    (define apply-overrides (object-get-attr config "apply_overrides"))
    (define init-config (object-get-attr config "init_config"))
    (define hash-password (object-get-attr auth "hash_password"))

    (define version-text "webvpn-server 0.0.2")

    (define (make-parser)
      (define parser
        ((object-get-attr argparse "ArgumentParser")
         #:prog "webvpn-server"
         #:description "TLS WebVPN portal and reverse proxy (commands: serve, init, check, hash-password)"))
      (define subparsers
        ((object-get-attr parser "add_subparsers") #:dest "command"))
      (make-serve-parser subparsers)
      (make-init-parser subparsers)
      (make-check-parser subparsers)
      (make-hash-parser subparsers)
      parser)

    (define (make-serve-parser subparsers)
      (define parser
        ((object-get-attr subparsers "add_parser") "serve"
         #:help "run the portal (the default)"))
      ((object-get-attr parser "add_argument") "--config"
       #:default None #:help "configuration file (default: beside the executable)")
      ((object-get-attr parser "add_argument") "--host"
       #:default None #:help "override the listening address")
      ((object-get-attr parser "add_argument") "--port"
       #:default None #:type int #:help "override the listening port")
      ((object-get-attr parser "add_argument") "--cert"
       #:default None #:help "override the certificate file")
      ((object-get-attr parser "add_argument") "--key"
       #:default None #:help "override the private key file")
      ((object-get-attr parser "add_argument") "--version"
       #:action "version" #:version version-text)
      parser)

    (define (make-init-parser subparsers)
      (define parser
        ((object-get-attr subparsers "add_parser") "init"
         #:help "write a new configuration, certificate and admin password"))
      ((object-get-attr parser "add_argument") "directory"
       #:nargs "?" #:default None
       #:help "directory for webvpn.json, cert.pem and key.pem (default: beside the executable)")
      ((object-get-attr parser "add_argument") "--host"
       #:default "127.0.0.1" #:help "listening address written to the configuration")
      ((object-get-attr parser "add_argument") "--port"
       #:default 8443 #:type int #:help "listening port written to the configuration")
      ((object-get-attr parser "add_argument") "--force"
       #:action "store_true" #:help "overwrite an existing configuration and certificate")
      parser)

    (define (make-check-parser subparsers)
      (define parser
        ((object-get-attr subparsers "add_parser") "check"
         #:help "validate the configuration, users and certificate files"))
      ((object-get-attr parser "add_argument") "--config"
       #:default None #:help "configuration file (default: beside the executable)")
      parser)

    (define (make-hash-parser subparsers)
      ((object-get-attr subparsers "add_parser") "hash-password"
       #:help "prompt for a password and print its PBKDF2 hash"))

    (define (parse-arguments)
      (define argv (object-get-attr sys "argv"))
      (define arguments (object-ref argv (slice 1 None)))
      (define first (if (= (len arguments) 0) None (object-ref arguments 0)))
      (define known (list "serve" "init" "check" "hash-password"))
      (define help-only
        (and (some? first) (or (= first "--help") (= first "-h"))))
      (define effective
        (if (or help-only (and (some? first) (in first known)))
            arguments
            (+ (list "serve") arguments)))
      ((object-get-attr (make-parser) "parse_args") effective))

    (define (resolved-config-path args)
      (define value (getattr args "config" None))
      (if (none? value) (default-config-path) value))

    (define (serve-command args)
      (define configuration (load-config (resolved-config-path args)))
      (apply-overrides configuration
                       (getattr args "host" None)
                       (getattr args "port" None)
                       (getattr args "cert" None)
                       (getattr args "key" None))
      (check-config configuration)
      (server.serve configuration))

    (define (init-command args)
      (define directory (getattr args "directory" None))
      (define base (if (none? directory) (default-init-directory) directory))
      (define result
        (init-config base "webvpn.json"
                     (getattr args "host" "127.0.0.1")
                     (getattr args "port" 8443)
                     (getattr args "force" #f)))
      (print (+ "config:      " (object-ref result "config")))
      (print (+ "certificate: " (object-ref result "cert")))
      (print (+ "private key: " (object-ref result "key")))
      (print (+ "username:    " (object-ref result "username")))
      (print (+ "password:    " (object-ref result "password")))
      (print "")
      (print "请立刻保存上面的密码；服务器只保存它的哈希。")
      (print (+ "下一步：修改 targets，然后运行 webvpn-server serve --config "
                (object-ref result "config"))))

    (define (check-command args)
      (define configuration (load-config (resolved-config-path args)))
      (check-config configuration)
      (print (+ "ok: " (object-ref configuration "config_path"))))

    (define (hash-password-command args)
      (define first ((object-get-attr getpass "getpass") "Password: "))
      (define second ((object-get-attr getpass "getpass") "Confirm: "))
      (if (not (equal? first second))
          (raise "两次输入的密码不一致")
          #t)
      (if (= (len first) 0)
          (raise "密码不能为空")
          #t)
      (print (hash-password first 600000)))

    (define (run-main)
      (define args (parse-arguments))
      (define command (getattr args "command" None))
      (cond
        [(or (none? command) (= command "serve")) (serve-command args)]
        [(= command "init") (init-command args)]
        [(= command "check") (check-command args)]
        [(= command "hash-password") (hash-password-command args)]
        [else (raise (+ "未知命令: " command))]))

    (define (fatal error)
      (log-error (error-text error))
      (sys.exit 1))

    (if (= __name__ "__main__")
        (with-handler (lambda (e) (fatal e)) (run-main))
        None)
    ))

(provide python)
