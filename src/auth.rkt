#lang racket/base

;; Authentication material: password hashes, server-side sessions, CSRF tokens
;; and the login rate limiter.  Nothing here knows about HTTP; the server
;; module decides what a failed login or an expired session means.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define bridge (import pyimports))
    (define util (import util))
    (define hashlib (object-get-attr bridge "hashlib"))
    (define hmac (object-get-attr bridge "hmac"))
    (define secrets (object-get-attr bridge "secrets"))
    (define re (object-get-attr bridge "re"))
    (define builtins (object-get-attr bridge "builtins"))
    (define py-list (object-get-attr builtins "list"))
    (define threading (object-get-attr bridge "threading"))

    (define text-split (object-get-attr util "text_split"))
    (define text-substr (object-get-attr util "text_substr"))
    (define text? (object-get-attr util "text_p"))
    (define integer? (object-get-attr util "integer_p"))
    (define encode-utf8 (object-get-attr util "encode_utf8"))
    (define decode-utf8 (object-get-attr util "decode_utf8"))
    (define to-text (object-get-attr util "to_text"))
    (define some? (object-get-attr util "some_p"))
    (define none? (object-get-attr util "none_p"))
    (define safe-int (object-get-attr util "safe_int"))
    (define now (object-get-attr util "now"))
    (define build-cookie (object-get-attr util "build_cookie"))
    (define clear-cookie (object-get-attr util "clear_cookie"))

    (define password-algorithm "pbkdf2_sha256")
    (define password-iterations 600000)
    (define min-iterations 1)
    (define max-iterations 2000000)
    (define session-cookie-name "webvpn_session")
    (define csrf-cookie-name "webvpn_csrf")
    (define session-id-pattern ((object-get-attr re "compile") "^[0-9a-f]{64}$"))
    (define hex-pattern ((object-get-attr re "compile") "^[0-9a-f]+$"))

    ;; A valid hash of a password nobody knows.  A login for a user that does
    ;; not exist is verified against this, so the expensive part takes the same
    ;; time whether the account exists or not.
    (define dummy-hash
      "pbkdf2_sha256$600000$30313233343536373839616263646566$23a32b64c8946cf67b28b8c98b79cad187587d6e27feb2344b746dd6f66f8681")

    ;; ---- password hashes

    (define (hash-password password iterations)
      (if (or (not (text? password)) (= (len password) 0))
          (raise "password must be a non-empty string")
          (hash-password-ok password iterations)))

    (define (hash-password-ok password iterations)
      (define count (safe-int iterations password-iterations))
      (if (or (< count min-iterations) (> count max-iterations))
          (raise "pbkdf2 iteration count out of range")
          (hash-password-with password count)))

    (define (hash-password-with password iterations)
      (define salt ((object-get-attr secrets "token_hex") 16))
      (define salt-bytes ((object-get-attr bytes "fromhex") salt))
      (define digest
        ((object-get-attr hashlib "pbkdf2_hmac") "sha256" (encode-utf8 password)
                                                     salt-bytes iterations))
      (+ password-algorithm "$" (str iterations) "$" salt "$"
         ((object-get-attr digest "hex"))))

    (define (hash-parts encoded)
      (if (text? encoded) (text-split encoded "$") (list)))

    (define (hex-text? value)
      (and (text? value)
           (some? ((object-get-attr hex-pattern "fullmatch") value))))

    (define (hash-shape-valid? parts)
      (define algorithm (object-ref parts 0))
      (define iterations (safe-int (object-ref parts 1) -1))
      (define salt (object-ref parts 2))
      (define digest (object-ref parts 3))
      (and (= algorithm password-algorithm)
           (>= iterations min-iterations)
           (<= iterations max-iterations)
           (hex-text? salt)
           (hex-text? digest)
           (= (len salt) 32)
           (= (len digest) 64)))

    (define (valid-hash? encoded)
      (define parts (hash-parts encoded))
      (if (= (len parts) 4)
          (hash-shape-valid? parts)
          #f))

    (define (verify-password password encoded)
      (if (or (not (text? password)) (not (text? encoded)))
          #f
          (verify-password-parts password (hash-parts encoded))))

    (define (verify-password-parts password parts)
      (if (not (= (len parts) 4))
          #f
          (verify-password-shape password parts)))

    (define (verify-password-shape password parts)
      (define algorithm (object-ref parts 0))
      (define iterations (safe-int (object-ref parts 1) -1))
      (define salt-text (object-ref parts 2))
      (define digest-text (object-ref parts 3))
      (if (not (hash-shape-valid? parts))
          #f
          (verify-password-digest password algorithm iterations salt-text digest-text)))

    (define (verify-password-digest password algorithm iterations salt-text digest-text)
      (define expected (with-handler (lambda (e) None)
                                     ((object-get-attr bytes "fromhex") digest-text)))
      (define salt (with-handler (lambda (e) None)
                                 ((object-get-attr bytes "fromhex") salt-text)))
      (if (or (eq? expected None) (eq? salt None))
          #f
          (verify-password-compare password algorithm iterations salt expected)))

    (define (verify-password-compare password algorithm iterations salt expected)
      (define actual
        (with-handler (lambda (e) None)
                      ((object-get-attr hashlib "pbkdf2_hmac") "sha256"
                                                                  (encode-utf8 password)
                                                                  salt iterations)))
      (if (eq? actual None)
          #f
          (hmac.compare_digest expected actual)))

    (define (verify-missing-user password)
      (verify-password password dummy-hash)
      #f)

    (define (verify-user-password password users username)
      (define encoded ((object-get-attr users "get") username None))
      (if (eq? encoded None)
          (verify-missing-user password)
          (verify-password password encoded)))

    ;; ---- sessions

    (define (make-session-store ttl max-sessions)
      (define store (dict))
      (object-set! store "sessions" (dict))
      (object-set! store "lock" (threading.Lock))
      (object-set! store "ttl" ttl)
      (object-set! store "max" max-sessions)
      store)

    (define (session-lock store)
      ((object-get-attr (object-ref store "lock") "acquire")))

    (define (session-unlock store)
      ((object-get-attr (object-ref store "lock") "release")))

    (define (expire-session sessions sid)
      ((object-get-attr sessions "pop") sid None)
      None)

    (define (cleanup-sessions-locked store current)
      (define sessions (object-ref store "sessions"))
      (define entries (tuple ((object-get-attr sessions "items"))))
      (tuple
       (map
        (lambda (entry)
          (define sid (object-ref entry 0))
          (define session (object-ref entry 1))
          (if (<= (object-ref session "exp") current)
              (expire-session sessions sid)
              None))
        entries)))

    (define (new-session-id sessions)
      (define sid ((object-get-attr secrets "token_hex") 32))
      (if (in sid sessions)
          (new-session-id sessions)
          sid))

    (define (session-entry store username current)
      (define sessions (object-ref store "sessions"))
      (define sid (new-session-id sessions))
      (define session (dict))
      (object-set! session "sid" sid)
      (object-set! session "namespace" (text-substr sid 0 16))
      (object-set! session "user" username)
      (object-set! session "csrf" ((object-get-attr secrets "token_hex") 32))
      (object-set! session "exp" (+ current (object-ref store "ttl")))
      (object-set! sessions sid session)
      sid)

    (define (create-session-locked store username current)
      (cleanup-sessions-locked store current)
      (define sessions (object-ref store "sessions"))
      (if (>= (len sessions) (object-ref store "max"))
          None
          (session-entry store username current)))

    (define (create-session store username)
      (session-lock store)
      (define sid (create-session-locked store username (now)))
      (session-unlock store)
      sid)

    (define (valid-session-id? sid)
      (and (text? sid)
           (some? ((object-get-attr session-id-pattern "fullmatch") sid))))

    (define (session-if-live sessions sid session current)
      (if (> (object-ref session "exp") current)
          session
          (expire-session sessions sid)))

    (define (get-session-locked store sid current)
      (define sessions (object-ref store "sessions"))
      (define session ((object-get-attr sessions "get") sid None))
      (if (eq? session None)
          None
          (session-if-live sessions sid session current)))

    (define (get-session store sid)
      (if (not (valid-session-id? sid))
          None
          (get-session-valid store sid)))

    (define (get-session-valid store sid)
      (session-lock store)
      (define session (get-session-locked store sid (now)))
      (session-unlock store)
      session)

    (define (drop-session store sid)
      (if (valid-session-id? sid)
          (drop-session-valid store sid)
          None))

    (define (drop-session-valid store sid)
      (session-lock store)
      ((object-get-attr (object-ref store "sessions") "pop") sid None)
      (session-unlock store)
      None)

    (define (session-value session key default)
      ((object-get-attr session "get") key default))

    (define (session-csrf? session token)
      (constant-equal (session-value session "csrf" None) token))

    ;; ---- cookies

    (define (session-cookie sid ttl)
      (build-cookie session-cookie-name sid "/" ttl "Lax"))

    (define (clear-session-cookie)
      (clear-cookie session-cookie-name "/" "Lax"))

    (define (csrf-cookie token)
      (build-cookie csrf-cookie-name token "/" 600 "Strict"))

    (define (clear-csrf-cookie)
      (clear-cookie csrf-cookie-name "/" "Strict"))

    (define (new-csrf-token)
      ((object-get-attr secrets "token_hex") 24))

    (define (constant-equal left right)
      (if (or (not (text? left)) (not (text? right)))
          #f
          (hmac.compare_digest left right)))

    ;; ---- login rate limiting

    (define (make-limiter max-attempts window)
      (define limiter (dict))
      (object-set! limiter "attempts" (dict))
      (object-set! limiter "lock" (threading.Lock))
      (object-set! limiter "max" max-attempts)
      (object-set! limiter "window" window)
      limiter)

    (define (limiter-lock limiter)
      ((object-get-attr (object-ref limiter "lock") "acquire")))

    (define (limiter-unlock limiter)
      ((object-get-attr (object-ref limiter "lock") "release")))

    (define (recent-failures limiter key current)
      (define attempts (object-ref limiter "attempts"))
      (define cutoff (- current (object-ref limiter "window")))
      (define entries ((object-get-attr attempts "get") key (list)))
      (py-list (filter (lambda (stamp) (> stamp cutoff)) entries)))

    (define (limiter-check limiter key current)
      (limiter-lock limiter)
      (define entries (recent-failures limiter key current))
      (object-set! (object-ref limiter "attempts") key entries)
      (define allowed (< (len entries) (object-ref limiter "max")))
      (limiter-unlock limiter)
      allowed)

    (define (limiter-fail limiter key current)
      (limiter-lock limiter)
      (define attempts (object-ref limiter "attempts"))
      (define entries ((object-get-attr attempts "get") key (list)))
      ((object-get-attr entries "append") current)
      (object-set! attempts key entries)
      (limiter-unlock limiter)
      None)

    (define (limiter-clear limiter key)
      (limiter-lock limiter)
      ((object-get-attr (object-ref limiter "attempts") "pop") key None)
      (limiter-unlock limiter)
      None)

    (define (limiter-retry-after limiter key current)
      (limiter-lock limiter)
      (define entries (recent-failures limiter key current))
      (define wait (if (= (len entries) 0)
                       0
                       (+ 1 (int (- (+ (min entries) (object-ref limiter "window")) current)))))
      (limiter-unlock limiter)
      (max 0 wait))
    ))

(provide python)
