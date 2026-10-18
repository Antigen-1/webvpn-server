#lang racket/base

;; The pages of the portal: login, target list and the error pages.  They are
;; plain HTML with inline CSS and no JavaScript; the server adds the security
;; headers, and every value that came from the configuration or the browser is
;; escaped here.

(require rkt-pythonize)
(begin-for-syntax (prelude-prefix "_webvpn_"))

(define python
  (#%python-code
    (define util (import util))
    (define html-escape (object-get-attr util "html_escape"))
    (define text-join (object-get-attr util "text_join"))

    (define style
      (+ "*,*::before,*::after{box-sizing:border-box}"
         "body{margin:0;min-height:100vh;background:#0b1220;color:#dbe4f0;"
         "font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans SC',sans-serif}"
         "a{color:#7cc4ff}"
         ".wrap{width:min(720px,92vw);margin:0 auto;padding:48px 0}"
         ".brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}"
         ".mark{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#2f81f7,#16b8a6);"
         "display:grid;place-items:center;font-weight:700;color:#04121f}"
         ".brand h1{font-size:18px;margin:0;letter-spacing:.2px}"
         ".brand p{margin:0;color:#8ea3bd;font-size:13px}"
         ".card{background:#121c2e;border:1px solid #22314b;border-radius:14px;padding:24px}"
         ".card h2{margin:0 0 6px;font-size:22px}"
         ".muted{color:#8ea3bd;font-size:14px}"
         "label{display:block;font-size:13px;color:#a9bad1;margin:18px 0 6px}"
         "input{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #2b3d5c;"
         "background:#0b1424;color:#eaf1fa;font:inherit}"
         "input:focus{outline:2px solid #2f81f7;outline-offset:1px;border-color:#2f81f7}"
         "button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:9px;"
         "background:#2f81f7;color:#fff;font:inherit;font-weight:600;cursor:pointer}"
         "button:hover{background:#4b93f8}"
         ".alert{margin:0 0 16px;padding:10px 12px;border-radius:9px;"
         "background:#3a1720;border:1px solid #6b2636;color:#ffb3c2;font-size:14px}"
         ".targets{display:grid;gap:12px;margin:22px 0 0}"
         ".target{display:block;text-decoration:none;color:inherit;background:#121c2e;"
         "border:1px solid #22314b;border-radius:12px;padding:16px 18px}"
         ".target:hover{border-color:#2f81f7;background:#152238}"
         ".target strong{display:block;font-size:16px;margin-bottom:2px}"
         ".target span{color:#8ea3bd;font-size:13px}"
         ".row{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-top:22px}"
         ".row form{margin:0}"
         ".link-btn{width:auto;margin:0;padding:9px 14px;background:#1b2a41;color:#cfe0f5;"
         "border:1px solid #2b3d5c;font-size:14px}"
         ".link-btn:hover{background:#243752}"
         "footer{margin-top:32px;color:#6f8199;font-size:12px;text-align:center}"))

    (define (page-shell title body)
      (+ "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
         "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         "<title>" (html-escape title) " · WebVPN</title><style>" style "</style></head>"
         "<body><main class=\"wrap\">"
         "<header class=\"brand\"><div class=\"mark\">W</div><div>"
         "<h1>WebVPN</h1><p>加密访问内网 Web 资源</p></div></header>"
         body
         "<footer>webvpn-server · TLS · 未经授权请勿访问</footer>"
         "</main></body></html>"))

    (define (alert error)
      (if (> (len error) 0)
          (+ "<p class=\"alert\">" (html-escape error) "</p>")
          ""))

    (define (login-page csrf next error)
      (page-shell "登录"
        (+ "<section class=\"card\"><h2>登录</h2>"
           "<p class=\"muted\">使用管理员分配的用户名和密码。</p>"
           (alert error)
           "<form method=\"post\" action=\"/login\">"
           "<input type=\"hidden\" name=\"csrf\" value=\"" (html-escape csrf) "\">"
           "<input type=\"hidden\" name=\"next\" value=\"" (html-escape next) "\">"
           "<label for=\"username\">用户名</label>"
           "<input id=\"username\" name=\"username\" autocomplete=\"username\" required maxlength=\"64\">"
           "<label for=\"password\">密码</label>"
           "<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>"
           "<button type=\"submit\">登录</button></form></section>")))

    (define (target-card target)
      (define name (html-escape (object-ref target "name")))
      (define label (html-escape (object-ref target "label")))
      (define host (html-escape (object-ref target "host")))
      (define port (object-ref target "port"))
      (+ "<a class=\"target\" href=\"/proxy/" name "/\">"
         "<strong>" label "</strong>"
         "<span>" host ":" (str port) " · 通过 WebVPN 访问</span></a>"))

    (define (target-cards targets)
      (if (= (len targets) 0)
          "<p class=\"muted\">管理员尚未配置内网站点。编辑 webvpn.json 的 targets 并重启服务。</p>"
          (+ "<div class=\"targets\">"
             (text-join "" (tuple (map target-card targets)))
             "</div>")))

    (define (portal-page username targets csrf)
      (page-shell "内网站点"
        (+ "<section class=\"card\"><h2>内网站点</h2>"
           "<p class=\"muted\">已登录：" (html-escape username) "</p>"
           (target-cards targets)
           "<div class=\"row\"><span class=\"muted\">退出后需要重新登录。</span>"
           "<form method=\"post\" action=\"/logout\">"
           "<input type=\"hidden\" name=\"csrf\" value=\"" (html-escape csrf) "\">"
           "<button class=\"link-btn\" type=\"submit\">退出登录</button></form></div></section>")))

    (define (error-page status message)
      (page-shell (+ "错误 " (str status))
        (+ "<section class=\"card\"><h2>" (str status) "</h2>"
           "<p class=\"muted\">" (html-escape message) "</p>"
           "<p><a href=\"/\">返回门户</a> · <a href=\"/login\">重新登录</a></p></section>")))

    (define (message-page title message)
      (page-shell title
        (+ "<section class=\"card\"><h2>" (html-escape title) "</h2>"
           "<p class=\"muted\">" (html-escape message) "</p>"
           "<p><a href=\"/\">返回门户</a></p></section>")))
    ))

(provide python)
