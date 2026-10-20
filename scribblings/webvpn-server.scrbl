#lang scribble/manual

@(require scribble/manual
          racket/base)

@title{webvpn-server}
@author{zhanghao}

@table-of-contents{}

本手册说明 @tt{webvpn-server} 的设计、部署、配置、安全模型、构建和测试。
项目本身用 Racket 编写：业务逻辑写在 LE 里，由
@hyperlink["https://pkgs.racket-lang.org/package/rkt-pythonize"]{rkt-pythonize}
在展开期编译成 Python；@tt{src/pyimports.py} 是唯一静态导入第三方/标准库的
文件，FastAPI 与 Uvicorn 只做 ASGI 与 TLS 的薄适配层。PyInstaller 最终把
生成的 Python 和依赖打成一个可执行文件。

@section{Overview 概述}

学校里的 WebVPN 通常做四件事：用 TLS 保护入口、要求用户登录、给出一个内网
站点门户、把内网 Web 页面通过反向代理送到浏览器，并改写页面里的链接和
Cookie，使内网地址不会直接暴露给客户端。本项目实现这四件事：

@itemlist[
  @item{HTTPS 入口：TLS 1.2 及以上，HTTP/1.1，自签名证书可由 @tt{init} 自动生成。}
  @item{鉴权：PBKDF2-HMAC-SHA256 密码哈希、服务端会话、登录 CSRF、退出 CSRF、
        按 IP 的登录限流。}
  @item{门户：登录后列出 @tt{targets} 中配置的内网站点。}
  @item{反向代理：@tt{/proxy/<name>/...} 转发到固定的上游 origin，拒绝任意 URL
        和路径穿越；不跟随上游重定向。}
  @item{重写：@tt{Location}、HTML 的 @tt{href/src/action/...}、@tt{srcset}、
        CSS @tt{url()}、根相对链接、上游 Cookie 的命名空间与 @tt{Path}。}
]

它不是通用 TCP VPN，不代理 WebSocket，不执行页面里的 JavaScript，也不尝试
改写 JavaScript 动态生成的 URL。它适合把可信的内网 Web 应用放到浏览器可访问
的 TLS 入口后面；配置内网站点前请阅读 @secref{security}。

@section{Quick start 快速开始}

@subsection{准备}

@itemlist[
  @item{Racket 9.1 或更高，以及已安装的 @tt{rkt-pythonize} 4.3.5。}
  @item{Python 3.11 或更高（本仓库在 3.14 上测试）。开发与测试使用项目内 @tt{.venv}；最终构建由
        @tt{rkt-pythonize/builder} 自己在 @tt{build/venv} 中安装依赖。}
  @item{@tt{openssl} 命令：@tt{init} 用它生成自签名证书。}
]

开发和测试的 Python 环境：

@verbatim|{
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
}|

@subsection{生成部署目录}

在源码目录中（构建 exe 后则直接运行 exe）：

@verbatim|{
racket run-dev.rkt init ./deploy
}|

或构建出可执行文件后：

@verbatim|{
./build/bin/webvpn-server init ./deploy
}|

@tt{init} 会创建 @filepath{deploy/webvpn.json}、@filepath{deploy/cert.pem}、
@filepath{deploy/key.pem}，生成一个随机管理员密码，并只把密码的 PBKDF2 哈希
写进配置。命令会把明文密码打印一次，请立即保存。

如果不给 @tt{init} 目录，配置写到可执行文件所在目录；源码运行时写到当前目录。
这与“配置文件与最终 exe 位于同一目录”的约定一致：PyInstaller onefile 进程的
@tt{sys.frozen} 为真，@tt{sys.executable} 仍指向原始 exe，因此程序在
@tt{webvpn-server} 旁边查找 @tt{webvpn.json}，而不是在解包临时目录里查找。

@subsection{配置内网站点}

编辑 @filepath{deploy/webvpn.json} 的 @tt{targets}。每个 target 的 @tt{url}
必须是一个 @tt{http://} 或 @tt{https://} origin：不能带路径、查询、片段或
账号密码。要访问挂载在子路径下的应用，请把子路径写在链接里，例如
@tt{/proxy/wiki/wiki/}，而不是把子路径放进 target 的 @tt{url}。

@verbatim|{
"targets": [
  {"name": "wiki", "label": "内部 Wiki", "url": "http://10.0.0.10:8080"},
  {"name": "git",  "label": "代码仓库",   "url": "https://git.internal.example"}
]
}|

@subsection{启动}

源码运行：

@verbatim|{
racket run-dev.rkt serve --config ./deploy/webvpn.json
}|

exe：

@verbatim|{
./build/bin/webvpn-server serve --config ./deploy/webvpn.json
}|

不带 @tt{--config} 时读取 exe 同目录（源码运行是当前目录）的
@filepath{webvpn.json}。浏览器打开 @tt{https://127.0.0.1:8443/}。自签名证书
会触发浏览器的安全警告，这是预期行为；正式部署请换用 CA 签发的证书。

@subsection{改密码和检查配置}

@verbatim|{
./build/bin/webvpn-server hash-password
./build/bin/webvpn-server check --config ./deploy/webvpn.json
}|

@tt{hash-password} 从终端读取两次密码，打印一行可以直接放进 @tt{users} 的
PBKDF2 哈希。@tt{check} 校验 JSON、用户哈希、target origin 与证书/私钥文件；
私钥如果是组或其他用户可读，检查会失败。

@section{Configuration 配置文件}

默认文件名是 @filepath{webvpn.json}，位置见上一节。项目根目录的
@filepath{webvpn.example.json} 是字段示例；其中的 @tt{users} 占位符是故意
无效的，@tt{check} 会拒绝它。不要直接复制使用，先运行 @tt{init} 或
@tt{hash-password}。

@subsection{字段}

@itemlist[
  @item{@tt{host}（默认 @tt{"127.0.0.1"}）：监听地址。局域网访问改成
        @tt{"0.0.0.0"}；改动后用 @tt{serve --host} 覆盖也可以。注意
        @tt{0.0.0.0} 只表示监听所有地址，不会让证书自动匹配客户端使用的
        IP/域名；请用 @tt{init --host <对外地址>} 生成证书，或换 CA 证书。}
  @item{@tt{port}（默认 @tt{8443}）：监听端口，1 到 65535。}
  @item{@tt{cert_file}、@tt{key_file}：证书和私钥路径。相对路径相对于配置文件
        所在目录，所以部署目录整体搬走仍然有效。}
  @item{@tt{session_ttl}（默认 @tt{28800} 秒）：会话有效期。}
  @item{@tt{login_max_attempts}（默认 @tt{5}）、@tt{login_window}（默认
        @tt{300} 秒）：同一个客户端 IP 在一个窗口内允许的失败登录次数。}
  @item{@tt{max_body}（默认 @tt{16777216} 字节）：请求体上限。超过直接返回
        @tt{413}，不会读入内存。}
  @item{@tt{max_response}（默认 @tt{33554432} 字节）：单个上游响应上限。}
  @item{@tt{upstream_timeout}（默认 @tt{30} 秒）：连接和读取上游的超时。}
  @item{@tt{trust_proxy}（默认 @tt{false}）：是否信任 @tt{X-Forwarded-For}。
        只有确定前面是可信反向代理时才开启；开启后客户端 IP 取该头的第一个
        合法 IP。Uvicorn 自身的 @tt{proxy_headers} 已关闭。}
  @item{@tt{verify_upstream_tls}（默认 @tt{true}）：是否校验上游 HTTPS 证书。
        内网自签名上游才考虑关闭。}
  @item{@tt{hsts}（默认 @tt{true}）：是否发送 HSTS。使用自签名证书时建议
        先设为 @tt{false}，换 CA 证书后再打开。}
  @item{@tt{blocked_request_headers}、@tt{blocked_response_headers}（默认
        @tt{[]}）：正则表达式数组，用来扩展内置的请求/响应头黑名单。对完整头名
        做大小写不敏感匹配，例如 @tt{"x-internal-.*"}。}
  @item{@tt{users}：对象，键是用户名，值是 @tt{hash-password} 的输出。
        @tt{init} 会创建 @tt{admin}。}
  @item{@tt{targets}：数组，每项有 @tt{name}（匹配
        @tt{[A-Za-z][A-Za-z0-9_-]{0,31}}）、@tt{label} 和 @tt{url}；@tt{name}
        在数组内必须唯一。}
]

未知字段会被忽略；示例配置里的 @tt{_comment} 字段就是这种用途。配置文件本身
含密码哈希，@tt{init} 以 @tt{0600} 写入；私钥同样以 @tt{0600} 写入，服务启动
时会检查。

@subsection{Header 黑名单}

请求和响应都采用“默认转发，黑名单排除”的机制。内置黑名单始终生效，
配置里的 @tt{blocked_request_headers} 和 @tt{blocked_response_headers} 只追加
规则，不能取消内置规则。

@itemlist[
  @item{请求方向：默认转发所有未被黑名单命中的头，因此 @tt{Authorization}、
        @tt{Content-Type}、@tt{Range}、@tt{If-*}、@tt{Origin}、@tt{Referer}、
        @tt{User-Agent} 等会自动通过。}
  @item{请求内置黑名单：@tt{Host}、@tt{Cookie}、@tt{Content-Length}、
        @tt{Accept-Encoding}、@tt{Expect}、逐跳头（@tt{Connection}、
        @tt{Keep-Alive}、@tt{TE}、@tt{Trailer}、@tt{Transfer-Encoding}、
        @tt{Upgrade}、@tt{Proxy-*}），以及 @tt{Forwarded}、@tt{Via}、
        @tt{X-Forwarded-*}、@tt{X-Real-IP}。@tt{Connection} 头里点名的其它头
        也会被动态加入本次请求的黑名单。}
  @item{响应方向：默认转发所有未被黑名单命中的头；内置黑名单包括逐跳头、
        @tt{Server}、@tt{Date}、@tt{Alt-Svc}、@tt{Via}、HSTS、CSP 等。
        配置黑名单先检查：命中的头直接丢弃；未命中的 @tt{Set-Cookie} 和
        @tt{Location} 再经过重写。}
  @item{正则匹配的是完整头名，大小写不敏感；规则写成 @tt{"x-internal-.*"} 时
        能匹配 @tt{X-Internal-Token}，写成 @tt{"token"} 不会匹配
        @tt{x-debug-token}，因为必须完整匹配。}
]

示例：

@verbatim|{
"blocked_request_headers": ["x-debug-.*", "x-internal-token"],
"blocked_response_headers": ["x-upstream-secret"]
}|

配置在加载时编译正则；非法正则、空字符串、超过 64 条或单条超过 256 个字符都会
让 @tt{load-config} / @tt{check} 失败，而不是在请求时才报错。

@section{Command line 命令行}

@verbatim|{
webvpn-server serve [--config FILE] [--host HOST] [--port PORT]
                    [--cert FILE] [--key FILE]
webvpn-server init [DIR] [--host HOST] [--port PORT] [--force]
webvpn-server check [--config FILE]
webvpn-server hash-password
}|

@itemlist[
  @item{@tt{serve}：启动 HTTPS 服务。@tt{--host/--port/--cert/--key} 覆盖配置文件
        中的同名字段。}
  @item{@tt{init}：写配置、证书和私钥，打印一次管理员密码；@tt{--force} 覆盖
        已存在文件。}
  @item{@tt{check}：只校验，不启动服务。成功输出 @tt{ok: <path>}。}
  @item{@tt{hash-password}：交互式读取密码，输出哈希。}
  @item{@tt{--version}：@tt{serve} 子命令支持，打印版本后退出。}
]

退出码：成功为 @tt{0}，配置/证书/Python 启动错误为 @tt{1}；参数错误由
@tt{argparse} 返回 @tt{2}。

@section{HTTP endpoints}

@itemlist[
  @item{@tt{GET /}：需要会话。返回门户，列出 targets。未登录时
        @tt{303} 到 @tt{/login?next=...}。}
  @item{@tt{GET /login}：登录页，设置 10 分钟有效的 @tt{webvpn_csrf} Cookie。}
  @item{@tt{POST /login}：表单字段 @tt{csrf}、@tt{username}、@tt{password}、
        @tt{next}。成功后轮换会话 ID、清掉 CSRF Cookie，并 @tt{303} 到
        @tt{next}（只接受站内绝对路径）。}
  @item{@tt{POST /logout}：需要会话和表单字段 @tt{csrf}；销毁服务端会话。}
  @item{@tt{GET /healthz}：不需要鉴权，返回 @tt{ok}，不泄露版本或配置。}
  @item{@tt{/proxy/<name>/...}：需要会话。支持 GET/HEAD/POST/PUT/PATCH/DELETE/
        OPTIONS。没有结尾斜杠的 @tt{/proxy/<name>} 会 @tt{308} 到带斜杠的地址。}
  @item{@tt{/favicon.ico}：@tt{204}。}
]

代理响应会去掉逐跳头、上游 @tt{Server/Date/HSTS/CSP}，用本服务自己的安全头；
@tt{Content-Length} 重新计算（HEAD 保留上游长度）。上游重定向不跟随，只改写后
交给浏览器。上游 Cookie 被重命名为 @tt{wv_<session>_<target>_<name>}，@tt{Domain} 被
去掉，@tt{Path} 收紧到 @tt{/proxy/<target>/}，并补上 @tt{Secure} 和必要的
@tt{SameSite}；请求时代理只把“本次会话 + 该 target”前缀的 Cookie 还原后
发给上游，门户的会话 Cookie 永远不会发给内网站点。

@section[#:tag "security"]{Security model 安全模型}

@subsection{已经实现的}

@itemlist[
  @item{TLS：Uvicorn + 自定义 SSL context，最低 TLS 1.2，禁用压缩，ALPN 只
        协商 @tt{http/1.1}；私钥权限在启动时检查。}
  @item{口令：PBKDF2-HMAC-SHA256，@tt{hash-password} 和 @tt{init} 使用 600000
        次迭代、16 字节随机 salt；比较使用 @tt{hmac.compare_digest}。缺失用户
        也会用一个固定 dummy 哈希做一次 PBKDF2，降低用户名枚举的时序差异。}
  @item{会话：256 位随机会话 ID，服务端内存存储，带过期和最大数量限制；
        登录成功后创建新 ID（防固定）；退出销毁服务端会话。}
  @item{Cookie：会话 @tt{HttpOnly; Secure; SameSite=Lax}，CSRF Cookie
        @tt{HttpOnly; Secure; SameSite=Strict}；门户页面不发 @tt{Cache-Control}
        可缓存响应。上游 Cookie 的名字带“会话命名空间 + target”前缀，退出或换一个
        会话登录后旧的内网 Cookie 不会被新会话使用。}
  @item{CSRF：登录使用双重提交（Cookie + 隐藏字段），失败后轮换；退出使用会话内
        CSRF 令牌。所有比较常量时间。}
  @item{登录限流：按客户端 IP 记录失败次数，返回 @tt{429} 和 @tt{Retry-After}；
        成功登录清空计数。@tt{trust_proxy} 关闭时只用 TCP 对端地址。}
  @item{开放重定向：@tt{next} 只接受以单个 @tt{/} 开头、无控制字符、长度不超过
        2048 的站内路径。}
  @item{代理目标：只允许配置中的 origin；上游连接由 @tt{http.client} 直接建立，
        不读取环境代理；不跟随重定向；路径拒绝 @tt{..}、反斜杠、NUL/CR/LF 和
        编码后的穿越形式。}
  @item{请求/响应：请求体流式读取并在 @tt{max_body} 处截断，上游响应在
        @tt{max_response} 处截断，连接和读取有超时。}
  @item{头部：响应头名称校验、值去掉 CR/LF；逐跳头丢弃；代理请求默认转发所有
        未被黑名单命中的头，内置黑名单还会动态包含 @tt{Connection} 点名的头；
        客户端的 @tt{Forwarded}、@tt{X-Forwarded-*}、@tt{X-Real-IP}、@tt{Via}
        默认被丢弃，@tt{Host} 固定为目标 origin，@tt{Accept-Encoding: identity}。
        @tt{blocked_request_headers} / @tt{blocked_response_headers} 可追加正则
        规则，非法正则会在启动/检查时被拒绝。}
  @item{错误：客户端只看到通用错误页，堆栈和上游细节只写 stderr；访问日志关闭，
        只记录登录/退出/代理错误，不记录查询字符串和令牌。}
]

@subsection{需要知道的限制}

@itemlist[
  @item{内网站点与门户同源。被代理页面的 JavaScript 以 WebVPN 的 origin 运行，
        能读取门户页面、发起同源请求；请只配置可信的内网站点，或把门户和代理
        部署到不同域名。}
  @item{上游 CSP 被丢弃，因为它的 @tt{'self'} 和绝对地址在代理 origin 下不再
        成立；代理页面因此没有原站的 CSP 保护。}
  @item{只重写服务端能看到的 HTML/CSS 和响应头。JavaScript 拼出的 URL、
        @tt{fetch()}、WebSocket、@tt{EventSource}、动态插入的 iframe 不会自动
        经过代理；依赖这些机制的应用需要额外适配。}
  @item{@tt{/proxy/} 是保留前缀；内网站点自己的 @tt{/proxy/...} 链接不会被
        重写。页面里的相对链接如果含 @tt{..}，浏览器可能解析到 target 前缀之外；
        优先使用根相对或绝对地址。}
  @item{HTML 的 @tt{meta refresh}、@tt{Link} 响应头、SVG @tt{xlink:href} 等位置
        没有专门重写；只有 @tt{Refresh} 响应头做了处理。}
  @item{上游 CORS 头按原样转发，不按代理 origin 重写；跨域前端可能失败。}
  @item{代理不替内网站点做 CSRF 防护；内网应用仍需自己的 CSRF 机制。会话 Cookie
        是 @tt{SameSite=Lax}，跨站 POST 不会带上它，但 GET 副作用仍由内网应用负责。}
  @item{会话保存在单进程内存中，重启后所有用户需要重新登录；部署多个 worker
        不会共享会话。}
  @item{没有按用户区分 target 的 ACL：所有能登录的用户都看到全部 targets。}
  @item{自签名证书只适合测试；浏览器的警告不是漏洞，但用户可能习惯性忽略。
        HSTS 在证书不受信任时可能造成麻烦，示例配置因此默认关闭。}
  @item{所有用户共用一份 JSON 配置和密码哈希文件；修改用户后需要重启服务。}
  @item{PyInstaller 的 onefile 会解包到临时目录，打包的字节码可以被取出分析；
        不要把 exe 当作代码保密手段。}
]

@section{Building the executable 构建}

在项目根目录：

@verbatim|{
racket build.rkt
}|

第一次构建会：

@itemlist[
  @item{创建 @tt{build/venv}，按 @filepath{requirements.txt} 安装 FastAPI、
        Uvicorn 及其依赖，并安装 PyInstaller 6.22.3；需要联网。}
  @item{把 @tt{src/} 下每个 @filepath{.rkt} 渲染成 @filepath{build/python/}
        里的 @filepath{.py}，@filepath{src/pyimports.py} 原样复制。}
  @item{运行 PyInstaller，写出 @filepath{build/bin/webvpn-server}
        （Windows 上是 @filepath{webvpn-server.exe}）。}
]

构建参数在 @filepath{build.rkt} 中：@tt{#:name "webvpn-server"}、
@tt{#:entry "main"}、@tt{#:onefile? #t}。PyInstaller 不能跨平台交叉编译：
在 Linux 上得到 Linux 可执行文件，在 Windows 上运行构建才得到 @filepath{.exe}。

@filepath{pyimports.py} 静态导入标准库、FastAPI、Uvicorn 以及 Uvicorn 会按名字
加载的 loop/protocol 模块，因此 PyInstaller 的静态分析能看到它们；
@filepath{build.rkt} 又把 Uvicorn 的这几个子模块列进 hidden imports 作为兜底。
配置、证书和私钥不打包：它们与 exe 同目录，由 @tt{init} 生成或由部署者提供。

依赖版本固定在 @filepath{requirements.txt}。升级 FastAPI/Uvicorn 后请重新跑
行为测试和 TLS 集成测试；PyInstaller 版本由 builder 默认值控制。

@section{Testing 测试}

先准备项目 venv：

@verbatim|{
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
}|

运行全部测试（推荐把 @tt{TMPDIR} 指到项目内，避免受限环境把临时文件写到只读
位置）：

@verbatim|{
mkdir -p .tmp
TMPDIR="$PWD/.tmp" raco test -x tests/
}|

测试不安装 PyInstaller，也不构建 exe；它们直接渲染 Python 并运行：

@itemlist[
  @item{@filepath{tests/sources.rkt}：每个 @tt{src/*.rkt} 都提供 @tt{python}；
        生成的 Python 只通过 @tt{pyimports} 或项目自己的模块导入；构建脚本、
        requirements 和示例配置存在。}
  @item{@filepath{tests/behavior_client.py}：用 Python 直接测试渲染出的
        util/auth/proxy/config，包括 PBKDF2、会话过期、限流、URL/HTML/CSS/
        srcset 重写、Cookie 命名空间、路径穿越、配置校验和 exe 同目录默认路径。}
  @item{@filepath{tests/integration_client.py}：启动真实 TLS 服务，执行
        @tt{init} 生成证书、登录、CSS/HTML 重写、Cookie 还原、重定向、HEAD、
        会话固定检查、退出、限流和 TLS 1.1 拒绝。需要 @tt{openssl}。}
]

@tt{PYTHON_EXE} 可以指定测试使用的 Python 解释器；默认优先使用项目
@tt{.venv}。集成测试的临时目录在系统临时目录，测试结束会删除。

本手册自身也是测试的一部分：@filepath{info.rkt} 的 @tt{scribblings} 字段让
@tt{raco setup} 构建它；也可以直接生成 HTML：

@verbatim|{
raco scribble --htmls --dest doc scribblings/webvpn-server.scrbl
}|

@section{Layout 代码结构}

@verbatim|{
src/main.rkt        命令行：serve/init/check/hash-password
src/config.rkt      JSON 配置、校验、默认 exe 同目录、证书生成
src/auth.rkt        PBKDF2、服务端会话、CSRF、登录限流、Cookie
src/pages.rkt       登录页、门户、错误页（无 JavaScript）
src/proxy.rkt       目标索引、URL/HTML/CSS 重写、Cookie 隔离、http.client
src/server.rkt      FastAPI 路由、鉴权、CSRF、代理编排、安全响应头
src/util.rkt        字符串/路径/URL/日志/JSON 等小工具
src/pyimports.py    唯一静态 import 第三方和标准库的 Python 桥
tests/              Rackunit 测试与两个 Python 测试脚本
scribblings/        Scribble 手册
build.rkt           rkt-pythonize/builder 的 onefile 构建
run-dev.rkt         不经过 PyInstaller 的渲染并运行
requirements.txt    Python 依赖（固定版本）
webvpn.example.json 配置字段示例（占位哈希故意无效）
}|

LE 不提供 @tt{let}、@tt{for}、类定义和装饰器；循环用递归或 Python 的
@tt{map/filter}，ASGI 的装饰器/协程/线程池适配集中在
@filepath{pyimports.py}，业务模块只调用普通函数。Racket 侧负责代码生成和
参数校验；所有运行时 Python 依赖都从 @filepath{pyimports.py} 取得。

@section{License 许可}

Apache-2.0 OR MIT。
