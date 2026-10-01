# Open DID Server

Open DID Server 是一个开源 DID 文档服务。它托管本实例签发的 `did:wba`（E1）和 `did:web` 文档，按标准 DID 路径把客户端上传的原文分发出去，并提供 Handle 到 DID 的查询。调用方用自己的认证私钥对 HTTP 请求签名；服务只接受一种有限形态的 ANP HTTP Message Signature。

它解决的是「把一份 DID 文档发布到这个域名，并让后续请求证明持有文档里的认证键」。首次发布要同时满足两件事：操作员发给你的发布凭据 `ANP-Publication-Token`，以及候选文档 `authentication` 键的持钥签名。发布凭据不能代替 DID 签名。文档一旦发布，更新只认已经发布的认证键，不认更新正文里新加的键。

首版明确不做这些事：

- 不是完整的 [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)。只接受标签 `sig1`、参数顺序 `created;expires;nonce;keyid`，以及接口文档里固定的签名组件。
- 不是账户系统，也不做 OAuth、可验证凭证、即时消息、端到端加密、多设备或 DID 轮换恢复。
- 不认证其他域名上已经存在的 DID。WBA 的精确 Handle 校验和 Web 的 Provider 域名校验是两套规则。

依赖的 SDK 是 PyPI 上的 `anp==1.0.5`（`https://pypi.org/simple`，wheel `anp-1.0.5-py3-none-any.whl`）。项目不使用本机源码路径。

接口、错误码和签名覆盖见 [docs/api.md](docs/api.md)。反向代理、备份和高水位限制见 [docs/deployment.md](docs/deployment.md)。设计依据是 [docs/plan.md](docs/plan.md)。

## 安装并在本机启动

需要 Python 3.11+ 和 [uv](https://docs.astral.sh/uv/)。命令在仓库根目录执行。下面的 DID 使用域名 `example.test`，HTTP 只监听 `127.0.0.1`。监听端口不写入 DID。

```bash
uv sync
export OPEN_DID_DATA_DIR=./data
export OPEN_DID_HOST=127.0.0.1
export OPEN_DID_PORT=8765
export PUBLIC_DID_DOMAIN=example.test
export PUBLIC_DID_PORT=443
export HANDLE_PROVIDER_DOMAIN=example.test
export REQUEST_BASE_URL=http://127.0.0.1:8765
export LOCAL_DEMO_MODE=1
uv run open-did-server init
uv run open-did-server create-grant \
  --owner demo-owner \
  --wba-path identities/wba/alice \
  --web-path identities/web/bob \
  --handle alice.example.test \
  --handle bob.example.test
uv run open-did-server serve
```

`create-grant` 只打印一次 `token=`。这个令牌、私钥、生成的身份和 `./data/` 里的数据库都不要提交到 Git。`./data/` 已被忽略。不要把 `LOCAL_DEMO_MODE=1` 的测试凭据用于正式域名。

服务起来之后，可以用下面两个独立进程示例。它们都通过真实 HTTP 访问 `--base-url`，不是进程内调用。

## 示例一：走完一次发布

`examples/client/run.py` 是本地演示客户端。它会：

1. 在 `--out` 生成一对 WBA E1 身份和一对 Web 身份（私钥只留在本机）。
2. 用发布凭据和持钥签名上传两份文档。
3. 按标准路径读回 `did.json`，核对返回的 `id` 等于上传的 DID。
4. 绑定 Handle，并做正向、反向查询。
5. 更新 WBA 文档（HTTP 签名之外，WBA 文档还有自己的 proof）。
6. 对 whoami 和 echo 发签名请求。

本地解析使用 SDK 的 `base_url_override`，输出里的 `resolution` 是 `development-demo`。这一步只说明「回环上的文档能被指到本地服务」，不是正式 HTTPS 验收。最后一行 `production_https` 在本地运行时是 `not-run`。

另开一个终端：

```bash
uv run python examples/client/run.py \
  --base-url http://127.0.0.1:8765 \
  --token '刚才打印的 token' \
  --out ./data/demo
```

每次运行都会新建密钥，所以 WBA 的指纹每次不同。下面是一次真实运行里能看出结果的几行（令牌和私钥没有出现在输出中）：

```json
{"step": "wba_document", "id": "did:wba:example.test:identities:wba:alice:e1_bR1sM4DO-B7JjbfxfhIkLwBA-Kpza0mHBRRfFpLVYak", "matched": true}
{"step": "web_document", "id": "did:web:example.test:identities:web:bob", "matched": true}
{"step": "wba_whoami", "did": "did:wba:example.test:identities:wba:alice:e1_bR1sM4DO-B7JjbfxfhIkLwBA-Kpza0mHBRRfFpLVYak", "auth_scheme": "http_signatures", "mode": "local-demo"}
{"step": "web_whoami", "did": "did:web:example.test:identities:web:bob", "auth_scheme": "http_signatures", "mode": "local-demo"}
{"step": "wba_resolve", "id": "did:wba:example.test:identities:wba:alice:e1_bR1sM4DO-B7JjbfxfhIkLwBA-Kpza0mHBRRfFpLVYak", "resolution": "development-demo", "base_url_override": "http://127.0.0.1:51595", "matched": true}
{"step": "production_https", "status": "not-run", "note": "Local HTTP and base_url_override are a development demo, not production HTTPS acceptance."}
```

`matched: true` 表示读回的文档 `id` 与上传的 DID 一致。`mode` 为 `local-demo` 表示这次服务开了本地演示开关。

## 示例二：命名系统测试

`examples/system/run.py` 把同一条发布路径拆成命名用例，并多做一次必须失败的重放。它复用示例一的上传和绑定请求，自己不再写第二套发布实现。HTTPS 时证书校验保持解释器默认值，解析文档时不使用 `base_url_override`。

先按上一节启动服务并创建覆盖 `identities/wba/alice`、`identities/web/bob`、`alice.example.test`、`bob.example.test` 的 grant。然后：

```bash
uv run python examples/system/run.py \
  --base-url http://127.0.0.1:8765 \
  --token '刚才打印的 token' \
  --domain example.test \
  --out ./data/system-demo
```

每个用例打印一行 JSON。`result` 为 `pass` 表示该成功用例通过；`rejected` 表示服务按预期拒绝了重放。进程退出码为 0 才表示整组通过。

| 用例 | 在检查什么 |
|---|---|
| `wba-upload` / `web-upload` | 上传返回 201，响应里的 DID 等于刚生成的文档 |
| `wba-read` / `web-read` | 标准 `did.json` 返回 200，且 `id` 等于上传的 DID |
| `wba-handle` / `web-handle` | `GET /.well-known/handle/{local}` 返回 200、`status=active`，且 DID 一致 |
| `wba-whoami` / `web-whoami` | 签名 whoami 返回 200，且 `did` 等于该文档 |
| `whoami-replay` | 同一条 whoami 签名再发一次，返回 401 `invalid_nonce` |

下面是一次回环真实运行的完整输出。WBA 指纹每次新建密钥都会变；Web 的 `id`、各用例的 `result` 和 HTTP 状态是这次运行的结果：

```json
{"case": "wba-upload", "result": "pass", "http": 201, "id": "did:wba:example.test:identities:wba:alice:e1_qqBxDPYx3AsyvFqO9hbiP30Lkfa1Th8XXkFDh9ErSFU"}
{"case": "wba-read", "result": "pass", "http": 200, "id": "did:wba:example.test:identities:wba:alice:e1_qqBxDPYx3AsyvFqO9hbiP30Lkfa1Th8XXkFDh9ErSFU", "matched": true}
{"case": "wba-handle", "result": "pass", "http": 200, "did": "did:wba:example.test:identities:wba:alice:e1_qqBxDPYx3AsyvFqO9hbiP30Lkfa1Th8XXkFDh9ErSFU", "status": "active", "matched": true}
{"case": "wba-whoami", "result": "pass", "http": 200, "did": "did:wba:example.test:identities:wba:alice:e1_qqBxDPYx3AsyvFqO9hbiP30Lkfa1Th8XXkFDh9ErSFU", "matched": true}
{"case": "web-upload", "result": "pass", "http": 201, "id": "did:web:example.test:identities:web:bob"}
{"case": "web-read", "result": "pass", "http": 200, "id": "did:web:example.test:identities:web:bob", "matched": true}
{"case": "web-handle", "result": "pass", "http": 200, "did": "did:web:example.test:identities:web:bob", "status": "active", "matched": true}
{"case": "web-whoami", "result": "pass", "http": 200, "did": "did:web:example.test:identities:web:bob", "matched": true}
{"case": "whoami-replay", "result": "rejected", "http": 401, "error": "invalid_nonce"}
```

## 在自己的 HTTPS 域名上跑系统测试

本地回环只证明服务进程和示例客户端说的是同一种 HTTP。正式形态是：TLS 在反向代理上终止，Open DID Server 仍只听回环，客户端签名的 URL 是 `https://你的域名/...`。

服务进程使用：

```bash
export LOCAL_DEMO_MODE=0
export PUBLIC_DID_DOMAIN=你的域名
export PUBLIC_DID_PORT=443
export HANDLE_PROVIDER_DOMAIN=你的域名
export REQUEST_BASE_URL=https://你的域名
export TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

`deploy/` 里有 Caddy、nginx 和 systemd 示例。受信代理只转发一份 `X-Forwarded-Proto: https` 和 `X-Forwarded-Host`。生产模式拒绝 `DID_RESOLUTION_BASE_URL_OVERRIDE`。

grant 的路径和 Handle 必须落在这个域名上。然后用同一套系统测试，证书校验保持默认开启：

```bash
uv run python examples/system/run.py \
  --base-url https://你的域名 \
  --token '刚才打印的 token' \
  --domain 你的域名 \
  --out ./data/system-demo
```

不要为了让这一步通过而关闭证书校验，也不要用 `base_url_override` 代替它。示例进程没有提供关闭校验的开关。

## 开发测试

```bash
uv run pytest
```

覆盖文档校验、签名格式、真实 HTTP 发布与 Handle、独立构造的签名基串、并发更新和重放、独立客户端进程、上面的系统测试示例，以及有效窗口内重启后的重放拒绝。

## License

[Apache License 2.0](LICENSE)。
