# HTTP API

首版只提供本文件列出的路径。除公开读取外，写接口和示例认证都使用有限的单个 `sig1` HTTP Message Signature。旧的 `Authorization: DIDWba` 和 Bearer 令牌不接受。

错误正文一律是 JSON：

```json
{"error": "invalid_signature", "message": "HTTP signature verification failed"}
```

认证失败（401）同时返回：

- `WWW-Authenticate: DIDWba realm="open-did-server", error="...", error_description="..."`
- `Cache-Control: no-store`
- `Accept-Signature`，值为该接口要求的 `sig1=(...)` 覆盖提示

`DIDWba` 是 ANP-02 的挑战方案名。Web DID 也使用这个方案名，并不表示文档被改写成了 WBA。

## 健康检查

`GET /healthz` 不需要签名。维护期间仍返回 200，并用 `maintenance: true` 说明名称与认证写入已暂停。公开 `did.json` 在维护期间继续可读。名称查询、写接口、whoami 和 echo 返回 `503 maintenance`。

## 发布凭据

`open-did-server create-grant` 在本地创建凭据，明文只打印一次，库里只保存 SHA-256。请求头名是 `ANP-Publication-Token`。它必须被写接口签名覆盖，不能单独代替 DID 认证。whoami 和 echo 忽略未签名的该头；若签名覆盖了它，则不再是 whoami/echo 的固定组件集合，返回 401。

凭据按稳定路径、Web 路径或完整 Handle 精确授权，没有前缀通配。未知、撤销、过期、超出范围或 owner 不一致都返回 `403 publication_forbidden`，并且发生在 DID 认证成功之后。

## 签名覆盖

组件顺序必须与下表完全一致，不能多也不能少。参数顺序固定为 `created`、`expires`、`nonce`、`keyid`。标签只能是 `sig1`。nonce 是 32 位小写十六进制。寿命最长 300 秒，时钟偏差 30 秒。

| 操作 | 组件 |
|---|---|
| `GET /examples/auth/whoami` | `@method` `@target-uri` `@authority` |
| `POST /examples/auth/echo` | 上一行，再加 `content-digest` `content-type` |
| 首次发布文档、首次绑定 Handle | echo 的集合，再加 `anp-publication-token` |
| 更新文档、更新 Handle 状态 | echo 的集合，再加 `if-match` `anp-publication-token` |

在把 Header 收成字典之前，重复的签名头、不支持的参数（包括 `alg`）、组件参数、逗号拼接的多签名和相对 `keyid` 都会被拒绝。`Content-Digest` 必须是正文的 `sha-256`。写接口的 `Content-Type` 必须正好是 `application/json`。

密码学校验通过还不够：`keyid` 必须出现在文档的 `authentication` 里，否则 `401 invalid_verification_method`。同一 `keyid` 加 nonce 在有效窗口内只能成功进入一次业务逻辑，包括并发请求和进程重启之后。401 的格式错误不消耗 nonce。已经认证成功随后得到 403、409、412 或 422 的请求会消耗 nonce。

SDK 会按固定顺序重排参数后再验签。本服务在调用 SDK 之前拒绝错误的参数顺序，因此“密码学上能验过、线上参数被调换”的请求仍然是 401。

## 文档

`POST /api/v1/did-documents`

首次发布。不要带 `If-Match`。成功 201，返回 `document_id`、原始 `did`、`content_path`、管理用 `etag`（`"v1"`）和内容 `content_etag`。服务保存客户端原始 UTF-8 字节，不改写 `id`。

`GET /api/v1/did-documents/{document_id}`

公开元数据，不返回私钥。

`PUT /api/v1/did-documents/{document_id}`

更新。必须带被签名覆盖的 `If-Match: "vN"`。缺少时 428，版本不符时 412。验签使用当前已发布文档，不信任正文里新加的键。WBA 文档的最终内容还必须带 `DataIntegrityProof` / `eddsa-jcs-2022` / `assertionMethod`。HTTP 签名不能代替这份文档 proof。

`deactivated: true` 和 `successorDid` 返回 `422 unsupported_did_lifecycle`。相对 DID URL 返回 `422 unsupported_relative_did_url`。私钥材料返回 `422 private_key_rejected`。

同一规范化 URL（主机大小写、显式 `:443`、等价百分号编码）再次发布返回 `409 canonical_url_conflict`。同一 WBA 稳定主体路径上的第二个指纹返回 `409 stable_subject_path_reserved`，即使 owner 相同。

标准分发：

- `GET` 或 `HEAD /.well-known/did.json`
- `GET` 或 `HEAD /{path}/did.json`

`Content-Type` 为 `application/did+json`。`Accept` 可以是 `application/did+json`、`application/json` 或 `*/*`，其他值 406。内容 ETag 匹配 `If-None-Match` 时返回 304。缓存为 `public, max-age=60`。查找使用配置的 `PUBLIC_DID_DOMAIN` 和 `PUBLIC_DID_PORT`，不用请求里的 Host 头。

活动 Handle 存在时，更新后的文档仍须保留该方法要求的声明，否则 `409 active_handle_declaration_conflict`。

## Handle

`PUT /api/v1/handles/{local-part}`

正文只能是 `{"did","status"}`，`status` 为 `active`、`suspended` 或 `revoked`。第一次写入必须是 `active`，且不能带 `If-Match`；记录已存在时返回 `409 handle_exists`。之后的状态变更使用 `If-Match: "gN"`。generation 从 `"1"` 起，没有前导零，`"9"` 之后是 `"10"`。相同状态的重复写入不增加 generation。

`GET /.well-known/handle/{local-part}` 是正向查询。`GET /api/v1/handles/by-did?did=` 是本实例反向查询。

- `active`：200，可作为活动绑定。
- `suspended`：200，`status` 为 `suspended`。SDK 的解析模型可以读到它，但它不是活动绑定。
- `revoked`：正向和反向都是 410。不能恢复，包括原来的 owner。

本地 DID 暂停会在同一事务里暂停依赖的活动 Handle 并增加 generation。恢复 DID 不会恢复 Handle。Handle 的暂停或撤销也不会自动停用 DID。DID 暂停入口是管理命令 `set-auth-status`，没有对应的公开 HTTP 写接口。

首次绑定提交前，不要求该 Handle 的公开入口已经返回 active。本地模式的响应字段 `verification` 是 `declaration-consistent`（WBA）或 `web-provider-domain`（Web），并写明这不是 `exact-handle`。正式模式才会对 WBA 做默认 TLS 的公开 HTTPS 读取；读不到时仍标为 `declaration-consistent`。

## 示例认证

`GET /examples/auth/whoami` 返回已认证的 `did`、`auth_scheme=http_signatures` 和 `mode`（`local-demo` 或 `production`）。正文必须为空。

`POST /examples/auth/echo` 在同样的身份字段之外回显 JSON 正文。

这两个接口只认本服务已经发布且本地认证状态为 `active` 的 DID。

## 外部 URL

直接访问时，验签 URL 是 `REQUEST_BASE_URL` 加上原始路径和查询，伪造的 `X-Forwarded-*` 无效。来源地址落在 `TRUSTED_PROXY_CIDRS` 时，改用 `X-Forwarded-Proto`、`X-Forwarded-Host` 和原始路径。正式模式要求转发协议是 `https`。客户端和服务器必须使用完全相同的绝对 URL 字符串，SDK 不会替双方规范化。
