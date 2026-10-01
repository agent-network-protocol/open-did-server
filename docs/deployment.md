# 部署与恢复

## 本地演示

默认监听 `127.0.0.1`，`LOCAL_DEMO_MODE=1`，`REQUEST_BASE_URL` 指向该回环地址。DID authority 仍是 `PUBLIC_DID_DOMAIN`（默认 `example.test`）。HTTP 端口不写入 DID。

示例客户端对回环 URL 签名，再用 SDK `resolve_did_document_sync(..., base_url_override=该回环地址)` 读取文档。输出里的 `resolution=development-demo` 只说明这次解析改写了传输地址。它不关闭 TLS 校验，也不能当成正式 HTTPS 通过。

本仓库的测试和 README 命令使用独立数据目录、测试身份和空闲端口，不连接现有 AWiki 服务。

## 反向代理

`deploy/Caddyfile`、`deploy/nginx.conf` 和 `deploy/open-did-server.service` 是同一套正式拓扑的示例：

1. 进程仍只监听回环。
2. `LOCAL_DEMO_MODE=0`。
3. `REQUEST_BASE_URL=https://对外域名`。
4. `TRUSTED_PROXY_CIDRS` 只包含本机代理地址，例如 `127.0.0.1/32`。
5. 代理设置单个 `X-Forwarded-Proto: https` 和单个 `X-Forwarded-Host: 对外域名`。

客户端签名的 `@target-uri` 和 `@authority` 必须等于服务端重建出的 URL。直接连到进程的请求即使带了转发头，也不会改用那组头。

正式模式拒绝 `DID_RESOLUTION_BASE_URL_OVERRIDE`。WBA 的公开 Handle 核对使用默认证书校验去 GET `https://{provider}/.well-known/handle/{local}`。不要为了演示关掉证书校验。

本次实现没有公网域名、证书或部署权限。正式 HTTPS 验收没有执行。本地 override 和回环 HTTP 都不是该项的通过记录。完成正式验收需要：

- 一个由部署者控制的 DNS 名，以及对应的 TLS 证书；
- 把 `PUBLIC_DID_DOMAIN`、`HANDLE_PROVIDER_DOMAIN` 和 `REQUEST_BASE_URL` 设成这个名字；
- 在代理后面用真实 HTTPS 重复客户端的上传、标准文档读取、Handle 查询和签名请求；
- 确认 WBA 绑定在公开入口可访问后，响应里的 `verification` 才能记为 `exact-handle`。

## 签名互通范围

首版互通的是本文件和 [api.md](api.md) 里的单个 `sig1` 形态：固定组件、固定参数顺序、Ed25519、标准 Base64 签名、`sha-256` 摘要。以下都不在首版互通结果里：

- 完整 RFC 9421 的任意组件、组件参数、`alg`、多签名和字典序之外的参数排列；
- 旧 `Authorization: DIDWba`；
- 由 `DidWbaVerifier` 颁发的 Bearer JWT。服务端示例不调用这个高层验证器。

SDK 的 `verify_handle_binding` 不会去读取 `serviceEndpoint`，WBA 域名比较也不处理百分号编码的端口。本服务不用它的成功结果报告 `exact-handle`。

## 备份、高水位和不能恢复的状态

数据目录里有两份必须一起考虑的状态：

| 文件 | 内容 |
|---|---|
| `server.db` | 文档原文、Handle、grant 摘要、nonce、维护标记 |
| `high-water.json` | Handle generation、revoked tombstone、已撤销 grant、WBA 稳定路径归属、只增的 `nonce_watermark` |

高水位文件不放进 SQLite 快照。进程在改变这些事实并提交之后更新它。启动时：

- 两边都空：写下空的高水位文件，正常服务。
- 数据库已有数据但高水位文件缺失，或文件里有一条数据库满足不了的事实：进入维护。公开 `did.json` 仍可读。名称、写入、whoami 和 echo 返回 503。
- 数据库包含文件里的全部事实，只是可能更新：把文件快进到数据库，不因此自动结束已有的维护窗口。

`clear-maintenance` 要同时满足两点：当前时间已经到达进入维护时记下的终点，以及 generation、tombstone、已撤销 grant 和稳定路径都能在数据库里找到。普通维护终点是签名寿命加一个时钟偏差（330 秒）。只缺少 nonce 水位时，终点是寿命加两倍偏差再加 1 秒。只等待不能补回丢失的路径归属、tombstone 或已撤销 grant。

恢复时的限制：

- 只恢复旧的 `server.db`、留下较新的高水位文件：服务保持维护，直到数据库重新包含那些 generation、tombstone、撤销 grant 和稳定路径。这是故意的，用来挡住用旧快照复活已撤销名称或凭据。
- 高水位里的 `nonce_watermark` 只增不减，每次成功消费的签名都加一。只恢复旧数据库、留下较新的水位时，服务进入维护。被接受的签名最多可以比服务器时钟超前一个偏差，并且在 `expires` 之后再保留一个偏差，所以这个窗口比普通维护更长。窗口结束前不会打开认证。窗口结束后，丢掉的 nonce 已经不能再被接受，这时可以清除这一项。进程在水位仍然超前时重新启动，会从当前时刻重新计算这个窗口。
- 两份文件一起恢复到同一个旧时间点时，水位也一起退回，服务看不出重放记录被回退。首版没有独立的分布式日志。
- `revoked` Handle 和已撤销 grant 在当前库里不能恢复。稳定主体路径不会分给第二个指纹 DID。
- 复制 SQLite 文件前先执行 `PRAGMA wal_checkpoint(TRUNCATE)`，并不要留下另一个时间点的 `-wal` / `-shm`，否则看起来被换掉的库仍会从 WAL 里放出较新的写入。
- 首版是单进程。多个 worker 需要共享的重放存储，不能各带一份内存 nonce。

`mark-maintenance` 会刷新这个签名窗口。维护期间返回的 503 不消耗 nonce。

私钥、发布令牌明文、`data/demo/` 里的身份和运行日志都不要提交到 Git。
