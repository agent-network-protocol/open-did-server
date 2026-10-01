# Open DID Server

开源 DID Server 参考实现：托管 `did:wba` 与 `did:web` 文档，提供 Handle 查询，并验证有限形态的 ANP HTTP Message Signatures。

首版范围：

- 本地生成身份，经真实 HTTP 上传公开文档，并按标准 DID 路径分发原文。
- 发布凭据 `ANP-Publication-Token` 与候选文档 `authentication` 私钥签名同时成立才能首次发布。后续更新只认已经发布的认证键。
- Handle 正向、反向查询和状态机。WBA 按精确解析入口声明处理，Web 按 Provider 域名声明处理。
- 只接受单个 `sig1` 的固定组件顺序。这不是完整的 [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)。

依赖的 SDK 是 PyPI 上的 `anp==1.0.5`（`https://pypi.org/simple`，wheel `anp-1.0.5-py3-none-any.whl`）。项目不使用本机源码路径。

接口、错误码和签名覆盖见 [docs/api.md](docs/api.md)。反向代理、备份和高水位限制见 [docs/deployment.md](docs/deployment.md)。设计依据仍是 [docs/plan.md](docs/plan.md)。

## 本地最短路径

需要 Python 3.11+ 和 [uv](https://docs.astral.sh/uv/)。下面的命令在仓库根目录执行。DID 使用域名 `example.test`，HTTP 只监听 `127.0.0.1`。监听端口不写入 DID。

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

`create-grant` 只打印一次 `token=`。另开一个终端，把令牌填进客户端。客户端会创建两个身份、上传、读取标准文档、绑定 Handle、更新 WBA 文档，并对 whoami / echo 签名。解析步骤使用 SDK 的 `base_url_override`，输出标记为 `resolution=development-demo`。这不是正式 HTTPS 验收。

```bash
uv run python examples/client/run.py \
  --base-url http://127.0.0.1:8765 \
  --token '刚才打印的 token' \
  --out ./data/demo
```

`./data/` 含数据库、高水位文件、私钥和令牌，已被 Git 忽略。不要把 `LOCAL_DEMO_MODE=1` 的测试凭据用于正式域名。

## 测试

```bash
uv run pytest
```

覆盖文档校验、签名格式、真实 HTTP 发布与 Handle、独立构造的签名基串、并发更新和重放、独立客户端进程，以及有效窗口内重启后的重放拒绝。

## 正式 HTTPS

把 `LOCAL_DEMO_MODE` 设为 `0`，`REQUEST_BASE_URL` 设为 `https://你的域名`，并用 `deploy/` 中的 Caddy、nginx 或 systemd 示例终止 TLS。受信代理必须重建出与客户端签名完全相同的 URL。

本次交付没有公网域名和证书，**没有完成正式 HTTPS 验收**。本地 HTTP 和关闭证书校验都不能代替那一步。

## License

[Apache License 2.0](LICENSE)。
