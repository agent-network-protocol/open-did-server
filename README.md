# Open DID Server

An open-source reference server for publishing DID documents, resolving human-readable Handles, and verifying ANP-signed HTTP requests.

Open DID Server 面向希望自行搭建 DID 服务的开发者，计划提供：

- `did:wba` 和 `did:web` DID 文档上传、校验与标准 HTTP 分发。
- Handle → DID、DID → Handle 查询及双向绑定示例。
- 使用 ANP SDK 签名的客户端，以及验证 HTTP Message Signatures 的服务端示例。
- 域名与 HTTPS 部署说明，以及无需修改 SDK 的本地 IP 演示方案。

当前处于方案阶段，仓库只包含文档和基础仓库文件，尚无可运行服务或客户端。

整体设计、接口草案、SDK 兼容边界和后续实施步骤见 [项目方案](docs/plan.md)。

## License

[Apache License 2.0](LICENSE)，与 ANP SDK 的许可证保持一致。
