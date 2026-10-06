[简体中文](README.md) ｜ [English](README.en.md)

# auth-gateway

单体 Go 二进制的 SSO 认证网关：终结网关会话 cookie，通过 OIDC + PKCE 完成登录，
再把请求反向代理到本地白名单上游，并把身份以请求头注入。

依赖只有 `gopkg.in/yaml.v3`，其余全部使用标准库：Redis 用自写的 RESP 客户端，
JWKS 验签用 `crypto/ecdsa`。

## 构建与运行

```sh
go build -o bin/auth-gateway ./cmd/auth-gateway
cp config.example.yaml config.yaml   # 按部署环境填写
./bin/auth-gateway -config config.yaml
```

配置缺失或密钥文件不存在时进程直接报错退出，不会退化为明文或危险默认值。
`listen` 只接受回环地址，网关由 nginx 反代进来，不直接对外。

## 环境变量

环境变量覆盖 YAML 中的对应项；默认值取自代码：

| 名称 | 默认值 | 说明 |
|---|---|---|
| `GATEWAY_CONFIG` | `config.yaml` | 配置文件路径 |
| `GATEWAY_LISTEN` | 无（`listen` 必填） | 覆盖 `listen` |
| `GATEWAY_ISSUER` | 无（`issuer` 必填） | 覆盖 `issuer` |
| `GATEWAY_REDIS_ADDR` | 无（`redis.addr` 必填） | 覆盖 `redis.addr` |
| `GATEWAY_REDIS_DB` | `2` | 覆盖 `redis.db`，范围 0..15 |

其余键（`session`、`token`、`audit`、`apps`）的示例见 `config.example.yaml`。

## 关键行为

- 路由：`/-/health`、`/_auth/{login,callback,logout,me}`；`/_auth/*` 先于会话检查。
- 按路径分流（可选 `routes`）：一个 app 可声明多条 `prefix`，最长前缀优先（等长按书写顺序）；
  `auth: required` 沿用整站鉴权行为，`auth: none` 为公开路径（不建会话、不注入身份头，但仍剥掉
  客户端伪造的身份头和网关 cookie）；未命中任何 prefix 返回 404。无 `routes` 的 app 行为不变。
- 会话 cookie：`__Host-<app>_session`，`HttpOnly; Secure; SameSite=Lax; Path=/`，无 Domain。
- 未登录：导航请求 302 到 `/_auth/login?next=…`；API 请求（JSON/XHR/cors）401 JSON 并清 cookie。
- 反代：只转发到配置白名单；先删除客户端身份头再注入 `X-Auth-User/App/Sid`；
  转发前剥掉网关自身 cookie；支持 WebSocket 与流式大文件；`proxy` 模式注入 Bearer。
- Redis：DB 默认 2，键带 `gw:` 前缀；`state` 一次性消费 TTL 10 分钟；会话 7 天滑动。
- Token：AES-256-GCM 加密后存 Redis，密钥读自 `token.encryption_key_file`（部署时按 0600 放置）。
- 审计：`audit.file` 为必填，追加写入登录 / 登出 / 拒绝 / 刷新事件，不记 token 与 cookie 值。

## 两条身份通道：网页 cookie / 原生 APP Bearer

同一个受保护路由同时支持两种调用方，二者都把身份映射为同一个上游头 `X-Auth-User`（值为 `sub`）：

- **网页**：OIDC + PKCE 登录后由网关下发会话 cookie `__Host-<app>_session`，后续请求靠 cookie 认证。
- **原生 APP / CLI**：无法共享浏览器 cookie store，走 PKCE + 系统安全存储，调用时携带
  `Authorization: Bearer <access_token>`。按 app 用 `accept_bearer: true` 开启（默认 `false`）。
  - 本地验签，不做逐请求 introspection：用 `/jwks.json` 公钥验 ES256，校验 `iss`、`aud`、
    `exp`/`nbf`（含 `clock_skew_minutes`）与 `jti` 撤销；`alg` 必须是 ES256，拒绝 `none`/`HS*`。
  - 通过后仅注入身份头，**不建、不改、不清任何 cookie**；失败一律 `401 JSON`（不 302，APP 不是浏览器）。
  - `bearer_audiences` 缺省为 `[<app.id>]`，出现空数组直接启动报错（不会退化为接受任意 aud）。
  - cookie 与 Bearer 同时存在时**优先 cookie**，浏览器行为不变。
- 注意：这里的「接受客户端 Bearer」与 `mode: proxy` 的「向上游**注入** Bearer」（用会话里保存的
  access_token）是两回事，开关各自独立，不要混用。
- `auth: none` 的公开路由不注入身份头，即使带了合法 Bearer 也不认证；`/_auth/*` 行为不变。

## 离线自测

`test/selftest.sh` 在回环地址上用私有端口 18930/18931/18932 与 Redis DB 2
（前缀 `gw:selftest:`）跑完全部验收，不需要真实 SSO：

```sh
bash test/selftest.sh
bash test/private_scan.sh   # 仓库私有信息扫描，期望 0 命中
bash test/legacy_ab.sh      # 老配置 A/B：改造前(9ef59dd) vs 当前，归一化输出必须完全一致
go test ./...
```

`cmd/mocksso` 与 `cmd/echoupstream` 是自测专用假服务，`test/wsprobe` 是原始
WebSocket 探针，均不可部署。

## 部署

构建产物是单个二进制 `bin/auth-gateway`。仓库不含 systemd 单元；进程只绑定回环地址，
外层由 nginx 终止 TLS 并反代到 `listen`。运行时需可达 `issuer`（OIDC 端点）与 `redis.addr`。
配置文件、`*.secret` 与 `token.key` 均不入库（见 `.gitignore`）。

## 许可证

MIT，见 `LICENSE`。
