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

环境变量可覆盖部分配置：`GATEWAY_CONFIG`、`GATEWAY_LISTEN`、`GATEWAY_ISSUER`、
`GATEWAY_REDIS_ADDR`、`GATEWAY_REDIS_DB`。

配置缺失或密钥文件不存在时进程直接报错退出，不会退化为明文或危险默认值。

## 关键行为

- 路由：`/-/health`、`/_auth/{login,callback,logout,me}`；`/_auth/*` 先于会话检查。
- 会话 cookie：`__Host-<app>_session`，`HttpOnly; Secure; SameSite=Lax; Path=/`，无 Domain。
- 未登录：导航请求 302 到 `/_auth/login?next=…`；API 请求（JSON/XHR/cors）401 JSON 并清 cookie。
- 反代：只转发到配置白名单；先删除客户端身份头再注入 `X-Auth-User/App/Sid`；
  转发前剥掉网关自身 cookie；支持 WebSocket 与流式大文件；`proxy` 模式注入 Bearer。
- Redis：DB 默认 2，键带 `gw:` 前缀；`state` 一次性消费 TTL 10 分钟；会话 7 天滑动。
- Token：AES-GCM 加密存放，密钥来自 0600 文件。

## 离线自测

`test/selftest.sh` 在回环地址上用私有端口 18930/18931/18932 与 Redis DB 2
（前缀 `gw:selftest:`）跑完 12 项验收，不需要真实 SSO：

```sh
bash test/selftest.sh
bash test/private_scan.sh   # 仓库私有信息扫描，期望 0 命中
go test ./...
```

`cmd/mocksso` 与 `cmd/echoupstream` 是自测专用假服务，`test/wsprobe` 是原始
WebSocket 探针，均不可部署。
