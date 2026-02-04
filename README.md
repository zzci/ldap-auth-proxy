# LDAP Authentication Proxy

一个 Rust 实现的 LDAP 认证代理服务器，将 LDAP 认证请求转换为 HTTP API 调用。

## 功能特性

- 支持 LDAP Bind (认证) 操作
- 将用户名/密码转发到远程 HTTP API 进行验证
- 支持多种 DN 格式解析用户名
- 支持匿名绑定
- 可配置的 API 端点和认证参数
- 异步处理，高性能

## 快速开始

### 1. 编译项目

```bash
cargo build --release
```

### 2. 配置

编辑 `config.toml` 文件：

```toml
[server]
bind_address = "0.0.0.0"
port = 3389  # 使用非特权端口，或使用 389 需要 root 权限
base_dn = "dc=example,dc=com"

[api]
url = "http://your-api-server/auth"
method = "POST"
timeout_secs = 30
username_field = "username"
password_field = "password"
success_field = "success"
```

### 3. 运行

```bash
# 直接运行
cargo run --release

# 或者使用编译好的二进制文件
./target/release/ldap-auth-proxy
```

### 4. 测试

使用 ldapsearch 测试认证：

```bash
# 使用 DN 格式
ldapsearch -H ldap://localhost:3389 -D "uid=admin,ou=users,dc=example,dc=com" -w admin123 -b "dc=example,dc=com"

# 使用简单用户名
ldapsearch -H ldap://localhost:3389 -D "admin" -w admin123 -b "dc=example,dc=com"
```

## 配置说明

### 服务器配置 [server]

| 参数 | 说明 | 默认值 |
|------|------|--------|
| bind_address | 绑定地址 | 0.0.0.0 |
| port | 监听端口 | 389 |
| base_dn | 基础 DN | dc=example,dc=com |

### API 配置 [api]

| 参数 | 说明 | 默认值 |
|------|------|--------|
| url | 认证 API 地址 | - |
| method | HTTP 方法 | POST |
| timeout_secs | 超时时间（秒） | 30 |
| api_key_header | API Key 头名称 | - |
| api_key | API Key 值 | - |
| username_field | 用户名字段名 | username |
| password_field | 密码字段名 | password |
| success_field | 响应中的成功字段 | success |
| success_value | 成功时的期望值 | true |

### 环境变量配置

也可以使用环境变量配置，格式为 `LDAP_PROXY__<SECTION>__<KEY>`：

```bash
export LDAP_PROXY__SERVER__PORT=3389
export LDAP_PROXY__API__URL=http://localhost:8080/auth
```

## API 接口要求

你的认证 API 需要接受以下格式的请求：

### 请求

```http
POST /api/auth HTTP/1.1
Content-Type: application/json

{
    "username": "用户名",
    "password": "密码"
}
```

### 响应

```json
{
    "success": true,
    "message": "认证成功"
}
```

或

```json
{
    "success": false,
    "message": "用户名或密码错误"
}
```

## 支持的 DN 格式

代理服务器可以从以下 DN 格式中提取用户名：

- `uid=username,ou=users,dc=example,dc=com`
- `cn=username,ou=users,dc=example,dc=com`
- `sAMAccountName=username,ou=users,dc=example,dc=com`
- `username@domain.com` (邮箱格式)
- `username` (纯用户名)

## 测试 Mock 服务器

项目包含一个用于测试的 Mock API 服务器：

```bash
# 启动 Mock 服务器
cargo run --example mock_api_server

# 有效的测试凭据：
# - admin / admin123
# - user / user123
# - test / test123
```

## 开发

```bash
# 运行测试
cargo test

# 运行带日志的调试模式
RUST_LOG=debug cargo run
```

## 许可证

MIT License
