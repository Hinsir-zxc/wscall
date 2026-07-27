# WSCALL 框架使用说明

> 基于自有二进制协议的轻量级 WebSocket RPC/事件服务框架，提供 Rust 服务端、Rust 客户端与 JavaScript 客户端实现。

---

## 1. 项目定位

WSCALL 在原生 WebSocket 之上承载一套自有的二进制帧协议，将“API 请求/响应”与“事件发送/回执”两种语义统一在 JSON 信封里表达，并内建 ChaCha20-Poly1305 与 AES-256-GCM 对称加密。

适用场景：

- 需要 WebSocket 长连接、双向 RPC 与服务端推送的实时后端。
- 对单连接吞吐、广播扇出、连接规模有性能要求的场景。
- 希望以“路由 + 过滤器 + 事件 + 异常映射”这一服务框架范式组织业务逻辑。

当前边界：

- 提供 Rust 服务端、Rust 客户端与 JavaScript 客户端 SDK（`wscall-client-js`）。
- 文件传输走“二进制复合帧 + 原始字节附件”（协议 v2），零 Base64 开销；大文件分块流式上传未纳入框架核心。

---

## 2. 仓库结构

采用 Cargo workspace 多 crate 架构，职责清晰分层：

| Crate | 角色 |
| --- | --- |
| `wscall-protocol` | 共享协议：帧编解码 `FrameCodec`、信封类型、加密模式、附件模型、协议错误。 |
| `wscall-server` | 服务端框架：`WscallServer`、路由/过滤器/事件/异常、连接生命周期、推送 `ServerHandle`。 |
| `wscall-client` | 客户端 SDK：`WscallClient`、API 调用、事件发送/监听、自动重连。 |
| `wscall` | facade 入口 crate，通过 feature `server` / `client` / `full` 汇总导出。 |

依赖关系：`wscall-server` 与 `wscall-client` 均依赖 `wscall-protocol`；`wscall` 依赖以上三者。

```
wscall (facade, feature-gated)
├── wscall-protocol  (共享协议)
├── wscall-server    (服务端)
└── wscall-client    (客户端)
```

### 2.1 引入方式

```toml
[dependencies]
wscall = { version = "0.5.0", features = ["full"] }
```

- 仅服务端：`features = ["server"]`
- 仅客户端：`features = ["client"]`

---

## 3. 交互协议

### 3.1 帧格式（协议 v2）

双向传输均为如下二进制帧：

```
| frame_len:u32(be) | message_type:u8 | encryption:u8 | payload:N bytes |
```

- `frame_len`：后续 `message_type + encryption + payload` 的总长度。
- `message_type`：`0x00` = API（请求/响应）；`0x01` = 事件（发送/回执）。
- `encryption`：`0x00` = 明文；`0x01` = ChaCha20-Poly1305；`0x02` = AES-256-GCM。
- 明文模式下 `payload` 为复合负载（见下）。
- 加密模式下 `payload` 为 `12 字节 nonce + 密文(含 tag)`，解密后为复合负载。

**复合负载结构**（解密后）：

```
| meta_len:u32(be) | JSON_bytes[meta_len] | att_count:u8 | [att_0] ... [att_N] |
```

- `meta_len`：JSON 元数据字节长度。
- `JSON_bytes`：PacketBody 序列化结果，`a` 字段省略（附件由二进制段承载）。
- `att_count`：附件数量（0~255）。
- 无附件时仅多 5 字节开销。

**单个附件二进制段**：

```
| id_len:u8 | id | name_len:u8 | name | ct_len:u8 | content_type | data_len:u32(be) | raw_data |
```

- 所有字符串为 UTF-8 原始字节，无 Base64。
- 附件以原始二进制传输，消除协议 v1 中 33% 的 Base64 流量膨胀。

**帧大小限制**：

- 服务端通过 `with_max_frame_bytes(n)` 配置，默认 **100 MiB**。
- 超限帧触发 413 错误响应帧（`request_id=0`，`code="frame_too_large"`），连接保持打开。

### 3.2 JSON 信封

为节约通信流量，信封采用精简短键 + 数字 `k` 标签。`request_id`/`event_id` 使用 per-connection `AtomicU64` 计数器，在 JSON 中序列化为数字（如 `"i":42`），从 26 字节的 UUIDv7 字符串降至 1–6 字节。`connection_id` 保持 **UUIDv7**（每连接仅生成一次，非热路径，时间有序，利于索引与存储局部性）。

字段映射表：

| 短键 | 全名 | 含义 | 适用变体 |
| --- | --- | --- | --- |
| `k` | kind | 数字标签：0=API请求 1=事件发送 2=API响应 3=事件回执 | 全部 |
| `i` | id | 请求ID / 事件ID（per-connection u64 计数器，JSON 数字） | 全部 |
| `r` | route | API 路由路径 | ApiRequest |
| `p` | params | API 请求参数 | ApiRequest |
| `m` | metadata | 元数据（可选，为空时省略） | ApiRequest, ApiResponse, EventEmit |
| `n` | name | 事件名称 | EventEmit |
| `d` | data | 事件数据（JSON 对象） | EventEmit |
| `e` | expect_ack | 是否期待回执 | EventEmit |
| `o` | ok | 是否成功 | ApiResponse, EventAck |
| `s` | status | HTTP 状态码 | ApiResponse |
| `d` | data | 响应数据 | ApiResponse |
| `rc` | receipt | 回执数据 | EventAck |
| `er` | error | 错误负载（可选，省略表示无错误） | ApiResponse, EventAck |

API 请求：

```json
{"k":0,"i":1,"r":"system.echo","p":{"message":"hello"}}
```

API 响应：

```json
{"k":2,"i":1,"o":true,"s":200,"d":{"echo":"hello"}}
```

事件发送：

```json
{"k":1,"i":2,"n":"chat.message","d":{"message":"hello"},"e":true}
```

事件回执：

```json
{"k":3,"i":2,"o":true,"rc":{"ok":true}}
```

`PacketBody` 共四种变体：`ApiRequest`(`k=0`) / `EventEmit`(`k=1`) / `ApiResponse`(`k=2`) / `EventAck`(`k=3`)，由数字 `k` 字段区分。`error`(`er`) 字段仅在出错时出现，成功时省略以节省流量。事件数据 `d` 恒为 JSON 对象。

### 3.3 加密与密钥协商

框架支持两种密钥模式，在连接建立时确定，后续所有帧统一使用该模式加密：

**PSK（预共享密钥）模式**

- 服务端通过 `with_chacha20_key` / `with_aes256_key` 配置全局共享 codec，所有连接复用同一密钥。
- 客户端通过 `connect_with_chacha20` / `connect_with_aes256` 传入相同密钥。
- 适合密钥可安全预分发的内部网络或可信环境。

**ECDH 动态密钥协商模式**

- 基于 X25519 椭圆曲线 Diffie-Hellman，在 WebSocket 升级后、正式 RPC 通信前完成握手。
- 每个连接独立协商出 32 字节 ChaCha20-Poly1305 会话密钥，密钥从不在线上传输。
- 会话密钥 = SHA-256(`wscall-ecdh-v1` ‖ shared_secret)，与服务端协议层共用同一 KDF。
- 握手时序：
  1. 客户端生成 X25519 keypair，发送 32 字节公钥（原始二进制 WebSocket 消息）。
  2. 服务端生成自身 keypair，读取客户端公钥后返回 32 字节服务端公钥。
  3. 双方各自用对方公钥与自身私钥派生相同会话密钥。
  4. 握手完成，后续所有帧用 ChaCha20-Poly1305 加密。
- 服务端 ECDH 模式下每连接拥有独立 codec（会话密钥不同），广播与定向推送通过 `ServerOutbound::Packet` 交由 writer task 使用 per-connection codec 编码。
- Rust 端使用 `x25519-dalek`；JS 端使用 `@noble/curves`。

### 3.4 文件参数策略

JSON 传参与文件混合采用“参数引用 + 二进制附件段”（协议 v2）：

- `params` / `data` 中以 `{"$file": "attachment-id"}` 引用附件。
- 附件以原始二进制段追加在 JSON 元数据之后，零 Base64 开销。
- `FileAttachment::inline_text` / `inline_bytes` 构造；`.data` 字段为 `Bytes`（引用计数不可变缓冲，clone 仅增加引用计数）。
- 单个附件 id/name/content_type 长度上限 255 字节，附件数量上限 255。

---

## 4. 服务端框架

### 4.1 启动与加密

```rust
// PSK 模式
let mut server = WscallServer::new().with_chacha20_key(KEY);
server.listen("127.0.0.1:9001").await?;

// ECDH 动态密钥协商模式（无需预共享密钥）
let mut server = WscallServer::new().with_ecdh();
server.listen("127.0.0.1:9001").await?;
```

- `with_chacha20_key([u8;32])` / `with_aes256_key([u8;32])`：PSK 模式，配置编解码器并设定默认加密模式。
- `with_ecdh()`：启用 ECDH 动态密钥协商，每连接独立握手派生会话密钥。
- 明文模式：`WscallServer::new()`。

### 4.2 路由与参数绑定

- `route(route, handler)`：原始路由，handler 收到 `ApiContext`，返回 `Result<Value, ApiError>`。
- `typed_route::<T>(route, handler)`：自动将 `ctx.params` 绑定为强类型 `T`。
- `validated_route::<T>(route, handler)`：绑定后运行 `validator::Validate`，错误聚合到 `ApiError::details`。

`ApiContext` 提供 `connection_id()`、`peer_addr()`、`route()`、`params()`、`bind::<T>()`、`bind_validated::<T>()`、`attachments()`、`metadata()`、`server()` 等。

### 4.3 过滤器与异常映射

- `filter(handler)`：前置过滤链，可鉴权/改写上下文，返回新 `ApiContext` 或 `ApiError`。
- `exception_handler(handler)`：全局异常映射，接收 `ExceptionContext`，产出统一 `ErrorPayload`（含 `code`/`message`/`status`/`details`）。

`ApiError` 内置 `bad_request` / `not_found` / `internal`，可 `.with_details(value)` 携带结构化信息。

### 4.4 事件与服务端推送

- `event_handler(name, handler)`：注册客户端发出的事件处理，返回回执 `Value`。`EventContext` 含 `event_id()`、`name()`、`data()`（返回 `&Map<String, Value>`）、`attachments()`、`metadata()`、`connection_id()`、`peer_addr()`、`server()` 等。
- `ServerHandle`（经 `ctx.server()` 或 `server.handle()` 获得）：
  - `broadcast_event(name, data, attachments)`：广播给所有连接，`data` 为 `Map<String, Value>`。
  - `send_event_to(connection_id, name, data, attachments)`：定向推送，`data` 为 `Map<String, Value>`。
  - `connection_count()`：当前连接数。

### 4.5 连接生命周期

- `on_connected(handler)` / `on_disconnected(handler)`：连接建立/断开回调，上下文含 `connection_id()`、`peer_addr()`、`reason()`、`server()`。
- 服务端在连接建立时自动下发 `system.notice` 事件。
- 心跳：服务端每 15s 发送 WebSocket Ping，45s 无任何入站消息触发空闲超时并断连。

### 4.6 并发与背压模型（性能关键）

- **请求并发化**：每条入站的 API 请求/事件由独立 `tokio::spawn` 任务执行（每连接以信号量 `max_in_flight` 限制，默认 64），读循环仅负责解码与分发。慢 handler 不再阻塞同一连接的后续消息；`request_id`/`event_id` 天然支持乱序响应。
- **广播零拷贝**：`broadcast_event` 将帧**编码一次**并以 `Bytes` 共享给所有接收者，成本不再随连接数 × 负载大小线性增长；单连接队列满时仅丢弃该连接的本次投递。
- **预编码**：所有出站帧在分发侧预编码为字节，写任务只搬运字节，编码可跨并发 handler 并行。
- **背压语义**：API 响应/事件回执走 `send().await`（背压），事件推送走 `try_send`（尽力而为）。
- **无锁连接表**：`DashMap` 替代单一 `RwLock<HashMap>`，读路径无锁，广播可并发遍历。
- **连接数上限**：`with_max_connections(n)` 在 accept 前获取许可，连接洪泛转为背压而非无界 spawn。
- **低延迟**：accept 后设置 `TCP_NODELAY`，关闭 Nagle 以降低小帧 RPC 延迟。
- **零拷贝类型化路由**：`typed_route` / `validated_route` 通过 `mem::take` 将 params 从上下文**移出**后 `from_value`，避免每请求深拷贝整棵 params JSON 树；公共 `bind` / `bind_and_validate` / `bind_validated` 行为不变。
- **生命周期 handler 并发**：`on_connected` / `on_disconnected` 以 `join_all` 并发执行，慢 handler 不再延迟连接建立与拆除。
- **日志**：库内使用 `tracing`，热路径不再竞争 stdout 锁；ACK 等高频消息默认 `debug` 级。

---

## 5. 客户端 SDK

### 5.1 连接

```rust
// 统一入口：WscallClient::connect(url, config)
// 默认配置（ECDH + ChaCha20 + 自动重连）
let client = WscallClient::connect(url, WscallClientConfig::default()).await?;

// ECDH 动态密钥协商（推荐默认）
let client = WscallClient::connect(url, WscallClientConfig::ecdh()).await?;

// 明文连接（仅开发环境）
let client = WscallClient::connect(url, WscallClientConfig::plaintext()).await?;

// PSK 加密连接
let client = WscallClient::connect(url, WscallClientConfig::psk_chacha20(KEY)).await?;
let client = WscallClient::connect(url, WscallClientConfig::psk_aes256(KEY)).await?;

// 禁用自动重连
let config = WscallClientConfig::ecdh().with_auto_reconnect(false);
let client = WscallClient::connect(url, config).await?;

// 多服务器故障转移
let config = WscallClientConfig::ecdh()
    .with_failover_url("ws://backup1:9001/socket")
    .with_failover_url("ws://backup2:9001/socket");
let client = WscallClient::connect("ws://primary:9001/socket", config).await?;
```

- `WscallClientConfig` 结构体封装所有用户可调参数：`codec`、`default_encryption`、`auto_reconnect`、`use_ecdh`、`failover_urls`。
- `Default` 实现采用 ECDH + ChaCha20 + 自动重连（推荐安全默认）。
- 便捷构造：`ecdh()` / `plaintext()` / `psk_chacha20(key)` / `psk_aes256(key)`。
- Builder 方法：`with_codec` / `with_default_encryption` / `with_auto_reconnect` / `with_use_ecdh` / `with_failover_url` / `with_failover_urls`。
- **故障转移**：`failover_urls` 配置备用 URL 列表。连接/重连时从上次成功的 URL 索引开始，按顺序遍历 `[primary] + failover_urls`，首个连通即返回（sticky failover）。所有 URL 均失败后才进入指数退避等待。
- 旧连接方法（`connect(url)`、`connect_with_auto_reconnect`、`connect_with_chacha20`、`connect_with_aes256`、`connect_with_ecdh`、`connect_with_settings`）已标记 `#[deprecated(since = "0.5.0")]`，内部转发至新统一路径。

所有 `request_id` / `event_id` 使用 per-connection `AtomicU64` 计数器生成（JSON 数字，1–6 字节）。`connection_id` 保持 UUIDv7（每连接仅生成一次，非热路径）。

### 5.2 API 调用与事件

- `call(route, params, attachments) -> Result<Value, ClientError>`：发起 API 请求，`request_id` 自动生成并匹配响应；默认超时 10s。
- `send_event(name, data, attachments) -> Result<Value, ClientError>`：发出事件并等待 ACK。
- `on_event(name, handler)`：注册服务端推送事件处理，handler 接收 `Arc<EventMessage>`（多 handler 共享同一分配，`Arc::clone` 仅增加引用计数），多个 handler **并发执行**（`join_all`）。
- `on_connected(handler)` / `on_disconnected(handler)`：连接生命周期回调，断连事件含 `will_reconnect` 与 `retry_after`。

### 5.3 自动重连

- `auto_reconnect` 默认 `true`。当设为 `false` 时，断连后不自动重连，`will_reconnect` 为 `false`、`retry_after` 为 `None`，调用方需自行管理重连。
- 当 `auto_reconnect = true` 时：连接断开（含空闲超时、服务端关闭、读写错误）后自动重连。
- **指数退避 + 抖动**：实际睡眠 = 指数退避（3s → 6s → 12s …，上限 30s）+ `[0, base/2)` 随机抖动，避免多客户端同步重连的惊群效应。
- `retry_after` 字段报告确定的指数退避值（不含抖动），便于展示。
- `close()` 主动关闭，不再重连（无论 `auto_reconnect` 设置）。

### 5.4 客户端性能模型

- **无锁 pending 表**：`pending_api`/`pending_event` 改为 `DashMap`，消除单 `Mutex` 对所有并发调用的串行化；响应分发与超时清理均无锁。
- **无锁出站句柄**：`writer` 字段使用 `arc_swap::ArcSwapOption`，`send_outbound` 读取无锁、无 `Option` 克隆。
- **事件 handler 并发**：服务端推送事件的多 handler 并发执行，慢 handler 不再阻塞读循环。
- **EventEmit 派发 spawn 化**：入站事件在独立任务处理，读循环不被慢 handler 队头阻塞；API 响应 / 事件 ACK 保持内联分发。
- **静态 metadata**：出站请求/事件的 metadata 由 `OnceLock` 构造一次后克隆复用，消除每调用重复构造 JSON 对象。
- **重连抖动随机源**：重连抖动改用 `getrandom` 操作系统随机源（替代时钟纳秒），避免同刻重连客户端抖动相关。
- **日志**：库内使用 `tracing`，不阻塞事件循环。

### 5.5 错误类型

`ClientError`：`WebSocket` / `Protocol` / `Disconnected` / `ConnectionClosed` / `IdleTimeout` / `Timeout` / `Remote(ErrorPayload)`。

---

## 6. 验证体系（`wscall::server::validation`）

### 6.1 内置函数式验证器

`required` / `assert_true` / `assert_false` / `not_empty` / `not_blank` / `no_whitespace` / `alphabetic` / `alphanumeric` / `ascii_alphanumeric` / `numeric_text` / `lowercase` / `uppercase` / `non_empty_vec` / `non_empty_map` / `positive_*` / `non_negative_*` / `percentage`。

### 6.2 宏验证器

- `wscall_regex_validator!(name, pattern, code)`：编译期缓存正则（`OnceLock`）。
- `wscall_min_length_validator!` / `wscall_max_length_validator!` / `wscall_length_range_validator!`
- `wscall_contains_validator!` / `wscall_not_contains_validator!` / `wscall_one_of_validator!`
- `wscall_numeric_min_validator!` / `wscall_numeric_max_validator!` / `wscall_numeric_range_validator!`

配合 `validator::Validate` 派生宏在结构体字段上使用 `#[validate(custom(function = "..."))]`。

### 6.3 自定义校验

实现 `ValidateParams` trait 的 `validate(&self) -> Result<(), ApiError>`，通过 `ctx.bind_and_validate::<T>()` 调用。

---

## 7. 协议层性能要点（`FrameCodec`）

- **加密器预计算缓存**：`ChaCha20Poly1305` / `Aes256Gcm` 在配置密钥时构造一次，以 `Arc` 在 codec 所有克隆间共享，编解码不再每帧重复密钥调度（AES-256 密钥扩展尤其受益）。
- **明文解码零拷贝**：明文路径以 `Bytes::slice()` 零拷贝切片直接共享帧底层缓冲，无分配；附件二进制段同样使用 `data.slice(pos..pos+len)` 零拷贝提取。
- **单缓冲编码**：`encode` 明文路径直接构建最终帧（`serde_json::to_writer` 直写 + 原地回填长度前缀），去除中间 JSON 缓冲与多次全缓冲拷贝；加密路径同样去除中间 JSON 缓冲。
- **单次解析反序列化**：`PacketBody::deserialize` 仅解析一次 JSON 对象后直接 move 字段，嵌套 `params`/`data`/`metadata`/`receipt` 不再二次遍历。
- **加密前预检大小**：先校验 JSON 序列化结果再加密，避免对超限负载做无谓加密后丢弃。

---

## 8. 快速上手

### 8.1 最小示例（`examples/quick_start.rs`）

```rust
use serde_json::json;
use tokio::time::{Duration, sleep};
use wscall::{WscallClient, WscallClientConfig, WscallServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_task = tokio::spawn(async move {
        let mut server = WscallServer::new();
        server.route("system.echo", |ctx| async move {
            Ok(json!({ "route": ctx.route(), "params": ctx.params() }))
        });
        server.listen("127.0.0.1:9010").await
    });
    sleep(Duration::from_millis(100)).await;

    let client = WscallClient::connect(
        "ws://127.0.0.1:9010/socket",
        WscallClientConfig::plaintext(),
    ).await?;
    let response = client
        .call("system.echo", json!({ "message": "hello" }), Vec::new())
        .await?;
    println!("response: {response}");
    client.close().await?;
    server_task.abort();
    Ok(())
}
```

### 8.2 完整 Demo

- `examples/demo_server.rs`：ChaCha20 / ECDH 加密、过滤器、异常映射、典型/强类型/校验路由、附件、聊天室广播与历史。
- `examples/demo_client.rs`：连接、事件监听、API 调用（含附件）、事件发送、历史查询。

运行（PSK 模式）：

```bash
cargo run --example demo_server --features server
# 另一终端
cargo run --example demo_client --features client
```

运行（ECDH 模式）：

```bash
cargo run --example demo_server --features server -- --ecdh
# 另一终端
cargo run --example demo_client --features client -- --ecdh
```

示例入口已安装 `tracing-subscriber`（`RUST_LOG` 控制），可观察库内日志；库本身不依赖任何特定订阅器。

---

## 9. 调优参数速查

| 位置 | 参数 | 默认 | 说明 |
| --- | --- | --- | --- |
| server | `SERVER_IDLE_TIMEOUT` | 45s | 入站空闲超时 |
| server | `SERVER_HEARTBEAT_INTERVAL` | 15s | 心跳 Ping 间隔 |
| server | `SERVER_OUTBOUND_QUEUE_CAPACITY` | 256 | 单连接出站队列容量 |
| server | `with_max_connections(n)` | 无上限 | 全局并发连接上限 |
| server | `with_max_in_flight(n)` | 64 | 单连接并发 handler 上限 |
| client | `CLIENT_IDLE_TIMEOUT` | 45s | 入站空闲超时 |
| client | `CLIENT_HEARTBEAT_INTERVAL` | 15s | 心跳 Ping 间隔 |
| client | `CLIENT_OUTBOUND_QUEUE_CAPACITY` | 256 | 出站队列容量 |
| client | `default_timeout` | 10s | API/事件调用默认超时 |
| client | `CLIENT_RECONNECT_BASE_DELAY_SECS` | 3s | 重连退避基数 |
| client | `CLIENT_RECONNECT_MAX_DELAY_SECS` | 30s | 重连退避上限 |
| protocol | `DEFAULT_MAX_FRAME_BYTES` | 100 MiB | 默认整帧大小上限（服务端可通过 `with_max_frame_bytes(n)` 覆盖） |

---

## 10. 测试

```bash
cargo test --workspace --all-features
```

覆盖：

- 协议层：明文/加密往返、超限拒绝。
- 服务端：内置与宏验证器。
- 集成（`tests/lifecycle_reconnect.rs`）：连接/断开生命周期回调、客户端意外断连后的自动重连与恢复调用。

---

## 11. 关键依赖

`tokio`（异步运行时）、`tokio-tungstenite`（WebSocket）、`serde`/`serde_json`（信封）、`aes-gcm` 与 `chacha20poly1305`（对称加密）、`x25519-dalek`（ECDH 密钥协商）、`sha2`（会话密钥派生）、`uuid`（标识）、`validator`（校验）、`dashmap`（无锁并发表）、`arc-swap`（无锁句柄）、`bytes`（零拷贝广播）、`tracing`（结构化日志）。

---

## 12. 设计取舍小结

1. 协议两层模型：WebSocket 二进制帧承载 WSCALL 帧，WSCALL 帧负载承载复合结构（JSON 元数据 + 二进制附件段）。
2. 加密在协议层统一处理，业务层无感。支持 PSK 预共享密钥与 ECDH 动态密钥协商两种模式，前者适合可信内网，后者适合零信任场景。
3. 文件走二进制复合帧（协议 v2），附件以原始字节传输，消除 Base64 的 33% 流量膨胀。
4. 服务端采用“读循环解码 + 信号量受限并发 handler + 预编码出站”模型，兼顾吞吐与背压。
5. 客户端采用“无锁 pending 表 + 无锁出站句柄 + 并发事件 handler + 指数退避抖动”模型，兼顾并发与稳定重连。
6. 库内日志统一 `tracing`，热路径无同步 IO 阻塞。
