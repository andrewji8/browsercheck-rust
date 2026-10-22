# browsercheck-rust

一站式浏览器与网络环境自检工具 —— [andrewji8/browsercheck](https://github.com/andrewji8/browsercheck)（Python/Flask）的 Rust 重构。

## 功能

| 端点 | 说明 |
| --- | --- |
| `GET /api/ip` | IPv4/IPv6 双栈、ASN、机房/代理识别、Tor 出口检测、风险评分 |
| `GET /api/webrtc` | 服务端观测 IP（配合浏览器端 WebRTC 探针） |
| `GET /api/dns` | 系统 DNS 解析器检测 + DNS 泄漏检测（whoami.akamai.net） |
| `GET /api/multi-geo` | 多 GeoIP 源并发查询，检测 split-tunnel |
| `GET /api/headers` | HTTP 头部分析（Sec-CH-UA、代理特征等） |
| `GET /api/engine-probe` | UA 引擎 / 浏览器 / 操作系统推断 |
| `GET /api/validate` | 服务端交叉校验（R2/R3/R4/R10 子集） |
| `POST /api/validate` | 完整 19 条交叉校验规则引擎 |
| `GET /api/ping` | 健康检查 |
| `GET /` | 前端页面（`static/index.html`，与原版一致） |

## 构建与运行

```bash
cargo build --release
PORT=8080 cargo run --release
# 浏览器打开 http://localhost:8080
```

环境变量：`PORT`（默认 5000）、`RUST_LOG`（日志级别）。

## 模块说明

- `src/main.rs` —— axum 路由与程序入口
- `src/state.rs` —— 共享状态（HTTP 客户端 + ASN 结果缓存）
- `src/geo.rs` —— 客户端 IP 提取、ip-api ASN 查询、Tor 出口列表、机房 ASN 表
- `src/dns.rs` —— 系统 DNS 解析器发现（trust-dns-resolver）+ DNS 泄漏探测
- `src/ua.rs` —— UA 解析（引擎 / 浏览器 / 操作系统）
- `src/util.rs` —— 语言↔国家、时区→国家、字体区域映射表
- `src/rules.rs` —— 19 条交叉校验规则引擎（R1–R19）
- `src/routes.rs` —— 全部 HTTP handler

## 与 Python 版的差异

- Web 框架：Flask → axum（tokio 异步）
- HTTP 客户端：httpx → reqwest（rustls）
- DNS：dnspython → trust-dns-resolver（读取系统解析器配置）
- pytz / pycountry → 内置映射表（`util::tz_to_country` / `lang_matches_country` / `detect_font_regions`）
- 响应 JSON 中的头部名称为小写（HTTP 头部名称规范 / axum `HeaderName` 行为），取值与原版一致
- 其余字段结构、规则编号、状态判定逻辑与原版 `server.py` 保持一致
