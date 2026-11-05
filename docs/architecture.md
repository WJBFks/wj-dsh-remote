# 架构（运行时视角）

## 组件与数据流

```text
┌────────────┐   HTTPS    ┌──────────────┐   HTTP    ┌──────────────────────────────┐
│ 手机/PC浏览器 │ ─────────> │ nginx :39443 │ ────────> │ dsh web 127.0.0.1:39666      │
└────────────┘            └──────────────┘           │                              │
                                                     │ wj-dsh-remote 宿主半         │
                                                     │  ├ /api/wj-pair/*  控制面     │
                                                     │  ├ /wj-remote/*    配对通道   │
                                                     │  ├ boot 脚本注入 index.html   │
                                                     │  └ LAN 转发 / tunnel / relay  │
                                                     └──────────────┬───────────────┘
                                                                    │ 回环请求（Host=127.0.0.1 + 进程内凭证）
                                                                    ▼
                                                          DSH /api/*、插件 exact 路由
```

## 两种页面

| 页面 | 来源 | 行为 |
|---|---|---|
| loopback（`127.0.0.1:39666`） | dsh 原生 | 原生 fetch/WS，不经过通道；插件面板只在本机可 mint 二维码 |
| 远程（公网 / LAN origin） | 经 `/wj-pair-app` 发放设备 cookie 后由 dsh 服务 | boot 脚本把白名单同源请求改写为 `/wj-remote/<path>`，附设备凭证 |

## 配对流程

```text
桌面 loopback 面板
  POST /api/wj-pair/issue            (仅 loopback 控制面)
   → 返回 https://<publicBaseUrl>/wj-pair-accept?pair=<token>
手机/PC 打开该链接
  GET /wj-pair-accept?pair=…         → 303 /wj-pair-app?grant=<one-time>
  GET /wj-pair-app?grant=…           → 200 + Set-Cookie: wj_dsh_pair=<deviceId>
  → 之后的同源请求进入 /wj-remote 通道（cookie 或 x-wj-remote-device 头）
```

- 设备会话落盘 `$DSH_HOME/wj-dsh-remote-devices.json`（0600，原子写）。
- 撤销：`POST /api/wj-pair/revoke`（loopback）→ 设备下一次请求 403 `unpaired`。
- 设备 cookie 寿命由 `idleExpireMs` 滑动控制（生产配置 90 天）。

## 请求改写（浏览器半 + boot 脚本）

两处实现同一套规则，规则表在 `src/remote-channel-rules.ts`（产物里内联为 `RULES`）：

1. **boot 脚本**（宿主注入 `index.html`，先于业务 bundle）：包装 `fetch`、`WebSocket`、
   `EventSource`、`img/script/iframe.src`，把同源且命中白名单的路径改写到 `/wj-remote`；
   同时负责 `__DSH_TRANSPORT__.ownsHost` 的授予（host mode）。
2. **client bundle**（`lib/client.js`）：`shouldRewriteFetchPath`，同上规则，作为页面内的
   兜底与面板自身请求的改写。

默认白名单：`/api/`、`/sidebar/`、`/git/`、`/pet/`，以及 `src/plugin-adapters/` 声明的
第三方只读前缀（例如 `dsh-market` 的目录接口）。

**为什么需要适配层**：第三方插件若把路由挂在精确前缀（`/dsh-market/*`），DSH 的 `/api`
前缀护栏覆盖不到；插件自己的 loopback 校验会拒绝公网 Host。把它们改写到 `/wj-remote`
即可让通道把 Host 改回 loopback。适配层不改第三方代码。

## 通道服务端

- `innerPathOf`：只接受 `/wj-remote/` 开头的安全路径；**前缀长度是编译期内联的 10**。
- 本地专用前缀拒绝代理：`/api/wj-pair`、`/api/update`、`/api/plugin-manager`。
- 转发时：Host 改回 `127.0.0.1:<port>`、丢弃 Origin/Referer/转发头、附进程内浏览器凭证、
  合成 `sec-fetch-site: same-origin`；设备凭证只用于门控，不会转发给内层。
- 未配对：403 `{"code":"unpaired"}`；已撤销设备与未配对等价。

## 配置项（宿主半）

| 键 | 作用 | 生产值 |
|---|---|---|
| `publicBaseUrl` | 二维码/入口的对外基址 | `https://49.234.185.243:39443` |
| `relay` | 是否向 `dsh-market.com` 注册固定域名租约 | `false` |
| `autoTunnel` | 是否自起 cloudflared quick tunnel | `false` |
| `idleExpireMs` | 设备空闲过期（滑动） | `7776000000`（90 天） |
| `requirePairingForLan` | LAN `/api` 是否强制配对 | `true`（默认） |
| `cookieName` | 设备 cookie 名 | `wj_dsh_pair`（默认） |

## 不变量

- 宿主始终只绑 `127.0.0.1`；公网入口由 nginx 提供。
- `trustedHosts` 为空：任何公网 Host 直连 `/api` 都会被 DSH 拒绝。
- 配对设备 = 完整控制凭证；通道的 `/api` 访问是设计内行为。
