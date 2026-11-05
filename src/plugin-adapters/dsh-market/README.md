# dsh-market 适配

**症状**（公网 origin，例如 `https://49.234.185.243:39443`）：

> 插件目录加载失败，请稍后重试
> 这个请求来自不受信任的地址，已拒绝。 / This request came from an untrusted origin and was refused.

**根因链**：

1. `dsh-market` 把自己的路由注册为 webServer 的 **exact** 路由：`/dsh-market/registry`、
   `/dsh-market/status`、`/dsh-market/installed` 等。exact 匹配优先于 connection 插件的
   `/api` 前缀护栏，所以 DSH 的 `/api` 信任规则管不到它。
2. 因此市场自己做入口校验（`dshmarket/lib/http.js` 的 `refuseUnadmitted` → host gate）：
   只接受 loopback、监听地址、或 `trustedHosts` 里声明过的 authority。
3. 本机部署刻意保持 `DSH_TRUSTED_HOST` 为空、profile patch 的 `trustedHosts` 也为空，
   于是公网浏览器带来的公网 Host 被拒 → 403，前端显示“目录加载失败”。
4. `wj-dsh-remote` 的改写白名单原本只覆盖 `/api/`、`/sidebar/`、`/git/`、`/pet/`，
   `/dsh-market/*` 不在其中，所以这些请求**没有**进入 `/wj-remote` 通道；
   一旦进入通道，Host 会被改写成 loopback 并带上进程内凭证，市场的校验就会放行。

**为什么只放只读接口**：

`install` / `update` / `remove` / `restart` / `rollback` / `cancel` 等写接口若也代理，
已配对设备就能远程安装任意 npm 插件 —— 从“能聊天、改文件”升级为“能执行任意插件代码”。
所以 `adapter.mjs` 的 `allow` 只列目录、状态、更新检查等只读路径；安装/更新仍回 loopback 做。

**已验证**：

```bash
# 通道本身可以承载市场只读接口（用已配对设备的 id 作为 cookie 值）
curl -s -b "wj_dsh_pair=<device-id>" \
  http://127.0.0.1:39666/wj-remote/dsh-market/registry
# → 200 + registry JSON
```

**改造后自检**：

1. `pnpm adapters:check` 应为 0；
2. 重新打包/安装并重启后，公网页面的“插件市场 → 发现”应正常出列表；
3. 点“安装”仍应被拒（本地/loopback 下才可用）——这是预期行为，不是回归；
4. loopback 页面行为不变。

**注意**：市场自身的 `sameOrigin` 校验允许“没有 Origin 头”的请求（源码注释里写明，
为兼容 Desktop 代理），而 `/wj-remote` 通道会丢弃 `Origin`/`Referer` 并补
`sec-fetch-site: same-origin`，所以即使将来放开写接口，CSRF 语义也不会被绕过。
