# AGENTS.md — wj-dsh-remote 维护指南

本文件是**仓库级**约定，给接手这个仓库的 agent / 维护者看。主机层面的约定见 `~/AGENTS.md`，
生产环境的运维背景见 `~/docs/dsh-web-access.md` 和 `~/docs/wj-dsh-remote-cutover.md`（仓库外）。

**当前版本**：`0.1.2`（以 `git log` 为准）
**基线**：`@linxin666/dsh-remote-web-ui@0.4.14`（上游最后一个支持浏览器远程的版本）
**已验证 DSH**：`0.2.1-rc.5`（`engines.dsh >= 0.2.1-rc.3`）
**许可证**：Apache-2.0，来源与修改记录见 `NOTICE`

---

## 1. 这是什么

`wj-dsh-remote` 是 `@linxin666/dsh-remote-web-ui@0.4.14` 的个人 fork，保留**浏览器扫码远程访问
DSH Web GUI** 的能力（上游已弃用该路径，改推原生 App 协议）。全部对外标识改成 `wj-*` 命名空间，
避免与上游插件冲突。

**这个仓库存在的理由**：上游 0.4.14 之后不再维护浏览器远程；本仓库冻结该能力并自行维护兼容性。

**不要做的事**：

- 不要把上游升到 `0.4.15+`（要求 `dsh >= 0.2.2-rc.1`，且浏览器远程已被移除）；
- 不要把 `relay` 默认改回 `true`（上游默认会向 `dsh-market.com` 注册公网租约）；
- 不要恢复 telemetry 心跳；
- 不要改第三方插件（`dsh-market` 等）的代码——用 `src/plugin-adapters/` 适配。

---

## 2. 目录与职责

| 路径 | 作用 |
|---|---|
| `lib/index.js` | **宿主半**（实际运行的产物）：配对服务、`/api/wj-pair/*` 路由、`/wj-remote` 通道、注入 `index.html` 的 boot 脚本、LAN 转发、relay/tunnel 控制 |
| `lib/client.js` | **浏览器半**（实际运行的产物）：电话图标/配对面板、设备名册、手机竖屏适配层、fetch/WebSocket/EventSource 改写 |
| `lib/types/**` | 随包发布的类型声明 |
| `src/**` | 源码，**当前不参与构建**（见第 5 节），用于对照与后续恢复构建 |
| `src/plugin-adapters/` | 第三方插件适配声明（`<plugin>/adapter.mjs` + README） |
| `scripts/adapters-sync.mjs` | 把适配声明注入 `lib/client.js`、`lib/index.js`（幂等，`--check`，`prepack` 自动跑） |
| `cordis.patch.yml` | profile 里的插件行：`id: wj-dsh-remote`、`name: wj-dsh-remote` |
| `locale/{en,zh}.json` | 面板文案 |
| `docs/` | 架构、上游同步、历史 README 存档 |
| `NOTICE` | 上游归属 + 本 fork 的修改清单（**新增修改时要更新**） |

运行时只有 `lib/` 会被 DSH 加载；`src/` 不参与执行。

---

## 3. 运行时架构（简版）

```text
手机/PC 浏览器 ──HTTPS──> nginx :39443 ──> dsh web 127.0.0.1:39666
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        │ wj-dsh-remote 宿主半 (lib/index.js)        │
                        │  /api/wj-pair/*   配对/设备管理（仅 loopback 控制面）│
                        │  /wj-remote/*     配对设备门控通道 → 回环转发     │
                        │  boot 脚本         注入 index.html，改写同源请求    │
                        └─────────────────────┬─────────────────────┘
                                              │ 请求带 loopback Host + 进程内凭证
                                        DSH /api/*、插件 exact 路由
```

关键事实：

- **launch token 固定**由仓库外的补丁实现（`~/.local/bin/dsh-web-token-patch.sh`），与本仓库无关；
  本仓库只依赖 `?token=` 登录后签发的 90 天 cookie，以及自己签发的设备 cookie。
- 浏览器在**非 loopback origin** 下：boot 脚本 + client bundle 把白名单内的同源请求改写为
  `/wj-remote/<原路径>`，并带上设备凭证；通道把 Host 改回 `127.0.0.1` 并附进程内凭证，
  于是 DSH 的 `/api` 护栏和插件的 loopback 校验都能通过。
- 配对设备 = **完整控制凭证**（等价于 launch token）。文档和 UI 都必须这样表述。

详细流程见 [docs/architecture.md](docs/architecture.md)。

---

## 4. 路由与状态（改名对照）

| 上游 | 本仓库 |
|---|---|
| `@linxin666/dsh-remote-web-ui` | `wj-dsh-remote` |
| 插件行 `remote-web-ui` | `wj-dsh-remote` |
| `/api/pair/*` | `/api/wj-pair/*` |
| `/pair-accept` / `/pair-app` / `/pair-ping` | `/wj-pair-accept` / `/wj-pair-app` / `/wj-pair-ping` |
| `/remote` 通道 | `/wj-remote` |
| `remote-web-ui-devices.json` | `wj-dsh-remote-devices.json` |
| `remote-web-ui-registry/` | `wj-dsh-remote-registry/` |
| `x-dsh-remote-device` | `x-wj-remote-device` |
| `dsh_pair` cookie | `wj_dsh_pair` |
| `dsh-remote-force-desktop` | `wj-dsh-remote-force-desktop` |

通道的本地专用前缀（永远不代理）：`/api/wj-pair`、`/api/update`、`/api/plugin-manager`。

常用配置键（`cordis.patch.yml` 的 `config`）：`publicBaseUrl`、`autoTunnel`、`relay`、`tunnelToken`、
`idleExpireMs`、`cookieName`、`devicesFile`、`lanBind`、`requirePairingForLan`。

---

## 5. 构建与产物（重要）

**当前没有构建链**：仓库直接发布手工维护的预编译 `lib/`。因此：

- 改行为时**必须同时改 `src/` 和 `lib/`**（或明确只在 `src/` 标注 TODO），否则运行时不会生效；
- 改 `lib/client.js` / `lib/index.js` 后必须 `node --check` 两个文件；
- **不要手改**适配注入块（`/* wj-adapters:start */ … /* wj-adapters:end */`），它由脚本生成；
- 若将来恢复构建（tsdown），从 `src/` 重新生成 `lib/` 后，`adapters-sync` 仍需在 pack 前跑一次。

### 适配层

```bash
pnpm adapters:sync     # 重新生成注入块（幂等）
pnpm adapters:check    # 漂移检测，CI/发布前用
npm pack               # prepack 自动跑 adapters:sync
```

新增适配：建 `src/plugin-adapters/<plugin>/adapter.mjs`（`id` / `prefix` / 只读 `allow`），
写同目录 README，`pnpm adapters:sync`，验证 `adapters:check` 为 0。

**默认只放只读接口**。把安装/更新/卸载类写接口代理进通道 = 允许已配对设备远程安装任意 npm 插件，
属于权限升级，必须单独评审。

适配层是**客户端策略**，不是服务端强制；配对设备本来就是全权凭证。不要把适配层描述成安全边界。

---

## 6. 从上游移植新版本（如果哪天需要）

1. 取上游对应版本的 npm tarball（含 `src/`），解到临时目录；
2. 按第 4 节的对照表做**有序**替换（长的先替换：`/pair-app.sw.js` → `/api/wj-pair` → `/pair-*` →
   `/remote` → header/cookie/storage → `remote-web-ui` → `wj-dsh-remote`）；
3. **检查内联长度常量**：打包器会把 `REMOTE_PREFIX.length` 之类折叠成数字。上游 `/remote` 长度 7，
   本仓库 `/wj-remote` 长度 **10**，对应 `pathname.slice(10)` / `path.slice(10)`。漏改会让
   `/wj-remote/*` 全部 404（这是 0.1.0 实际踩过的坑）；
4. **检查相对路径**：浏览器半有 `"api/pair/..."` 这类不带前导斜杠的调用，不能只替换 `/api/pair`；
5. 检查 boot 脚本字符串里的转义（见 `docs/upstream-sync.md`）；
6. 重跑 `adapters:sync`，`node --check`，然后按第 7 节验证。

更细的步骤与陷阱清单见 [docs/upstream-sync.md](docs/upstream-sync.md)。

---

## 7. 验证清单（改动后必跑）

```bash
# 1) 静态
node --check lib/index.js
node --check lib/client.js
node scripts/adapters-sync.mjs --check

# 2) 隔离环境（不要直接拿生产试）
DSH_HOME=/tmp/dsh-dev dsh plugin --profile web add /path/to/wj-dsh-remote-*.tgz
DSH_HOME=/tmp/dsh-dev dsh web --host 127.0.0.1 --port 3191 --no-open

# 3) 路由（未配对）
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3191/api/wj-pair/status   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3191/remote               # 404
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3191/wj-pair-accept       # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3191/wj-remote/plugins/events  # 403

# 4) 配对 → 通道 → 撤销（issue → accept 303 → app 200 → /wj-remote/* 200 → revoke → 403）
#    参考 ~/docs/wj-dsh-remote-cutover.md 第 8 节
```

页面级验证（boot 脚本与 client bundle）：

```bash
# 取到 dsh-auth cookie 后
curl -s -b "$C" http://127.0.0.1:PORT/ > /tmp/root.html
grep -c 'wj-adapters' /tmp/root.html          # 适配生效时 ≥1
```

---

## 8. 部署（生产）

生产 profile 在 `~/.dsh/profiles/web`，服务是 `dsh-web.service`（user 单元），入口
`127.0.0.1:39666`，公网 nginx `https://49.234.185.243:39443`。

```bash
cd ~/.dsh/profiles/web
dsh plugin --profile web add github:WJBFks/wj-dsh-remote
# patch 行的 id 必须是 wj-dsh-remote（0.1.0 切换时已完成）
systemctl --user restart dsh-web
```

验证：`/api/wj-pair/status` 200、`publicUrl` 正确、`/remote` 404、公网带 token 303、
无 relay/telemetry 日志。**手机需要重新扫码一次**（设备库存的是新命名空间）。

回滚：恢复 `~/backups/dsh-pre-wj-switch-*.tgz` 里的 profile 文件 + `dsh plugin --profile web install`
+ 重启。完整步骤见 `~/docs/wj-dsh-remote-cutover.md`。

---

## 9. 安全不变量

- `trustedHosts` 保持为空；不要为了修插件市场去开 `--trusted-host`（会同时打开 DSH `/api` 护栏）。
- `relay` 默认 `false`；`autoTunnel` 默认 `false`；telemetry 关闭。
- 不碰 nginx、证书、launch token（`~/.dsh/web-launch-token.secret`）。
- 不把配对设备描述成"只读"——它是完整控制凭证。
- 不把 `/api/wj-pair`、`/api/update`、`/api/plugin-manager` 加入任何代理白名单。

---

## 10. Git 约定

- 直接在 `main` 上提交，`git push origin main`（个人仓库，无 PR 流程）。
- 版本号：行为变更/新适配 → patch 位 +1；破坏性重命名 → minor。
- 提交信息用 `x.y.z: 摘要`，正文列行为变化与验证方式。
- 不提交 `node_modules/`、`*.tgz`、`pnpm-lock.yaml`（已在 `.gitignore`）。
- 修改上游代码时更新 `NOTICE` 的修改清单。

---

## 11. 已知坑速查

| 坑 | 说明 |
|---|---|
| `slice(7)` vs `slice(10)` | 前缀长度被内联；`/wj-remote` 是 10，漏改导致通道全 404 |
| 相对 `api/pair/*` | 浏览器半的 fetch 路径不带前导 `/`，替换要覆盖 |
| boot 字符串转义 | 注入 boot 脚本时反斜杠要双写（`\\/`），否则正则失效或脚本语法错误 |
| `link:` 安装 | 链接包不沿 profile 解析 `@deepseek-ai/*` peers，会 `Cannot find package '@deepseek-ai/cordis'`；用 tarball/github |
| cloudflared 构建脚本被忽略 | pnpm 默认忽略其 postinstall；`autoTunnel` 关闭时无影响 |
| 旧 relay 租约 | 0.1.0 切换窗口里旧插件曾注册过 `dsh-market.com` 租约；本地凭证在 `~/.dsh/remote-web-ui-registry/`，可走 `POST /api/relay/unregister`（需 id+secret）清理 |
| 设备库路径变更 | `wj-dsh-remote-devices.json` 与旧库不迁移；旧库保留用于回滚 |
