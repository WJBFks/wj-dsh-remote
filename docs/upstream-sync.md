# 从上游移植 / 重新 fork

本仓库以 `@linxin666/dsh-remote-web-ui@0.4.14` 为基线，**手工维护预编译 `lib/`**。
如果将来需要从上游新版本重新 fork（或把某个上游修复搬过来），按本文执行。

> 前提：上游 0.4.15+ 已把 `engines.dsh` 提到 `>=0.2.2-rc.1`，并声明浏览器远程退役。
> 除非确认新版本仍保留 `/remote` 通道，否则不要移植——先读上游 README 的 deprecation notice。

---

## 1. 取上游源码

```bash
cd /tmp && rm -rf upstream && mkdir upstream && cd upstream
npm pack @linxin666/dsh-remote-web-ui@<version>
tar xzf linxin666-dsh-remote-web-ui-<version>.tgz
ls package            # lib/ src/ locale/ cordis.patch.yml package.json LICENSE
```

tarball 自带 `src/`（TypeScript），无需 clone 整个 monorepo。

---

## 2. 有序重命名

必须**按顺序**替换，且长的字符串先处理，否则会互相污染（例如先替换 `remote-web-ui` 会把
`@linxin666/dsh-remote-web-ui` 变成 `@linxin666/wj-dsh-remote`）。

| # | 查找 | 替换 |
|---|---|---|
| 1 | `@linxin666/dsh-remote-web-ui` | `wj-dsh-remote` |
| 2 | `dsh-remote-web-ui` | `wj-dsh-remote` |
| 3 | `/pair-app.sw.js` | `/wj-pair-app.sw.js` |
| 4 | `/api/pair` | `/api/wj-pair` |
| 5 | `/pair-accept` | `/wj-pair-accept` |
| 6 | `/pair-ping` | `/wj-pair-ping` |
| 7 | `/pair-app` | `/wj-pair-app` |
| 8 | `"/remote"` / `'/remote'` / `` `/remote `` | `"/wj-remote"` / `'/wj-remote'` / `` `/wj-remote `` |
| 9 | `x-dsh-remote-device` | `x-wj-remote-device` |
| 10 | `dsh-remote-device`（剩余） | `wj-remote-device` |
| 11 | `dsh-remote-force-desktop` | `wj-dsh-remote-force-desktop` |
| 12 | `dsh_pair` | `wj_dsh_pair` |
| 13 | `remote-web-ui`（剩余） | `wj-dsh-remote` |

同时处理 `lib/*.js`、`src/**`、`locale/*.json`、`cordis.patch.yml`。
`lib/*.js.map` 里的 `sourcesContent` 可以不动（只是调试用）。

---

## 3. 必须人工复核的 5 处（自动化替换覆盖不到）

### 3.1 路径前缀长度被内联

打包器会把 `REMOTE_PREFIX.length` 折叠成数字。上游 `/remote` 长度 **7**，本仓库 `/wj-remote`
长度 **10**：

```bash
grep -n 'slice(7)\|slice(10)\|\.length === 7' lib/index.js lib/client.js
```

`innerPathOf` 用 `pathname.slice(10)`，upgrade 路由用 `path.slice(10)`。漏改的表现是
`/wj-remote/*` 全部 404（0.1.0 实际踩过）。

其他前缀也可能有内联长度（`/api/pair/` = 10 → `wj` 版 13），一并检查。

### 3.2 浏览器半的相对路径

```bash
grep -n '"api/pair/\|'"'"'api/pair/' lib/client.js src/client/*.ts
```

这些 fetch 调用不带前导 `/`，只替换 `/api/pair` 不会命中。统一改成 `api/wj-pair/`。

### 3.3 boot 脚本字符串的转义

服务端注入 `index.html` 的 boot 脚本是**单引号 JS 字符串**拼接而成：

- 字符串里的双引号写成 `\"`；
- 要让运行时得到正则转义 `\/`，文件里必须写 `\\/`（两个反斜杠 + 斜杠）。

改完必须把**实际服务的页面**里的内联脚本抽出来做语法检查：

```bash
curl -s -b "$COOKIE" http://127.0.0.1:PORT/ > /tmp/root.html
python3 - <<'PY'
import re
h=open('/tmp/root.html',encoding='utf8').read()
for m in re.finditer(r'<script[^>]*>(.*?)</script>', h, re.S):
    if 'wj-adapters' in m.group(1) or '__DSH_REMOTE_CHANNEL_BOOT__' in m.group(1):
        open('/tmp/boot.js','w',encoding='utf8').write(m.group(1)); break
PY
node --check /tmp/boot.js
```

### 3.4 telemetry

上游浏览器半有一次匿名心跳（`dsh-web-ui-telemetry-*`，POST 到 `dsh-market.com`）。
本仓库要求关闭：

```js
// lib/client.js 里把
if (isTelemetrySuppressed()) return;
// 改成
return; /* telemetry disabled in the wj-dsh-remote fork */
```

### 3.5 relay 默认值

上游 `relay` 默认 `true`，任何新装实例都会向 `dsh-market.com` 领租约。本仓库要求默认 `false`：

```bash
grep -n 'relay: z.boolean().default(true)\|relay: true' lib/index.js
# 改成 default(false) 和 relay: false
```

---

## 4. 同步产物与适配

```bash
# 用新产物替换 lib/ 后：
node scripts/adapters-sync.mjs          # 重新注入插件适配规则
node scripts/adapters-sync.mjs --check  # 必须 exit 0
node --check lib/index.js
node --check lib/client.js
```

如果 `adapters-sync` 报 "anchor not found"，说明上游改了 `shouldRewriteFetchPath` 或 boot 脚本的
形状：更新 `scripts/adapters-sync.mjs` 里的 `CLIENT_ANCHOR` / `BOOT_ANCHOR` 后再跑。

---

## 5. 验证（与 AGENTS.md 第 7 节一致）

1. 隔离 profile 安装 tarball，起在 `127.0.0.1:3191`；
2. 路由：`/api/wj-pair/status` 200、`/remote` 404、`/wj-pair-accept` 200、未配对
   `/wj-remote/plugins/events` 403；
3. 配对：`issue → accept(303) → app(200, Set-Cookie)`，通道内 `/wj-remote/plugins/events` 200；
4. 撤销：`revoke` 后同一请求 403 `unpaired`；
5. 页面：`grep -c 'wj-adapters' root.html` ≥ 1，内联 boot 脚本 `node --check` 通过；
6. 生产部署前再跑一次 `adapters:check`。

---

## 6. 发布

```bash
# 版本号：行为/移植 → patch；破坏性改名 → minor
npm version patch --no-git-tag-version   # 或手工改 package.json
node scripts/adapters-sync.mjs --check
npm pack                                 # prepack 自动 sync
git add -A && git commit -m "0.1.x: ..." && git push origin main
```

同时更新 `NOTICE` 的修改清单与 `AGENTS.md` 顶部的版本/commit 信息。

---

## 7. 常见失败模式

| 现象 | 原因 |
|---|---|
| `/wj-remote/*` 全 404，未配对也是 404 | 前缀长度没改（`slice(7)`） |
| `/wj-remote/*` 403 `unpaired`，但明明已配对 | 设备 cookie 名还是 `dsh_pair`，或相对路径没替换导致配对接口 404 |
| 页面白屏 / boot 脚本语法错误 | boot 字符串转义错误（`\/` 没写成 `\\/`，或引号没转义） |
| 新装实例向 `dsh-market.com` 注册 | `relay` 默认值没改 |
| 浏览器仍发心跳 | telemetry 早退没加 |
| 适配块重复叠加 | 手改了 `/* wj-adapters:start */` 区块；应只跑脚本 |
| `link:` 安装后插件不加载 | 缺 `@deepseek-ai/*` peer 解析，改用 tarball/github 安装 |
