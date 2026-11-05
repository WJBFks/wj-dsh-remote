# 插件适配目录（plugin adapters）

这里存放**第三方插件**与 `wj-dsh-remote` 远程通道之间的适配声明。每个子目录对应一个插件，
目录名即插件名（例如 `dsh-market/`）。

## 为什么需要这一层

`wj-dsh-remote` 的远程通道只会把**白名单内的同源路径**从
`/xxx` 改写为 `/wj-remote/xxx`（见 `remote-channel-rules.ts` 的
`shouldRewriteFetchPath` 与 `remote-channel-boot.ts` 注入的 boot 脚本）。

默认白名单覆盖 DSH 自己的 `/api/`、`/sidebar/`、`/git/`、`/pet/`。
第三方插件如果把自己的路由挂在别的精确前缀上（`dsh-market` 就是 `/dsh-market/*`），
这些请求不会进入通道，带着公网 Host 直达 DSH，被插件自己的
loopback/trustedHosts 校验拒绝。

适配层只做一件事：**把该插件的只读路径追加进白名单**，不改第三方插件的任何代码。

## 目录约定

```
src/plugin-adapters/
  README.md                 ← 本文件
  dsh-market/
    adapter.mjs             ← 适配声明（prefix + allow 列表）
    README.md               ← 该插件的失败现象、验证方式、边界
```

`adapter.mjs` 默认导出一个对象：

| 字段 | 含义 |
|---|---|
| `id` | 唯一标识，用于生成注释/去重 |
| `prefix` | 第三方插件在 origin 上的精确路由前缀，例如 `/dsh-market` |
| `allow` | 前缀下的**只读**相对路径，精确匹配或以 `/` 开头子路径匹配 |

写操作（安装、更新、卸载、重启、回滚）**默认不放行**：把它们代理进通道等于让
已配对设备可以安装任意 npm 插件，属于权限升级。确需放行时单独评审。

## 如何落地到产物

仓库发布的是预编译 `lib/`，没有常驻构建链，所以用一个生成脚本把适配声明注入两处：

- `lib/client.js` —— 浏览器端 `shouldRewriteFetchPath`
- `lib/index.js` —— 服务端注入 `index.html` 的 boot 脚本（其中 `sf(p)` 是同一套规则）

```bash
pnpm adapters:sync     # 按 src/plugin-adapters/*/adapter.mjs 重新生成注入块（幂等）
pnpm adapters:check    # 只检查产物是否与声明一致，漂移则 exit 1
```

`prepack` 会自动跑 `adapters:sync`，所以 `npm pack` / GitHub 安装拿到的产物一定包含当前适配。
注入块用 `/* wj-adapters:start */ … /* wj-adapters:end */` 包裹，重复执行不会叠加。

## 新增一个适配

1. 新建 `src/plugin-adapters/<plugin>/adapter.mjs`，填 `id` / `prefix` / 只读 `allow`；
2. 在 `<plugin>/README.md` 写清失败现象、为什么走通道、如何验证；
3. `pnpm adapters:sync`，`node --check lib/client.js lib/index.js`；
4. 打包安装后在公网 origin 验证对应页面。

## 验证方式（dsh-market 已知可行）

```bash
# 已配对设备的 cookie 值就是设备 id，可直接模拟通道请求
DEV=$(python3 -c "import json;print(list(json.load(open('$HOME/.dsh/wj-dsh-remote-devices.json')))[0])")
curl -s -o /dev/null -w '%{http_code}\n' \
  -b "wj_dsh_pair=$DEV" http://127.0.0.1:39666/wj-remote/dsh-market/registry   # 期望 200
```
