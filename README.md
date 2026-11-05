# wj-dsh-remote

Personal fork of [`@linxin666/dsh-remote-web-ui`](https://github.com/zhu1090093659/dsh-web/tree/main/packages/dsh-remote-web-ui) **0.4.14**: scan-to-pair remote access to the DeepSeek Harness (`dsh`) Web GUI from a phone or another PC.

The fork exists because upstream deprecated the browser-facing remote path in favour of a native-app protocol, and 0.4.14 is the last release that keeps the browser path working on the `dsh 0.2.1` line. Everything is renamed into the `wj-*` namespace so this package can never collide with the upstream plugin.

> **Status:** fork (`0.1.1`) of 0.4.14. Renames only, plus three safety changes: `relay` defaults to **false** (upstream defaults to true and claims a lease on dsh-market.com), the daily telemetry heartbeat is **disabled**, and the browser half's relative `/api/pair/*` calls were rewritten to `/api/wj-pair/*`. Built against `dsh >= 0.2.1-rc.3`; verified on `dsh 0.2.1-rc.5`.

## What it does

- Pairs a phone or another PC with a one-time token / QR code.
- Serves the **same official Web GUI** on the remote device; phones get a portrait touch layer.
- Gates cross-device traffic through its own `/wj-remote` channel; revocable per-device sessions.
- Optional LAN forwarder, Cloudflare quick tunnel and fixed-hostname relay (both off by default here).

## Install

```bash
# from GitHub (lib/ is committed, no build step needed) - recommended
dsh plugin --profile web add github:WJBFks/wj-dsh-remote

# from a local tarball
npm pack && dsh plugin --profile web add ./wj-dsh-remote-0.1.0.tgz
```

`link:` installs also work, but a linked package resolves `@deepseek-ai/*`
peers by walking up from the checkout, so point its `node_modules/@deepseek-ai`
at the host SDK first (the upstream monorepo does the same with
`scripts/host-sdk-link.mjs`); the tarball/GitHub forms do not need this.

Then restart the profile (`dsh web`) and open the phone icon next to the settings button.

## Profile patch (example)

`~/.dsh/profiles/web/cordis.patch.yml`:

```yaml
- id: wj-dsh-remote
  config:
    idleExpireMs: 7776000000          # 90 days
    publicBaseUrl: https://example.com:39443
    autoTunnel: false
    relay: false
```

All other config keys are the upstream ones (`cookieName`, `pairTtlMs`, `devicesFile`, …); only the row id changed.

## Renamed surface

| Upstream | This fork |
|---|---|
| `@linxin666/dsh-remote-web-ui` | `wj-dsh-remote` |
| plugin row `remote-web-ui` | `wj-dsh-remote` |
| `/api/pair/*` | `/api/wj-pair/*` |
| `/pair-accept`, `/pair-app`, `/pair-ping` | `/wj-pair-accept`, `/wj-pair-app`, `/wj-pair-ping` |
| `/remote` channel | `/wj-remote` |
| `remote-web-ui-devices.json` | `wj-dsh-remote-devices.json` |
| `remote-web-ui-registry/` | `wj-dsh-remote-registry/` |
| `x-dsh-remote-device` header | `x-wj-remote-device` |
| `dsh_pair` cookie | `wj_dsh_pair` |

`/remote-bridge/pair/token` (relay bridge control-plane path) is intentionally left untouched.


## 插件适配（plugin adapters）

`src/plugin-adapters/` 存放第三方插件与远程通道之间的适配声明，每个插件一个子目录
（例如 `dsh-market/`）。第三方插件本身一行不改。

为什么需要：远程通道只改写白名单内的同源路径。DSH 自己的 `/api/`、`/sidebar/`、`/git/`、`/pet/`
已在白名单里，但第三方插件如果把路由挂在其他精确前缀上（`dsh-market` 就是 `/dsh-market/*`），
这些请求不会进入通道，会带着公网 Host 直达插件，被插件自己的 loopback 校验拒绝。

一个适配就是 `adapter.mjs` 里的 `prefix` + 只读 `allow` 列表：

```js
export default {
  id: 'dsh-market',
  prefix: '/dsh-market',
  allow: ['registry', 'status', 'installed', 'updates', /* ... 只读路径 */],
}
```

仓库发布预编译 `lib/`，所以适配通过一个生成脚本注入两处（浏览器 fetch 规则 + 服务端注入的
boot 脚本）：

```bash
pnpm adapters:sync     # 幂等重生成
pnpm adapters:check    # CI/发布前检查是否漂移
```

`prepack` 会自动执行 `adapters:sync`。写操作（安装/更新/卸载/重启）默认**不**放行：把写接口
代理进通道等于让已配对设备可以远程安装任意 npm 插件，属于权限升级。


## Documentation

| 文档 | 内容 |
|---|---|
| [AGENTS.md](AGENTS.md) | 维护约定：目录职责、构建/产物约束、适配层规范、验证清单、部署与回滚、安全不变量、已知坑 |
| [docs/architecture.md](docs/architecture.md) | 运行时架构：两种页面、配对流程、请求改写、通道服务端、配置项 |
| [docs/upstream-sync.md](docs/upstream-sync.md) | 从上游重新 fork / 移植的逐步指南与陷阱清单 |
| [src/plugin-adapters/README.md](src/plugin-adapters/README.md) | 插件适配层协议（`adapter.mjs`、生成脚本、只读策略） |
| [src/plugin-adapters/dsh-market/README.md](src/plugin-adapters/dsh-market/README.md) | dsh-market 适配的根因、验证与边界 |
| [docs/upstream-readme.md](docs/upstream-readme.md) | 上游 0.4.14 README 存档（历史参考） |

## Known limitations

- Upstream keeps the browser path frozen; `dsh 0.2.2+` will need compatibility work here.
- The client half targets official DOM semantic suffixes (`[class$="_composerSeat"]` etc.); official UI renames can break the touch layer.
- The package still declares upstream's `dependencies`; the browser bundle is prebuilt in `lib/`.
- Upstream's relay/tunnel integration still points at the author's `dsh-market.com` infrastructure; it is disabled by default here, and enabling it is opt-in.
- `dsh-market`'s **install/update** buttons still require a loopback page (by design); only its read-only catalog routes ride the remote channel — see below.

## License and attribution

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Based on the dsh-web project's `dsh-remote-web-ui@0.4.14`; modifications are documented in NOTICE.
