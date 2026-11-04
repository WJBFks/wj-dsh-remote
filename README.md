# wj-dsh-remote

Personal fork of [`@linxin666/dsh-remote-web-ui`](https://github.com/zhu1090093659/dsh-web/tree/main/packages/dsh-remote-web-ui) **0.4.14**: scan-to-pair remote access to the DeepSeek Harness (`dsh`) Web GUI from a phone or another PC.

The fork exists because upstream deprecated the browser-facing remote path in favour of a native-app protocol, and 0.4.14 is the last release that keeps the browser path working on the `dsh 0.2.1` line. Everything is renamed into the `wj-*` namespace so this package can never collide with the upstream plugin.

> **Status:** fork (`0.1.0`) of 0.4.14. Renames only, plus three safety changes: `relay` defaults to **false** (upstream defaults to true and claims a lease on dsh-market.com), the daily telemetry heartbeat is **disabled**, and the browser half's relative `/api/pair/*` calls were rewritten to `/api/wj-pair/*`. Built against `dsh >= 0.2.1-rc.3`; verified on `dsh 0.2.1-rc.5`.

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

## Known limitations

- Upstream keeps the browser path frozen; `dsh 0.2.2+` will need compatibility work here.
- The client half targets official DOM semantic suffixes (`[class$="_composerSeat"]` etc.); official UI renames can break the touch layer.
- The package still declares upstream's `dependencies`; the browser bundle is prebuilt in `lib/`.
- Upstream's relay/tunnel integration still points at the author's `dsh-market.com` infrastructure; it is disabled by default here, and enabling it is opt-in.

## License and attribution

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Based on the dsh-web project's `dsh-remote-web-ui@0.4.14`; modifications are documented in NOTICE.
