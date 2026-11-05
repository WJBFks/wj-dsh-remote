# 从源码构建 lib/

仓库平时发布预编译 `lib/`。**改权限逻辑或面板 UI 时必须重新构建**，不要继续在压缩产物上做字符串补丁。

## 1. 准备构建工作区

上游 0.4.14 的 monorepo 构建链（tsdown + lightningcss + shared 预设）。已在
`~/dsh-web-build` 建好，可复用；重建步骤：

```bash
git clone --filter=blob:none --no-checkout https://github.com/zhu1090093659/dsh-web.git ~/dsh-web-build
cd ~/dsh-web-build
git sparse-checkout init --cone
git sparse-checkout set packages/dsh-remote-web-ui shared
git checkout 81a09ab9          # chore(release): bump to 0.4.14
pnpm install --ignore-scripts
```

## 2. 把本仓库源码放进去

```bash
cd ~/dsh-web-build/packages/dsh-remote-web-ui
cp -a ~/wj-dsh-remote/src/. src/
# bundle 的模块 id 必须是包名
sed -i "s#clientBundle('@linxin666/dsh-remote-web-ui'#clientBundle('wj-dsh-remote'#" tsdown.config.ts
# 让 __DSH_PKG_VERSION__ 反映 fork 版本
python3 - <<'PY'
import json
p='package.json'; d=json.load(open(p)); d['name']='wj-dsh-remote'; d['version']='0.2.0'
json.dump(d,open(p,'w'),indent=2,ensure_ascii=False)
PY
pnpm build
```

产物：`lib/index.js`（host）、`lib/client.js`（浏览器半）、`lib/types/`。

## 3. 回填到本仓库

```bash
cd ~/wj-dsh-remote
cp ~/dsh-web-build/packages/dsh-remote-web-ui/lib/index.js  lib/index.js
cp ~/dsh-web-build/packages/dsh-remote-web-ui/lib/client.js lib/client.js
cp -a ~/dsh-web-build/packages/dsh-remote-web-ui/lib/types/. lib/types/
node scripts/adapters-sync.mjs
node --check lib/index.js && node --check lib/client.js
```

注意：

- 构建产物**外部化** `zod`/`yaml`/`@deepseek-ai/*` 等依赖，`package.json` 的
  `dependencies` 必须覆盖它们（已覆盖）；
- 构建产物的体积/格式与 npm 上 0.4.14 不同，属正常；
- 适配注入块由 `adapters-sync` 生成，**不要手写**；
- 源码里的三处 fork 默认值必须保留：`relay` 默认 `false`、telemetry 早退、
  `api/wj-pair` 相对路径。

## 4. 验证

```bash
npm pack
rm -rf /tmp/dsh-build-test && mkdir -p /tmp/dsh-build-test
DSH_HOME=/tmp/dsh-build-test dsh plugin --profile web add "$PWD"/wj-dsh-remote-*.tgz
DSH_HOME=/tmp/dsh-build-test dsh web --host 127.0.0.1 --port 3199 --no-open
# 另开一个 shell：
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3199/api/wj-pair/status   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3199/remote               # 404
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3199/wj-remote/plugins/events  # 403
```

再加页面级检查：取 `?token=` 换 cookie 后抓 `/`，确认 `grep -c wj-adapters` ≥ 1，
并把内联 boot 脚本抽出来 `node --check`。

## 5. 建议

- 构建工作区不要提交进本仓库（体积大），只提交 `lib/` 与 `src/`；
- 每次改 `src/` 后按「构建 → 回填 → adapters:sync → 打包 → 隔离验证」走一遍；
- 版本位：行为/权限变更走 minor，纯修复走 patch，并同步 `AGENTS.md` 与 `NOTICE`。
