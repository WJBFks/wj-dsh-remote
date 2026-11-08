/**
 * dsh-market adapter — route the market's read-only HTTP surface through the
 * paired-device channel (`/wj-remote/...`) when the page is served from a
 * non-loopback origin.
 *
 * Why this is needed
 * ------------------
 * dsh-market registers its routes as webServer **exact** routes
 * (`/dsh-market/<name>`), which win over the connection plugin's `/api`
 * prefix fence. It therefore enforces its own admission check: loopback,
 * the listener bind address, or an authority declared in `trustedHosts`.
 * This deployment deliberately keeps `trustedHosts` empty, so a browser on
 * the public nginx origin presents a public Host and the market answers
 * 403 "This request came from an untrusted origin and was refused."
 *
 * Routing those requests through `/wj-remote` fixes it without touching
 * dsh-market: the channel rewrites Host to loopback and attaches the
 * process's inner credential, which is exactly what the market's fence
 * accepts. Verified with:
 *
 *   curl -b "wj_dsh_pair=<paired device id>" \
 *     http://127.0.0.1:39666/wj-remote/dsh-market/registry   # 200
 *
 * Read vs admin routes
 * ---------------------
 * `allow` lists GET-style catalog/status routes open to every paired device.
 * `gated` lists mutating endpoints (`install`, `update`, `uninstall`,
 * `restart`, `rollback`, ...): they are rewritten onto the channel too, but
 * the channel refuses them unless the calling device holds admin level (9).
 * That keeps "install arbitrary plugin code" out of level 0-8 devices while
 * letting an admin phone fix the market from away.
 *
 * To allow one more read-only endpoint, append its path (without the
 * `/dsh-market/` prefix) to `allow` and run `pnpm adapters:sync`. Mutating
 * endpoints go to `gated` instead; their minimum level is enforced in
 * `src/remote-api.ts` (keep the two lists in sync).
 */
export default {
  id: 'dsh-market',
  /** The exact-route prefix this adapter claims on the origin. */
  prefix: '/dsh-market',
  /** Paths *under* the prefix, relative, matched exactly or with a sub-path. */
  allow: [
    'registry',
    'status',
    'installed',
    'updates',
    'updates/summary',
    'find-compatible',
    'discovery-compatibility',
    'snapshots',
    'logs',
    'presets',
    'bundle-order',
    'groups',
    'check',
    'changelog',
    'build-env',
    'channel',
    'entry-visibility',
    // UI preferences (the settings-page sidebar tip and the card actions).
    // They mutate only the market's own visibility/favourite/note state, not
    // the host: allowed so the panel is usable remotely. Install/update/remove
    // stay out on purpose.
    'sidebar-entry',
    'favorite',
    'note',
    'github-proxy',
    'api/v1/capabilities',
  ],
  /** Mutating actions: proxied for admin devices only (level >= 9). */
  gated: [
    'install',
    'uninstall',
    'update',
    'restart',
    'rollback',
    'cancel',
    'toggle',
    'block',
    'dismiss-broken',
    'restore',
    'restore-snapshot',
    'delete-snapshot',
    'backup',
    'setup-pnpm',
    'migrate-source',
    'approve-builds',
    'self-uninstall',
    'host-recovery',
    'host-recovery/restore',
    'update-exempt',
    'use-skin',
    'webdav',
    'gist',
    'region',
    'api/v1/restart',
    'api/v1/rollback',
  ],
}
