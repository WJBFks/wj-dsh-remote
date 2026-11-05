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
 * Read-only by design
 * -------------------
 * Only GET-style catalog/status routes are listed. The mutating endpoints
 * (`install`, `update`, `remove`, `restart`, `rollback`, `cancel`, ...) stay
 * physically local on purpose: proxying them would let a paired remote
 * device install arbitrary npm packages, i.e. escalate "can chat and edit
 * files" into "can execute arbitrary plugin code".
 *
 * To allow one more read-only endpoint, append its path (without the
 * `/dsh-market/` prefix) to `allow` and run `pnpm adapters:sync`.
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
}
