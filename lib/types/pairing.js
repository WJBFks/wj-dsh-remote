/**
 * Pairing state machine: one active one-time token, a device-session table,
 * and presence tracking. Pure TypeScript with injected clock/randomness so
 * the whole security semantics are unit-testable without cordis. The
 * cordis-facing surfaces (routes, the api/gate listener) live next door.
 *
 * Security invariants:
 * - One active token at a time; `issue()` replaces it, so a refreshed QR
 *   immediately invalidates the previous link.
 * - A token is a bearer credential for its whole window: it is refused only
 *   when unknown, expired, or after `stop()`, and the same link may pair
 *   repeatedly within that window (each accept mints a fresh device session).
 *   Mobile flows routinely split across cookie contexts (camera preview to
 *   in-app browser to the system browser), and the later context must be
 *   able to complete its own pairing from the same link.
 * - Tokens expire; `accept()` on an expired token is refused like an
 *   unknown one (no oracle for validity).
 * - `stop()` revokes every device session and clears the token, so paired
 *   devices are cut off on their next gated request.
 * - `revoke()` drops one device session; idle sessions older than
 *   `idleExpireMs` are deleted on sweep, load, and the next gated request.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { sameIngressFrame } from "./ingress-sync.js";
import { publicIdOf } from "./device-id.js";
/**
 * Default idle-expiry window: 30 days without a heartbeat or a gated
 * request. The reopen service worker refreshes lastSeenAt on every
 * navigation it serves, so the window only runs out through genuine
 * disuse; 30 days matches the browser-credential lifetimes the surrounding
 * flow was built around, while the effective device lifetime stays shorter
 * than the 365-day cookie because of this sweep. Override per deployment
 * through the idleExpireMs config.
 */
export const DEFAULT_IDLE_EXPIRE_MS = 30 * 24 * 60 * 60 * 1000;
/** Cap on the persisted/displayed User-Agent string. */
const MAX_USER_AGENT_CHARS = 180;
/** Cap on a user-defined device name. */
const MAX_DEVICE_NAME_CHARS = 64;
/** Thrown by issue() for an address outside the sampled LAN literals. */
export class UnknownLanAddressError extends Error {
    /**
     * @param address - the offending literal.
     */
    constructor(address) {
        super(`wj-dsh-remote: unknown LAN address ${JSON.stringify(address)}`);
        this.name = 'UnknownLanAddressError';
    }
}
/** Real clock/entropy: 32 random hex chars per token. */
export const defaultClock = {
    now: () => Date.now(),
    randomToken: () => randomBytes(16).toString('hex'),
};
/**
 * The pairing state machine. Structural mutations issue/accept/stop/revoke
 * and config updates (LAN bases, tunnel, posture) notify state listeners
 * after the commit point that makes them true, and notification dedupes
 * against the last emitted snapshot. Presence-only updates (touchDevice /
 * heartbeat) just mark the store dirty and broadcast on the next sweep,
 * which also surfaces time-driven transitions (a device aging offline)
 * without any mutation.
 */
export class PairingService {
    config;
    clock;
    fs;
    tokens = new Map();
    devices = new Map();
    listeners = new Set();
    lastEmitted;
    stopped = false;
    tokenSerial = 0;
    /** LAN base URLs keyed by the advertised IP literal (interface order). */
    lanBases = new Map();
    /** Public (tunneled) base URL, e.g. a Cloudflare Tunnel quick URL. */
    publicBase;
    /** Auto-tunnel status, while the auto-tunnel feature is active. */
    tunnelStatus;
    relayStatus;
    ingressStatus;
    posture;
    /** True when lastSeenAt changed since the last persist (flushed on sweep). */
    dirty = false;
    /**
     * @param config - tunables. The settings surface replaces the object (a
     * fresh literal) when a committed section changes; every operation reads
     * the current one.
     * @param clock - clock/entropy source (injectable for tests).
     */
    constructor(config, clock = defaultClock, fs = {}) {
        this.config = config;
        this.clock = clock;
        this.fs = fs;
        this.loadPersisted();
    }
    /**
     * Restore device sessions persisted by a previous process run. A corrupt
     * or missing file is tolerated (an empty device table, never a throw) —
     * persistence is an availability convenience, not a security boundary.
     *
     * Every still-valid session is restored, deliberately without applying
     * `maxDevices`: the constructor runs with whatever cap the configuration
     * layer has delivered so far (the schema default until the saved settings
     * row is applied), and trimming here would permanently drop authorizations
     * the user never revoked — the trimmed table reaches disk on the next
     * heartbeat/sweep write. The cap is enforced where a device is admitted
     * (see `accept`), against the configuration in force at that moment.
     */
    loadPersisted() {
        const file = this.config.devicesFile;
        if (file === undefined)
            return;
        try {
            const saved = JSON.parse(readFileSync(file, 'utf8'));
            if (typeof saved !== 'object' || saved === null)
                return;
            for (const [deviceId, session] of Object.entries(saved)) {
                if (typeof deviceId !== 'string')
                    continue;
                if (typeof session !== 'object' || session === null)
                    continue;
                const { createdAt, lastSeenAt, userAgent, name, publicId, level } = session;
                if (typeof createdAt !== 'number' || typeof lastSeenAt !== 'number')
                    continue;
                const label = typeof userAgent === 'string' ? sanitizeUserAgent(userAgent) : undefined;
                const customName = typeof name === 'string' ? sanitizeDeviceName(name) : undefined;
                const savedPublicId = typeof publicId === 'string' && /^[0-9a-z]{6}$/u.test(publicId)
                    ? publicId
                    : publicIdOf(this.config.idPepper, deviceId);
                const savedLevel = typeof level === 'number' && Number.isInteger(level) && level >= 0 && level <= 9
                    ? level
                    : (this.config.defaultDeviceLevel ?? 0);
                this.devices.set(deviceId, {
                    createdAt,
                    lastSeenAt,
                    publicId: savedPublicId,
                    level: savedLevel,
                    ...(label !== undefined ? { userAgent: label } : {}),
                    ...(customName !== undefined ? { name: customName } : {}),
                });
            }
            if (this.evictIdle())
                this.persistRevocation();
        }
        catch {
            // Unreadable/corrupt: start empty rather than refusing to boot.
        }
    }
    /** Drop sessions whose lastSeenAt is older than idleExpireMs. */
    evictIdle() {
        const now = this.clock.now();
        const limit = this.config.idleExpireMs ?? DEFAULT_IDLE_EXPIRE_MS;
        let removed = false;
        for (const [id, session] of [...this.devices]) {
            if (now - session.lastSeenAt > limit) {
                this.devices.delete(id);
                removed = true;
            }
        }
        return removed;
    }
    /**
     * Write the current device table to the configured file. Called on the
     * mutation boundaries that change the set of live sessions (accept, stop,
     * revoke, idle eviction) and, throttled, from sweep() so lastSeenAt
     * survives a restart without a write per request.
     *
     * Device ids are session credentials (the gate authorizes requests by the
     * cookie's device id), so the file is written 0600 via a temp file and
     * atomic rename; a crash mid-write can never leave a half-written store.
     */
    persist() {
        const file = this.config.devicesFile;
        if (file === undefined)
            return true;
        try {
            mkdirSync(dirname(file), { recursive: true });
            const temp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
            const payload = {};
            for (const [id, session] of this.devices)
                payload[id] = session;
            writeFileSync(temp, JSON.stringify(payload), { mode: 0o600 });
            renameSync(temp, file);
            this.dirty = false;
            return true;
        }
        catch (error) {
            console.error('wj-dsh-remote: failed to persist paired devices', error);
            return false;
        }
    }
    /**
     * Persist a table change that REVOKES access (stop, per-device revoke, idle
     * eviction). A failed write would leave the revoked session on disk, and
     * {@link loadPersisted} restores that file verbatim on the next start — the
     * device's still-valid cookie would authorize again after an explicit
     * revocation. When the write cannot be made durable, the stale store is
     * removed instead (a missing file already loads as an empty table), so the
     * failure costs a re-pair rather than silently undoing the revocation.
     */
    persistRevocation() {
        if (this.persist())
            return;
        const file = this.config.devicesFile;
        if (file === undefined)
            return;
        try {
            if (this.fs.removeFile !== undefined)
                this.fs.removeFile(file);
            else
                rmSync(file, { force: true });
            console.error('wj-dsh-remote: the device revocation could not be persisted; removed the stale device store so a restart cannot restore it');
        }
        catch (error) {
            console.error('wj-dsh-remote: the device revocation could not be persisted and the stale device store could not be removed', error);
        }
    }
    /** The default LAN base URL (the first interface; undefined when not LAN-reachable). */
    get lanBaseUrl() {
        return this.lanBases.values().next().value;
    }
    /** The LAN base URL for one specific literal (undefined when not constructible). */
    lanBaseUrlFor(address) {
        return this.lanBases.get(address);
    }
    /** The LAN IP literals QR links can be built from (interface order). */
    get lanAddresses() {
        return [...this.lanBases.keys()];
    }
    /** Set the LAN base URLs once the server bind is known (interface order). */
    setLanBases(entries) {
        this.lanBases = new Map(entries.map(entry => [entry.address, entry.base]));
        this.notify();
    }
    /** The configured public (tunneled) base URL, when present. */
    get publicBaseUrl() {
        return this.publicBase;
    }
    /**
     * Set or clear the public base URL (a tunnel in front of this server). The
     * value is canonicalized to its origin: a trailing slash (what a browser
     * address-bar copy produces) or a path would mint a dead `//wj-pair-accept`
     * link, which WHATWG resolves as an authority rather than a path.
     */
    setPublicBaseUrl(url) {
        this.publicBase = url === undefined ? undefined : canonicalBaseUrl(url);
        this.notify();
    }
    /** Set or clear the auto-tunnel status frame (undefined when the feature is off). */
    setTunnelStatus(status) {
        this.tunnelStatus = status;
        this.notify();
    }
    /** Set or clear the relay-registry status frame (undefined when not in play). */
    setRelayStatus(status) {
        this.relayStatus = status;
        this.notify();
    }
    /** Set or clear the ingress-sync status frame (undefined before it ever ran). */
    setIngressStatus(status) {
        this.ingressStatus = status;
        this.notify();
    }
    /** Set the latest /api posture probe result (see posture.ts). */
    setPosture(snapshot) {
        this.posture = snapshot;
        this.notify();
    }
    /**
     * Issue a fresh token, replacing (invalidating) any previous one. A
     * stopped service re-arms through this call (the panel's refresh button).
     * @param workspaceId - optional workspace the QR link should land in.
     * @param address - optional LAN IP literal the QR must be built from; the
     * default is the public base (when configured) or the first interface.
     * Unknown addresses are refused.
     * @returns the token secret and its expiry.
     * @throws {Error} when no reachable base exists (no non-loopback bind and
     * no public base) — callers surface this as the lan-required state instead
     * of minting an unusable QR.
     */
    issue(workspaceId, address) {
        // The rule lives in the bases the caller registered, not in this message:
        // a non-loopback bind (the wildcard where the host still accepts it, a
        // concrete interface literal where it does not — see lanBasesOf in
        // index.ts) or a public base is what makes a QR reachable. The message
        // keeps the wildcard wording only as the operator's most familiar form.
        if (this.lanBases.size === 0 && this.publicBase === undefined) {
            throw new Error('wj-dsh-remote: pairing requires a reachable bind (--host 0.0.0.0 or publicBaseUrl)');
        }
        if (address !== undefined && !this.lanBases.has(address)) {
            throw new UnknownLanAddressError(address);
        }
        const now = this.clock.now();
        const token = this.clock.randomToken();
        this.tokens.clear();
        this.stopped = false;
        this.tokenSerial += 1;
        this.tokens.set(token, {
            id: `t${this.tokenSerial}`,
            issuedAt: now,
            expiresAt: now + this.config.tokenTtlMs,
            ...(workspaceId !== undefined ? { workspaceId } : {}),
            ...(address !== undefined ? { address } : {}),
        });
        this.notify();
        return { token, expiresAt: now + this.config.tokenTtlMs };
    }
    /**
     * Redeem a token and bind a device session. The token is a bearer
     * credential for its whole window, not a single-use nonce: it is refused
     * only when unknown, past its expiry, or after stop(), and every successful
     * call — including a repeat within the same window — mints a fresh device
     * session (see the module doc for the mobile cookie-context rationale).
     * @param token - the token secret from the QR link.
     * @param userAgent - optional User-Agent header captured at accept.
     * @returns the new device id, or a refusal code.
     */
    accept(token, userAgent) {
        const record = this.tokens.get(token);
        if (record === undefined || this.stopped || this.clock.now() > record.expiresAt) {
            return { ok: false, code: 'invalid' };
        }
        const deviceId = this.clock.randomToken();
        const now = this.clock.now();
        // FIFO-evict until a slot is free. The loop (not a single delete) covers a
        // table that is already over the cap: restore keeps every persisted session
        // (see loadPersisted), so the excess is collected here, once the store is
        // actually asked to admit a new device, rather than at startup on a cap the
        // configuration may not have delivered yet.
        while (this.devices.size >= this.config.maxDevices) {
            let oldest;
            for (const [id, session] of this.devices) {
                if (oldest === undefined || session.createdAt < oldest.createdAt)
                    oldest = { id, createdAt: session.createdAt };
            }
            if (oldest === undefined)
                break;
            this.devices.delete(oldest.id);
        }
        const label = sanitizeUserAgent(userAgent);
        this.devices.set(deviceId, {
            createdAt: now,
            lastSeenAt: now,
            publicId: publicIdOf(this.config.idPepper, deviceId),
            level: this.config.defaultDeviceLevel ?? 0,
            ...(label !== undefined ? { userAgent: label } : {}),
        });
        this.persist();
        this.notify();
        return { ok: true, deviceId };
    }
    /**
     * Stop remote control: revoke every device session and clear the token.
     * The phone's next gated /api request 403s; the panel falls back to
     * stopped until a fresh QR is issued.
     */
    stop() {
        this.tokens.clear();
        this.devices.clear();
        this.persistRevocation();
        this.stopped = true;
        this.notify();
    }
    /**
     * Revoke one paired device. The next gated request from that cookie is
     * refused; other sessions stay live. Unknown ids are a no-op.
     * @param deviceId - the cookie value of the device to drop.
     * @returns true when a live session was removed.
     */
    revoke(deviceId) {
        if (this.stopped)
            return false;
        const target = this.devices.has(deviceId) ? deviceId : this.idOfPublicId(deviceId);
        if (target === undefined || !this.devices.delete(target))
            return false;
        this.persistRevocation();
        this.notify();
        return true;
    }
    /**
     * Set or clear one device's user-defined name. The label is display
     * metadata only — the device id stays the sole credential — so renaming
     * never widens or narrows what that cookie can reach. A blank name clears
     * the label and restores the User-Agent-derived fallback.
     * @param deviceId - the cookie value of the device to rename.
     * @param name - the new label (cleared when blank after sanitizing).
     * @returns true when a live session was renamed.
     */
    rename(deviceId, name) {
        const resolved = this.devices.has(deviceId) ? deviceId : this.idOfPublicId(deviceId);
        const session = resolved === undefined ? undefined : this.liveSession(resolved);
        if (session === undefined)
            return false;
        const cleaned = sanitizeDeviceName(name);
        if (cleaned === undefined)
            delete session.name;
        else
            session.name = cleaned;
        this.persist();
        this.notify();
        return true;
    }
    /**
     * Collapse pairing records the operator identifies as one physical device:
     * keep the most recently active session and revoke the rest, so repeated
     * scans stop consuming `maxDevices` slots. The survivor keeps its own
     * name when it has one; otherwise it adopts a name from the records being
     * dropped, so collapsing never loses a label the operator typed.
     *
     * Pairing deliberately mints a session per accept (mobile cookie contexts
     * split), so this is an explicit operator action rather than an automatic
     * merge at accept: two different phones can present the same User-Agent,
     * and silently dropping one session would revoke a credential the user
     * never revoked.
     * @param deviceIds - the records to collapse (two or more).
     * @returns the surviving device id, or a refusal when the ids are not a
     *   same-User-Agent group of live sessions.
     */
    mergeDuplicates(deviceIds) {
        if (this.stopped)
            return { ok: false, code: 'unknown-device' };
        const ids = [...new Set(deviceIds.map(id => (this.devices.has(id) ? id : this.idOfPublicId(id) ?? id)))];
        if (ids.length < 2)
            return { ok: false, code: 'not-duplicates' };
        const sessions = [];
        for (const id of ids) {
            const session = this.devices.get(id);
            if (session === undefined)
                return { ok: false, code: 'unknown-device' };
            sessions.push(session);
        }
        // One User-Agent is the whole duplicate-group definition the panel uses;
        // refusing a mixed set keeps this from becoming a bulk-revoke shortcut
        // for rows the operator never grouped together.
        if (new Set(sessions.map(session => session.userAgent ?? '')).size !== 1) {
            return { ok: false, code: 'not-duplicates' };
        }
        let keep = 0;
        for (let index = 1; index < ids.length; index += 1) {
            const candidate = sessions[index];
            const current = sessions[keep];
            if (candidate.lastSeenAt > current.lastSeenAt
                || (candidate.lastSeenAt === current.lastSeenAt && candidate.createdAt < current.createdAt)) {
                keep = index;
            }
        }
        const survivor = sessions[keep];
        if (survivor.name === undefined) {
            const inherited = sessions.find(session => session.name !== undefined)?.name;
            if (inherited !== undefined)
                survivor.name = inherited;
        }
        const keptId = ids[keep];
        for (const id of ids) {
            if (id !== keptId)
                this.devices.delete(id);
        }
        this.persistRevocation();
        this.notify();
        return { ok: true, deviceId: keptId };
    }
    /**
     * The api/gate path: record activity for a device id and report whether
     * the request may proceed. Unknown or revoked ids (including any device
     * after stop() or idle expiry) are refused.
     *
     * Presence refreshes are throttled on purpose: every gated request (and
     * the mobile SSE keepalive) lands here, so a broadcast per call would fan
     * a full snapshot out to every status stream on the hot path. The refresh
     * only updates lastSeenAt and marks the store dirty; the snapshot reaches
     * listeners at the next sweep() (structural changes notify immediately).
     * @param deviceId - the cookie value of the requesting device.
     * @returns true when the device session is live and was refreshed.
     */
    touchDevice(deviceId) {
        const session = this.liveSession(deviceId);
        if (session === undefined)
            return false;
        session.lastSeenAt = this.clock.now();
        this.dirty = true;
        return true;
    }
    /** Explicit presence heartbeat (the phone's client sends these). */
    heartbeat(deviceId) {
        return this.touchDevice(deviceId);
    }
    /**
     * Periodic sweep: drop idle sessions, flush a dirty lastSeenAt, and
     * re-evaluate the derived snapshot (a device aging past the offline
     * window flips the phase to disconnected). Emits only when the snapshot
     * actually changed.
     */
    sweep() {
        const evicted = this.evictIdle();
        if (evicted)
            this.persistRevocation();
        else if (this.dirty)
            this.persist();
        this.notify();
    }
    /** The current snapshot (fresh object per call — stable between emits). */
    snapshot() {
        const now = this.clock.now();
        const devices = [...this.devices.entries()]
            .sort((a, b) => a[1].createdAt - b[1].createdAt)
            .map(([id, session]) => this.toDeviceSnapshot(id, session, now));
        const onlineCount = devices.filter(device => device.online).length;
        const token = this.activeToken();
        return {
            phase: this.derivePhase(onlineCount, token !== undefined),
            lanAvailable: this.lanBases.size > 0,
            lanAddresses: [...this.lanBases.keys()],
            ...(this.publicBase !== undefined ? { publicUrl: this.publicBase } : {}),
            ...(this.tunnelStatus !== undefined ? { tunnel: this.tunnelStatus } : {}),
            ...(this.relayStatus !== undefined ? { relay: this.relayStatus } : {}),
            ...(this.ingressStatus !== undefined ? { ingress: this.ingressStatus } : {}),
            ...(this.posture !== undefined ? { posture: this.posture } : {}),
            ...(token !== undefined ? { tokenId: token.record.id, tokenExpiresAt: token.record.expiresAt } : {}),
            deviceCount: this.devices.size,
            onlineCount,
            devices,
        };
    }
    /** Whether a cookie value names a currently live (non-idle) device session. */
    hasDevice(deviceId) {
        return this.liveSession(deviceId) !== undefined;
    }
    /** Public identity (publicId + level) of a live device, or undefined. */
    deviceIdentity(deviceId) {
        const session = this.liveSession(deviceId);
        return session === undefined ? undefined : { publicId: session.publicId, level: session.level };
    }
    /** Resolve a public id to its cookie id. */
    idOfPublicId(publicId) {
        for (const [id, session] of this.devices) {
            if (session.publicId === publicId)
                return id;
        }
        return undefined;
    }
    /** Set one device's level (0..9). Returns false for an unknown public id. */
    setLevel(publicId, level) {
        const id = this.idOfPublicId(publicId);
        if (id === undefined)
            return false;
        const session = this.devices.get(id);
        if (session === undefined)
            return false;
        session.level = Math.max(0, Math.min(9, Math.trunc(level)));
        this.persist();
        this.notify();
        return true;
    }
    /**
     * Number of device sessions in the table, including idle ones whose idle
     * window has not been swept yet. Restore keeps every persisted session
     * (see `loadPersisted`), so this can exceed the configured cap until the
     * next `accept` trims the excess.
     */
    deviceCount() {
        return this.devices.size;
    }
    /** Subscribe to snapshot changes (each emit passes a fresh snapshot). */
    onState(listener) {
        this.listeners.add(listener);
        return () => { this.listeners.delete(listener); };
    }
    activeToken() {
        for (const [token, record] of this.tokens) {
            if (this.stopped)
                return undefined;
            if (this.clock.now() > record.expiresAt)
                continue;
            return { token, record };
        }
        return undefined;
    }
    /**
     * Return a live session, deleting it first when idle-expired. Side-effecting
     * so a stale cookie cannot pass the gate between sweeps.
     */
    liveSession(deviceId) {
        if (this.stopped)
            return undefined;
        const session = this.devices.get(deviceId);
        if (session === undefined)
            return undefined;
        const limit = this.config.idleExpireMs ?? DEFAULT_IDLE_EXPIRE_MS;
        if (this.clock.now() - session.lastSeenAt > limit) {
            this.devices.delete(deviceId);
            this.persistRevocation();
            this.notify();
            return undefined;
        }
        return session;
    }
    toDeviceSnapshot(_id, session, now) {
        return {
            publicId: session.publicId,
            level: session.level,
            createdAt: session.createdAt,
            lastSeenAt: session.lastSeenAt,
            online: this.isOnlineAt(session, now),
            ...(session.userAgent !== undefined ? { userAgent: session.userAgent } : {}),
            ...(session.name !== undefined ? { name: session.name } : {}),
        };
    }
    derivePhase(onlineCount, hasToken) {
        if (this.lanBases.size === 0 && this.publicBase === undefined)
            return 'lan-required';
        if (this.stopped)
            return 'stopped';
        if (onlineCount > 0)
            return 'connected';
        if (this.devices.size > 0)
            return 'disconnected';
        if (hasToken)
            return 'waiting';
        return 'stopped';
    }
    isOnlineAt(session, now) {
        return now - session.lastSeenAt <= this.config.offlineAfterMs;
    }
    notify() {
        const snapshot = this.snapshot();
        if (this.lastEmitted !== undefined && snapshotsEqual(this.lastEmitted, snapshot))
            return;
        this.lastEmitted = snapshot;
        for (const listener of this.listeners) {
            try {
                listener(snapshot);
            }
            catch (error) {
                // A throwing subscriber must not break the emit loop or the caller.
                console.error('wj-dsh-remote: pairing state listener failed', error);
            }
        }
    }
}
/** Structural equality over the snapshot's wire fields. */
function snapshotsEqual(a, b) {
    return a.phase === b.phase
        && a.lanAvailable === b.lanAvailable
        && sameStrings(a.lanAddresses, b.lanAddresses)
        && a.publicUrl === b.publicUrl
        && tunnelEqual(a.tunnel, b.tunnel)
        && relayEqual(a.relay, b.relay)
        && ingressEqual(a.ingress, b.ingress)
        && postureEqual(a.posture, b.posture)
        && a.tokenId === b.tokenId
        && a.tokenExpiresAt === b.tokenExpiresAt
        && a.deviceCount === b.deviceCount
        && a.onlineCount === b.onlineCount
        && devicesEqual(a.devices, b.devices);
}
/** Per-device roster equality (order is pairing time). */
function devicesEqual(a, b) {
    return a.length === b.length && a.every((device, index) => {
        const other = b[index];
        return other !== undefined
            && device.publicId === other.publicId
            && device.level === other.level
            && device.createdAt === other.createdAt
            && device.lastSeenAt === other.lastSeenAt
            && device.online === other.online
            && device.userAgent === other.userAgent
            && device.name === other.name;
    });
}
/** Tunnel frame equality (undefined equals undefined; fields compared shallowly). */
function tunnelEqual(a, b) {
    return a === b || (a !== undefined && b !== undefined
        && a.state === b.state && a.url === b.url && a.error === b.error);
}
/**
 * Ingress frame equality: the audit state, not the timestamp. A re-read that
 * proves the same convergence must not emit a second snapshot.
 * @param a - one frame (or undefined).
 * @param b - the other frame (or undefined).
 * @returns whether both describe the same audit state.
 */
function ingressEqual(a, b) {
    if (a === b)
        return true;
    if (a === undefined || b === undefined)
        return false;
    return sameIngressFrame(a, b);
}
/** Relay frame equality (same shape as the tunnel frame). */
function relayEqual(a, b) {
    return a === b || (a !== undefined && b !== undefined
        && a.state === b.state && a.url === b.url && a.error === b.error);
}
/**
 * Posture equality. A probe round can change this frame while every other field
 * stays put — the common case, since the probe re-runs on a settings change and
 * on a tunnel reaching running, and a quick-tunnel restart churns the probed
 * host set. Leaving the frame out of the comparison suppressed those emits, so
 * the loopback SSE stream and the desktop panel could sit on a stale "exposed"
 * (or stale "clean") verdict for as long as the phase and roster stayed put.
 */
function postureEqual(a, b) {
    if (a === b)
        return true;
    // A frame that is not an object at all (a hand-built context can pass
    // anything) counts as changed instead of throwing out of the setter.
    if (!isPostureFrame(a) || !isPostureFrame(b))
        return false;
    return a.checkedAt === b.checkedAt && hostsEqual(a.hosts, b.hosts);
}
/** Whether a value has the shape a posture frame is compared on. */
function isPostureFrame(value) {
    return typeof value === 'object' && value !== null;
}
/**
 * Per-host posture equality (a round's verdicts, in probe order). Tolerates a
 * frame that is not the expected shape: this runs inside the emit path, outside
 * the listener error containment, so a malformed snapshot handed in by another
 * host-fiber caller must degrade to "changed" instead of throwing out of the
 * setter that produced it.
 */
function hostsEqual(a, b) {
    if (a === b)
        return true;
    if (!Array.isArray(a) || !Array.isArray(b))
        return false;
    return a.length === b.length && a.every((host, index) => {
        const other = b[index];
        return isPostureHost(host) && isPostureHost(other) && host.host === other.host && host.exposed === other.exposed;
    });
}
/** Whether a value has the shape one probed host is compared on. */
function isPostureHost(value) {
    return typeof value === 'object' && value !== null;
}
/** Element-wise string list equality (interface order is meaningful). */
function sameStrings(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}
/**
 * Canonical origin of a public base URL. An unparsable value is returned
 * verbatim so the caller's malformed-base warning stays the single owner of
 * that case.
 * @param url - the configured public base.
 */
export function canonicalBaseUrl(url) {
    try {
        return new URL(url).origin;
    }
    catch {
        return url;
    }
}
/** Strip control characters and cap the User-Agent stored with a session. */
export function sanitizeUserAgent(raw) {
    if (raw === undefined)
        return undefined;
    return sanitizeLabel(raw, MAX_USER_AGENT_CHARS);
}
/**
 * Strip control characters and cap a user-defined device name. A blank result
 * clears the label (undefined), restoring the User-Agent-derived fallback.
 * @param raw - the operator's input.
 * @returns the cleaned label, or undefined when nothing visible remains.
 */
export function sanitizeDeviceName(raw) {
    return sanitizeLabel(raw, MAX_DEVICE_NAME_CHARS);
}
/** Shared cleaner: collapse whitespace/control characters, cap, and blank-to-undefined. */
function sanitizeLabel(raw, max) {
    const cleaned = raw.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
    if (cleaned === '')
        return undefined;
    return cleaned.length <= max ? cleaned : cleaned.slice(0, max);
}
