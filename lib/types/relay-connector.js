/**
 * The relay's two connectors. The quick tunnel keeps serving every instance
 * that has not migrated, and the named connector is established beside it on
 * the same relay hostname and left idle while the wildcard Worker route still
 * shadows the CNAME. The control plane's `mode` names the connector the phone
 * is meant to be served from; nothing here switches the edge — it only keeps
 * both sides up, so a server-side flip needs no plugin restart and a rollback
 * is the same flip back.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { dshHome } from "./dsh-home.js";
import { claimRelayLease, relayClaimRetryOf, releaseRelayLease, } from "./relay-control.js";
import { createTunnelChildGuard } from "./tunnel-orphan.js";
import { TunnelManager } from "./tunnel.js";
/**
 * The crash-recovery record slot the idle named connector owns. Kept apart
 * from the quick connector's slot so each connector's leftover child is reaped
 * by the start that belongs to it instead of overwriting its sibling's record.
 */
export function namedTunnelChildRecordFile(home = dshHome()) {
    return join(home, 'wj-dsh-remote-tunnel-child-named.json');
}
/**
 * Read this plugin's own version from its package manifest (the claim reports
 * it so the migration can measure adoption by released version).
 * @returns the version, or undefined when the manifest cannot be read.
 */
export function readPluginVersion() {
    try {
        const parsed = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
        return typeof parsed.version === 'string' && parsed.version !== '' ? parsed.version : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * The dedupe key of one claim trigger: the local origin port plus the quick
 * tunnel URL the start reported. A settings sync re-runs the tunnel plan with
 * the same key; a tunnel restart mints a new quick URL and therefore claims
 * again (which is also what keeps the lease's `last_seen_at` inside the cron
 * GC's TTL).
 * @param port - the bound web server port, or undefined before it settles.
 * @param target - the quick tunnel URL, or undefined while none is minted.
 * @returns the key, or undefined when there is nothing to claim yet.
 */
export function relayClaimKeyOf(port, target) {
    if (port === undefined)
        return undefined;
    return String(port) + '|' + (target ?? '');
}
/**
 * Build the named connector the relay keeps beside the quick tunnel.
 *
 * Health probing is off on purpose: while the wildcard Worker route answers
 * the relay hostname, a probe of the idle connector's public URL sees the
 * Worker's offline page and would declare a healthy connector dead, restarting
 * it forever (the failure mode issue #1723 fixed for the quick tunnel).
 * @param options - an existing manager (tests); defaults spawn the real one.
 */
export function createNamedRelayConnector(options = {}) {
    const manager = options.manager ?? new TunnelManager({
        healthCheckIntervalMs: 0,
        orphan: createTunnelChildGuard({ file: namedTunnelChildRecordFile() }),
    });
    return {
        start(token, hostname) {
            manager.start({ kind: 'named', token, publicUrl: 'https://' + hostname });
        },
        stop() {
            manager.stop();
        },
        get info() {
            return manager.info;
        },
    };
}
/**
 * Own the lease half of the relay: claim it on every tunnel start, bring the
 * named connector up beside the quick one, and retry a failed claim with a
 * capped backoff while the quick connector keeps serving.
 */
export class RelayConnectorPair {
    identity;
    options;
    stateValue = { state: 'idle' };
    leaseValue;
    attempts = 0;
    timer;
    disposed = false;
    constructor(identity, options = {}) {
        this.identity = identity;
        this.options = options;
    }
    /** The lease half's current state. */
    get state() {
        return this.stateValue;
    }
    /** The connector the phone is served from, for the last accepted lease. */
    get served() {
        return this.leaseValue?.mode;
    }
    /** The last accepted lease (undefined until one lands). */
    get lease() {
        return this.leaseValue;
    }
    /**
     * Claim one lease and start (or restart) the named connector for it. A
     * refusal is graded into a retry and never tears down the quick connector:
     * the instance keeps the origin the registry already gave it.
     * @param input - the local origin port and the reporting plugin version.
     * @returns the accepted lease, or undefined when the attempt did not land.
     */
    async start(input) {
        // A disposed pair stays disposed: a pending retry must not resurrect it.
        if (this.disposed)
            return undefined;
        this.clearTimer();
        this.setState({ state: 'claiming' });
        const claimFn = this.options.claim ?? ((request) => claimRelayLease(request));
        let outcome;
        try {
            outcome = await claimFn({
                id: this.identity.id,
                secret: this.identity.secret,
                newSecret: this.identity.fresh === true ? this.identity.secret : undefined,
                port: input.port,
                pluginVersion: input.pluginVersion,
            });
        }
        catch (error) {
            outcome = { ok: false, status: 0, error: error instanceof Error ? error.message : String(error) };
        }
        if (this.disposed)
            return undefined;
        if (outcome.ok) {
            // The row exists now: never claim a fresh id twice.
            this.identity.fresh = false;
            this.attempts = 0;
            this.leaseValue = outcome.claim;
            this.startNamed(outcome.claim);
            this.startBridge(outcome.claim, input.port);
            this.setState({ state: 'claimed', mode: outcome.claim.mode, hostname: outcome.claim.hostname });
            return outcome.claim;
        }
        this.setState({ state: 'failed', error: outcome.error });
        const retry = relayClaimRetryOf(outcome, this.attempts, {
            baseDelayMs: this.options.baseDelayMs,
            maxDelayMs: this.options.maxDelayMs,
        });
        if (retry.refreshIdentity)
            this.identity.fresh = true;
        if (retry.retry)
            this.scheduleRetry(input, retry.delayMs);
        return undefined;
    }
    /**
     * The plugin's offline action (toggle off, profile unmount): release the
     * lease and stop the idle connector. Never retires — the hostname is the
     * phone's bookmark, and the tunnel behind it survives.
     */
    async release() {
        const releaseFn = this.options.release ?? ((identity) => releaseRelayLease(identity));
        try {
            await releaseFn(this.identity);
        }
        catch {
            // Best effort: an unreleased row is recovered by the 90-day GC.
        }
        this.stopNamed();
    }
    /** Stop retrying and drop the connector (the relay half was disposed). */
    dispose() {
        this.disposed = true;
        this.clearTimer();
        this.stopNamed();
        this.setState({ state: 'idle' });
    }
    startNamed(claim) {
        const startNamed = this.options.startNamed;
        // A bridged lease carries no tunnel: there is no token to run, and the
        // transport is the bridge connector, so no second cloudflared starts.
        if (startNamed === undefined || claim.tunnel === undefined)
            return;
        try {
            startNamed(claim.tunnel.token, claim.hostname);
        }
        catch (error) {
            // The connector failing to spawn must not lose the accepted lease.
            console.warn('wj-dsh-remote: the named connector could not start (' + (error instanceof Error ? error.message : String(error)) + ')');
        }
    }
    stopNamed() {
        try {
            this.options.stopNamed?.();
        }
        catch {
            // Stopping an already-stopped connector is not an error worth surfacing.
        }
        try {
            this.options.stopBridge?.();
        }
        catch {
            // Same for the bridge half.
        }
    }
    /** Bring the bridge connector up for one accepted lease, if it carries one. */
    startBridge(claim, port) {
        const startBridge = this.options.startBridge;
        if (startBridge === undefined || claim.bridge === undefined)
            return;
        try {
            startBridge({ claim, identity: this.identity, port });
        }
        catch (error) {
            // The bridge failing to start must not lose the accepted lease: quick
            // keeps serving, exactly as it does when the claim itself is refused.
            console.warn('wj-dsh-remote: the bridge connector could not start (' + (error instanceof Error ? error.message : String(error)) + ')');
        }
    }
    scheduleRetry(input, delayMs) {
        if (this.disposed)
            return;
        this.attempts += 1;
        const timerFn = this.options.timerFn ?? ((fn, ms) => {
            const timer = setTimeout(fn, ms);
            timer.unref?.();
            return timer;
        });
        this.timer = timerFn(() => {
            this.timer = undefined;
            void this.start(input);
        }, delayMs);
        this.timer.unref?.();
    }
    clearTimer() {
        if (this.timer === undefined)
            return;
        clearTimeout(this.timer);
        this.timer = undefined;
    }
    setState(state) {
        this.stateValue = state;
        try {
            this.options.onState?.(state);
        }
        catch {
            // A throwing observer must not break the lease lifecycle.
        }
    }
}
