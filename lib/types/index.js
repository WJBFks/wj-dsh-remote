/**
 * Mobile remote control for the dsh web GUI — host half. Mounts the pairing
 * service (one-time tokens, device sessions, revocation), the /api/wj-pair
 * route family (issue/accept/stop/heartbeat/status/events), the api/gate
 * listener that enforces pairing on every other /api request from
 * non-loopback hosts, and the presence sweep. The browser half (the
 * `./client` entry) renders the sidebar entry, the pairing panel, and the
 * phone-side pair/accept + deep-link flow.
 */
import { join } from 'node:path';
import { setInterval as nodeSetInterval, setTimeout as nodeSetTimeout } from 'node:timers';
import z from '@deepseek-ai/schemastery';
import { DEFAULT_IDLE_EXPIRE_MS, PairingService } from "./pairing.js";
import { dshHome } from "./dsh-home.js";
import { loadIdPepper } from "./device-id.js";
import { isPairedDeviceRequest, makeGateListener } from "./gate.js";
import { RemoteWebUiPairing } from "./pairing-access.js";
import { makeRoutes, PAIRING_SOURCE_OPTIONS } from "./routes.js";
import { makeRemoteApiRoutes, makeRemoteApiUpgradeRoutes } from "./remote-api.js";
import { startRemotePresencePet } from "./remote-presence-pet.js";
import { claimPostureKey, postureTargets, probePosture, releasePostureKey } from "./posture.js";
import { lanIPv4Addresses } from "./lan.js";
import { ensureFirewallRule, firewallSummary, removeFirewallRule } from "./firewall.js";
import { lanBindState, removeManagedBlock } from "./lan-bind.js";
import { FORWARD_UPSTREAM_HOST, LanForwarder } from "./lan-forward.js";
import { isHttpUrl, tunnelPlanOf } from "./tunnel-plan.js";
import { ingressInputOf, IngressSync, livePortOf } from "./ingress-sync.js";
import { loadRelayIdentity, RelayRegistrar } from "./relay-registry.js";
import { RelayConnectorPair, createNamedRelayConnector, readPluginVersion, relayClaimKeyOf } from "./relay-connector.js";
import { createRelayBridgeRunner } from "./relay-bridge-connector.js";
import { firewallActionNeeded, forwardPlanOf, isLanReachableBind, resolveManagedProfile } from "./lan-bind-plan.js";
import { bindUrlHostOf, isWildcardLiteral, wildcardBindSupported } from "./host-bind-capability.js";
import { createInnerAuth } from "./inner-auth.js";
import { withIdentityEncoding } from "./http.js";
import { TunnelManager } from "./tunnel.js";
import { PublicBaseKeeper } from "./public-base.js";
import { mountOnce } from "./mount-once.js";
import { runDetached } from "./detached-work.js";
import { REMOTE_CHANNEL_BOOT_SCRIPT } from "./remote-channel-boot.js";
import { UUID_POLYFILL_SCRIPT } from "./uuid-polyfill.js";
/** Stable cordis plugin name. */
export const name = 'wj-dsh-remote';
/** Services required before the pairing surfaces can mount. */
export const inject = ['webServer', 'typertGateway', 'connection'];
/**
 * Settings namespace of the remote-control capability. Under the 0.1.7
 * settings model the namespace IS the Host profile entry id, so this is also
 * the id the browser half asks `ctx.configForms` for (the family binder
 * resolves the same value to the owning entry). Spelled here rather than
 * imported: the browser half spells the same value and must not depend on a
 * Host package.
 */
export const REMOTE_WEB_UI_SETTINGS_NAMESPACE = 'wj-dsh-remote';
/**
 * Plugin config schema. Under the 0.1.7 settings model this schema IS the
 * entry's settings page: the Host derives one form per profile entry from it
 * and serves that form only when at least one field is `volatile()`. The marker
 * is also what admits a write and what keeps the edit on the live path — the
 * Loader commits the new value into the field's reference and announces
 * `loader/volatile-update` on this fiber instead of remounting the row, so the
 * pairing service, its device sessions, the tunnel and the route registrations
 * survive a settings save (see {@link applyImpl}'s sync).
 *
 * The schema is left to inference rather than annotated with `z<Config>`: a
 * volatile field's parsed output is a live reference while its accepted input
 * stays the plain value, so the two sides no longer share one shape and the
 * annotation would reject the schema the Host must be given.
 *
 * The deployment-level fields (`trustedHosts`, `devicesFile`, `profile`) are
 * deliberately NOT volatile: they belong in the profile patch, so the form
 * leaves them to the operator instead of offering a card control that a
 * document write could not honor.
 */
export const Config = z.object({
    tokenTtlMs: z.number().step(1).min(60_000).default(10 * 60_000).volatile(),
    offlineAfterMs: z.number().step(1).min(5_000).default(25_000).volatile(),
    maxDevices: z.number().step(1).min(1).max(64).default(4).volatile(),
    idleExpireMs: z.number().step(1).min(60_000).default(DEFAULT_IDLE_EXPIRE_MS).volatile(),
    cookieName: z.string().min(1).default('wj_dsh_pair').volatile(),
    requirePairingForLan: z.boolean().default(true).volatile(),
    publicBaseUrl: z.string().volatile(),
    trustedHosts: z.array(z.string()),
    devicesFile: z.string(),
    autoTunnel: z.boolean().default(false).volatile(),
    tunnelToken: z.string().role('secret').volatile(),
    ingressSync: z.boolean().default(false).volatile(),
    cfApiToken: z.string().role('secret').volatile(),
    cfAccountId: z.string().volatile(),
    cfTunnelId: z.string().volatile(),
    relay: z.boolean().default(false).volatile(),
    lanBind: z.boolean().volatile(),
    profile: z.string().pattern(/^[A-Za-z0-9][A-Za-z0-9._-]*$/),
    enabled: z.boolean().default(true).volatile(),
    pairingSource: z.union([...PAIRING_SOURCE_OPTIONS]).default('auto').volatile(),
});
/** Presence sweep cadence (a stale device flips to disconnected within two sweeps). */
const SWEEP_INTERVAL_MS = 10_000;
/**
 * Re-plan retry while the quick tunnel waits for the webServer port to bind
 * (a recompose pass can run this apply ahead of the listener's bind).
 */
const PORT_SETTLE_RETRY_MS = 1_000;
/** Read one resolved config field, following the live reference the schema produces. */
function readConfigField(field, fallback) {
    if (field === undefined)
        return fallback;
    if (typeof field === 'object' && field !== null && typeof field.get === 'function') {
        const value = field.get();
        return value === undefined ? fallback : value;
    }
    return field;
}
/**
 * Read one optional resolved config field. A volatile reference is read at
 * call time, so an unset field stays `undefined` rather than falling back to a
 * schema default (the distinction the LAN toggle and the tunnel plan depend on).
 */
function readOptionalConfigField(field) {
    if (field === undefined)
        return undefined;
    if (typeof field === 'object' && field !== null && typeof field.get === 'function') {
        return field.get();
    }
    return field;
}
/**
 * The single mapping from resolved plugin config to the pairing service
 * config. Both the constructed service and every later apply of this row
 * reuse it, so no field can be silently dropped.
 */
export function pairingConfigOf(resolved) {
    return {
        tokenTtlMs: resolved.tokenTtlMs,
        offlineAfterMs: resolved.offlineAfterMs,
        maxDevices: resolved.maxDevices,
        idleExpireMs: resolved.idleExpireMs,
        cookieName: resolved.cookieName,
        devicesFile: resolved.devicesFile,
        idPepper: idPepper(),
    };
}
/** Default paired-session store: `$DSH_HOME/wj-dsh-remote-devices.json`. */
export function defaultDevicesFile(home = dshHome()) {
    return join(home, 'wj-dsh-remote-devices.json');
}
/** Per-install pepper for public ids; loaded once per process. */
let cachedIdPepper;
function idPepper() {
    cachedIdPepper ??= loadIdPepper(dshHome());
    return cachedIdPepper;
}
/** Schema defaults, re-read for hand-built test contexts (the loader applies them normally). */
const DEFAULTS = {
    tokenTtlMs: 10 * 60_000,
    offlineAfterMs: 25_000,
    maxDevices: 4,
    idleExpireMs: DEFAULT_IDLE_EXPIRE_MS,
    cookieName: 'wj_dsh_pair',
    requirePairingForLan: true,
    publicBaseUrl: undefined,
    trustedHosts: undefined,
    devicesFile: defaultDevicesFile(),
    autoTunnel: false,
    tunnelToken: undefined,
    ingressSync: false,
    cfApiToken: undefined,
    cfAccountId: undefined,
    cfTunnelId: undefined,
    relay: false,
    lanBind: undefined,
    profile: resolveManagedProfile(undefined, undefined, process.env.DSH_PROFILE),
    enabled: true,
    pairingSource: 'auto',
};
/**
 * The launched profile the Host publishes on its `profileContext` service
 * (`{ name, dir, patchPath, … }`). The Desktop client boots the "desktop"
 * profile without exporting DSH_PROFILE, so the environment alone resolves
 * the wrong profile there and the LAN bind toggle would edit a profile that
 * is not running.
 * @param ctx - host plugin context.
 * @returns the profile name when the Host publishes one; undefined otherwise.
 */
function launchedProfileName(ctx) {
    const fact = ctx.get('profileContext');
    return typeof fact?.name === 'string' && fact.name.length > 0 ? fact.name : undefined;
}
/**
 * Mount the pairing service, routes, gate listener, and presence sweep.
 * @param ctx - host plugin context carrying webServer.
 * @param config - resolved plugin config (schema defaults applied by the loader).
 */
export const apply = mountOnce('wj-dsh-remote', applyImpl);
/**
 * What the running host accepts as a bind, sampled once per boot: the installed
 * webserver schema decides the wildcard (see host-bind-capability.ts) and the
 * interface list is frozen for the same reason the QR bases are.
 *
 * The plugin no longer writes a bind anywhere (issue #1917), so the schema
 * answer is reported to the settings card and never turned into a profile row;
 * the LAN edge listens on a concrete interface literal, which every schema
 * line accepts.
 * @param configOf - schema factory override (test seam); the installed package's own by default.
 * @returns the capability the LAN-edge plan is computed against.
 */
export function lanBindCapabilityOf(configOf) {
    return {
        wildcardSupported: wildcardBindSupported(configOf),
        candidates: lanIPv4Addresses(),
    };
}
/**
 * The LAN URL bases a non-loopback bind is reachable by. A wildcard bind
 * answers every interface, so each candidate gets its own base (a multi-homed
 * machine can pick the network the phone actually reaches). A concrete literal
 * is only reachable at that literal, so it is the only base advertised.
 * @param host - the live bind, or the block host on a process whose bind is not settled.
 * @param port - the bound port.
 * @returns the bases, empty when the bind stays on this machine.
 */
export function lanBasesOf(host, port) {
    if (typeof host !== 'string' || !isLanReachableBind(host))
        return [];
    const addresses = isWildcardLiteral(host)
        ? lanIPv4Addresses()
        // A literal with no URL form (a non-loopback IPv6 zone id) is unadvertisable:
        // an invented base would cost a phone the whole pairing attempt.
        : [bindUrlHostOf(host)].filter((address) => address !== undefined && address !== '');
    return addresses.map(address => ({ address, base: `http://${address}:${String(port)}` }));
}
/**
 * The LAN-bind status frame the loopback-only `/api/wj-pair/lan-bind` endpoint
 * serves, built as one pure value so every field has direct unit coverage.
 *
 * `bindHost` is the address LAN clients can actually dial - the forwarder's
 * listener, or the running bind when the operator pointed `--host` at the
 * network - because that is what the card renders as "bind: host:port".
 * `localBindHost` keeps the host process's own listener visible beside it.
 * @param input - the facts read at request time.
 * @param firewallOf - firewall summary reader (injected in tests).
 * @returns the frame the settings card reads.
 */
export function lanBindFrameOf(input, firewallOf = firewallSummary) {
    const capability = {
        wildcardSupported: input.wildcardSupported,
        candidates: input.candidates,
    };
    const plan = forwardPlanOf(input.setting, input.startupHost, capability);
    // Reachability is the LAN edge, never the host's own bind: the forwarder's
    // listener when it is up, and the running bind when the operator made the
    // host itself listen on the network (the forwarder yields that port).
    const reachHost = input.forward.listening ? input.forward.address : input.bindHost;
    return {
        profile: input.profile,
        setting: input.setting ?? null,
        blockHost: input.blockHost ?? null,
        bindHost: reachHost,
        localBindHost: input.bindHost ?? null,
        port: input.port,
        lanUrls: input.port !== undefined
            ? lanBasesOf(reachHost, input.port).map(entry => entry.base)
            : [],
        firewall: input.port !== undefined
            ? firewallOf(input.port, isLanReachableBind(reachHost))
            : { ok: true, managed: false },
        platform: process.platform,
        /** The LAN address the forwarder plans to listen on; null when it must stay off. */
        desiredHost: plan.host ?? null,
        /** Whether the running host's schema accepts the wildcard bind (reported only). */
        wildcardSupported: input.wildcardSupported,
        /** The concrete LAN literals this process could listen on. */
        supportedHosts: input.candidates,
        /** The toggle is on but this machine has no LAN IPv4 address to listen on. */
        lanBlocked: plan.reason === 'no-address',
        // Always false: nothing this plugin does needs a restart any more. The
        // field stays in the frame because the card renders it (the copy for the
        // new failure states lands with the client/i18n follow-up).
        pendingRestart: false,
        /** The block a previous version wrote was removed by this process. */
        legacyBlockRemoved: input.legacyBlockRemoved,
        /** The LAN edge itself: what it listens on, and why not when it is off. */
        forward: {
            listening: input.forward.listening,
            host: input.forward.address ?? null,
            port: input.forward.port ?? null,
            // A listening edge has no "why off": the reason only describes a stopped one.
            reason: input.forward.listening ? null : (input.forwardReason ?? null),
            error: input.forward.error ?? null,
        },
    };
}
function applyImpl(ctx, config) {
    const envPublicBase = process.env.DSH_REMOTE_PUBLIC_BASE_URL?.trim() || undefined;
    // The settings are read through the volatile references at every call rather
    // than captured once: a settings save commits into those references and
    // announces `loader/volatile-update` (see the listener below), so resolving
    // them here is what makes a live edit reach the running instance without a
    // remount — and keeps the device sessions, the tunnel and the routes alive.
    const resolve = () => ({
        tokenTtlMs: readConfigField(config?.tokenTtlMs, DEFAULTS.tokenTtlMs),
        offlineAfterMs: readConfigField(config?.offlineAfterMs, DEFAULTS.offlineAfterMs),
        maxDevices: readConfigField(config?.maxDevices, DEFAULTS.maxDevices),
        idleExpireMs: readConfigField(config?.idleExpireMs, DEFAULTS.idleExpireMs),
        cookieName: readConfigField(config?.cookieName, DEFAULTS.cookieName),
        requirePairingForLan: readConfigField(config?.requirePairingForLan, DEFAULTS.requirePairingForLan),
        publicBaseUrl: readOptionalConfigField(config?.publicBaseUrl) ?? envPublicBase,
        trustedHosts: readOptionalConfigField(config?.trustedHosts),
        devicesFile: readConfigField(config?.devicesFile, DEFAULTS.devicesFile),
        autoTunnel: readConfigField(config?.autoTunnel, DEFAULTS.autoTunnel),
        tunnelToken: readOptionalConfigField(config?.tunnelToken),
        ingressSync: readConfigField(config?.ingressSync, DEFAULTS.ingressSync),
        cfApiToken: readOptionalConfigField(config?.cfApiToken),
        cfAccountId: readOptionalConfigField(config?.cfAccountId),
        cfTunnelId: readOptionalConfigField(config?.cfTunnelId),
        relay: readConfigField(config?.relay, DEFAULTS.relay),
        lanBind: readOptionalConfigField(config?.lanBind),
        profile: resolveManagedProfile(readOptionalConfigField(config?.profile), launchedProfileName(ctx), process.env.DSH_PROFILE),
        enabled: readConfigField(config?.enabled, DEFAULTS.enabled),
        pairingSource: readConfigField(config?.pairingSource, DEFAULTS.pairingSource),
    });
    const service = new PairingService(pairingConfigOf(resolve()));
    // ── auto tunnel ─────────────────────────────────────────────────────────
    // The minted public URL becomes the QR base (and the pairing fence's
    // trusted host). Phone /api traffic rides the plugin's own /remote channel,
    // which is NOT subject to the connection trust fence — so no fence
    // mutation is needed here (a distributable plugin must not change the
    // harness's connection plugin).
    const tunnel = new TunnelManager();
    // Relay registry: one stable `<id>.dsh-market.com` subdomain per profile
    // in front of the quick tunnel. The QR base prefers the relay origin once
    // it is registered; until then (or when the registry is unreachable) the
    // raw quick URL is used, exactly as before. Named tunnels keep their fixed
    // dashboard hostname and never touch the relay.
    let relayRegistrar;
    // The named connector half: claimed on every tunnel start and run beside the
    // quick tunnel on the same hostname. The control plane's `mode` decides which
    // of the two the phone is served from, so both stay up and a server-side flip
    // (or its rollback) needs no plugin restart.
    const namedRelayConnector = createNamedRelayConnector();
    /**
     * Whether the lease's own named connector runs. It is the quick tunnel's
     * sibling, so a plan that runs no quick tunnel leaves it off: the claim is
     * made for the bridge grant, not to start a second tunnel.
     */
    let namedConnectorWanted = false;
    // The bridge half: a socket to this instance's Durable Object meeting point,
    // beside the quick tunnel. The control plane's mode decides which transport
    // serves the phone, so the bridge idles while the instance is still quick.
    const bridgeRelayConnector = createRelayBridgeRunner({
        onState: (state) => {
            if (state.state === 'connected')
                console.log('wj-dsh-remote: relay bridge attached for ' + state.instance);
            if (state.state === 'failed')
                console.warn('wj-dsh-remote: relay bridge dial failed (' + state.error + ') — retrying with the same credential');
        },
    });
    let relayPair;
    /** The claim input the pair last ran for (dedupes settings-sync re-runs). */
    let relayClaimedFor;
    /** The version a claim reports, read once from this package's manifest. */
    let pluginVersion;
    /**
     * The public base the pairing fence trusts. A tunnel reconnect must not
     * strip the host the QR still shows: named and relay hosts never change,
     * and a quick tunnel's host survives a bounded grace window (issue #1547).
     */
    const publicBase = new PublicBaseKeeper((base) => { service.setPublicBaseUrl(base); });
    /** The tunnel target the registrar last announced (dedupes sync re-runs). */
    let relayAnnouncedFor;
    /**
     * Drop the registry mapping (the announce half). The lease half is
     * transport-owned — the bridge dials the object directly — so a plan that
     * runs no quick tunnel stops announcing but never drops the lease.
     */
    const disposeRelayAnnouncer = (unregister = false) => {
        const registrar = relayRegistrar;
        relayRegistrar = undefined;
        relayAnnouncedFor = undefined;
        publicBase.setRelay(undefined);
        if (registrar === undefined)
            return;
        // Toggle-off removes the registry row so the stable origin stops
        // proxying; teardown/mode changes keep the row (the phone then sees the
        // relay's offline page instead of a dangling claim, and re-enabling
        // reuses the same identity).
        if (unregister)
            void registrar.unregister().catch(() => undefined);
        registrar.dispose();
    };
    /** Drop the whole relay half: the mapping, the lease and every connector. */
    const disposeRelayHalf = (unregister = false) => {
        disposeRelayAnnouncer(unregister);
        const pair = relayPair;
        relayPair = undefined;
        relayClaimedFor = undefined;
        // The named connector never outlives the relay half (a plan change to a
        // manual named tunnel leaves only the operator's own tunnel running), and
        // neither does the bridge socket.
        namedRelayConnector.stop();
        bridgeRelayConnector.stop();
        if (pair === undefined)
            return;
        // Toggle-off releases the lease: the tunnel and the CNAME stay, so
        // re-enabling claims an instance that creates nothing. It never retires
        // — the hostname is the phone's bookmark.
        if (unregister)
            void pair.release().catch(() => undefined);
        pair.dispose();
    };
    const ensureRelayRegistrar = () => {
        if (resolve().relay === false)
            return undefined;
        if (relayRegistrar === undefined) {
            try {
                const identity = loadRelayIdentity(resolve().profile);
                relayRegistrar = new RelayRegistrar(identity, (state) => {
                    service.setRelayStatus(state.state === 'off' ? undefined : state);
                    if (state.state === 'running') {
                        publicBase.setRelay(state.url);
                    }
                    else if (state.state === 'off') {
                        publicBase.setRelay(undefined);
                    }
                    else if (state.state === 'failed') {
                        // Keep the last relay URL on failures: the phone origin only
                        // breaks when the mapping itself goes stale, not when one
                        // refresh call fails. The registrar retries with backoff.
                        console.warn(`wj-dsh-remote: relay registration failed (${state.error}) — the stable origin may serve its offline page until the retry lands`);
                    }
                });
            }
            catch (error) {
                console.warn(`wj-dsh-remote: relay registry unavailable (${error instanceof Error ? error.message : String(error)}) — the quick URL is the QR base`);
            }
        }
        return relayRegistrar;
    };
    const ensureRelayPair = () => {
        if (resolve().relay === false)
            return undefined;
        if (relayPair === undefined) {
            try {
                const identity = loadRelayIdentity(resolve().profile);
                pluginVersion ??= readPluginVersion();
                relayPair = new RelayConnectorPair(identity, {
                    startNamed: (token, hostname) => {
                        // The claim is also made without a quick tunnel (the bridge grant
                        // is the reason); only the quick plan starts the sibling tunnel.
                        if (namedConnectorWanted)
                            namedRelayConnector.start(token, hostname);
                    },
                    startBridge: (start) => { bridgeRelayConnector.start(start); },
                    onState: (state) => {
                        if (state.state === 'claimed') {
                            console.log(`wj-dsh-remote: relay lease claimed — the ${state.mode} connector serves ${state.hostname}`);
                        }
                        else if (state.state === 'failed') {
                            // Not fatal: the quick connector keeps the origin the registry
                            // already gave the phone, and the pair retries with backoff.
                            console.warn(`wj-dsh-remote: relay lease claim failed (${state.error}) — the quick connector keeps serving, retrying`);
                        }
                    },
                });
            }
            catch (error) {
                console.warn(`wj-dsh-remote: relay lease unavailable (${error instanceof Error ? error.message : String(error)}) — the quick tunnel path is unchanged`);
            }
        }
        return relayPair;
    };
    /**
     * Claim the named lease for one tunnel start. Deduped on the local origin
     * port plus the quick URL, so a settings sync never re-claims while a real
     * restart (a new quick hostname) does — the claim is also what keeps the
     * lease's `last_seen_at` inside the cron GC's TTL.
     */
    const claimRelayLeaseFor = (port, target) => {
        const key = relayClaimKeyOf(port, target);
        if (key === undefined || relayClaimedFor === key)
            return;
        const pair = ensureRelayPair();
        // The relay toggle being off leaves no pair: the key stays unrecorded so
        // turning it back on claims the lease this trigger would have claimed.
        if (pair === undefined || port === undefined)
            return;
        relayClaimedFor = key;
        void pair.start({ port, pluginVersion }).catch(() => undefined);
    };
    const announceRelay = (registrar, target) => {
        if (relayAnnouncedFor === target)
            return;
        relayAnnouncedFor = target;
        void registrar.announce(target);
    };
    // 'off' until a sync pass turns a mode on; the phase listener only feeds
    // the public base while a plugin-managed tunnel (quick or named) runs.
    let tunnelMode = resolve().autoTunnel ? 'quick' : 'off';
    /**
     * Retry timer while the quick tunnel waits for the webServer port to bind
     * (undefined when no deferral is pending). Unref'd: never keeps the
     * process alive on its own.
     */
    let portSettleTimer;
    /** Dedupes the unbound-port warning to one line per unsettled episode. */
    let portSettleWarned = false;
    /** Re-plan once the port settles: the tunnel target and the lease both need it. */
    const schedulePortSettleRetry = () => {
        if (portSettleTimer !== undefined)
            return;
        portSettleTimer = nodeSetTimeout(() => {
            portSettleTimer = undefined;
            sync();
        }, PORT_SETTLE_RETRY_MS);
        portSettleTimer.unref();
    };
    tunnel.onPhase((info) => {
        if (tunnelMode === 'off')
            return;
        if (info.phase === 'running' && info.url !== undefined) {
            publicBase.markRunning(info.url);
            service.setTunnelStatus({ state: 'running', url: info.url });
            const registrar = tunnelMode === 'quick' ? ensureRelayRegistrar() : undefined;
            if (registrar !== undefined)
                announceRelay(registrar, info.url);
            if (tunnelMode === 'quick')
                claimRelayLeaseFor(ctx.webServer.port, info.url);
            runPostureProbe();
        }
        else if (info.phase === 'starting') {
            // A quick-tunnel restart mints a new hostname, but the old one is not
            // dropped at once: the edge may still deliver a connection the phone
            // already opened, and the reconnect usually lands inside the grace
            // window (issue #1547). A named tunnel keeps its fixed hostname, and a
            // registered relay its stable subdomain, so neither is ever dropped
            // here — the previous code cleared the relay base on every restart.
            publicBase.markReconnecting();
            service.setTunnelStatus({ state: 'starting' });
        }
        else if (info.phase === 'failed') {
            publicBase.markReconnecting();
            service.setTunnelStatus(info.error === undefined ? { state: 'failed' } : { state: 'failed', error: info.error });
        }
    });
    ctx.effect(() => () => {
        disposeRelayHalf();
        publicBase.dispose();
        tunnel.dispose();
        if (portSettleTimer !== undefined)
            clearTimeout(portSettleTimer);
    }, 'wj-dsh-remote: auto tunnel');
    // ── update-only ingress sync (issue #1948) ────────────────────────────────
    // A named tunnel's public hostname is permanent, but its ingress rule names a
    // fixed local port: after a port change the hostname keeps resolving and
    // answers 502. This runner keeps that one number following the port the host
    // actually bound — one read on start, one proven write on drift, nothing else.
    // Its frame rides the pairing snapshot, so the panel and the settings card can
    // explain a failure without the account token leaving this process.
    let ingressEnabledOnce = false;
    const ingress = new IngressSync({
        onFrame: (frame) => {
            if (frame.state !== 'off')
                ingressEnabledOnce = true;
            service.setIngressStatus(ingressEnabledOnce ? frame : undefined);
            if (frame.state === 'failed' || frame.state === 'conflict') {
                const code = frame.code === undefined ? '' : ` (${frame.code})`;
                const detail = frame.detail === undefined ? '' : `: ${frame.detail}`;
                console.warn(`wj-dsh-remote: ingress sync ${frame.state}${code}${detail}`);
            }
        },
    });
    ctx.effect(() => () => { ingress.dispose(); }, 'wj-dsh-remote: ingress sync');
    // The bind facts are known by now (webServer is an inject edge): the LAN
    // bases are frozen per process, matching the CLI's once-per-invocation
    // sampling stance. The QR can only advertise addresses the fence accepts;
    // every interface gets its own base URL so a multi-homed machine can pick
    // the network the phone can actually reach.
    // A recompose pass can hand the plugin a webServer whose facts have not
    // settled yet (host unset, port undefined); deriving LAN bases from that
    // would advertise :undefined links or clear a working set, so the bases
    // only update when both facts are readable.
    // The reachability signal is "the bind is not loopback", never equality with
    // the wildcard: a host that refuses wildcard binds serves the LAN from one
    // concrete interface address, which an equality check would read as
    // local-only (issue #1893).
    const bindKnown = typeof ctx.webServer.host === 'string' && ctx.webServer.host !== ''
        && Number.isFinite(ctx.webServer.port);
    if (bindKnown) {
        service.setLanBases(lanBasesOf(ctx.webServer.host, ctx.webServer.port));
    }
    // Push the effective configuration into the service and gate. The service
    // config object is read per operation (token mint, touch, sweep), and the
    // gate re-reads its fence flag per request, so a saved edit takes effect
    // without a restart (the Host reloads this row, and apply re-runs). When
    // `enabled` is off, the pairing routes and sweep timer are dropped and all
    // device/token state is revoked, but the gate listener stays mounted so a
    // LAN-exposed /api stays behind pairing (now vetoing every non-loopback
    // request) instead of opening the fence.
    let disposeRoutes;
    let disposeSweep;
    // LAN-bind facts for the settings card, re-read per request so a hot
    // rebind (the patch watcher recomposes the process) and a fresh toggle
    // round are both reflected without a restart.
    let lastKnownPort;
    let lastFirewallApplied;
    // What the running host accepts, sampled once per boot: the schema cannot
    // change under a running process, and the candidate list is frozen for the
    // same reason the QR bases are. One value therefore drives both the block the
    // re-assert writes and the capability the status frame reports, so the card
    // never explains a literal the write path would not have chosen.
    const capability = lanBindCapabilityOf();
    const lanBindStatus = () => {
        const resolvedNow = resolve();
        let state;
        try {
            state = lanBindState(resolvedNow.profile);
        }
        catch {
            // An unsafe profile value must not take the whole status endpoint down.
            state = { blockPresent: false };
        }
        const port = Number.isFinite(ctx.webServer.port) ? ctx.webServer.port : lastKnownPort;
        if (Number.isFinite(ctx.webServer.port))
            lastKnownPort = ctx.webServer.port;
        return lanBindFrameOf({
            profile: resolvedNow.profile,
            setting: resolvedNow.lanBind,
            blockHost: state.host,
            bindHost: ctx.webServer.host,
            forward: forwarder.snapshot(),
            forwardReason,
            legacyBlockRemoved,
            port,
            wildcardSupported: capability.wildcardSupported,
            candidates: capability.candidates,
            startupHost: ctx.get('webStartup')?.host,
        });
    };
    // The process's inner browser credential: the proxied /api re-issues to
    // 127.0.0.1, where the connection route enforces the harness browser-auth
    // cookie (authority-bound; no loopback exemption on this cohort), so a
    // device's own cookie can never satisfy the inner check. The plugin
    // redeems its own launch token once and attaches the cookie to inner
    // requests; the credential is only ever exercised behind the pairing gate
    // in remote-api.ts.
    const innerAuth = createInnerAuth(() => {
        if (!Number.isFinite(ctx.webServer.port))
            return undefined;
        try {
            return ctx.connection.authenticatedUrl?.(`http://127.0.0.1:${String(ctx.webServer.port)}/`);
        }
        catch {
            return undefined;
        }
    });
    // The official index document for the /wj-pair-app landing, fetched from the
    // inner loopback with the process credential and cached briefly (the shell
    // is static; skins/injections settle right after boot).
    const APP_SHELL_TTL_MS = 30_000;
    let appShellCache;
    const fetchAppShell = async () => {
        if (!Number.isFinite(ctx.webServer.port))
            return undefined;
        if (appShellCache !== undefined && Date.now() - appShellCache.at < APP_SHELL_TTL_MS)
            return appShellCache.html;
        const cookie = await innerAuth.ready();
        try {
            const response = await fetch(`http://127.0.0.1:${String(ctx.webServer.port)}/`, withIdentityEncoding({
                headers: cookie !== undefined ? { cookie } : undefined,
            }));
            if (!response.ok) {
                // A stale credential (secret rotation, 30-day TTL) must not wedge every
                // later landing: drop it so the next attempt re-redeems, exactly as the
                // proxy path does on an upstream 401.
                if (response.status === 401 || response.status === 403)
                    innerAuth.invalidate();
                return undefined;
            }
            const html = await response.text();
            appShellCache = { at: Date.now(), html };
            return html;
        }
        catch {
            return undefined;
        }
    };
    const routes = [
        ...makeRoutes({
            service,
            requirePairingForLan: () => resolve().requirePairingForLan,
            pairingSource: () => resolve().pairingSource,
            lanBindStatus,
            indexDocument: fetchAppShell,
            trustedHosts: () => {
                const list = [];
                const envHosts = process.env.DSH_REMOTE_TRUSTED_HOSTS;
                if (typeof envHosts === 'string' && envHosts.trim() !== '') {
                    for (const item of envHosts.split(',')) {
                        const trimmed = item.trim();
                        if (trimmed !== '')
                            list.push(trimmed);
                    }
                }
                const cfgHosts = resolve().trustedHosts;
                if (Array.isArray(cfgHosts)) {
                    for (const item of cfgHosts) {
                        if (typeof item === 'string') {
                            const trimmed = item.trim();
                            if (trimmed !== '')
                                list.push(trimmed);
                        }
                    }
                }
                return list;
            },
        }),
        // The remote desktop channel: a paired-credential-gated `/wj-remote` prefix
        // that re-issues fenced paths to loopback (see remote-api.ts). The gate is
        // unconditional — requirePairingForLan governs the plain /api surface and
        // the desktop's client-side rewrite only; it is never an authorization
        // input here, because this channel attaches the process's own browser
        // credential to everything it forwards (issue #1665).
        ...makeRemoteApiRoutes({
            service,
            port: () => ctx.webServer.port,
            auth: innerAuth,
        }),
    ];
    const upgrades = makeRemoteApiUpgradeRoutes({
        service,
        port: () => ctx.webServer.port,
        auth: innerAuth,
    });
    const gate = makeGateListener(service, () => resolve().requirePairingForLan, () => resolve().enabled);
    ctx.effect(() => ctx.on('api/gate', gate), 'wj-dsh-remote: api gate');
    // ── posture probe ─────────────────────────────────────────────────────────
    // Guardrail for the one seam this plugin cannot mount a gate into: the
    // connection plugin's /api Host fence. Forged-Host probes against every
    // advertised origin (public base + LAN bases) make a re-opened /api (a
    // re-added --trusted-host, or the SDK's LAN auto-trust under 0.0.0.0)
    // visible on the panel and the log instead of silently trusted.
    let postureKey;
    let postureWasExposed = false;
    const runPostureProbe = () => {
        if (!resolve().enabled)
            return;
        // The probe and the LAN targets need the bound port; before it settles
        // (a recompose pass) there is nothing honest to probe — keep the previous
        // snapshot and let the next trigger retry.
        const port = ctx.webServer.port;
        if (port === undefined)
            return;
        const targets = postureTargets(service.publicBaseUrl, service.lanAddresses, port);
        if (targets.length === 0) {
            postureKey = undefined;
            service.setPosture(undefined);
            return;
        }
        const key = targets.join('|');
        const claim = claimPostureKey(postureKey, key);
        if (!claim.run)
            return;
        postureKey = claim.next;
        void probePosture({ port, targets }).then((snapshot) => {
            service.setPosture(snapshot);
            const exposedHosts = snapshot.hosts.filter(host => host.exposed).map(host => host.host);
            const exposed = exposedHosts.length > 0;
            if (exposed && !postureWasExposed) {
                console.error(`wj-dsh-remote: CRITICAL — the /api fence is OPEN for [${exposedHosts.join(', ')}]: unpaired clients reach the full host API. Remove --trusted-host for these hosts (pairing covers them) or bind loopback.`);
            }
            else if (!exposed && postureWasExposed) {
                console.log('wj-dsh-remote: the /api posture probe is clean again (every advertised origin refused with 403).');
            }
            postureWasExposed = exposed;
        }).catch(() => {
            // Keep the previous snapshot; drop the in-flight key so the same
            // targets retry instead of sticking on a failed round.
            postureKey = releasePostureKey(postureKey, key);
        });
    };
    // The first round waits for the connection plugin's /api route: a probe
    // before it mounts would read the SPA fallback and false-positive.
    const initialPostureTimer = nodeSetTimeout(() => { runPostureProbe(); }, 5_000);
    initialPostureTimer.unref();
    ctx.effect(() => () => { clearTimeout(initialPostureTimer); }, 'wj-dsh-remote: posture probe boot');
    // Sibling plugins (dsh-better-sidebar, …) look this up by name. Absent when this
    // plugin is not installed; stop() / enabled=false still refuse cookies.
    new RemoteWebUiPairing(ctx, (request) => {
        if (!resolve().enabled)
            return false;
        return isPairedDeviceRequest(service, request);
    });
    // Remote-presence to pet-visibility link: while a paired device is online
    // (an active phone mirror), hide the host-global pet through the pet's OWN
    // hide switch; when the last device has been offline for a grace window,
    // show it again (user design; the pet plugin is optional, so the seam is
    // resolved per transition and every failure degrades to a no-op).
    const presencePet = startRemotePresencePet({
        onState: listener => service.onState(listener),
        pet: () => {
            try {
                return ctx.get('pet');
            }
            catch {
                return undefined;
            }
        },
    });
    ctx.effect(() => presencePet, 'wj-dsh-remote: remote-presence pet visibility');
    if (service.lanAddresses.length > 0) {
        const urls = service.lanAddresses.map(ip => `http://${ip}:${String(ctx.webServer.port)}`).join(' , ');
        console.log(`wj-dsh-remote: the paired Web GUI is reachable on LAN at ${urls}`);
    }
    // The LAN-exposure note lives with the LAN edge (warnLanExposure below): the
    // forwarder announces it when it starts, and the --host yield announces it
    // when the host itself binds the network.
    // ── the LAN edge (issue #1917) ──────────────────────────────────────────
    // This plugin owns no bind. The web server's row is the profile's own, and it
    // was never this plugin's to rewrite: a same-id patch row replaces the whole
    // config (so --host/--port were swallowed), and the profile patch is exactly
    // what the Host's HMR config watcher refreshes from (so writing it rebound the
    // live listener mid-session). LAN reachability comes from the runtime
    // forwarder instead (lan-forward.ts): the host keeps listening on loopback and
    // the forwarder serves the LAN address on the same port.
    const forwarder = new LanForwarder();
    /** Why the forwarder is off as of the last reconcile; the status frame reports it. */
    let forwardReason = 'off';
    /** Whether this process removed the block a previous version left behind. */
    let legacyBlockRemoved = false;
    /** The legacy cleanup runs once per process, ahead of every other bind step. */
    let legacyCleanupDone = false;
    /** One operator-facing line per stop reason, so a sync loop cannot flood the log. */
    const warnedForwardReasons = new Set();
    let lanExposureWarned = false;
    /** One honest note that LAN exposure rests on pairing, not on the harness fence. */
    const warnLanExposure = () => {
        if (lanExposureWarned)
            return;
        lanExposureWarned = true;
        // Cohort honesty (see the README security model): the pairing gate covers
        // the plugin's own /remote channel; direct /api from LAN origins is
        // governed by the harness fence + browser-auth cookie, and this cohort's
        // api/gate seam has no emitter — so stop()/revoke() cannot invalidate a
        // browser credential a device has already redeemed.
        console.warn('wj-dsh-remote: LAN-exposed edge — pairing gates the /remote channel; direct /api stays under the harness fence + browser auth (stop() does not revoke an already-redeemed browser credential)');
    };
    /** The address a LAN client dials right now: the forwarder, else the host's own bind. */
    const lanEdgeHost = () => {
        const state = forwarder.snapshot();
        return state.listening ? state.address : ctx.webServer.host;
    };
    /**
     * Point the pairing service at the authority phones actually dial. The QR
     * bases and the phone-facing fences compare the Host header against this
     * list, so following the forwarder is what keeps a paired phone paired.
     */
    const applyLanBases = () => {
        if (!Number.isFinite(ctx.webServer.port))
            return;
        service.setLanBases(lanBasesOf(lanEdgeHost(), ctx.webServer.port));
    };
    /**
     * Remove the managed block a previous version (<= 0.4.8) wrote, once per
     * process and before anything else touches the profile. A surviving block
     * keeps replacing the web server row's config wholesale, so every later start
     * ignores --host/--port and binds a literal an older plugin guessed - the
     * exact failure this issue is about. Nothing is written back.
     * @param profile - the managed profile whose patch file may carry the block.
     */
    const cleanupLegacyBlock = (profile) => {
        if (legacyCleanupDone)
            return;
        legacyCleanupDone = true;
        try {
            const result = removeManagedBlock(profile);
            legacyBlockRemoved = result.removed;
            if (result.removed) {
                console.log(`wj-dsh-remote: removed the lan-bind block a previous version wrote into profile ${profile} (${result.host ?? '?'}:${String(result.port ?? '?')}); the web server row is never rewritten again`);
            }
        }
        catch (error) {
            // A block that cannot be removed keeps swallowing the bind on every later
            // start, so this failure is reported loudly instead of skipped. The LAN
            // edge still runs: it does not depend on the profile file at all.
            console.error(`wj-dsh-remote: failed to remove the lan-bind block from profile ${profile}: ${error instanceof Error ? error.message : String(error)}`);
        }
    };
    /**
     * Bring the LAN edge in line with the toggle. Every failure here costs the LAN
     * edge only: the loopback listener is never touched, so an address that
     * disappeared after a network change or a port already taken cannot brick the
     * host - the reason is logged and reported on the status frame.
     * @param value - the effective plugin configuration.
     */
    const applyForwardEdge = (value) => {
        const startup = ctx.get('webStartup');
        // The interface list is re-sampled per reconcile (unlike the schema answer,
        // which cannot change under a running process): a machine that changed
        // networks must not keep serving a LAN address it no longer has, and the
        // plan follows the address it does have.
        const liveCapability = { wildcardSupported: capability.wildcardSupported, candidates: lanIPv4Addresses() };
        const plan = forwardPlanOf(value.lanBind, startup?.host, liveCapability);
        forwardReason = plan.reason;
        const state = forwarder.snapshot();
        const port = Number.isFinite(ctx.webServer.port) ? ctx.webServer.port : undefined;
        if (plan.host === undefined || port === undefined) {
            if (state.listening)
                void forwarder.stop().then(applyLanBases);
            else
                applyLanBases();
            if (plan.reason !== undefined && !warnedForwardReasons.has(plan.reason)) {
                warnedForwardReasons.add(plan.reason);
                if (plan.reason === 'host-bind') {
                    console.log(`wj-dsh-remote: the web server itself binds ${startup?.host ?? ''} (from --host), so the LAN forwarder yields that port and this plugin adds no listener`);
                    warnLanExposure();
                }
                else if (plan.reason === 'no-address') {
                    console.error('wj-dsh-remote: lanBind is on but this machine has no LAN IPv4 address to listen on; LAN access stays off, use a tunnel instead');
                }
            }
            return;
        }
        if (state.listening && state.address === plan.host && state.port === port)
            return;
        const host = plan.host;
        void forwarder.start(host, port).then((next) => {
            if (next.listening) {
                console.log(`wj-dsh-remote: LAN forwarder listening on ${host}:${String(port)} -> ${FORWARD_UPSTREAM_HOST}:${String(next.upstreamPort)}; the web server itself stays on loopback`);
                warnLanExposure();
            }
            else {
                console.error(`wj-dsh-remote: the LAN forwarder could not listen on ${host}:${String(port)} (${next.error ?? 'unknown error'}); loopback access is unaffected and the LAN edge stays off`);
            }
            applyLanBases();
        });
    };
    /**
     * The bind work one sync runs: the legacy block removal, the LAN edge, and the
     * firewall rule. It never writes a profile file except to remove the block an
     * older version left there.
     *
     * The scheduling that reaches it still runs through runDetached (see
     * scheduleLanBindWork): a settings save holds the Host's exclusive HMR
     * transaction in its async context, and a config-file write from inside that
     * context makes the watcher's refresh re-enter it ("HMR transactions cannot be
     * nested", #1751/#1754). The removal is a no-op on every boot after the first,
     * so the ordinary path writes nothing at all.
     * @param value - the effective plugin configuration.
     */
    const applyLanBindWork = (value) => {
        cleanupLegacyBlock(value.profile);
        applyForwardEdge(value);
        if (value.lanBind === undefined)
            return;
        // Keep the firewall rule aligned with the toggle (managed platforms only;
        // see firewall.ts). The probes and rule rewrites are blocking subprocesses,
        // so they run only when the desired state actually moved - not on every
        // unrelated settings save. The port is the live bind port; without it there
        // is nothing to align yet.
        const livePort = Number.isFinite(ctx.webServer.port) ? ctx.webServer.port : undefined;
        if (livePort === undefined) {
            console.error('wj-dsh-remote: cannot align the host firewall rule — the web server port is not known yet');
            return;
        }
        const nextFirewall = { enabled: value.lanBind === true, port: livePort };
        if (!firewallActionNeeded(lastFirewallApplied, nextFirewall))
            return;
        const ruleOk = nextFirewall.enabled ? ensureFirewallRule(nextFirewall.port) : removeFirewallRule(nextFirewall.port);
        if (ruleOk) {
            lastFirewallApplied = nextFirewall;
        }
        else {
            console.error('wj-dsh-remote: the host firewall rule could not be updated (admin rights required on managed platforms)');
        }
    };
    // The forwarder and its connections belong to this activation: a dispose (or a
    // remount) must leave no orphan listener behind.
    ctx.effect(() => () => { void forwarder.stop(); }, 'wj-dsh-remote: lan forwarder');
    // The LAN bind assertion never blocks the caller: one pending work item is
    // enough, and it always re-reads the config through `resolve()` at run time
    // so a toggle flipped twice before the tick lands on the last value.
    //
    // The scheduling itself runs through runDetached: the settings save that
    // drives sync() holds the Host's exclusive HMR transaction in its async
    // context, and a `setImmediate` scheduled directly from here would inherit
    // that mark (measured on Node 24), so the write would still land inside the
    // transaction the watcher then tries to re-enter. Scheduling from the
    // module-scope resource starts the timer - and therefore the write - with no
    // store at all.
    let lanBindWorkPending = false;
    const scheduleLanBindWork = () => {
        if (lanBindWorkPending)
            return;
        lanBindWorkPending = true;
        runDetached(() => setImmediate(() => {
            lanBindWorkPending = false;
            try {
                applyLanBindWork(resolve());
            }
            catch (error) {
                // A deferred assertion must never surface as an unhandled rejection:
                // the settings save that triggered it already answered, and the card
                // reads the live block state back on its own poll.
                console.error(`wj-dsh-remote: the deferred lan-bind assertion failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
    };
    ctx.effect(() => () => { lanBindWorkPending = false; }, 'wj-dsh-remote: lan-bind work');
    // Apply one tunnel plan to the running surfaces. The plugin-managed tunnels
    // own the public base while one runs: the URL lands in the service through
    // the tunnel's phase listener (the minted quick URL, or the named tunnel's
    // fixed public hostname). The manual publicBaseUrl applies only when no
    // tunnel runs.
    const applyTunnelPlan = (value, port) => {
        const plan = tunnelPlanOf(value, port);
        tunnelMode = plan.mode;
        publicBase.setMode(plan.mode);
        const liveTunnelUrl = publicBase.quickUrl();
        namedConnectorWanted = plan.mode === 'quick';
        if (plan.mode !== 'quick') {
            // The relay only fronts the quick tunnel; named mode owns its fixed
            // dashboard hostname and the off mode has no public base at all. Only
            // the announce half goes here: the bridge reaches the object without a
            // tunnel, so the lease survives a plan that runs no quick tunnel.
            disposeRelayAnnouncer();
            namedRelayConnector.stop();
            if (value.relay === false)
                disposeRelayHalf(true);
            if (plan.mode !== 'named')
                publicBase.refresh();
        }
        else if (value.relay === false) {
            // The relay toggle is off: no stable origin, the raw quick URL is the
            // QR base exactly as before the relay existed.
            disposeRelayHalf(true);
            publicBase.refresh();
        }
        else if (liveTunnelUrl !== undefined) {
            // The relay just turned on (or the registrar is new) while the tunnel
            // already runs: announce now — no phase event will fire for an
            // unchanged target.
            const registrar = ensureRelayRegistrar();
            if (registrar !== undefined)
                announceRelay(registrar, liveTunnelUrl);
        }
        if (plan.mode === 'quick') {
            for (const ignored of plan.ignored) {
                console.warn(`wj-dsh-remote: autoTunnel is on — ignoring the configured ${ignored}`);
            }
            // With the relay on, the connector stamps the stable origin as the
            // origin-side Host (`--http-host-header`): the plugin fence and the
            // harness browser-auth are Host-bound to the relay origin, and the
            // Workers relay cannot control the origin-side Host (fetch forces it
            // to the URL authority). The target identity change is also what
            // restarts a running tunnel on a relay toggle.
            const registrar = ensureRelayRegistrar();
            const originHostHeader = registrar === undefined ? undefined : new URL(registrar.baseUrl).host;
            tunnel.start(originHostHeader === undefined
                ? plan.targetUrl
                : { kind: 'quick', targetUrl: plan.targetUrl, originHostHeader });
        }
        else if (plan.mode === 'named') {
            // The hostname is fixed and known before the process runs, so publish it
            // now: a named tunnel that fails to start must not leave the previous
            // mode's ephemeral host as the QR and fence base.
            publicBase.markRunning(plan.publicUrl);
            tunnel.start({ kind: 'named', token: plan.token, publicUrl: plan.publicUrl });
        }
        else {
            tunnel.stop();
            // A named-tunnel token without a usable public hostname cannot serve
            // the QR: stay off and say exactly what is missing instead of running
            // a tunnel nothing points at.
            if (value.tunnelToken !== undefined && value.tunnelToken !== '') {
                console.warn('wj-dsh-remote: tunnelToken is set but publicBaseUrl is missing or not a valid URL — fill the fixed public hostname of the named tunnel (e.g. https://dsh.example.com) to run it');
            }
            // A malformed public base is ignored with a warning — LAN-only behavior
            // stays intact rather than silently minting unusable QR links.
            if (value.publicBaseUrl !== undefined && !isHttpUrl(value.publicBaseUrl)) {
                console.warn(`wj-dsh-remote: ignoring malformed publicBaseUrl ${JSON.stringify(value.publicBaseUrl)} (expected https://host[:port])`);
                service.setPublicBaseUrl(undefined);
            }
            else {
                service.setPublicBaseUrl(value.publicBaseUrl);
            }
        }
    };
    /**
     * Feed the ingress sync the resolved settings. The bound port is the only
     * target fact, so an unbound listener schedules a zero-request wait and the
     * port-settle retry re-plans it. The quick tunnel is never an ingress target:
     * it mints a new hostname per start and owns the public base while it runs,
     * so a deployment on it has no named tunnel to update (the switch reads as
     * off there rather than editing an unrelated tunnel).
     * @param value - the resolved settings.
     * @param port - the bound web server port, undefined before the listener binds.
     */
    const scheduleIngressSync = (value, port) => {
        // The switch precedence and the hostname derivation live in the tested
        // adapter (ingressInputOf): this call site only supplies the settings.
        ingress.schedule(ingressInputOf(value, port));
    };
    // Apply the effective configuration to the running surfaces once per
    // activation: the service tunables, the LAN-bind block/firewall, the tunnel
    // plan, the pairing routes, the presence sweep, and the posture probe.
    const sync = () => {
        const value = resolve();
        service.config = pairingConfigOf(value);
        scheduleLanBindWork();
        // The quick tunnel's loopback target URL needs the bound port. A recompose
        // pass can run this apply before the listener binds: defer the tunnel
        // branch (and re-plan on a short timer) instead of minting an
        // http://127.0.0.1:undefined target; everything else in sync applies.
        // Read through the normalizer: a half-read webServer can hand NaN/Infinity,
        // and that must take the unbound-port path (settle retry, no request) rather
        // than mint a ":NaN" target or leave every dependent surface waiting.
        const livePort = livePortOf(ctx.webServer.port);
        const tunnelNeedsPort = livePort === undefined && value.autoTunnel === true;
        if (tunnelNeedsPort) {
            if (!portSettleWarned) {
                portSettleWarned = true;
                console.warn('wj-dsh-remote: autoTunnel is on but the web server port is not bound yet — the quick tunnel starts once the port settles');
            }
            schedulePortSettleRetry();
        }
        else {
            portSettleWarned = false;
            applyTunnelPlan(value, livePort);
        }
        // The ingress sync learns the live port in both branches: an unbound
        // listener is a zero-request wait there, and the same settle timer delivers
        // the port — no second retry loop of its own.
        scheduleIngressSync(value, livePort);
        if (livePort === undefined && !tunnelNeedsPort && value.ingressSync === true)
            schedulePortSettleRetry();
        // The lease and the bridge are transport-owned, not tunnel-owned: a
        // bridge-mode instance has to reach its object even when no quick tunnel
        // runs (the claim is the only answer that carries the bridge grant, and
        // without it the edge reports no-connector forever). The dedupe key keeps
        // a settings sync from re-claiming, and a fresh quick URL re-claims.
        if (value.enabled && value.relay !== false) {
            if (livePort === undefined)
                schedulePortSettleRetry();
            else
                claimRelayLeaseFor(livePort, publicBase.quickUrl());
        }
        const enabled = value.enabled;
        if (!enabled) {
            service.stop();
            // The tunnel branch above follows the plan, not the master switch, so an
            // explicit "off" must also drop the public ingress it started: otherwise
            // the cloudflared child keeps a live public URL (and the relay keeps its
            // stable row) while the panel says remote control is stopped. The relay
            // row is deliberately kept so re-enabling reuses the same origin.
            tunnel.stop();
            disposeRelayHalf();
            publicBase.reset();
        }
        if (disposeRoutes === undefined && enabled) {
            disposeRoutes = ctx.effect(() => {
                const disposers = [
                    ...routes.map(route => ctx.webServer.register(route)),
                    ...upgrades.map(route => ctx.webServer.registerUpgrade(route)),
                ];
                return () => { for (const dispose of disposers)
                    dispose(); };
            }, 'wj-dsh-remote: pairing routes');
        }
        else if (disposeRoutes !== undefined && !enabled) {
            disposeRoutes();
            disposeRoutes = undefined;
        }
        if (disposeSweep === undefined && enabled) {
            disposeSweep = ctx.effect(() => {
                const timer = nodeSetInterval(() => { service.sweep(); }, SWEEP_INTERVAL_MS);
                timer.unref();
                return () => { clearInterval(timer); };
            }, 'wj-dsh-remote: presence sweep');
        }
        else if (disposeSweep !== undefined && !enabled) {
            disposeSweep();
            disposeSweep = undefined;
        }
        // Settings changed the reachable posture (manual publicBaseUrl, bind):
        // re-probe unless the target set is unchanged.
        runPostureProbe();
    };
    // Inject the crypto.randomUUID polyfill before any other script runs, so that
    // the main bundle doesn't crash on non-secure contexts (LAN HTTP)
    ctx.effect(() => ctx.on('webserver/index-inject', (table) => {
        table.push({ kind: 'script', placement: 'head', text: UUID_POLYFILL_SCRIPT });
    }), 'wj-dsh-remote: uuid polyfill');
    // Issue #987: the browser-half channel patch installs at this plugin's
    // boot entry, but dsh-client-connection boots earlier and opens its event
    // streams unrewritten — on a non-loopback origin the SDK fence rejects
    // them and the workspace list never loads. Contribute the rewrite as a
    // parse-time head script so it is active before ANY boot entry runs; the
    // client apply adopts the installed seat instead of patching twice. The
    // row follows the live steady-state decision (enabled + pairing gate); the
    // script itself skips loopback origins.
    ctx.effect(() => ctx.on('webserver/index-inject', (table) => {
        const value = resolve();
        if (!value.enabled || !value.requirePairingForLan)
            return;
        table.push({ kind: 'script', placement: 'head', text: REMOTE_CHANNEL_BOOT_SCRIPT });
    }), 'wj-dsh-remote: remote channel boot patch');
    // The settings write path. The Host commits the new values into this row's
    // volatile references and announces it here instead of remounting the row, so
    // `sync` is what re-applies them: it re-reads every field through those
    // references (see `resolve`) and is idempotent, so a save that changes
    // nothing observable is a no-op while a disable, a bind flip or a tunnel
    // change lands on the live instance without dropping the pairing service,
    // its device sessions or the route registrations.
    ctx.on('loader/volatile-update', () => { sync(); });
    // No settings registration: the Host derives this plugin's settings page
    // from the exported `Config` schema, whose volatile fields are what make the
    // page writable and what route a save through the live path above.
    sync();
}
