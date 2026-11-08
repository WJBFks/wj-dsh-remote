/**
 * Remote control — browser half. Registers the `remote` dictionaries, the
 * sidebar-foot entry (phone trigger + pairing panel + update trigger), and
 * the pair boot flow (accept + presence heartbeats) plus the one-time
 * failed-pair notice. The portrait-touch adaptation of the official UI
 * lives in the separate wj-dsh-mobile plugin; this plugin no longer installs it.
 * on dispose, so disabled plugin entries stay inert. Export discipline: packages/client/AGENTS.md — the
 * /client surface carries only what cordis loading needs plus types.
 */
import { createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { FooterRemoteEntry } from "./FooterRemoteEntry.js";
import { PairFailedNotice } from "./PairFailedNotice.js";
import { RemoteSettingsCard, RemoteSettingsCardController } from "./RemoteSettingsCard.js";
import { en, zh } from "./locales.js";
import { PAIR_FAILED_MARKER, runPairBootFlow } from "./deep-link.js";
import { readPairGatePolicy, sendHeartbeat, shouldStopHeartbeat } from "./pair-api.js";
import { channelTransition, installRemoteChannel, pageOriginFacts, remoteChannelRequired, REMOTE_CHANNEL_BOOT_GLOBAL, } from "./remote-channel.js";
import { isLocalPage } from "../remote-channel-rules.js";
import { FenceNotice } from "./FenceNotice.js";
import { reportDailyHeartbeat } from "./telemetry.js";
import { installPluginCard } from "./plugin-card-seat.js";
import { createServedEntryForm } from "./settings-entry-form.js";
/** Dictionary namespace owned by this plugin. */
const NS = 'remote';
/**
 * Settings namespace the remote-control card edits: the family identity of
 * this plugin's own settings form, and the row id a standalone bundle install
 * carries.
 */
const REMOTE_WEB_UI_NS = 'wj-dsh-remote';
/** Profile entry id the family aggregate's generated row carries. */
const AGGREGATE_ENTRY_ID = 'web-ui-wj-dsh-remote';
/** Profile entry ids this package's patch rows carry, most specific first. */
const REMOTE_WEB_UI_ENTRY_IDS = [AGGREGATE_ENTRY_ID, 'ui-wj-dsh-remote', REMOTE_WEB_UI_NS];
/**
 * The profile entry id this package's own row carries, for a page that serves
 * no family binder.
 *
 * The shared describe mirror answers asynchronously, so at plugin activation it
 * usually holds nothing yet — and an unanswered or empty mirror is not evidence
 * of absence. Binding the bare namespace there left the card bound to an entry
 * the Host does not serve, and the form is bound once per session, so the card
 * never recovered (every save answered `No configurable plugin entry`). The
 * aggregate row id matches nearly every deployment; only a mirror that answers
 * with OTHER plugins' rows falls back to the namespace itself (the pre-0.1.7
 * keying shape), because that answer is the one that actually proves this
 * package's own row is not served.
 * @param forms - the shared configuration forms service.
 * @returns the entry id to bind.
 */
export function servedEntryId(forms) {
    let served;
    try {
        served = forms.describe().getSnapshot().view?.namespaces.map(view => view.ns);
    }
    catch {
        // A mirror that refuses the read is unanswered too, not absent.
        served = undefined;
    }
    if (served === undefined || served.length === 0)
        return AGGREGATE_ENTRY_ID;
    return REMOTE_WEB_UI_ENTRY_IDS.find(id => served.includes(id)) ?? REMOTE_WEB_UI_NS;
}
/**
 * Bind the settings form the remote-control card reads and writes.
 *
 * The family binder comes first: it resolves this package's family namespace
 * onto the profile entry id the Host serves the form under, and keeps the
 * loopback bridge as its own fallback. A page without that group (or one where
 * its client half has not applied yet) binds through the shared forms service,
 * on the entry id the describe mirror justifies and rebound as soon as the
 * mirror answers — see {@link createServedEntryForm}.
 * @param ctx - client context carrying the family binder and/or the shared forms service.
 * @returns the form the card stages and saves through.
 */
export function bindSettingsForm(ctx) {
    const family = ctx.get('webUiSettings');
    if (family !== undefined && typeof family.bind === 'function') {
        return family.bind({ namespace: REMOTE_WEB_UI_NS });
    }
    return createServedEntryForm({
        forms: ctx.configForms,
        entryIds: REMOTE_WEB_UI_ENTRY_IDS,
    });
}
/** Heartbeat cadence from a paired phone (presence + revocation liveness). */
const HEARTBEAT_INTERVAL_MS = 10_000;
/** Services required by this plugin. */
export const inject = ['slots', 'locale', 'connection', 'configForms', 'remote'];
/**
 * Register the remote-control surface.
 * @param ctx - client root context.
 */
export function apply(ctx) {
    // Portrait-touch adaptation moved to the standalone wj-dsh-mobile plugin.
    // Anonymous install heartbeat (docs/telemetry.md): one beat per browser per
    // UTC day, package name only, silent failure.
    reportDailyHeartbeat([{ name: 'wj-dsh-remote' }]);
    ctx.effect(() => {
        try {
            return ctx.locale.register(NS, { zh, en });
        }
        catch {
            return () => { };
        }
    }, 'wj-dsh-remote: dictionaries');
    const t = ctx.locale.bind(NS);
    // The settings form this card edits. The family group's binder resolves a
    // family namespace to the profile entry that owns it and binds that entry's
    // shared form (natively, or over its loopback bridge); without that group the
    // namespace IS the owning entry id, so the official service is addressed
    // directly.
    const settingsForm = bindSettingsForm(ctx);
    const enabled = () => {
        const snapshot = settingsForm.getSnapshot();
        return snapshot.status === 'ready'
            ? snapshot.value?.enabled ?? true
            : snapshot.status === 'unavailable';
    };
    // Sidebar foot entry: the sidebar foot seat is `sidebar.footer.action` in
    // the 0.1.2 shell composition (the legacy `sidebar.remote` seat is gone
    // upstream). The pairing link is origin-agnostic, so the entry needs no
    // workspace source.
    ctx.slots.inject('sidebar.footer.action', () => {
        let disposeEntry;
        const syncEntry = () => {
            if (enabled() && disposeEntry === undefined) {
                try {
                    disposeEntry = ctx.slots.register({ name: 'sidebar.footer.action', id: 'wj-dsh-remote', locale: NS }, FooterRemoteEntry);
                }
                catch {
                    // ignore registration collision
                }
            }
            else if (!enabled() && disposeEntry !== undefined) {
                disposeEntry();
                disposeEntry = undefined;
            }
        };
        const unsubscribe = settingsForm.subscribe(syncEntry);
        syncEntry();
        return () => {
            unsubscribe();
            disposeEntry?.();
        };
    });
    // Plugin configuration card: one staged form over the `wj-dsh-remote`
    // settings namespace, contributed to whichever plugin-card seat the running
    // host declares (the family group's list seat, or the official
    // bundle-configuration seat on the plugin manager page when dsh-web-settings
    // is not installed).
    const remoteSettings = new RemoteSettingsCardController(settingsForm);
    installPluginCard(ctx, {
        bundle: 'wj-dsh-remote',
        id: 'wj-dsh-remote',
        order: 90,
        locale: NS,
        inject: () => remoteSettings.inject(),
        component: RemoteSettingsCard,
    });
    ctx.effect(() => () => { remoteSettings.dispose(); }, 'wj-dsh-remote: settings card');
    // Phone-side boot flow + heartbeats. Loopback pages (the desktop) never
    // heartbeat; the server ignores unpaired heartbeats anyway. Both run only
    // while the plugin is enabled.
    let disposeRuntime;
    const syncRuntime = () => {
        if (enabled() && disposeRuntime === undefined) {
            disposeRuntime = ctx.effect(() => {
                const connection = ctx.get('connection');
                const loopback = connection?.isLoopback ?? true;
                runPairBootFlow(ctx, window.location.search);
                if (loopback)
                    return () => { };
                const timer = window.setInterval(() => {
                    void sendHeartbeat().then((status) => {
                        // A revoked (401) or fenced-off (403) page can never be accepted
                        // again without re-pairing, so the 10 s wake source stops instead of
                        // polling a refusal for the lifetime of the tab.
                        if (shouldStopHeartbeat(status))
                            window.clearInterval(timer);
                    }).catch(() => { });
                }, HEARTBEAT_INTERVAL_MS);
                return () => { window.clearInterval(timer); };
            }, 'wj-dsh-remote: pair flow + heartbeats');
        }
        else if (!enabled() && disposeRuntime !== undefined) {
            disposeRuntime();
            disposeRuntime = undefined;
        }
    };
    settingsForm.subscribe(syncRuntime);
    syncRuntime();
    // Remote desktop channel: on a non-loopback origin (LAN address or public
    // tunnel) the connection plugin's /api fence refuses this desktop Web GUI,
    // and pairing is the access control — so the SDK client's /api traffic is
    // rewritten onto this plugin's gated /remote/api prefix (remote-channel.ts)
    // while the fence setting demands it. Loopback origins are untouched.
    let disposeChannel;
    let hostPairingPolicy;
    let unpairedWhilePolicyPending = false;
    let fenceNotice;
    const showFenceNotice = () => {
        if (fenceNotice !== undefined)
            return;
        const node = document.createElement('div');
        document.body.appendChild(node);
        const root = createRoot(node);
        root.render(createElement(FenceNotice, { t, onRetry: () => { window.location.reload(); } }));
        fenceNotice = { unmount: () => { root.unmount(); node.remove(); }, node };
    };
    const hideFenceNotice = () => {
        fenceNotice?.unmount();
        fenceNotice = undefined;
    };
    const handleUnpaired = () => {
        if (settingsForm.getSnapshot().status !== 'ready' && hostPairingPolicy === undefined) {
            unpairedWhilePolicyPending = true;
            return;
        }
        showFenceNotice();
    };
    const channelActive = () => remoteChannelRequired(pageOriginFacts(window), settingsForm.getSnapshot(), hostPairingPolicy);
    // The parse-time boot patch (issue #987), when the served index carried
    // it: already installed before any boot entry ran, so adopting its seat
    // beats patching a second time (which would double-rewrite onto
    // /remote/remote/...).
    const bootSeat = () => window[REMOTE_CHANNEL_BOOT_GLOBAL];
    const syncChannel = () => {
        const transition = channelTransition(channelActive(), disposeChannel !== undefined);
        if (transition === 'install') {
            const seat = bootSeat();
            if (seat !== undefined) {
                seat.onUnpaired = handleUnpaired;
                seat.onPaired = hideFenceNotice;
                // Replay a signal raised before adoption (early unpaired responses).
                if (seat.pendingUnpaired) {
                    seat.pendingUnpaired = false;
                    handleUnpaired();
                }
                disposeChannel = ctx.effect(() => () => {
                    seat.onUnpaired = null;
                    seat.onPaired = null;
                }, 'wj-dsh-remote: remote desktop channel (boot patch)');
            }
            else {
                disposeChannel = ctx.effect(() => {
                    const restore = installRemoteChannel(window, { onUnpaired: handleUnpaired, onPaired: hideFenceNotice });
                    return restore;
                }, 'wj-dsh-remote: remote desktop channel');
            }
        }
        else if (transition === 'retire' && disposeChannel !== undefined) {
            disposeChannel();
            disposeChannel = undefined;
            // Retire the provisional parse-time install with the channel: the
            // desktop now rides plain /api, so the rewrite must go (its seat
            // removes the global; a later re-activation patches afresh).
            bootSeat()?.restore();
            // Retire the notice with the channel: once requirePairingForLan turns
            // off (or the plugin is disabled) the desktop rides plain /api again,
            // so an unpaired notice raised while the channel was briefly active
            // (the settings snapshot loads after boot) must not outlive it. The
            // installed channel is the only path that raises the notice, so with
            // the channel gone nothing can re-raise it (issue #808).
            hideFenceNotice();
        }
        else if (transition === 'none' && !channelActive()) {
            // The channel was never adopted (policy settled to off before apply
            // ran): the provisional boot patch still retires.
            bootSeat()?.restore();
        }
    };
    settingsForm.subscribe(syncChannel);
    syncChannel();
    const pageOrigin = pageOriginFacts(window);
    if (!isLocalPage(pageOrigin.hostname, pageOrigin.protocol, pageOrigin.transportOwnsHost) && settingsForm.getSnapshot().status !== 'ready') {
        void readPairGatePolicy().then((policy) => {
            hostPairingPolicy = policy.requirePairingForLan;
            syncChannel();
            if (hostPairingPolicy && unpairedWhilePolicyPending)
                showFenceNotice();
            unpairedWhilePolicyPending = false;
        }).catch(() => {
            // Fail closed when the policy endpoint is unavailable or malformed.
            hostPairingPolicy = true;
            syncChannel();
            if (unpairedWhilePolicyPending)
                showFenceNotice();
            unpairedWhilePolicyPending = false;
        });
    }
    // One-time failed-pair toast. The accept result lands asynchronously, so
    // the marker check is deferred past the accept round trip.
    ctx.effect(() => {
        const timer = window.setTimeout(() => {
            if (sessionStorage.getItem(PAIR_FAILED_MARKER) === null)
                return;
            sessionStorage.removeItem(PAIR_FAILED_MARKER);
            const mount = document.createElement('div');
            document.body.appendChild(mount);
            const root = createRoot(mount);
            root.render(createElement(PairFailedNotice, { t }));
            // The toast owns its dismissal; the root lives for the page lifetime.
            void root;
        }, 1500);
        return () => { window.clearTimeout(timer); };
    }, 'wj-dsh-remote: failed-pair notice');
}
