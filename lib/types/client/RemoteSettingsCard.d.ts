/**
 * The remote-control settings card: pairing security and device limits.
 * Registers into the `web-ui.plugin.item` child slot the Web UI plugin group
 * renders, bound to the `wj-dsh-remote` profile entry's configuration form.
 */
import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots';
import type { ConfigForm } from '@deepseek-ai/dsh-client-ui-settings/client';
import type { SnapshotStore } from '@deepseek-ai/dsh-client-store';
import { type CardActions, type CardShell, type FieldState as CardFieldState } from './settings-form.ts';
import type { TranslateNS } from '@deepseek-ai/dsh-client-ui-slots';
/** The remote-control fields this card edits (the namespace's full schema). */
export interface RemoteSettings {
    /** Master switch for the plugin. */
    enabled?: boolean;
    /** Token lifetime in ms; the QR link dies after this. */
    tokenTtlMs?: number;
    /** A device is "online" while its lastSeenAt is newer than this (ms). */
    offlineAfterMs?: number;
    /** Hard cap on paired device sessions (oldest evicted when full). */
    maxDevices?: number;
    /** Idle sessions older than this (ms) are deleted. */
    idleExpireMs?: number;
    /** Cookie name carrying the paired device id. */
    cookieName?: string;
    /** Fence flag: whether non-loopback /api requests must carry a live paired-device cookie. */
    requirePairingForLan?: boolean;
    /** Public (tunneled) base URL the QR link is built from when set. */
    publicBaseUrl?: string;
    /** When on, the plugin runs its own Cloudflare quick tunnel automatically. */
    autoTunnel?: boolean;
    /**
     * Cloudflare named-tunnel token: when set (and autoTunnel is off), the
     * plugin runs the named tunnel toward the fixed public hostname — a phone
     * paired once keeps its session across restarts.
     */
    tunnelToken?: string;
    /**
     * Update-only ingress sync: keeps the named tunnel's existing rule for this
     * public hostname pointing at the port the host actually bound.
     */
    ingressSync?: boolean;
    /** Account-level Cloudflare API token (stored redacted by the Host). */
    cfApiToken?: string;
    /** Cloudflare account id the named tunnel belongs to. */
    cfAccountId?: string;
    /** The named tunnel id (not its run token). */
    cfTunnelId?: string;
    /**
     * Stable-origin relay: when on (default), the quick tunnel is fronted by a
     * fixed `<id>.dsh-market.com` subdomain so the phone's bookmark and
     * pairing cookie survive restarts without any setup.
     */
    relay?: boolean;
    /**
     * LAN bind toggle: once flipped, the plugin manages the profile patch's
     * webserver block (a LAN literal of this machine / 127.0.0.1) and the host
     * firewall rule.
     */
    lanBind?: boolean;
}
/** What the remote-control card renders. */
export interface RemoteSettingsCardState extends CardShell {
    /** Master switch. */
    enabled: CardFieldState;
    /** Token lifetime. */
    tokenTtlMs: CardFieldState;
    /** Device offline threshold. */
    offlineAfterMs: CardFieldState;
    /** Paired-device cap. */
    maxDevices: CardFieldState;
    /** Idle-expiry window. */
    idleExpireMs: CardFieldState;
    /** Device cookie name. */
    cookieName: CardFieldState;
    /** LAN fence flag. */
    requirePairingForLan: CardFieldState;
    /** Public (tunneled) base URL. */
    publicBaseUrl: CardFieldState;
    /** Auto public tunnel switch. */
    autoTunnel: CardFieldState;
    /** Named-tunnel token (stored redacted by the Host). */
    tunnelToken: CardFieldState;
    /** Update-only Cloudflare ingress sync switch. */
    ingressSync: CardFieldState;
    /** Cloudflare API token (stored redacted by the Host). */
    cfApiToken: CardFieldState;
    /** Cloudflare account id. */
    cfAccountId: CardFieldState;
    /** Cloudflare tunnel id. */
    cfTunnelId: CardFieldState;
    /** Stable-origin relay switch. */
    relay: CardFieldState;
    /** LAN bind toggle. */
    lanBind: CardFieldState;
}
/** The registration-side face the card's slot entry injects. */
export interface RemoteSettingsCardFace extends CardActions {
    hooks: {
        /** Card snapshot bound by the renderer as useRemoteSettingsCard. */
        remoteSettingsCard: SnapshotStore<RemoteSettingsCardState>;
    };
}
/** Bridges the `wj-dsh-remote` form onto the card's staged form. */
export declare class RemoteSettingsCardController {
    private readonly form;
    private readonly store;
    /** @param scope - the configuration form for the `wj-dsh-remote` entry. */
    constructor(scope: ConfigForm<RemoteSettings>);
    private projection;
    /**
     * Build the face the card's slot registration injects.
     * @returns the card's snapshot and its form actions.
     */
    inject(): RemoteSettingsCardFace;
    /**
     * Release the card's form subscription and bound stores; the slot
     * disposer calls this on teardown.
     */
    dispose(): void;
}
/** Props the renderer binds for the remote-control card. */
export type RemoteSettingsCardProps = PropsRuntime<'web-ui.plugin.item'> & PropsLocale<'remote'> & InjectFace<RemoteSettingsCardFace>;
/**
 * Render the remote-control card.
 * @param props - locale copy, the card snapshot, and its form actions.
 * @returns the card.
 */
export declare function RemoteSettingsCard(props: RemoteSettingsCardProps): import("react").JSX.Element;
/**
 * Live LAN facts above the toggle: the address LAN clients dial, the host
 * process's own listener beside it, the firewall summary, and the reachable LAN
 * URLs. Polls the loopback-only status endpoint; a failure (non-loopback
 * origin) renders nothing — the pairing panel carries the loopback banner
 * instead.
 *
 * Issue #1917 deleted the managed profile block: a runtime forwarder now holds
 * the LAN edge, so the card reports that edge instead of a written block — the
 * address it listens on, why it does not listen (the operator's --host takes the
 * port, or this machine has no LAN address), the bind failure verbatim, and
 * whether the block an older version wrote was cleaned up. The host process's
 * own listener stays visible, so "the LAN entry is a forwarder" is readable
 * rather than inferred. A pre-#1917 host half sends no `forward` field and the
 * frame is read defensively.
 */
export declare function LanBindStatus({ t }: {
    t: TranslateNS<'remote'>;
}): import("react").JSX.Element | null;
/**
 * The live Cloudflare ingress-sync state beside its switch (issue #1948): the
 * public hostname being tracked, the service an apply wrote (or already found),
 * and the reason a failing or conflicting run stopped writing. Reads the
 * pairing status view, which only carries this block to a loopback caller or a
 * live paired device — a card opened anywhere else renders nothing. One read on
 * open, then every 10 s while the card stays expanded.
 */
export declare function IngressStatus({ t }: {
    t: TranslateNS<'remote'>;
}): import("react").JSX.Element | null;
//# sourceMappingURL=RemoteSettingsCard.d.ts.map