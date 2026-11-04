/**
 * The relay's two connectors. The quick tunnel keeps serving every instance
 * that has not migrated, and the named connector is established beside it on
 * the same relay hostname and left idle while the wildcard Worker route still
 * shadows the CNAME. The control plane's `mode` names the connector the phone
 * is meant to be served from; nothing here switches the edge — it only keeps
 * both sides up, so a server-side flip needs no plugin restart and a rollback
 * is the same flip back.
 */
import { type RelayClaim, type RelayClaimOutcome, type RelayClaimRequest, type RelayConnectorMode } from './relay-control.ts';
import type { RelayIdentity } from './relay-registry.ts';
import { TunnelManager, type TunnelInfo } from './tunnel.ts';
/**
 * The crash-recovery record slot the idle named connector owns. Kept apart
 * from the quick connector's slot so each connector's leftover child is reaped
 * by the start that belongs to it instead of overwriting its sibling's record.
 */
export declare function namedTunnelChildRecordFile(home?: string): string;
/**
 * Read this plugin's own version from its package manifest (the claim reports
 * it so the migration can measure adoption by released version).
 * @returns the version, or undefined when the manifest cannot be read.
 */
export declare function readPluginVersion(): string | undefined;
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
export declare function relayClaimKeyOf(port: number | undefined, target: string | undefined): string | undefined;
/** The idle named connector: start, stop and report, nothing else. */
export interface NamedRelayConnector {
    /** Run one named connector for the lease (token via the environment). */
    start(token: string, hostname: string): void;
    /** Stop the connector (the relay half was disposed). */
    stop(): void;
    readonly info: TunnelInfo;
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
export declare function createNamedRelayConnector(options?: {
    manager?: TunnelManager;
}): NamedRelayConnector;
/** The lease half's observable state (logged, and read by the tests). */
export type RelayPairState = {
    state: 'idle';
} | {
    state: 'claiming';
} | {
    state: 'claimed';
    mode: RelayConnectorMode;
    hostname: string;
} | {
    state: 'failed';
    error: string;
};
/** Everything the bridge connector needs to run for one accepted lease. */
export interface RelayBridgeStart {
    claim: RelayClaim;
    identity: RelayIdentity;
    port: number;
}
/** Injectable seams of the lease half (defaults are the real control plane). */
export interface RelayConnectorPairOptions {
    /** One claim attempt. */
    claim?: (request: RelayClaimRequest) => Promise<RelayClaimOutcome>;
    /** Start the named connector for one accepted lease. */
    startNamed?: (token: string, hostname: string) => void;
    /** Stop the named connector. */
    stopNamed?: () => void;
    /** Start (or restart) the bridge connector for one accepted lease. It runs
     * beside the quick tunnel and idles while the instance's mode is quick, so a
     * server-side flip needs no plugin restart. */
    startBridge?: (start: RelayBridgeStart) => void;
    /** Stop the bridge connector. */
    stopBridge?: () => void;
    /** Release the lease (the offline action, never a retire). */
    release?: (identity: RelayIdentity) => Promise<void>;
    /** Observe the lease state (logs only — the card still renders the registry). */
    onState?: (state: RelayPairState) => void;
    baseDelayMs?: number;
    maxDelayMs?: number;
    /** Schedule one retry; defaults to an unref'd node timer. */
    timerFn?: (fn: () => void, ms: number) => {
        unref?: () => void;
    };
}
/**
 * Own the lease half of the relay: claim it on every tunnel start, bring the
 * named connector up beside the quick one, and retry a failed claim with a
 * capped backoff while the quick connector keeps serving.
 */
export declare class RelayConnectorPair {
    private readonly identity;
    private readonly options;
    private stateValue;
    private leaseValue;
    private attempts;
    private timer;
    private disposed;
    constructor(identity: RelayIdentity, options?: RelayConnectorPairOptions);
    /** The lease half's current state. */
    get state(): RelayPairState;
    /** The connector the phone is served from, for the last accepted lease. */
    get served(): RelayConnectorMode | undefined;
    /** The last accepted lease (undefined until one lands). */
    get lease(): RelayClaim | undefined;
    /**
     * Claim one lease and start (or restart) the named connector for it. A
     * refusal is graded into a retry and never tears down the quick connector:
     * the instance keeps the origin the registry already gave it.
     * @param input - the local origin port and the reporting plugin version.
     * @returns the accepted lease, or undefined when the attempt did not land.
     */
    start(input: {
        port: number;
        pluginVersion?: string;
    }): Promise<RelayClaim | undefined>;
    /**
     * The plugin's offline action (toggle off, profile unmount): release the
     * lease and stop the idle connector. Never retires — the hostname is the
     * phone's bookmark, and the tunnel behind it survives.
     */
    release(): Promise<void>;
    /** Stop retrying and drop the connector (the relay half was disposed). */
    dispose(): void;
    private startNamed;
    private stopNamed;
    /** Bring the bridge connector up for one accepted lease, if it carries one. */
    private startBridge;
    private scheduleRetry;
    private clearTimer;
    private setState;
}
//# sourceMappingURL=relay-connector.d.ts.map