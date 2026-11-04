/**
 * The bridge connector: the plugin side of the relay bridge, grown from the
 * shadow-flight probe (`probe/relay-bridge/connector.mjs`).
 *
 * It dials the instance's Durable Object meeting point over WSS and serves
 * every stream the object multiplexes onto that one socket -- HTTP requests
 * with streamed bodies and responses, and the phone's own WebSocket upgrades.
 *
 * Two rules are not negotiable here:
 *
 *  1. The credential is the relay identity's own long-lived id and secret, sent
 *     in the upgrade's `authorization` header so it never appears in a URL. A
 *     dropped socket is re-dialed with the same credential; the object replaces
 *     the socket it already holds, so a reconnect needs no new ticket and no
 *     new instance.
 *  2. The connector never invents the `Host` it sends upstream. It carries the
 *     public origin the phone dialed -- the object reads it from the request
 *     URL and puts it in the frame, and the fallback is this instance's claimed
 *     relay hostname. It never substitutes the loopback authority it dials: the
 *     host's local control plane (`/wj-remote-bridge/pair/token`, `/api/wj-pair/*`,
 *     `/api/update/*`, `/api/plugin-manager`) is gated on the socket address
 *     AND a loopback Host, so rewriting this header would publish that control
 *     plane on the public origin.
 *
 * Frames mirror `market/worker/src/relay-bridge.js`: control frames are JSON
 * text, payload frames are `[kind:u8][streamId:u32be][payload]`.
 */
import type { RelayBridgeStart } from './relay-connector.ts';
/** The upgrade carries the lease secret here, never in the URL. */
export declare const BRIDGE_AUTH_HEADER = "authorization";
/** Response frames this connector will not forward upstream. */
export declare const BRIDGE_HOP_BY_HOP: Set<string>;
/** Where a dropped socket restarts: fast first, then patient. */
export declare const BRIDGE_RETRY_BASE_MS = 1000;
export declare const BRIDGE_RETRY_MAX_MS = 30000;
/** One header pair as the frame contract carries it. */
export type BridgeHeaderPairs = ReadonlyArray<readonly [string, string]>;
/** The upgrade URL one instance dials (the id is not a secret). */
export declare function relayBridgeDialUrl(endpoint: string, id: string): string;
/**
 * The `Host` one bridged request travels with.
 * @param frameHost - the public origin the object read from the request URL.
 * @param hostname - this instance's claimed relay hostname.
 * @returns a public origin, never the upstream authority this connector dials.
 */
export declare function bridgeUpstreamHost(frameHost: unknown, hostname: string): string;
/**
 * The upstream headers of one bridged request: the phone's own, minus the hops
 * this transport owns, with the public `Host` put back explicitly.
 */
export declare function bridgeUpstreamHeaders(frameHeaders: unknown, host: string): Record<string, string>;
/** The headers of the bridge socket's own upgrade. */
export declare function bridgeUpgradeHeaders(endpoint: string, secret: string): Record<string, string>;
/** One client frame, masked as RFC 6455 requires of the dialing side. */
export declare function encodeBridgeFrame(opcode: number, payload: Uint8Array): Uint8Array;
/** One frame of a WebSocket the connector dialed. */
export interface BridgeFrame {
    opcode: number;
    payload: Buffer;
}
/**
 * A frame reader for the connector's own client side, reassembling fragmented
 * messages and unmasking nothing: only servers send unmasked frames here.
 */
export declare function createBridgeFrameParser(onFrame: (frame: BridgeFrame) => void): (incoming: Buffer) => void;
/** The connector's observable state (logged, and read by the tests). */
export type RelayBridgeState = {
    state: 'idle';
} | {
    state: 'dialing';
} | {
    state: 'connected';
    instance: string;
} | {
    state: 'failed';
    error: string;
};
/**
 * What the connector records on disk: its state plus the lease it dials.
 * The Desktop host runs this plugin in a process whose stdout nobody reads, so
 * without this record a connector that never attached (or a lease that never
 * claimed) leaves no trace at all.
 */
export interface RelayBridgeStateRecord {
    state: RelayBridgeState['state'];
    instance: string;
    hostname: string;
    endpoint: string;
    upstream: string;
    /** When the record was written (ISO 8601). */
    at: string;
    /** The dial failure, for a `failed` record. */
    error?: string;
}
/** Where the connector records its state (`$DSH_HOME/wj-dsh-remote-relay-bridge.json`). */
export declare function relayBridgeStateFile(home?: string): string;
/**
 * Record one connector state. Best effort on purpose: a home that cannot be
 * written must never take the socket down with it.
 * @param file - the record path (see `relayBridgeStateFile`).
 * @param record - the state and the lease it belongs to.
 */
export declare function writeRelayBridgeState(file: string, record: RelayBridgeStateRecord): void;
/** Everything one bridge connector needs to run. */
export interface RelayBridgeConnectorOptions {
    /** The upgrade endpoint the claim reported. */
    endpoint: string;
    /** The relay identity id. */
    id: string;
    /** The relay identity secret (the same long-lived credential). */
    secret: string;
    /** This instance's relay hostname, the fallback public origin. */
    hostname: string;
    /** The local origin the connector serves, `http://127.0.0.1:<port>`. */
    upstream: string;
    baseDelayMs?: number;
    maxDelayMs?: number;
    /** Schedule one retry; defaults to an unref'd node timer. */
    timerFn?: (fn: () => void, ms: number) => {
        unref?: () => void;
    };
    onState?: (state: RelayBridgeState) => void;
}
/**
 * The connector itself: one socket to the object, one upstream request or
 * WebSocket per stream id, and a reconnect that keeps the same credential.
 */
export declare class RelayBridgeConnector {
    private socket;
    private parser;
    private timer;
    private stateValue;
    private attempts;
    private disposed;
    private readonly requests;
    private readonly peers;
    private readonly options;
    constructor(options: RelayBridgeConnectorOptions);
    /** The connector's current state. */
    get state(): RelayBridgeState;
    /** Whether a bridge socket is attached right now. */
    get connected(): boolean;
    /** Dial the object (or schedule the next attempt if the dial fails). */
    start(): void;
    /** Close the socket and stop retrying (the relay half was disposed). */
    stop(): void;
    private dial;
    private attach;
    /** Send one control frame: a text frame, which is how the object tells a
     * control frame from a payload chunk. */
    private sendText;
    /** Send one payload frame: a binary frame carrying a chunk. */
    private sendChunk;
    private write;
    private onBridgeFrame;
    private onControl;
    /** Start one upstream HTTP request for a bridged stream. */
    private startHttp;
    /** Open one upstream WebSocket for a phone's upgrade. */
    private openSocket;
    /** Report one failed dial and retry with the same credential. */
    private fail;
    private scheduleRetry;
    private clearTimer;
    /** Drop every stream this socket carried: the object re-opens them. */
    private teardown;
    private setState;
}
/** The plugin-side owner of one bridge connector. */
export interface RelayBridgeRunner {
    /** Start (or restart) the connector for one accepted lease. */
    start(start: RelayBridgeStart): void;
    /** Stop it (the relay half was disposed). */
    stop(): void;
    readonly state: RelayBridgeState;
}
/**
 * Build the runner the relay pair drives: one connector per accepted lease,
 * rebuilt when a later claim names a different endpoint, and stopped with the
 * relay half. The bridge keeps its socket up while the instance's mode is
 * quick, so a server-side flip needs no plugin restart.
 * @param options - a state observer (logs and the on-disk record).
 */
export declare function createRelayBridgeRunner(options?: {
    onState?: (state: RelayBridgeState) => void;
    /** Where to record the state; `null` keeps the runner in memory only. */
    stateFile?: string | null;
    /** The clock the record timestamps with (tests pass a fixed one). */
    now?: () => string;
}): RelayBridgeRunner;
//# sourceMappingURL=relay-bridge-connector.d.ts.map