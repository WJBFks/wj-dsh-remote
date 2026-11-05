/**
 * Browser-side wire helpers for the /api/wj-pair surface. Plain fetch over
 * same-origin /api (like the connection client); JSON bodies, string
 * responses for the error codes.
 *
 * The paths are DOCUMENT-RELATIVE (issue #1707): the GUI is served with
 * `<base href="./">`, so a sub-path deployment resolves them against its entry
 * directory instead of escaping to the origin root.
 */
/** issue() response. */
export interface IssueResult {
    ok: true;
    url: string;
    token: string;
    expiresAt: number;
    /** Every constructible LAN base address (interface order). */
    lanAddresses: string[];
    /** The configured public (tunneled) base URL, when present. */
    publicBaseUrl?: string;
}
/** issue() refusal: the server is not LAN-reachable. */
export interface IssueLanRequired {
    ok: false;
    code: 'lan-required';
}
/** issue() refusal: the requested LAN address is not constructible. */
export interface IssueUnknownAddress {
    ok: false;
    code: 'unknown-address';
}
/** issue() refusal: the loopback-only fence rejected this origin. */
export interface IssueLoopbackRequired {
    ok: false;
    code: 'forbidden';
}
export type IssueResponse = IssueResult | IssueLanRequired | IssueUnknownAddress | IssueLoopbackRequired;
/** Public policy fields returned by the pairing status endpoint. */
export interface PairGatePolicy {
    requirePairingForLan: boolean;
}
/** Read the host-authoritative desktop pairing policy. */
export declare function readPairGatePolicy(): Promise<PairGatePolicy>;
/** accept() refusal codes. */
export type AcceptFailure = {
    ok: false;
    code: 'invalid' | 'forbidden';
};
/** One auto-tunnel status frame (absent while the feature is off). */
export interface TunnelStatusFrame {
    state: 'starting' | 'running' | 'failed';
    url?: string;
    error?: string;
}
/** One relay-registry status frame (absent while the relay is not in play). */
export interface RelayStatusFrame {
    state: 'off' | 'registering' | 'running' | 'failed';
    /** The stable relay origin, once registered. */
    url?: string;
    /** Human-readable failure detail of the last sync attempt. */
    error?: string;
}
/**
 * One update-only Cloudflare ingress-sync frame (issue #1948; absent until the
 * feature ran in this host process). Every field is an audit fact about the
 * public hostname and the local port — never the account token.
 */
export interface IngressStatusFrame {
    state: 'off' | 'waiting' | 'applied' | 'failed' | 'conflict';
    /** The public hostname the sync tracks (from publicBaseUrl). */
    hostname?: string;
    /** The local web server port the service follows. */
    port?: number;
    /** The ingress service string after the last run. */
    service?: string;
    /** The ingress service an apply moved away from. */
    previousService?: string;
    /** How many ingress rules the read document carried. */
    ruleCount?: number;
    /** Index of the rule the sync owns. */
    ruleIndex?: number;
    /** Whether the last run actually wrote the remote document. */
    changed?: boolean;
    /** Machine-readable reason of a failed or conflict state. */
    code?: string;
    /** Human-readable detail (hostname, port, status, API message). */
    detail?: string;
    /** When the state was reached (ms epoch). */
    at?: number;
}
/**
 * Read the ingress-sync frame off the pairing status view. The status route
 * carries this block only to a desktop (loopback) caller or a live paired
 * device, so another origin reads nothing here and the card renders no line.
 * @returns the frame, or undefined when the view carries none (or is unreadable).
 */
export declare function readIngressStatus(): Promise<IngressStatusFrame | undefined>;
/** One /api posture frame (host half probe; see src/posture.ts). */
export interface PostureFrame {
    checkedAt: number;
    hosts: {
        host: string;
        exposed: boolean;
    }[];
}
/** One /api/wj-pair/events frame. */
export interface PairStateFrame {
    type: 'state';
    phase: 'lan-required' | 'stopped' | 'waiting' | 'connected' | 'disconnected';
    lanAvailable: boolean;
    tokenId?: string;
    tokenExpiresAt?: number;
    deviceCount: number;
    onlineCount: number;
    /** Per-device roster (loopback events only). */
    devices?: DeviceFrame[];
    /** Auto-tunnel status, while the auto-tunnel feature is active. */
    tunnel?: TunnelStatusFrame;
    /** Relay-registry status, while the stable-origin relay is in play. */
    relay?: RelayStatusFrame;
    /** Latest /api fence posture probe, once a round has completed. */
    posture?: PostureFrame;
    /** The caller's own identity (public id + level). */
    self?: {
        level: number;
        publicId?: string;
        loopback?: boolean;
    };
}
/** One authorized-device row from the status stream. */
export interface DeviceFrame {
    /** Public, non-secret id shown in the panel. */
    publicId: string;
    /** Permission level 0..9. */
    level: number;
    createdAt: number;
    lastSeenAt: number;
    online: boolean;
    userAgent?: string;
    /** User-defined label; the panel falls back to the UA-derived name. */
    name?: string;
}
/**
 * Mint a fresh pairing token (one active token at a time — this invalidates
 * any previous link).
 * @param address - optional LAN IP literal the QR must be built from (the
 * default is the first interface); unknown literals refuse with
 * 'unknown-address'.
 * @returns the issued link, the lan-required refusal (server never bound
 * 0.0.0.0), or the forbidden refusal (the loopback-only fence rejected this
 * origin — the panel is a desktop control endpoint).
 */
export declare function issuePair(address?: string): Promise<IssueResponse>;
/**
 * Accept a pairing token (the phone's first open of the QR link). Success
 * sets the device cookie; the page then reloads to boot with it.
 * @param token - the token from the URL.
 * @returns the wire result.
 */
export declare function acceptPair(token: string): Promise<{
    ok: true;
} | AcceptFailure>;
/** The caller's own identity (public id + level). */
export declare function fetchMe(): Promise<{
    level: number;
    publicId?: string;
    loopback?: boolean;
} | undefined>;
/** Change one device's level (level 10 / loopback only). */
export declare function setPairLevel(publicId: string, level: number): Promise<boolean>;
/** Revoke mobile access (paired devices + the current token). */
export declare function stopPair(): Promise<void>;
/**
 * Revoke one paired device from the loopback panel.
 * @param deviceId - the session id of the row to drop.
 */
export declare function revokePair(deviceId: string): Promise<void>;
/**
 * Set or clear one device's panel label. An empty name clears it and restores
 * the User-Agent-derived fallback.
 * @param deviceId - the session id of the row to rename.
 * @param name - the new label ('' clears it).
 * @returns true when the host stored the label; false for an unknown row.
 */
export declare function renamePair(deviceId: string, name: string): Promise<boolean>;
/**
 * Collapse duplicate pairing rows the operator grouped as one device. The host
 * keeps the most recently active row and revokes the rest.
 * @param deviceIds - the grouped session ids (two or more).
 * @returns the surviving device id, or undefined when the host refused the
 *   group (unknown row, or not one User-Agent).
 */
export declare function mergePairDevices(deviceIds: readonly string[]): Promise<string | undefined>;
/**
 * Presence heartbeat from a paired phone.
 * @returns the response status, so the caller can stop polling once the server
 *   proves this page is not paired (see {@link shouldStopHeartbeat}).
 */
export declare function sendHeartbeat(): Promise<number>;
/**
 * Whether a heartbeat answer means "this page can never be accepted again" and
 * the 10 s wake source should stop: 401 (unpaired, or the device was revoked)
 * and 403 (the fence refused it) are permanent for this page, while a network
 * error or a 5xx is transient and keeps the cadence.
 * @param status - the heartbeat response status.
 */
export declare function shouldStopHeartbeat(status: number): boolean;
/** Whether the current page URL carries a pairing token. */
export declare function readPairParams(search: string): {
    pair?: string;
};
/**
 * Strip one query parameter from the current URL without reloading.
 * @param name - the parameter to remove.
 * @returns the new search string ('' when empty).
 */
export declare function stripParam(name: string): string;
/**
 * The LAN edge forwarder's state (issue #1917: a runtime forwarder replaced the
 * managed profile block). The wire key of the address is `host`.
 */
export interface LanForwardFrame {
    /** Whether the forwarder is answering on the LAN right now. */
    listening: boolean;
    /** The address it listens on; absent while it does not listen. */
    host?: string | null;
    /** The port it listens on; absent while it does not listen. */
    port?: number | null;
    /**
     * Why it does not listen: 'off' (toggle off or never flipped), 'host-bind'
     * (the operator bound a non-loopback address with --host, so the forwarder
     * yields the port), 'no-address' (this machine has no LAN IPv4 to listen on).
     */
    reason?: string | null;
    /** The bind failure verbatim (EADDRINUSE, EADDRNOTAVAIL, ...). */
    error?: string | null;
}
/** LAN-bind status frame from the loopback-only card endpoint. */
export interface LanBindFrame {
    profile: string;
    /** The config toggle: true/false once flipped, null while untouched. */
    setting: boolean | null;
    /** The bind default a pre-#1917 managed patch block still pins. */
    blockHost: string | null;
    /** The address LAN clients actually dial: the forwarder, or the running bind. */
    bindHost?: string;
    port: number;
    lanUrls: string[];
    firewall: {
        ok: boolean;
        managed: boolean;
        note?: string;
    };
    platform: string;
    /** true when the running bind has not caught up with the toggle yet. */
    pendingRestart?: boolean;
    /** The host process's own listener, when the LAN edge sits beside it (issue #1917). */
    localBindHost?: string | null;
    /** A bind block a previous version wrote was removed by this process (issue #1917). */
    legacyBlockRemoved?: boolean;
    /** The LAN edge this plugin runs itself; absent on a pre-#1917 host half. */
    forward?: LanForwardFrame;
    /**
     * What the next write or start will pin: a concrete LAN literal on a host
     * that refuses wildcard binds, '0.0.0.0' where the wildcard is still
     * accepted, and null when the toggle was never set or nothing can be pinned.
     * Optional so a pre-0.2.1-rc.2 host half still parses.
     */
    desiredHost?: string | null;
    /** Whether the running host's webserver schema accepts a wildcard bind. */
    wildcardSupported?: boolean;
    /** The non-loopback IPv4 addresses of this process this host could pin. */
    supportedHosts?: string[];
    /** The toggle is on but nothing bindable could be pinned. */
    lanBlocked?: boolean;
}
/**
 * Whether a bind literal reaches the LAN, which is what the card reports as
 * "LAN access is on". The wildcard counts (legacy blocks written before
 * 0.2.1-rc.2, and hosts that still accept it), and so does any other
 * non-loopback literal — a concrete interface address, or an IPv6 literal that
 * is not the loopback (a zone suffix such as fe80::1%eth0 included).
 * @param host - the block host, the live bind, or undefined when absent.
 * @returns whether the address is reachable from another device.
 */
export declare function isLanHost(host: string | null | undefined): boolean;
/** A failed LAN-bind read, carrying the HTTP status when the server answered. */
export declare class LanBindStatusError extends Error {
    readonly status: number | undefined;
    /**
     * @param status - the response status, or undefined when the request failed
     *   before a response (network error).
     * @param message - the diagnostic message.
     */
    constructor(status: number | undefined, message: string);
}
/** Read the LAN-bind facts (loopback-only endpoint). */
export declare function readLanBindStatus(): Promise<LanBindFrame>;
/**
 * Whether a LAN-bind status failure means this origin can never read the
 * endpoint (401/403 from the loopback-only fence), so a poll should stop
 * instead of retrying a known refusal; a transient error keeps the cadence.
 * @param status - the response status, or undefined for a network failure.
 */
export declare function shouldStopLanBindPoll(status: number | undefined): boolean;
/** Human-readable expiry clock, e.g. "10:35". */
export declare function formatClock(epochMs: number): string;
/** Calendar + clock for last-seen timestamps, e.g. "2026-08-19 10:35". */
export declare function formatLastSeen(epochMs: number): string;
/**
 * Copy text to the clipboard with a fallback for insecure contexts
 * (plain-HTTP LAN origins lack navigator.clipboard).
 * @param text - the text to copy.
 * @returns whether the copy succeeded.
 */
export declare function copyText(text: string): Promise<boolean>;
//# sourceMappingURL=pair-api.d.ts.map