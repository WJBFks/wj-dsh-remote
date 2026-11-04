/**
 * Relay control-plane client: the lease claim that turns one relay identity
 * into a lease row (the tunnel transports get a tunnel, its ingress, a CNAME
 * and the per-instance connector token; the bridge transport gets neither
 * block, because its data plane owns no Cloudflare object) plus the release
 * bookkeeping.
 *
 * Claiming is best-effort and additive. Every failure is graded into a retry
 * decision instead of breaking the quick tunnel that already serves the phone:
 * the control plane answers `mode`, so an instance whose claim cannot land
 * keeps the origin the registry gave it.
 */
import type { RelayIdentity } from './relay-registry.ts';
/** The control-plane endpoints (market apex, never a relay hostname). */
export declare const RELAY_CLAIM_URL = "https://dsh-market.com/api/relay/claim";
export declare const RELAY_RELEASE_URL = "https://dsh-market.com/api/relay/release";
/** Which connector serves the relay hostname. `bridge` is the Durable Object
 * meeting point (`relay-bridge-connector.ts`), `named` the instance's own cloud
 * tunnel, `quick` today's Worker proxy path. */
export type RelayConnectorMode = 'named' | 'quick' | 'bridge';
/** What a bridge connector needs to dial: an endpoint and a credential to
 * present. The credential is the lease's own long-lived id and secret -- the
 * reply names it rather than repeating a secret in a body. */
export interface RelayBridgeGrant {
    endpoint: string;
    instance: string;
    credential: 'lease-secret';
}
/** One accepted lease, as the control plane answers it. */
export interface RelayClaim {
    mode: RelayConnectorMode;
    /** The instance's own tunnel. Absent for a bridged lease: there is nothing
     * to run and no token to run it with. */
    tunnel?: {
        id: string;
        token: string;
    };
    hostname: string;
    /** The CNAME target behind the hostname; absent for a bridged lease too. */
    dns?: {
        target: string;
    };
    /** Present when the control plane can route this instance over the bridge. */
    bridge?: RelayBridgeGrant;
}
/** What one claim attempt resolved to. */
export type RelayClaimOutcome = {
    ok: true;
    claim: RelayClaim;
} | {
    ok: false;
    status: number;
    error: string;
    retryAfterMs?: number;
};
/** One claim request (the lease the caller wants refreshed). */
export interface RelayClaimRequest {
    id: string;
    secret: string;
    /** Carried only by a fresh identity: the first claim creates the row. */
    newSecret?: string;
    /** Local origin port the lease ingress points at (`ctx.webServer.port`). */
    port: number;
    /** The plugin version, for the adoption readout of the migration. */
    pluginVersion?: string;
}
/** The capped backoff a failed claim retries on. */
export declare const CLAIM_RETRY_BASE_MS = 5000;
export declare const CLAIM_RETRY_MAX_MS = 60000;
/** Build the claim body (an absent value is omitted, never sent as null). */
export declare function relayClaimBody(request: RelayClaimRequest): string;
/** One lease read back from an accepted claim, or undefined for a bad shape. */
export declare function relayClaimOf(value: unknown): RelayClaim | undefined;
/** The bridge grant of one accepted lease, or undefined when it carries none. */
export declare function relayBridgeGrantOf(value: unknown): RelayBridgeGrant | undefined;
/**
 * Claim one lease. A transport failure is graded like `502 cf-api-unavailable`
 * (status 0) so the caller retries on the same path as a refused upstream.
 * @param request - the lease to refresh.
 * @param options - endpoint and fetch seams (defaults are the real ones).
 */
export declare function claimRelayLease(request: RelayClaimRequest, options?: {
    url?: string;
    fetchFn?: typeof fetch;
}): Promise<RelayClaimOutcome>;
/**
 * Release one lease (the plugin's offline action: toggle off, profile
 * unmount). Best-effort — a release that never lands only leaves the row
 * marked active, which the 90-day GC recovers.
 */
export declare function releaseRelayLease(identity: RelayIdentity, options?: {
    url?: string;
    fetchFn?: typeof fetch;
}): Promise<void>;
/** How one failed claim should be retried. */
export interface RelayClaimRetry {
    /** Whether another attempt is worth making at all. */
    retry: boolean;
    /** How long to wait before that attempt. */
    delayMs: number;
    /**
     * Whether the identity must be re-claimed with `new_secret`: the control
     * plane lost the row (a D1 restore or a manual wipe), which is the one
     * condition a fresh claim fixes.
     */
    refreshIdentity: boolean;
}
/**
 * Grade one failed claim into a retry decision.
 *
 * `403 auth-failed` is terminal: the id belongs to another secret and no
 * number of retries can take it back. Everything else retries on a capped
 * exponential backoff, with the control plane's own `retryAfterMs` (a 502
 * names it) raising the floor so a retry cannot land inside a known outage.
 * @param outcome - the refused attempt.
 * @param attempt - how many attempts already failed (0 for the first).
 * @param options - backoff bounds (defaults are the shipped ones).
 */
export declare function relayClaimRetryOf(outcome: Extract<RelayClaimOutcome, {
    ok: false;
}>, attempt: number, options?: {
    baseDelayMs?: number;
    maxDelayMs?: number;
}): RelayClaimRetry;
//# sourceMappingURL=relay-control.d.ts.map