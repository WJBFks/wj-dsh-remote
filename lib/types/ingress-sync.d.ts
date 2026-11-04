/**
 * Update-only Cloudflare tunnel ingress sync (issue #1948).
 *
 * A named tunnel's public hostname is permanent — that is the whole point of
 * the mode — but the ingress rule behind it names a fixed local port. When
 * `dsh web` listens on another port (an operator changed `--port`, a profile
 * carries a different value, a second instance took the old one), the hostname
 * keeps resolving and answers 502 while this plugin still believes it is
 * published. This module converges exactly that one number and nothing else:
 *
 * - a read (GET) is the only request a healthy start makes;
 * - the plan proves the whole document except the matched rule's `service`
 *   string is unchanged, and refuses (a conflict) anything it cannot prove —
 *   no added or removed rule, no moved ingress entry, no touched top-level
 *   key, no invented catch-all;
 * - the service it retargets has to be this machine's own: loopback, or one of
 *   this host's LAN addresses. Another host's address is a conflict, never a
 *   write, because the port there belongs to whatever that address serves;
 * - only a proven drift is written, as one full-document PUT (the API offers
 *   no patch for a single rule);
 * - the write is read back once. A disagreement is a conflict, never an
 *   automatic rewrite: one tunnel document has one writer, and a deployment
 *   whose dashboard or another sync owns it has to be reconciled by a human.
 *
 * Everything is offline-testable: the HTTP call and the timers are injected
 * seams, and the default seam itself refuses to send the account token to any
 * origin but `https://api.cloudflare.com`. The token never enters a log line,
 * a status frame, a child process argument, or any browser-visible state — it
 * exists only inside the `Authorization` header of the two requests that need
 * it.
 */
/** The only origin the Cloudflare API token is ever sent to. */
export declare const CLOUDFLARE_API_ORIGIN = "https://api.cloudflare.com";
/** One JSON object as the API document holds it. */
export type JsonObject = Record<string, unknown>;
/**
 * The configurations endpoint of one tunnel. The account and tunnel ids are
 * opaque path segments, so they are encoded rather than interpolated raw.
 * @param accountId - the Cloudflare account id.
 * @param tunnelId - the named tunnel id (never the tunnel's token).
 * @returns the absolute API URL the sync reads and writes.
 */
export declare function ingressConfigUrl(accountId: string, tunnelId: string): string;
/**
 * The lower-cased hostname a configured public base names. Wildcards are not
 * supported by this sync (the target rule must match one exact hostname), so a
 * wildcard base is refused here rather than matched loosely later.
 * @param publicBaseUrl - the configured public base URL.
 * @returns the hostname to match in the ingress, or undefined when the value
 *   is missing, unparsable, not http(s), or a wildcard.
 */
export declare function hostnameOf(publicBaseUrl: string | undefined): string | undefined;
/**
 * Retarget one tunnel service string at a port, changing nothing else. The
 * authority's host (including an IPv6 literal and any userinfo), the path, the
 * query, and the fragment are preserved byte for byte, so the plan can prove
 * the only difference in the document is the port digits.
 * @param service - the rule's current service string (e.g. `http://127.0.0.1:3080`).
 * @param port - the port this host's web server actually bound.
 * @returns the retargeted service, or undefined when the value is not an
 *   http(s) origin this sync can safely rewrite.
 */
export declare function serviceWithPort(service: string, port: number): string | undefined;
/**
 * The authority host of one service string, with IPv6 brackets kept. The port
 * and any userinfo are dropped, so the host can be judged on its own.
 * @param service - the rule's service string.
 * @returns the host, or undefined when the value is not an http(s) origin.
 */
export declare function serviceHostOf(service: string): string | undefined;
/**
 * One service string with its userinfo removed, for everything that leaves
 * this process. A tunnel service may carry `user:password@`, and the
 * update-only write has to preserve that byte for byte — but an audit frame, a
 * log line, or the settings card has no business showing a credential the
 * operator put there for the origin.
 * @param service - the rule's service string.
 * @returns the same service with any `userinfo@` dropped.
 */
export declare function redactServiceUserinfo(service: string): string;
/**
 * Whether one service authority host is a target this host may own: a loopback
 * literal (any 127.0.0.0/8 address, `::1`, or `localhost`) or one of this
 * machine's own LAN IPv4 addresses. A service pointing anywhere else — another
 * machine, a DNS name, a NAS — is not this plugin's to retarget, and rewriting
 * its port would break whatever service that address actually is.
 * @param host - the authority host of the service (brackets kept for IPv6).
 * @param lanHosts - this machine's LAN IPv4 addresses.
 * @returns whether the service may be retargeted.
 */
export declare function isRetargetableHost(host: string, lanHosts?: readonly string[]): boolean;
/**
 * One document with the target rule's `service` string replaced by a marker.
 * Two documents whose stripped forms are identical differ at that one key and
 * nowhere else — which is the invariant the plan must prove before it writes.
 * @param document - the tunnel configuration document.
 * @param ruleIndex - the ingress rule the sync owns.
 * @returns the canonical JSON of the stripped document.
 */
export declare function withoutTargetService(document: unknown, ruleIndex: number): string;
/** Why a plan refuses to write. Every code is a zero-write verdict. */
export type IngressConflictCode = 'hostname' | 'config-shape' | 'ingress-shape' | 'rule-shape' | 'wildcard' | 'missing' | 'duplicate' | 'no-catch-all' | 'service-shape' | 'service-host';
/** What one document read asks the plan to converge on. */
export interface IngressTarget {
    /** The lower-cased public hostname of the named tunnel. */
    hostname: string;
    /** The port this host's web server actually bound. */
    port: number;
    /**
     * The LAN IPv4 addresses this machine owns (`lanIPv4Addresses()`). The plan
     * refuses a service that points anywhere but loopback or one of these, so an
     * update-only write can never retarget a service that belongs to another host.
     */
    allowedHosts?: readonly string[];
}
/** The verdict of one plan: read-only, one write, or a refusal. */
export type IngressPlan = {
    outcome: 'unchanged';
    hostname: string;
    ruleIndex: number;
    ruleCount: number;
    service: string;
} | {
    outcome: 'apply';
    hostname: string;
    ruleIndex: number;
    ruleCount: number;
    from: string;
    to: string;
    /** The full document to PUT: identical to the read document except one service. */
    document: JsonObject;
} | {
    outcome: 'conflict';
    code: IngressConflictCode;
    hostname: string;
    detail: string;
};
/**
 * Plan one update-only ingress change against a document read from the API.
 *
 * The supported shape is a Cloudflare tunnel configuration: an object whose
 * `ingress` is an array of rule objects, exactly one of which carries the
 * target hostname, and whose last rule is a catch-all (no `hostname`). A
 * document outside that shape — a missing `ingress`, a wildcard anywhere, a
 * duplicated hostname, no catch-all, a rule that is not an object, a service
 * that is not an http(s) origin, or a service whose host is not this machine —
 * is a conflict and produces no document, so the caller cannot accidentally
 * write. The two service strings the verdict reports are redacted of userinfo:
 * they are audit facts, and the write itself is carried by the document.
 * @param config - the `result.config` document read from the API.
 * @param target - the hostname, the port, and this machine's own addresses.
 * @returns unchanged (one read is enough), apply (the document to PUT), or a
 *   conflict with the reason.
 */
export declare function planIngressUpdate(config: unknown, target: IngressTarget): IngressPlan;
/**
 * Read the tunnel configuration out of one API envelope. The API answers
 * `{ success, result: { config: {...} }, errors }`; a body that shapes
 * differently is reported, never guessed at.
 * @param body - the parsed response body.
 * @returns the config document, or undefined when the envelope carries none.
 */
export declare function configOfEnvelope(body: unknown): JsonObject | undefined;
/**
 * The API's own error messages from one envelope, joined for the audit frame.
 * Cloudflare answers 4xx/5xx with a populated `errors` array; the messages are
 * safe to show (they name the credential's missing permission, never its value).
 * @param body - the parsed response body.
 * @returns a short joined summary, or undefined when the envelope carries none.
 */
export declare function errorsOfEnvelope(body: unknown): string | undefined;
/** One HTTP call the sync makes. */
export interface IngressHttpRequest {
    method: 'GET' | 'PUT';
    url: string;
    headers: Record<string, string>;
    body?: string;
}
/** One HTTP answer the sync reads. */
export interface IngressHttpResponse {
    status: number;
    /** The parsed JSON body (or the raw text when it was not JSON). */
    body: unknown;
}
/** The injected HTTP seam: tests never reach a real API through it. */
export type IngressFetch = (request: IngressHttpRequest) => Promise<IngressHttpResponse>;
/**
 * The default seam: one `fetch` round trip, and a hard refusal to send the
 * account token outside the Cloudflare API even if a caller builds such a URL.
 * @param request - the call to make.
 * @returns the status and parsed body.
 */
export declare const defaultIngressFetch: IngressFetch;
/** Timer seam (injected in tests; a synchronous double makes a run immediate). */
export interface IngressTimer {
    setTimeout(fn: () => void, ms: number): unknown;
    clearTimeout(handle: unknown): void;
}
/** The observable state one sync reports. */
export type IngressSyncState = 'off' | 'waiting' | 'applied' | 'failed' | 'conflict';
/**
 * One audit frame. It carries the public hostname, the local port, the two
 * service strings, the rule position, and a failure reason — never the token,
 * never the credential's account id, and never a response body.
 */
export interface IngressSyncFrame {
    state: IngressSyncState;
    /** The public hostname read from `publicBaseUrl`. */
    hostname?: string;
    /** The port this host's web server actually bound. */
    port?: number;
    /** The service string the remote rule holds after the last run. */
    service?: string;
    /** The service string an apply moved away from. */
    previousService?: string;
    /** How many ingress rules the read document carried. */
    ruleCount?: number;
    /** Index of the rule this sync owns. */
    ruleIndex?: number;
    /** Whether the last run actually wrote the document. */
    changed?: boolean;
    /** Machine-readable reason of a failed or conflict frame. */
    code?: string;
    /** Human-readable detail (hostname, port, status, API message) — no secret. */
    detail?: string;
    /** When this state was reached (ms epoch). */
    at: number;
}
/** What one {@link IngressSync.schedule} call asks the runner to converge on. */
export interface IngressSyncInput {
    /** The master switch AND the ingress toggle; false makes no request at all. */
    enabled: boolean;
    /** The lower-cased public hostname (`hostnameOf(publicBaseUrl)`). */
    hostname: string | undefined;
    /** The bound web server port; undefined before the listener binds. */
    port: number | undefined;
    /** Account-level API token (secret; only ever in the Authorization header). */
    token: string | undefined;
    /** Cloudflare account id. */
    accountId: string | undefined;
    /** Named tunnel id. */
    tunnelId: string | undefined;
}
/** Injectable seams and timings. */
export interface IngressSyncOptions {
    /** HTTP seam; defaults to the guarded real `fetch`. */
    fetch?: IngressFetch;
    /** Clock (injected in tests). */
    now?: () => number;
    /** Short debounce before a scheduled run starts (ms). */
    debounceMs?: number;
    /** First backoff step of a transient failure (ms; doubles per retry). */
    retryBaseMs?: number;
    /** Retries after the first attempt; bounded for the whole run. */
    maxRetries?: number;
    /** Timer seam (injected in tests). */
    timer?: IngressTimer;
    /**
     * This machine's LAN IPv4 addresses (injected in tests; the live list by
     * default). The plan refuses to retarget a service hosted anywhere else.
     */
    lanHosts?: () => readonly string[];
    /** Frame sink (the host writes it into the pairing snapshot). */
    onFrame?: (frame: IngressSyncFrame) => void;
}
/** Debounce before a scheduled run: a port settle and a settings save coalesce. */
export declare const DEFAULT_INGRESS_DEBOUNCE_MS = 300;
/** First backoff step of a retried request. */
export declare const DEFAULT_INGRESS_RETRY_BASE_MS = 500;
/** Retries after the first attempt of one request (so three attempts at most). */
export declare const DEFAULT_INGRESS_MAX_RETRIES = 2;
/**
 * Two audit frames that describe the same state (the timestamp is not part of
 * it). The pairing snapshot dedupe uses this, so a re-read that proves the same
 * convergence never emits a second event.
 * @param a - one frame.
 * @param b - the other frame.
 * @returns whether both describe the same state.
 */
export declare function sameIngressFrame(a: IngressSyncFrame, b: IngressSyncFrame): boolean;
/** The resolved plugin settings this adapter reads (nothing else is consulted). */
export interface IngressSettingsSlice {
    /** The plugin master switch. */
    enabled: boolean;
    /** The ingress-sync switch. */
    ingressSync?: boolean;
    /** Whether the quick tunnel runs (it owns the public base and mints its own hostname). */
    autoTunnel?: boolean;
    /** The fixed public hostname of the named tunnel. */
    publicBaseUrl?: string;
    /** Account-level API token (a settings secret). */
    cfApiToken?: string;
    /** Cloudflare account id. */
    cfAccountId?: string;
    /** Named tunnel id. */
    cfTunnelId?: string;
}
/**
 * Normalize one web server port into a target or into nothing. A recompose pass
 * can hand the plugin a half-read webServer whose port is `NaN` or
 * `Infinity`; that is not a port, and treating it as one would either mint a
 * `127.0.0.1:NaN` target or leave the caller waiting forever. The host reads
 * the port through this, so a non-finite value takes exactly the path an
 * unbound one does: the existing port-settle retry re-plans it.
 * @param port - the live `ctx.webServer.port`.
 * @returns the port, or undefined when it is not a finite number.
 */
export declare function livePortOf(port: number | undefined): number | undefined;
/**
 * The one place resolved settings become a sync input, so "which switch turns
 * this on" is testable without a cordis context. Three conditions, all
 * required: the master switch, the ingress toggle, and the quick tunnel being
 * off — a quick tunnel mints a new hostname per start and owns the public base,
 * so that deployment has no named tunnel to update and the sync reads as off
 * instead of editing an unrelated tunnel.
 * @param value - the resolved settings.
 * @param port - the bound web server port, undefined before the listener binds.
 * @returns the input to schedule.
 */
export declare function ingressInputOf(value: IngressSettingsSlice, port: number | undefined): IngressSyncInput;
/**
 * Converge one named tunnel's ingress service onto this host's actual port.
 *
 * Scheduling is single-flight and generation-guarded: a later schedule (a
 * settings save, a port settle) supersedes an in-flight run at its next
 * checkpoint — before every request attempt, so a running backoff cannot
 * outlive its target, and again immediately before the single PUT. Ports
 * arrive late, and a half-read webServer can hand a non-finite number: neither
 * one schedules anything, so no request is made and the caller's existing
 * port-settle re-plan delivers the real port.
 */
export declare class IngressSync {
    private readonly http;
    private readonly now;
    private readonly debounceMs;
    private readonly retryBaseMs;
    private readonly maxRetries;
    private readonly timer;
    private readonly onFrame;
    private readonly lanHosts;
    private current;
    private input;
    private generation;
    private pending;
    private debounce;
    /** The serialized run chain: one run at a time, queued schedules after it. */
    private chain;
    /** Whether the chain currently holds a live run (a later schedule only queues). */
    private running;
    /** Whether the sink has been told about a state yet (the first one always goes out). */
    private emitted;
    /** The `hostname|port|account|tunnel|token-digest` a read last proved converged. */
    private settledKey;
    /** Backoff waits in flight, so a dispose can cut them short. */
    private readonly waits;
    private disposed;
    /**
     * @param options - seams, timings, and the frame sink.
     */
    constructor(options?: IngressSyncOptions);
    /** The latest audit frame. */
    get frame(): IngressSyncFrame;
    /**
     * Ask the sync to converge on one input. Safe to call on every settings save
     * and every port settle: an already-converged target is a no-op, and an
     * unchanged schedule does not repeat its frame.
     * @param input - the switch, the target, and the credentials to use.
     */
    schedule(input: IngressSyncInput): void;
    /**
     * Await every run scheduled so far. A test seam: the host never awaits it,
     * and a synchronous timer double makes the whole chain settle immediately.
     * @returns the settled run chain.
     */
    settled(): Promise<void>;
    /** Release the timers; an in-flight run finishes its checkpoints as no-ops. */
    dispose(): void;
    /**
     * Drop every claim this sync holds on a target: a newer generation (so an
     * in-flight run cannot write, settle, or report an applied frame), no queued
     * run, no converged identity, no pending debounce. Every branch of
     * {@link schedule} that ends up without a target calls this, so "there is
     * nothing to converge on" and "the switch is off" are one rule rather than
     * four that can drift apart.
     */
    private invalidate;
    private armDebounce;
    private cancelDebounce;
    /**
     * Append one run to the serialized chain. The `running` flag is raised before
     * the link starts, so a schedule that lands while a run is in flight only
     * raises `pending` and the live loop picks it up with the newest generation
     * instead of stacking a second link that would read again after it settled.
     */
    private pump;
    /** One converge attempt toward the current target, superseded by any newer schedule. */
    private run;
    /** Record the converged target identity and publish the frame that says so. */
    private converged;
    /**
     * Publish one frame, dropping a repeat that describes the same state. The
     * first publish always goes out, so a sink that starts from nothing learns
     * the current state even when it is the initial `off`.
     */
    private publish;
    /**
     * One request with the bounded retry policy: 429, 5xx, and a network failure
     * are retried at most {@link DEFAULT_INGRESS_MAX_RETRIES} times; 401/403 and
     * any other 4xx are terminal, because repeating them cannot help.
     *
     * The run's generation is part of the request: it is checked before every
     * attempt, retries included, so a target superseded while a 429/5xx/network
     * backoff was running stops there instead of writing a document for a port
     * this host no longer serves. The answer is `stale` (or `disposed`) and the
     * caller drops it without publishing.
     */
    private send;
    /**
     * Wait one backoff step on the injected timer. The wait is tracked so a
     * dispose can release it at once: the interrupted run then wakes, sees the
     * dispose at its next attempt check, and stops instead of sleeping out a
     * backoff nobody is waiting for.
     * @param ms - how long the step lasts.
     * @returns a promise that settles when the step ends or is cancelled.
     */
    private wait;
    /** Release every pending backoff wait (dispose); the interrupted run aborts. */
    private cancelWaits;
}
//# sourceMappingURL=ingress-sync.d.ts.map