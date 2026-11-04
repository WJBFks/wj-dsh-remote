/**
 * The `api/gate` listener: application-level access control layered on top
 * of the transport fence (the fence is Host/Origin based and explicitly not
 * an authentication layer — packages/client/connection documents this
 * event as the sanctioned seam for pairing/revocation).
 *
 * Policy: loopback requests (the desktop) pass without a device identity;
 * every non-loopback /api request must carry a live, non-revoked device
 * cookie — intended to make the QR the only way into a LAN-exposed dsh web
 * and to give "停止" real teeth for direct /api callers.
 *
 * Cohort reality (0.1.2-alpha.2): NOTHING emits api/gate in the official
 * runtime, so this listener never fires there and direct /api is governed
 * solely by the harness fence + browser-auth cookie. The pairing gate with
 * real teeth lives on the plugin's own /remote channel (remote-api.ts); the
 * listener stays wired for cohort lines that do carry the seam, and the
 * README security model states the gap plainly.
 */
import type { IncomingMessage } from 'node:http';
import type { PairingService } from './pairing.ts';
/**
 * Read one cookie value from a Cookie header.
 * @param header - the raw Cookie header value (or undefined).
 * @param name - the cookie name.
 * @returns the value, or undefined when absent.
 */
export declare function readCookie(header: string | undefined, name: string): string | undefined;
/**
 * The effective Host hostname of a request.
 * @param request - node HTTP request.
 * @returns the normalized hostname, or undefined when unparsable.
 */
export declare function hostnameOf(request: IncomingMessage): string | undefined;
/**
 * Whether the request arrived at this process over a loopback upstream: a
 * loopback socket and a loopback Host header, with the forwarding headers
 * deliberately ignored. A reverse proxy (a Cloudflare tunnel, frp, nginx) dials
 * 127.0.0.1:<port> and rewrites the Host to that upstream literal, so this is
 * the shape of a tunneled request as much as of the desktop one.
 *
 * It answers "this process is reachable at a loopback authority", never "this
 * request is the desktop": the desktop decision is {@link isLoopbackClient},
 * which a forwarded request never satisfies. Only the fences that decide whether
 * a Host is answerable at all (the pairing status view, the reachability beacon,
 * the pairing entry pages) may be built on this predicate; every decision that
 * hands out a credential or the desktop payload stays on {@link isLoopbackClient}
 * (issue #1919 keeps #1906 shut: reachability for the visitor, payload and
 * control plane for the desktop).
 * @param request - node HTTP request.
 * @returns true when the socket and the Host both name loopback.
 */
export declare function isLoopbackUpstream(request: IncomingMessage): boolean;
/**
 * Whether a request comes from the desktop loopback client: a loopback upstream
 * ({@link isLoopbackUpstream}) reached with no forwarding header. This is the
 * same decision the shared copy makes in `isLoopbackRequest` (sans the browser
 * same-origin markers, which the /api/wj-pair routes apply separately through
 * `isTrustedApiRequest`), and it carries the same proxy rule: a reverse proxy
 * rewrites the Host to its own 127.0.0.1:<port> upstream and connects over
 * loopback, so a request that arrives with CF-Connecting-IP or X-Forwarded-For
 * is a forwarded one and is never the desktop (issue #1906). Every decision
 * that grants the desktop payload or a control plane (the api/gate listener,
 * the events stream, /api/wj-pair/issue, /api/wj-pair/stop, /api/wj-pair/revoke,
 * /api/wj-pair/lan-bind) reads this predicate, so the rule holds for all of them.
 * @param request - node HTTP request.
 * @returns true for a local desktop request with no proxy in front of it.
 */
export declare function isLoopbackClient(request: IncomingMessage): boolean;
/**
 * Build the api/gate listener for one pairing service.
 * @param service - the pairing service.
 * @param requirePairingForLan - when false, non-loopback requests pass
 * without a device cookie (the feature then only manages tokens/status;
 * revocation of paired devices still holds). A function is re-read per
 * request, so a settings edit takes effect without a restart. Defaults to true.
 * @param enabled - when false, every non-loopback request is vetoed while
 * loopback stays available. A function is re-read per request so the fence
 * stays mounted for the plugin lifetime and disabling the plugin cannot open
 * a LAN-exposed /api. Defaults to true.
 * @returns the cordis waterfall listener: call `next()` to delegate,
 * return false (without calling it) to veto with 403.
 */
export declare function makeGateListener(service: PairingService, requirePairingForLan?: boolean | (() => boolean), enabled?: boolean | (() => boolean)): (request: IncomingMessage, method: string | undefined, next: () => boolean | Promise<boolean>) => boolean | Promise<boolean>;
/**
 * Whether a request carries a live, non-revoked paired-device cookie for
 * this service. Sibling host routes outside /api (the right-panel
 * /sidebar/* routes, etc.) use the same check via the remoteWebUiPairing service.
 * @param service - the pairing service that owns the device table.
 * @param request - the incoming HTTP request.
 * @returns true when the cookie names a live session (and lastSeenAt was refreshed).
 */
export declare function isPairedDeviceRequest(service: PairingService, request: IncomingMessage): boolean;
//# sourceMappingURL=gate.d.ts.map