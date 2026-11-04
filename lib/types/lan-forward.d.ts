/**
 * The LAN edge the lan-bind toggle owns (issue #1917).
 *
 * The toggle used to pin the LAN address into the profile's webserver row. That
 * row is the only place the harness takes its bind from, and rewriting it
 *   - replaced the official row's whole config (so the row's own
 *     `host: !!js ctx.webStartup.host ?? '127.0.0.1'` expression and the CLI
 *     `--host`/`--port` never reached it), and
 *   - the profile patch is watched by the Host's HMR config watcher, so the
 *     write recomposed the running process and rebound the live listener.
 *
 * This module keeps the host bound to loopback and gives LAN clients their own
 * listener: a forwarder on the machine's LAN address, on the same port, that
 * re-issues every request (HTTP and WebSocket upgrade alike) to
 * `127.0.0.1:<port>`. Two consequences are load-bearing:
 *
 * 1. The upstream leg is loopback, so the socket alone would read as "the
 *    desktop". The forwarder therefore DROPS whatever Host the client sent and
 *    stamps the LAN authority it was reached at, plus `X-Forwarded-For`. Every
 *    fence that decides "is this the desktop" (`isLoopbackClient`, the pairing
 *    gate, the `/wj-remote` gate) then keeps refusing the forwarded request, while
 *    the phone-facing fences still match the LAN authority the QR advertises.
 * 2. A bind that cannot be taken (address gone after a network change, port
 *    taken) only loses the LAN edge: the loopback listener is never touched, so
 *    the host cannot be bricked and the failure is reported on the status
 *    frame.
 *
 * Nothing here writes a file: the forwarder is runtime state, so a network
 * change needs no profile edit and no restart.
 *
 * @module wj-dsh-remote/lan-forward
 */
import { type IncomingMessage } from 'node:http';
/** The upstream the forwarder re-issues to: the process's own loopback listener. */
export declare const FORWARD_UPSTREAM_HOST = "127.0.0.1";
/** What the forwarder is doing right now, for the status frame and the logs. */
export interface LanForwardState {
    /** Whether the LAN listener is bound. */
    listening: boolean;
    /** The LAN address it listens on (undefined when it never bound). */
    address: string | undefined;
    /** The port it listens on (the web server's own port). */
    port: number | undefined;
    /** The loopback port it re-issues to. */
    upstreamPort: number | undefined;
    /** Why the last bind attempt failed, when it did. */
    error: string | undefined;
}
/** The idle state: nothing bound, nothing failed. */
export declare const IDLE_FORWARD_STATE: LanForwardState;
/**
 * The `Host` authority a listener at `address:port` is reached at. IPv6
 * literals are bracketed like any URL authority.
 * @param address - the listen address (a literal).
 * @param port - the listen port.
 * @returns the authority text a request to that listener carries.
 */
export declare function authorityOf(address: string, port: number): string;
/**
 * The headers the loopback leg carries for one request: the client's own
 * headers minus the hop-by-hop and forwarder-owned ones, plus the LAN authority
 * the client actually reached and its address.
 * @param request - the request as it arrived on the LAN listener.
 * @param authority - the LAN authority the forwarder listens at.
 * @param clientAddress - the client's socket address, when readable.
 * @returns the headers for the loopback request.
 */
export declare function forwardedHeaders(request: IncomingMessage, authority: string, clientAddress: string | undefined): Record<string, string>;
/**
 * Rebuild a WebSocket handshake for the loopback leg. The client's own headers
 * travel through verbatim (so `Sec-WebSocket-*` and any application protocol
 * survive) except the ones the forwarder owns.
 * @param request - the upgrade request as it arrived on the LAN listener.
 * @param authority - the LAN authority the forwarder listens at.
 * @param clientAddress - the client's socket address, when readable.
 * @returns the handshake request head to write on the loopback leg.
 */
export declare function forwardedHandshake(request: IncomingMessage, authority: string, clientAddress: string | undefined): string;
/** One listener, its live connections, and its last bind outcome. */
export declare class LanForwarder {
    private server;
    private config;
    private state;
    /** Every socket this forwarder opened on either leg. */
    private readonly sockets;
    /** Every in-flight loopback request, so a teardown cannot leave one running. */
    private readonly upstreams;
    /** What the forwarder is doing right now. */
    snapshot(): LanForwardState;
    /**
     * Bind the LAN listener, or report why it could not be bound.
     *
     * Never throws: a bind failure is the ordinary outcome after a network change
     * (the address is gone) or a port collision, and the loopback listener must
     * keep serving regardless.
     * @param address - the LAN address to listen on.
     * @param port - the port to listen on (the web server's own port).
     * @param upstreamPort - the loopback port to re-issue to; defaults to `port`.
     * @returns the settled state.
     */
    start(address: string, port: number, upstreamPort?: number): Promise<LanForwardState>;
    private bind;
    /**
     * Close the LAN listener and every connection it opened, then resolve once the
     * port is released. Safe to call when nothing is bound.
     */
    stop(): Promise<void>;
    private releaseSockets;
    private trackUpstream;
    private forwardHttp;
    private forwardUpgrade;
}
//# sourceMappingURL=lan-forward.d.ts.map