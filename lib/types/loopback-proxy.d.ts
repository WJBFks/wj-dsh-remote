/**
 * Loopback-shaped reverse proxy used by the remote desktop channel: after
 * the pairing cookie gate, traffic is re-issued to 127.0.0.1 so sibling
 * plugin fences (socket + Host loopback) accept it. Origin, cookies, and
 * caller-controlled Sec-Fetch markers are dropped, and HTTP requests receive
 * a synthetic same-origin marker so sibling loopback routes that require a
 * browser tripwire accept the authenticated proxy.
 *
 * Every other request header is forwarded unchanged, because a plugin may
 * authenticate its own calls with a header of its own: an allowlist here
 * silently dropped those markers and made the plugin refuse every remote
 * write request (issue #1925).
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type { InnerAuth } from './inner-auth.ts';
/**
 * Pipe one HTTP request to loopback and stream the response back.
 * @param req - the already-gated outer request.
 * @param res - the outer response.
 * @param port - local webServer port.
 * @param upstreamPath - path + query on 127.0.0.1 (must start with `/`).
 * @param auth - when given, the process's inner browser-auth credential is
 *   attached so the connection plugin's /api route (fence + browser auth,
 *   authority-bound cookie, no loopback exemption on this cohort) accepts
 *   the re-issued request; a 401 answer invalidates the cached credential.
 */
export declare function proxyLoopbackHttp(req: IncomingMessage, res: ServerResponse, port: number, upstreamPath: string, auth?: InnerAuth): void;
/**
 * Rebuild a WebSocket handshake as loopback-shaped and pipe both directions.
 * @param req - the already-gated upgrade request.
 * @param socket - the client duplex.
 * @param head - bytes already read past the handshake.
 * @param port - local webServer port.
 * @param upstreamPath - path + query on 127.0.0.1.
 * @param cookie - the inner browser-auth credential for the handshake, when
 *   the upstream route enforces it (the gateway event-stream mux does).
 */
export declare function proxyLoopbackUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, port: number, upstreamPath: string, cookie?: string): void;
//# sourceMappingURL=loopback-proxy.d.ts.map