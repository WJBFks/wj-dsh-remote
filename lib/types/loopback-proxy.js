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
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { writeJson } from "./http.js";
/** WebSocket handshake headers forwarded to the loopback upstream. */
const WS_FORWARD_HEADERS = [
    'sec-websocket-key',
    'sec-websocket-version',
    'sec-websocket-extensions',
    'sec-websocket-protocol',
];
/**
 * Request headers the re-issue never carries: hop-by-hop headers (RFC 9110
 * 7.6.1), the ones this proxy owns or rewrites, the forwarding marks of a hop
 * that stood in between, and the browser fetch metadata that describes the
 * caller's own request. Everything else is passed through, so a plugin that
 * authenticates its calls with a header of its own keeps working behind the
 * pairing gate (issue #1925).
 *
 * The forwarding marks (x-forwarded-*, cf-connecting-ip, forwarded) must not
 * ride along: the re-issued request is a loopback one, and an edge stamp would
 * make the local fences classify it as remote and refuse every route
 * (shared/host/loopback.ts owns that rule). x-wj-remote-device is the
 * caller's own live device credential: the channel consumes it at its gate and
 * never hands it further, the same way the WS query parameter is stripped.
 * accept-encoding, range and if-range stay out because the response headers
 * copied below carry neither content-encoding nor content-range, so an invited
 * compressed or partial body could never be described to the caller.
 */
const REQUEST_HEADER_DENYLIST = new Set([
    // hop-by-hop
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'expect',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    // rewritten by this proxy: the loopback authority and the tripwire marker
    'host',
    'sec-fetch-site',
    // the caller's own origin, its cookie jar, and the credential the gate consumed
    'origin',
    'referer',
    'cookie',
    'x-wj-remote-device',
    // forwarding marks: a re-issued request is loopback, not forwarded
    'forwarded',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-forwarded-proto',
    'x-real-ip',
    'cf-connecting-ip',
    // response shaping (see the doc comment above): these ask the upstream for a
    // body the copied response headers cannot describe
    'accept-encoding',
    'range',
    'if-range',
]);
/**
 * Prefixes the re-issue never carries: the browser fetch metadata
 * (sec-fetch-*, sec-ch-*) describes the outer request, not this one.
 */
const REQUEST_HEADER_DENY_PREFIXES = ['sec-'];
/**
 * Header names the caller nominated as hop-by-hop through its own Connection
 * header (RFC 9110 7.6.1): whatever it names stops at this proxy too.
 * @param connection - the outer request Connection header value.
 * @returns the nominated names, lowercased.
 */
function nominatedHeaders(connection) {
    const nominated = new Set();
    if (connection === undefined)
        return nominated;
    for (const value of Array.isArray(connection) ? connection : [connection]) {
        for (const token of value.split(',')) {
            const name = token.trim().toLowerCase();
            if (name !== '')
                nominated.add(name);
        }
    }
    return nominated;
}
/**
 * Headers of the loopback re-issue: the caller headers minus the ones the
 * channel owns, plus the rewritten authority, the synthetic same-origin
 * tripwire, and the inner credential that replaces the caller cookie.
 * @param req - the already-gated outer request.
 * @param port - local webServer port.
 * @param cookie - the inner credential, when one resolved.
 * @returns headers to send to 127.0.0.1.
 */
function forwardedRequestHeaders(req, port, cookie) {
    const nominated = nominatedHeaders(req.headers.connection);
    const headers = {};
    for (let index = 0; index + 1 < req.rawHeaders.length; index += 2) {
        const name = req.rawHeaders[index].toLowerCase();
        if (REQUEST_HEADER_DENYLIST.has(name) || nominated.has(name))
            continue;
        if (REQUEST_HEADER_DENY_PREFIXES.some(prefix => name.startsWith(prefix)))
            continue;
        const value = req.rawHeaders[index + 1];
        const previous = headers[name];
        // Repeated headers reach the upstream as one comma-joined value, the same
        // way node folds duplicates on the receiving side.
        headers[name] = previous === undefined ? value : `${previous}, ${value}`;
    }
    headers.host = `127.0.0.1:${String(port)}`;
    headers['sec-fetch-site'] = 'same-origin';
    if (cookie !== undefined)
        headers.cookie = cookie;
    return headers;
}
/** Response headers copied from the loopback upstream (no hop-by-hop). */
const HTTP_FORWARD_RESPONSE_HEADERS = [
    'content-type',
    'content-length',
    'content-disposition',
    'cache-control',
    'etag',
    'last-modified',
];
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
export function proxyLoopbackHttp(req, res, port, upstreamPath, auth) {
    void Promise.resolve(auth?.ready())
        .catch(() => undefined)
        .then((cookie) => { pipeLoopbackHttp(req, res, port, upstreamPath, auth, typeof cookie === 'string' ? cookie : undefined); });
}
function pipeLoopbackHttp(req, res, port, upstreamPath, auth, cookie) {
    const headers = forwardedRequestHeaders(req, port, cookie);
    const upstream = httpRequest({
        host: '127.0.0.1',
        port,
        path: upstreamPath,
        method: req.method,
        headers,
    }, (upstreamRes) => {
        // The cached credential went stale (secret rotation, credential store
        // reset): drop it so the next request re-redeems. The in-flight response
        // still pipes through untouched.
        if (upstreamRes.statusCode === 401 && cookie !== undefined)
            auth?.invalidate();
        const out = {};
        for (const name of HTTP_FORWARD_RESPONSE_HEADERS) {
            const value = upstreamRes.headers[name];
            if (value !== undefined)
                out[name] = value;
        }
        res.writeHead(upstreamRes.statusCode ?? 502, out);
        upstreamRes.pipe(res);
        // Inner leg died mid-response (reset, truncation): tear the outer leg
        // down instead of letting the truncated response raise an unhandled
        // 'error' with no listener.
        upstreamRes.on('error', () => { res.destroy(); });
        // Outer leg died before the response finished (phone left mid-request):
        // reset the inner request so the loopback server stops working on a call
        // nobody will read. Guarded so a normal completion never destroys a
        // keep-alive socket the agent would reuse.
        res.on('close', () => {
            if (!upstreamRes.readableEnded)
                upstream.destroy();
        });
    });
    upstream.on('error', () => {
        if (!res.headersSent) {
            writeJson(res, 502, { ok: false, error: { code: 'upstream-failure', message: 'upstream request failed' } });
            return;
        }
        res.destroy();
    });
    // The outer request aborted mid-body: reset the inner request instead of
    // feeding it a truncated body that still gets processed (mirror of the
    // upgrade path's two-leg teardown).
    req.on('error', () => { upstream.destroy(); });
    req.pipe(upstream);
}
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
export function proxyLoopbackUpgrade(req, socket, head, port, upstreamPath, cookie) {
    const lines = [
        `GET ${upstreamPath} HTTP/1.1`,
        `Host: 127.0.0.1:${String(port)}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
    ];
    if (cookie !== undefined)
        lines.push(`Cookie: ${cookie}`);
    for (const name of WS_FORWARD_HEADERS) {
        const value = req.headers[name];
        if (value === undefined)
            continue;
        lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
    }
    const handshake = `${lines.join('\r\n')}\r\n\r\n`;
    const upstream = connect(port, '127.0.0.1');
    socket.setKeepAlive(true, 20_000);
    upstream.setKeepAlive(true, 20_000);
    const tearDown = () => {
        upstream.destroy();
        socket.destroy();
    };
    upstream.on('error', tearDown);
    socket.on('error', tearDown);
    upstream.on('close', () => { socket.destroy(); });
    socket.on('close', () => { upstream.destroy(); });
    upstream.on('connect', () => {
        upstream.write(handshake);
        if (head.length > 0)
            upstream.write(head);
        socket.pipe(upstream);
        upstream.pipe(socket);
    });
}
