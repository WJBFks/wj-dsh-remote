/**
 * Browser-side wire helpers for the /api/wj-pair surface. Plain fetch over
 * same-origin /api (like the connection client); JSON bodies, string
 * responses for the error codes.
 *
 * The paths are DOCUMENT-RELATIVE (issue #1707): the GUI is served with
 * `<base href="./">`, so a sub-path deployment resolves them against its entry
 * directory instead of escaping to the origin root.
 */
/** Read the host-authoritative desktop pairing policy. */
export async function readPairGatePolicy() {
    const response = await fetch('api/pair/status');
    if (!response.ok)
        throw new Error(`wj-dsh-remote: status failed with ${String(response.status)}`);
    const value = await response.json();
    if (typeof value.requirePairingForLan !== 'boolean') {
        throw new Error('wj-dsh-remote: status omitted requirePairingForLan');
    }
    return { requirePairingForLan: value.requirePairingForLan };
}
/** A non-empty wire string, or undefined. */
function wireString(value) {
    return typeof value === 'string' && value !== '' ? value : undefined;
}
/** A finite wire number, or undefined. */
function wireNumber(value) {
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}
/**
 * Read the ingress-sync frame off the pairing status view. The status route
 * carries this block only to a desktop (loopback) caller or a live paired
 * device, so another origin reads nothing here and the card renders no line.
 * @returns the frame, or undefined when the view carries none (or is unreadable).
 */
export async function readIngressStatus() {
    const response = await fetch('api/pair/status');
    if (!response.ok)
        return undefined;
    const value = await response.json();
    const raw = value.ingress;
    if (typeof raw !== 'object' || raw === null)
        return undefined;
    const frame = raw;
    const state = frame.state;
    if (state !== 'off' && state !== 'waiting' && state !== 'applied' && state !== 'failed' && state !== 'conflict')
        return undefined;
    return {
        state,
        hostname: wireString(frame.hostname),
        port: wireNumber(frame.port),
        service: wireString(frame.service),
        previousService: wireString(frame.previousService),
        ruleCount: wireNumber(frame.ruleCount),
        ruleIndex: wireNumber(frame.ruleIndex),
        changed: typeof frame.changed === 'boolean' ? frame.changed : undefined,
        code: wireString(frame.code),
        detail: wireString(frame.detail),
        at: wireNumber(frame.at),
    };
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
export async function issuePair(address) {
    const response = await fetch('api/pair/issue', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
            ...(address !== undefined ? { address } : {}),
        }),
    });
    if (!response.ok) {
        if (response.status === 409)
            return { ok: false, code: 'lan-required' };
        if (response.status === 403)
            return { ok: false, code: 'forbidden' };
        if (response.status === 400)
            return { ok: false, code: 'unknown-address' };
        throw new Error(`wj-dsh-remote: issue failed with ${String(response.status)}`);
    }
    return await response.json();
}
/**
 * Accept a pairing token (the phone's first open of the QR link). Success
 * sets the device cookie; the page then reloads to boot with it.
 * @param token - the token from the URL.
 * @returns the wire result.
 */
export async function acceptPair(token) {
    const response = await fetch('api/pair/accept', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token }),
    });
    if (response.ok)
        return { ok: true };
    // 409 is the legacy "already used" answer a pre-bearer-token host could send;
    // it means the same thing to the caller as a 404.
    if (response.status === 404 || response.status === 409)
        return { ok: false, code: 'invalid' };
    return { ok: false, code: 'forbidden' };
}
/** Revoke mobile access (paired devices + the current token). */
export async function stopPair() {
    const response = await fetch('api/pair/stop', { method: 'POST' });
    if (!response.ok)
        throw new Error(`wj-dsh-remote: stop failed with ${String(response.status)}`);
}
/**
 * Revoke one paired device from the loopback panel.
 * @param deviceId - the session id of the row to drop.
 */
export async function revokePair(deviceId) {
    const response = await fetch('api/pair/revoke', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ deviceId }),
    });
    if (response.status === 404)
        return;
    if (!response.ok)
        throw new Error(`wj-dsh-remote: revoke failed with ${String(response.status)}`);
}
/**
 * Set or clear one device's panel label. An empty name clears it and restores
 * the User-Agent-derived fallback.
 * @param deviceId - the session id of the row to rename.
 * @param name - the new label ('' clears it).
 * @returns true when the host stored the label; false for an unknown row.
 */
export async function renamePair(deviceId, name) {
    const response = await fetch('api/pair/rename', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ deviceId, name }),
    });
    if (response.status === 404)
        return false;
    if (!response.ok)
        throw new Error(`wj-dsh-remote: rename failed with ${String(response.status)}`);
    return true;
}
/**
 * Collapse duplicate pairing rows the operator grouped as one device. The host
 * keeps the most recently active row and revokes the rest.
 * @param deviceIds - the grouped session ids (two or more).
 * @returns the surviving device id, or undefined when the host refused the
 *   group (unknown row, or not one User-Agent).
 */
export async function mergePairDevices(deviceIds) {
    const response = await fetch('api/pair/merge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ deviceIds }),
    });
    if (response.status === 404 || response.status === 409)
        return undefined;
    if (!response.ok)
        throw new Error(`wj-dsh-remote: merge failed with ${String(response.status)}`);
    const value = await response.json();
    return typeof value.deviceId === 'string' ? value.deviceId : undefined;
}
/**
 * Presence heartbeat from a paired phone.
 * @returns the response status, so the caller can stop polling once the server
 *   proves this page is not paired (see {@link shouldStopHeartbeat}).
 */
export async function sendHeartbeat() {
    const response = await fetch('api/pair/heartbeat', { method: 'POST' });
    return response.status;
}
/**
 * Whether a heartbeat answer means "this page can never be accepted again" and
 * the 10 s wake source should stop: 401 (unpaired, or the device was revoked)
 * and 403 (the fence refused it) are permanent for this page, while a network
 * error or a 5xx is transient and keeps the cadence.
 * @param status - the heartbeat response status.
 */
export function shouldStopHeartbeat(status) {
    return status === 401 || status === 403;
}
/** Whether the current page URL carries a pairing token. */
export function readPairParams(search) {
    const params = new URLSearchParams(search);
    const pair = params.get('pair');
    return pair !== null && pair !== '' ? { pair } : {};
}
/**
 * Strip one query parameter from the current URL without reloading.
 * @param name - the parameter to remove.
 * @returns the new search string ('' when empty).
 */
export function stripParam(name) {
    const url = new URL(window.location.href);
    url.searchParams.delete(name);
    return url.search;
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
export function isLanHost(host) {
    if (typeof host !== 'string' || host === '')
        return false;
    if (host === '0.0.0.0')
        return true;
    return host !== '127.0.0.1' && host !== '::1' && host !== 'localhost';
}
/** A failed LAN-bind read, carrying the HTTP status when the server answered. */
export class LanBindStatusError extends Error {
    status;
    /**
     * @param status - the response status, or undefined when the request failed
     *   before a response (network error).
     * @param message - the diagnostic message.
     */
    constructor(status, message) {
        super(message);
        this.status = status;
        this.name = 'LanBindStatusError';
    }
}
/** Read the LAN-bind facts (loopback-only endpoint). */
export async function readLanBindStatus() {
    const response = await fetch('api/pair/lan-bind');
    if (!response.ok)
        throw new LanBindStatusError(response.status, `wj-dsh-remote: lan-bind status failed with ${String(response.status)}`);
    return await response.json();
}
/**
 * Whether a LAN-bind status failure means this origin can never read the
 * endpoint (401/403 from the loopback-only fence), so a poll should stop
 * instead of retrying a known refusal; a transient error keeps the cadence.
 * @param status - the response status, or undefined for a network failure.
 */
export function shouldStopLanBindPoll(status) {
    return status === 401 || status === 403;
}
/** Human-readable expiry clock, e.g. "10:35". */
export function formatClock(epochMs) {
    const date = new Date(epochMs);
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}
/** Calendar + clock for last-seen timestamps, e.g. "2026-08-19 10:35". */
export function formatLastSeen(epochMs) {
    const date = new Date(epochMs);
    const year = String(date.getFullYear());
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day} ${formatClock(epochMs)}`;
}
/**
 * Copy text to the clipboard with a fallback for insecure contexts
 * (plain-HTTP LAN origins lack navigator.clipboard).
 * @param text - the text to copy.
 * @returns whether the copy succeeded.
 */
export async function copyText(text) {
    if (typeof navigator !== 'undefined' && navigator.clipboard !== undefined) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        }
        catch {
            // fall through to the execCommand path
        }
    }
    try {
        const area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand('copy');
        area.remove();
        return ok;
    }
    catch {
        return false;
    }
}
