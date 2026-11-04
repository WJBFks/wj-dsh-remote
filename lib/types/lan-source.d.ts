/**
 * The landing page's network-source decision: which origin a paired phone
 * should keep using.
 *
 * The QR link can only name one base, and the server cannot know whether the
 * scanning phone sits on this machine's own network: the public (relayed)
 * base is the only one that is always reachable, so the QR names it and the
 * phone decides at connect time. The device-gated landing (/wj-pair-app) is the
 * plugin's own page already rendered ahead of the official shell's boot, so it
 * is the natural place to probe: after the page is served, a short
 * cross-origin `fetch` per LAN candidate (a no-cors GET at
 * {@link LAN_PING_PATH}) tells the browser whether that LAN origin answers,
 * and the first one that does becomes the new origin. A probe that finds
 * nothing, or that runs out of budget, changes nothing — the page the phone
 * already holds stays paired and usable, so the probe can never block pairing.
 *
 * Browsers do not block this probe. An https page may not normally fetch
 * `http://` subresources, but a host that is an IP literal is exempt from both
 * the block and the automatic upgrade (verified against Chrome: the console
 * reports "This request was not upgraded to HTTPS because its URL's host is an
 * IP address" and delivers the response), which is exactly the shape every LAN
 * candidate has.
 *
 * @module wj-dsh-remote/lan-source
 */
/** sessionStorage key holding this session's source decision. */
export declare const LAN_SOURCE_STORAGE_KEY = "dsh-remote-lan-source";
/**
 * Probe budget for the whole candidate set. Long enough for a LAN round trip,
 * short enough that a phone on another network never waits on it — the probe
 * is fire-and-forget and the page it runs on is already usable.
 */
export declare const LAN_SOURCE_PROBE_TIMEOUT_MS = 800;
/**
 * How recently a LAN hop must have been taken for a return to a non-LAN origin
 * to read as "the hop did not stick". A phone that fails to load the LAN page
 * re-scans the QR (which always names the public base) within seconds, and the
 * landing then has to choose the public source instead of hopping again into
 * the same black hole; a deliberate return much later is a fresh decision and
 * re-probes.
 */
export declare const LAN_SOURCE_RETRY_WINDOW_MS = 120000;
/** One probe payload: everything the injected script needs, JSON-serializable. */
export interface LanSourceHop {
    /**
     * The LAN origins the probe may hop to, normalized (`https://host:port` with
     * a default port dropped) so they compare equal to `location.origin`.
     */
    candidates: readonly string[];
    /** The path the hop targets on the winning origin. */
    path: string;
    /** The path the probe itself requests, on each candidate. */
    pingPath: string;
    /** The one-time grant the hop consumes on the winning origin. */
    grant: string;
}
/**
 * Build the inline script that runs the source decision on the landing page.
 * Reads every browser global through `window`, so a test can run it against
 * one fake object (the same seam the parse-time boot patch uses).
 * @param hop - the probe payload for this landing render.
 * @returns the `<script>` element to splice into the landing's head.
 */
export declare function appShellLanSwitchScript(hop: LanSourceHop): string;
//# sourceMappingURL=lan-source.d.ts.map