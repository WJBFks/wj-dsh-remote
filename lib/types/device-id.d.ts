/**
 * Public device identifiers.
 *
 * The device cookie value is a session credential and must never be rendered.
 * The panel shows a *public id* instead: an HMAC of the cookie under a
 * per-install pepper, so the host can prove "this public id belongs to that
 * cookie" while the public id itself cannot be turned back into a credential.
 *
 * Format: 6 characters of Crockford base32 (no i/l/o/u), 30 bits — enough for a
 * handful of devices and far from a credential.
 */
/** Displayed length; 12 × 5 bits = 60 bits. */
export declare const PUBLIC_ID_LENGTH = 6;
/** File holding the pepper, relative to DSH_HOME. */
export declare const PEPPER_FILE = "wj-dsh-remote-id-pepper";
/**
 * Derive the public id of one device.
 * @param pepper - per-install secret (32 random bytes).
 * @param deviceId - the cookie value / session credential.
 * @returns 12-character public identifier.
 */
export declare function publicIdOf(pepper: Buffer, deviceId: string): string;
/**
 * Load the pepper, creating it on first use.
 *
 * A missing/unreadable pepper is generated and persisted; the file is 0600 and
 * atomic. Losing the pepper only changes every public id (sessions, cookies
 * and levels are unaffected), so it belongs in the same backup set as the
 * launch token.
 * @param home - the DSH_HOME directory.
 * @returns the pepper bytes.
 */
export declare function loadIdPepper(home: string): Buffer;
//# sourceMappingURL=device-id.d.ts.map