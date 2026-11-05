/**
 * Public device identifiers.
 *
 * The device cookie value is a session credential and must never be rendered.
 * The panel shows a *public id* instead: an HMAC of the cookie under a
 * per-install pepper, so the host can prove "this public id belongs to that
 * cookie" while the public id itself cannot be turned back into a credential.
 *
 * Format: 12 characters of Crockford base32 (no i/l/o/u), ~60 bits.
 */

import { createHmac, randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

/** Unambiguous base32 alphabet (Crockford, lower-case). */
const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz'

/** Displayed length; 12 × 5 bits = 60 bits. */
export const PUBLIC_ID_LENGTH = 12

/** File holding the pepper, relative to DSH_HOME. */
export const PEPPER_FILE = 'wj-dsh-remote-id-pepper'

/**
 * Derive the public id of one device.
 * @param pepper - per-install secret (32 random bytes).
 * @param deviceId - the cookie value / session credential.
 * @returns 12-character public identifier.
 */
export function publicIdOf(pepper: Buffer, deviceId: string): string {
  const digest = createHmac('sha256', pepper).update(deviceId).digest()
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of digest) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5 && out.length < PUBLIC_ID_LENGTH) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
    if (out.length === PUBLIC_ID_LENGTH) break
  }
  return out
}

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
export function loadIdPepper(home: string): Buffer {
  const file = join(home, PEPPER_FILE)
  try {
    const raw = readFileSync(file)
    if (raw.length >= 16) return raw
  } catch {
    // fall through to create
  }
  const pepper = randomBytes(32)
  try {
    mkdirSync(dirname(file), { recursive: true })
    const tmp = `${file}.tmp.${process.pid}`
    writeFileSync(tmp, pepper, { mode: 0o600 })
    renameSync(tmp, file)
  } catch {
    // A read-only home still gets a per-process pepper; ids change per restart.
  }
  return pepper
}
