/**
 * The lan-bind block this plugin used to write, and its removal (issue #1917).
 *
 * Up to 0.4.8 the toggle pinned the LAN address into the profile's
 * `cordis.patch.yml` as a managed `- id: webserver` row. That approach is
 * retired for two measured reasons:
 *
 * 1. A same-id patch row REPLACES the whole row config, so the block silently
 *    swallowed the official row's own bind expression; the CLI `--host` /
 *    `--port` never reached the running row, and the machine's port came from
 *    a literal this plugin guessed.
 * 2. The profile patch is exactly what the Host's HMR config watcher refreshes
 *    from, so writing it recomposed the running process and rebound the live
 *    listener - the "takes effect on the next start" premise was false, and a
 *    write made mid-session moved the bind under the running host.
 *
 * LAN reachability now comes from a runtime forwarder instead (lan-forward.ts),
 * so the host always listens on loopback and this module's only remaining job
 * is to remove the block older versions left behind. The removal is
 * strip-only: no write appends anything, so the official webserver row (and
 * every other row) stays byte-identical. The block discipline (markers, atomic
 * write) follows the dsh-LAN reference implementation (MIT).
 */
export declare const LAN_BIND_BLOCK_BEGIN = "# --- wj-dsh-remote lan-bind block (managed - do not edit) ---";
export declare const LAN_BIND_BLOCK_END = "# --- end wj-dsh-remote lan-bind block ---";
/**
 * A bind host the managed block may pin. `'0.0.0.0'` only on a host whose
 * webserver schema still accepts the wildcard, `'127.0.0.1'` for the toggle
 * off, and otherwise one concrete interface address of this machine (see
 * lan-bind-plan.ts / host-bind-capability.ts, issue #1893).
 */
export type LanBindHost = string;
/**
 * The absolute path of the profile patch file this toggle manages. The value
 * is config-controlled (and the runtime/environment fallbacks bypass schema
 * validation entirely), so the path is guarded twice: the profile must be a
 * single safe path segment, and the resolved file must stay under the
 * profiles directory.
 */
export declare function profilePatchFile(profile: string, home?: string): string;
/**
 * Remove the managed block (its markers and the webserver row this plugin
 * wrote) from patch content, keeping every other row.
 *
 * The markers travel with the file through writers that append rows through
 * the YAML document API: the appended rows land at the end of the sequence,
 * which is BEFORE a trailing END comment, so the region between the markers
 * can hold rows this plugin never wrote. Deleting the whole region silently
 * removed the user's model, plugin and remote-control rows on the next rewrite
 * - the remote-control row carries the LAN toggle itself, so the feature reset
 * to `undefined` and the phone was locked out again after a restart (DSH
 * Desktop report, 2026-09-30). Only the managed item is removed here; every
 * foreign row is kept in place and the fresh block is appended after them (the
 * same-id row last wins).
 * @param content - the patch file text.
 * @returns the text with the markers and the managed row removed.
 */
export declare function stripManagedBlock(content: string): string;
/** The bind state a managed block pinned (undefined when there is no block). */
export interface ManagedBindState {
    host: LanBindHost | (string & {});
    port: number | undefined;
}
/**
 * Parse the block's pinned bind out of patch content. A block whose values
 * were hand-edited reports the literals as-is so the card can surface them
 * instead of silently claiming one of the two known states.
 */
export declare function managedBindOf(content: string): ManagedBindState | undefined;
/** File-level state of a patch file a previous version wrote to. */
export declare function lanBindState(profile: string, home?: string): {
    blockPresent: boolean;
    host?: string;
    port?: number;
};
/** What one legacy-block cleanup did, for the settings card and the log. */
export interface LegacyBlockCleanup {
    /** Whether the file actually carried the managed block. */
    removed: boolean;
    /** The bind the removed block pinned, when it could be read. */
    host: string | undefined;
    /** The port the removed block pinned, when it could be read. */
    port: number | undefined;
}
/**
 * Remove the managed block a previous version wrote, and nothing else.
 *
 * The file is rewritten atomically (unique temp file + rename, so a concurrent
 * reader never sees a half-written patch) with its original permissions
 * preserved, and only when the block is actually there: a second run finds no
 * markers, writes nothing, and leaves the bytes identical, which is what makes
 * the plugin's once-per-boot call idempotent.
 *
 * The official `- id: webserver` row every profile carries is a FOREIGN row -
 * the strip keeps it verbatim (see stripManagedBlock). Nothing is appended, so
 * the profile keeps the row's own bind expression and the CLI flags keep
 * reaching it.
 *
 * A failure (an unreadable file, a read-only profile) is NOT swallowed here:
 * callers report it, because a silent failure leaves a block that keeps
 * swallowing the bind on every later start.
 * @param profile - the managed profile name.
 * @param home - DSH home (test seam).
 * @returns what was removed; `removed: false` when there was nothing to do.
 */
export declare function removeManagedBlock(profile: string, home?: string): LegacyBlockCleanup;
//# sourceMappingURL=lan-bind.d.ts.map