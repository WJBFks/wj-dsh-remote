/**
 * Crash recovery for the tunnel's cloudflared child. A host that dies without
 * tearing its tunnel down hands the child over to launchd/systemd, where it
 * keeps its edge registration forever: the next host then runs a second
 * connector beside an orphan nobody serves, and the old process holds a
 * hostname no tunnel answers on any more.
 *
 * The manager records the spawned child under the DSH home right after the
 * spawn (pid plus the exact command line ps/proc reports) and drops the record
 * when that child is stopped, so a record only outlives the process that wrote
 * it when that process crashed. The next start reaps exactly that pid, and
 * only while it is still alive AND its command line still equals the recorded
 * one: a recycled pid or a rewritten record can therefore never make the
 * plugin signal a process it did not spawn. Nothing here matches by pattern,
 * by process name, or by any pid this plugin did not record itself.
 *
 * A record also carries the pid of the host that spawned the child. Two live
 * hosts can share one DSH home (two profiles, or a plugin reload inside one
 * host), and each owns its own child; only a host that is gone leaves a child
 * behind, so a record whose owner is still running is left untouched.
 */
/**
 * The spawned child as its tunnel handle exposes it (node's `ChildProcess`
 * fits: `pid` plus the argv it was spawned with).
 */
export interface TunnelChildProcess {
    /** The child's pid. */
    pid?: number;
    /** The argv the child was spawned with, executable first. */
    spawnargs?: readonly string[];
}
/** What the plugin records about one child it spawned. */
export interface TunnelChildRecord {
    /** The child's pid. */
    pid: number;
    /**
     * The child's full argv joined with single spaces — the same line `ps`
     * prints. Anything else (a wrapper, a rewritten command) is a mismatch.
     */
    command: string;
    /** The host process that spawned the child; a live owner keeps it. */
    ownerPid: number;
    /** ISO timestamp of the recording (diagnostics only). */
    recordedAt: string;
}
/** How one recorded leftover was settled. */
export type TunnelOrphanVerdict = 
/** There was no usable record. */
'none'
/** The record did not identify a live child this plugin spawned: only the file was dropped. */
 | 'stale'
/** The recorded child still belongs to a running host: it was left alone. */
 | 'owned'
/** The recorded orphan was signalled away and the record dropped. */
 | 'reaped';
/** Injectable seams of the reaper (defaults read the real process table). */
export interface TunnelOrphanSeams {
    /** Whether a pid is still alive. */
    alive?: (pid: number) => boolean;
    /** Read a pid's exact command line, or undefined when it cannot be read. */
    command?: (pid: number) => Promise<string | undefined>;
    /** Signal one recorded pid (never a pattern). */
    signal?: (pid: number, signal: NodeJS.Signals) => void;
    /** Bounded wait between liveness polls. */
    wait?: (ms: number) => Promise<void>;
    /** How long the signalled child gets to honour SIGTERM before SIGKILL. */
    graceMs?: number;
}
/** The crash-recovery face the tunnel manager drives. */
export interface TunnelChildGuard {
    /** Reap the leftover child a crashed host recorded; resolves once settled. */
    reap(): Promise<TunnelOrphanVerdict>;
    /**
     * Record a freshly spawned child so the next host start can reap it.
     * @returns whether a record was written (a handle without its OS process, or
     * an unwritable home, writes nothing and must not clear a sibling's record).
     */
    record(child: TunnelChildProcess | undefined): boolean;
    /** Drop the record: the child is stopped, so nothing is left to reap. */
    clear(): void;
}
/** How long an orphan gets to honour SIGTERM before it is killed. */
export declare const DEFAULT_ORPHAN_GRACE_MS = 3000;
/** The record file this plugin owns: `$DSH_HOME/wj-dsh-remote-tunnel-child.json`. */
export declare function tunnelChildRecordFile(home?: string): string;
/**
 * Read one record, ignoring a file that cannot identify a child (`pid` and
 * `command` absent or malformed): only a well-formed record may ever lead to a
 * signal.
 * @param file - the record file.
 * @returns the record, or undefined when there is none to trust.
 */
export declare function readTunnelChildRecord(file: string): TunnelChildRecord | undefined;
/**
 * Write one record owner-only, creating the DSH home when it is missing.
 * @param file - the record file.
 * @param record - what to record about the spawned child.
 */
export declare function recordTunnelChild(file: string, record: TunnelChildRecord): void;
/** Drop one record; an absent file is not an error. */
export declare function clearTunnelChildRecord(file: string): void;
/**
 * Whether a pid is still in the process table. `EPERM` means the process
 * exists but belongs to another user, which still counts as alive.
 * @param pid - the pid to probe.
 * @returns whether the pid exists.
 */
export declare function processAlive(pid: number): boolean;
/**
 * Read one pid's exact command line: `/proc/<pid>/cmdline` on Linux,
 * `ps -ww -o command=` elsewhere. Arguments are joined with single spaces in
 * both cases, which is exactly how a recorded argv is stored.
 * @param pid - the pid to read.
 * @returns the command line, or undefined when it cannot be read.
 */
export declare function processCommandLine(pid: number): Promise<string | undefined>;
/**
 * Turn one `/proc/<pid>/cmdline` read (argv, NUL-separated, usually with a
 * trailing NUL) into the line `ps` prints, so both platforms compare against
 * the same recorded shape.
 * @param raw - the raw `/proc/<pid>/cmdline` text.
 * @returns the joined command line, or undefined for an empty file.
 */
export declare function parseProcCommandLine(raw: string): string | undefined;
/**
 * Settle one recorded leftover: reap exactly the recorded child when it is
 * still the process that record describes, and leave every other process
 * strictly alone.
 * @param file - the record file.
 * @param seams - process-table and signal seams (defaults read the real table).
 * @returns which way the record was settled.
 */
export declare function reapRecordedTunnelChild(file: string, seams?: TunnelOrphanSeams): Promise<TunnelOrphanVerdict>;
/** Seams of the file-backed guard (the record file defaults to the DSH home). */
export interface TunnelChildGuardOptions extends TunnelOrphanSeams {
    /** The record file; resolved per call so a changed DSH home is honoured. */
    file?: string;
}
/**
 * Build the file-backed crash-recovery guard the tunnel manager uses: the
 * record lives at {@link tunnelChildRecordFile} unless a file is given.
 * @param options - record file and process seams (all optional).
 * @returns the guard.
 */
export declare function createTunnelChildGuard(options?: TunnelChildGuardOptions): TunnelChildGuard;
//# sourceMappingURL=tunnel-orphan.d.ts.map