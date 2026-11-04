/** Derive a short, non-sensitive device label from a browser User-Agent. */
export declare function deviceNameFromUserAgent(userAgent?: string): string | undefined;
/**
 * The label shown for one authorized device: the operator's name first, then
 * the User-Agent-derived name, then the caller's "unknown device" copy.
 * @param device - a roster row (custom name and/or User-Agent).
 * @param unknown - the localized fallback for a row with neither.
 * @returns the display label.
 */
export declare function deviceDisplayName(device: {
    name?: string;
    userAgent?: string;
}, unknown: string): string;
/**
 * Group roster rows that report the same non-empty User-Agent. A group of two
 * or more is a duplicate-pairing candidate (one phone that paired from several
 * cookie contexts, or two physically identical devices): the panel offers the
 * merge action but never assumes they are the same device.
 * @param devices - the roster in display order.
 * @returns the duplicate groups, each in roster order.
 */
export declare function duplicateDeviceGroups<T extends {
    userAgent?: string;
}>(devices: readonly T[]): T[][];
//# sourceMappingURL=device-name.d.ts.map