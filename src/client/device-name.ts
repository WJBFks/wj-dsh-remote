/** Derive a short, non-sensitive device label from a browser User-Agent. */
export function deviceNameFromUserAgent(userAgent?: string): string | undefined {
  if (userAgent === undefined || userAgent.trim() === '') return undefined

  const os = /Windows NT/i.test(userAgent)
    ? 'Windows'
    : /Android/i.test(userAgent)
      ? 'Android'
      : /iPhone|iPad|iPod/i.test(userAgent)
        ? 'iOS'
        : /Macintosh|Mac OS X/i.test(userAgent)
          ? 'macOS'
          : /Linux/i.test(userAgent)
            ? 'Linux'
            : undefined

  const browser = /Edg(?:A|iOS)?\//i.test(userAgent)
    ? 'Edge'
    : /(?:OPR|Opera)\//i.test(userAgent)
      ? 'Opera'
      : /(?:Chrome|CriOS)\//i.test(userAgent)
        ? 'Chrome'
        : /(?:Firefox|FxiOS)\//i.test(userAgent)
          ? 'Firefox'
          : /Safari\//i.test(userAgent) && /Version\//i.test(userAgent)
            ? 'Safari'
            : undefined

  if (os !== undefined && browser !== undefined) return `${os} · ${browser}`
  return os ?? browser
}

/**
 * The label shown for one authorized device: the operator's name first, then
 * the User-Agent-derived name, then the caller's "unknown device" copy.
 * @param device - a roster row (custom name and/or User-Agent).
 * @param unknown - the localized fallback for a row with neither.
 * @returns the display label.
 */
export function deviceDisplayName(
  device: { name?: string; userAgent?: string },
  unknown: string,
): string {
  const name = device.name?.trim()
  if (name !== undefined && name !== '') return name
  return deviceNameFromUserAgent(device.userAgent) ?? unknown
}

/**
 * Group roster rows that report the same non-empty User-Agent. A group of two
 * or more is a duplicate-pairing candidate (one phone that paired from several
 * cookie contexts, or two physically identical devices): the panel offers the
 * merge action but never assumes they are the same device.
 * @param devices - the roster in display order.
 * @returns the duplicate groups, each in roster order.
 */
export function duplicateDeviceGroups<T extends { userAgent?: string }>(devices: readonly T[]): T[][] {
  const groups = new Map<string, T[]>()
  for (const device of devices) {
    const userAgent = device.userAgent?.trim()
    if (userAgent === undefined || userAgent === '') continue
    const group = groups.get(userAgent)
    if (group === undefined) groups.set(userAgent, [device])
    else group.push(device)
  }
  return [...groups.values()].filter(group => group.length > 1)
}
