/**
 * LAN address derivation for the pairing URLs. Mirrors the dsh CLI's
 * boot-time sampling (apps/cli/src/app-cli-entry.ts `resolveLanTrust`): the
 * pairing links may only name addresses the /api trust fence was configured
 * with, so the same non-internal IPv4 derivation applies here — an external
 * plugin cannot read the CLI's sampled snapshot, but the fence accepts
 * exactly these literals, which is the property that matters.
 *
 * One derivation is deliberately narrower than the CLI's: everything this
 * module returns is advertised to a phone (the QR base, the landing page's
 * LAN probe, and the fence's trusted-literal list), and an advertised literal
 * the peer can never reach costs a phone the whole pairing attempt. A macOS
 * host running a fake-IP proxy (Clash/Surge/Mihomo) samples its TUN gateway as
 * `198.18.0.1`, which is a benchmarking-range address no LAN peer can route
 * to; the old derivation advertised it like any other interface. The filter
 * below drops the interface kinds and address ranges a peer cannot reach, and
 * keeps everything else — RFC1918, ULA-side IPv4 and a routable public literal
 * (a VPS whose NIC is its only reachable base must stay advertisable).
 *
 * @module wj-dsh-remote/lan
 */
import { networkInterfaces } from 'node:os';
/**
 * Whether an interface name belongs to a tunnel, VPN adapter, or virtual
 * machine/container bridge, so its address is not an authority a LAN peer
 * can dial.
 * @param name - the interface name from `os.networkInterfaces()`.
 * @returns true when the interface must not be advertised.
 */
export declare function isUnadvertisableInterface(name: string): boolean;
/**
 * Whether an IPv4 literal can be advertised to a pairing peer.
 * @param address - a dotted-quad IPv4 literal.
 * @returns true when a peer could plausibly reach it.
 */
export declare function isAdvertisableIPv4(address: string): boolean;
/** One sampled interface address. */
export interface LanCandidate {
    /** The interface name the address was sampled from. */
    iface: string;
    /** The IPv4 literal. */
    address: string;
}
/** The `networkInterfaces()` shape, injectable so the filter is testable. */
export type NetworkInterfaceMap = ReturnType<typeof networkInterfaces>;
/**
 * Every IPv4 interface address this machine can advertise to a pairing peer:
 * non-internal, on a non-tunnel and non-virtual interface, outside the ranges
 * no peer can route to.
 * @param interfaces - the sampled interface map (defaults to the live one).
 * @returns the candidates in interface order (possibly empty).
 */
export declare function lanIPv4Candidates(interfaces?: NetworkInterfaceMap): LanCandidate[];
/**
 * Non-internal, reachable IPv4 interface addresses of this machine — the
 * IP-literal authorities an all-interfaces bind is reachable by on the LAN.
 * @param interfaces - the sampled interface map (defaults to the live one).
 * @returns the addresses in interface order (possibly empty).
 */
export declare function lanIPv4Addresses(interfaces?: NetworkInterfaceMap): string[];
//# sourceMappingURL=lan.d.ts.map