import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { setInterval, setTimeout as setTimeout$1 } from "node:timers";
import z from "@deepseek-ai/schemastery";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, networkInterfaces } from "node:os";
import { isAbsolute as isAbsolute$1, join as join$1 } from "node:path/posix";
import { Service } from "@deepseek-ai/cordis";
import { z as z$1 } from "zod";
import http, { createServer, request } from "node:http";
import { connect } from "node:net";
import { execFile, spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { Tunnel, bin, install } from "cloudflared";
import https from "node:https";
import * as webserver from "@deepseek-ai/dsh-host-webserver";
import { AsyncResource } from "node:async_hooks";
//#region src/lan.ts
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
/**
* Interface-name stems of tunnels and VPN adapters: interfaces whose address
* is a private point-to-point endpoint on this machine, never an authority a
* peer on the local network can dial. Matching is case-insensitive and
* anchored at the start, so `utun0`/`utun4` both match while a hypothetical
* `en0utun` does not. Windows reports adapter *descriptions* rather than POSIX
* stems (`Tailscale`, `WireGuard Tunnel`, `OpenVPN Wintun`), which the same
* list covers by prefix.
*/
const TUNNEL_INTERFACE_PREFIXES = [
	"utun",
	"tun",
	"tap",
	"ppp",
	"ipsec",
	"wg",
	"wireguard",
	"tailscale",
	"nordlynx",
	"proton",
	"openvpn",
	"zt"
];
/**
* Interface-name stems of virtual machine and container bridges: `docker0`,
* `vethXXXX`, `br-<id>`, `virbr0`, `vmnet8`, `vboxnet0` and the Hyper-V
* `vEthernet` adapters. Their RFC1918 addresses belong to a NAT the host
* shares with its own guests, so a phone on the physical LAN cannot reach
* them; `bridge0`/`br0` are deliberately absent because a real bridged LAN
* (macOS Internet Sharing) is exactly the address a phone does reach.
*/
const VIRTUAL_INTERFACE_PREFIXES = [
	"docker",
	"veth",
	"virbr",
	"vmnet",
	"vboxnet",
	"vethernet",
	"br-"
];
/**
* IPv4 ranges no peer on the local network can reach. The list is a denial
* list rather than an RFC1918 allowlist on purpose: a host whose only
* interface is a routable public literal (a VPS, a standalone server) would
* otherwise lose its only constructible base and fall back to the
* `lan-required` banner.
* @param octets - the four address octets, in order.
* @returns true when an address in this range must not be advertised.
*/
function isUnreachableIPv4(octets) {
	const [a = 0, b = 0] = octets;
	if (a === 0) return true;
	if (a === 127) return true;
	if (a === 100 && b >= 64 && b <= 127) return true;
	if (a === 169 && b === 254) return true;
	if (a === 198 && (b === 18 || b === 19)) return true;
	if (a >= 224) return true;
	return false;
}
/**
* Whether an interface name belongs to a tunnel, VPN adapter, or virtual
* machine/container bridge, so its address is not an authority a LAN peer
* can dial.
* @param name - the interface name from `os.networkInterfaces()`.
* @returns true when the interface must not be advertised.
*/
function isUnadvertisableInterface(name) {
	const lower = name.toLowerCase();
	return [...TUNNEL_INTERFACE_PREFIXES, ...VIRTUAL_INTERFACE_PREFIXES].some((prefix) => lower.startsWith(prefix));
}
/**
* Whether an IPv4 literal can be advertised to a pairing peer.
* @param address - a dotted-quad IPv4 literal.
* @returns true when a peer could plausibly reach it.
*/
function isAdvertisableIPv4(address) {
	const parts = address.split(".");
	if (parts.length !== 4) return false;
	const octets = parts.map((part) => /^\d{1,3}$/.test(part) ? Number(part) : NaN);
	if (octets.some((octet) => !Number.isInteger(octet) || octet > 255)) return false;
	return !isUnreachableIPv4(octets);
}
/**
* Every IPv4 interface address this machine can advertise to a pairing peer:
* non-internal, on a non-tunnel and non-virtual interface, outside the ranges
* no peer can route to.
* @param interfaces - the sampled interface map (defaults to the live one).
* @returns the candidates in interface order (possibly empty).
*/
function lanIPv4Candidates(interfaces = networkInterfaces()) {
	const candidates = [];
	for (const [name, addresses] of Object.entries(interfaces)) {
		if (isUnadvertisableInterface(name)) continue;
		for (const iface of addresses ?? []) {
			if (iface.family !== "IPv4" || iface.internal) continue;
			if (!isAdvertisableIPv4(iface.address)) continue;
			candidates.push({
				iface: name,
				address: iface.address
			});
		}
	}
	return candidates;
}
/**
* Non-internal, reachable IPv4 interface addresses of this machine — the
* IP-literal authorities an all-interfaces bind is reachable by on the LAN.
* @param interfaces - the sampled interface map (defaults to the live one).
* @returns the addresses in interface order (possibly empty).
*/
function lanIPv4Addresses(interfaces = networkInterfaces()) {
	return lanIPv4Candidates(interfaces).map((candidate) => candidate.address);
}
//#endregion
//#region src/ingress-sync.ts
/**
* Update-only Cloudflare tunnel ingress sync (issue #1948).
*
* A named tunnel's public hostname is permanent — that is the whole point of
* the mode — but the ingress rule behind it names a fixed local port. When
* `dsh web` listens on another port (an operator changed `--port`, a profile
* carries a different value, a second instance took the old one), the hostname
* keeps resolving and answers 502 while this plugin still believes it is
* published. This module converges exactly that one number and nothing else:
*
* - a read (GET) is the only request a healthy start makes;
* - the plan proves the whole document except the matched rule's `service`
*   string is unchanged, and refuses (a conflict) anything it cannot prove —
*   no added or removed rule, no moved ingress entry, no touched top-level
*   key, no invented catch-all;
* - the service it retargets has to be this machine's own: loopback, or one of
*   this host's LAN addresses. Another host's address is a conflict, never a
*   write, because the port there belongs to whatever that address serves;
* - only a proven drift is written, as one full-document PUT (the API offers
*   no patch for a single rule);
* - the write is read back once. A disagreement is a conflict, never an
*   automatic rewrite: one tunnel document has one writer, and a deployment
*   whose dashboard or another sync owns it has to be reconciled by a human.
*
* Everything is offline-testable: the HTTP call and the timers are injected
* seams, and the default seam itself refuses to send the account token to any
* origin but `https://api.cloudflare.com`. The token never enters a log line,
* a status frame, a child process argument, or any browser-visible state — it
* exists only inside the `Authorization` header of the two requests that need
* it.
*/
/** The only origin the Cloudflare API token is ever sent to. */
const CLOUDFLARE_API_ORIGIN = "https://api.cloudflare.com";
/** Whether a value is a JSON object (not an array, not null). */
function isJsonObject$1(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/**
* The configurations endpoint of one tunnel. The account and tunnel ids are
* opaque path segments, so they are encoded rather than interpolated raw.
* @param accountId - the Cloudflare account id.
* @param tunnelId - the named tunnel id (never the tunnel's token).
* @returns the absolute API URL the sync reads and writes.
*/
function ingressConfigUrl(accountId, tunnelId) {
	return `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${encodeURIComponent(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/configurations`;
}
/**
* The lower-cased hostname a configured public base names. Wildcards are not
* supported by this sync (the target rule must match one exact hostname), so a
* wildcard base is refused here rather than matched loosely later.
* @param publicBaseUrl - the configured public base URL.
* @returns the hostname to match in the ingress, or undefined when the value
*   is missing, unparsable, not http(s), or a wildcard.
*/
function hostnameOf$1(publicBaseUrl) {
	if (publicBaseUrl === void 0 || publicBaseUrl.trim() === "") return void 0;
	try {
		const url = new URL(publicBaseUrl);
		if (url.protocol !== "http:" && url.protocol !== "https:") return void 0;
		const hostname = url.hostname.toLowerCase();
		if (hostname === "" || hostname.includes("*")) return void 0;
		return hostname;
	} catch {
		return;
	}
}
/**
* Retarget one tunnel service string at a port, changing nothing else. The
* authority's host (including an IPv6 literal and any userinfo), the path, the
* query, and the fragment are preserved byte for byte, so the plan can prove
* the only difference in the document is the port digits.
* @param service - the rule's current service string (e.g. `http://127.0.0.1:3080`).
* @param port - the port this host's web server actually bound.
* @returns the retargeted service, or undefined when the value is not an
*   http(s) origin this sync can safely rewrite.
*/
function serviceWithPort(service, port) {
	if (!Number.isInteger(port) || port < 1 || port > 65535) return void 0;
	const match = /^(https?:\/\/)([^/?#]*)([\s\S]*)$/.exec(service);
	if (match === null) return void 0;
	const scheme = match[1];
	const authority = match[2];
	const rest = match[3];
	const at = authority.lastIndexOf("@");
	const userinfo = at >= 0 ? authority.slice(0, at + 1) : "";
	const hostPart = authority.slice(at + 1);
	let host;
	if (hostPart.startsWith("[")) {
		const end = hostPart.indexOf("]");
		if (end < 0) return void 0;
		host = hostPart.slice(0, end + 1);
		const after = hostPart.slice(end + 1);
		if (after !== "" && !/^:\d*$/.test(after)) return void 0;
	} else {
		const colon = hostPart.lastIndexOf(":");
		const after = colon >= 0 ? hostPart.slice(colon) : "";
		if (after !== "" && !/^:\d*$/.test(after)) return void 0;
		host = colon >= 0 ? hostPart.slice(0, colon) : hostPart;
	}
	if (host === "" || host === "[]") return void 0;
	return `${scheme}${userinfo}${host}:${String(port)}${rest}`;
}
/**
* The authority host of one service string, with IPv6 brackets kept. The port
* and any userinfo are dropped, so the host can be judged on its own.
* @param service - the rule's service string.
* @returns the host, or undefined when the value is not an http(s) origin.
*/
function serviceHostOf(service) {
	const match = /^(https?:\/\/)([^/?#]*)([\s\S]*)$/.exec(service);
	if (match === null) return void 0;
	const authority = match[2];
	const hostPart = authority.slice(authority.lastIndexOf("@") + 1);
	if (hostPart.startsWith("[")) {
		const end = hostPart.indexOf("]");
		return end < 0 ? void 0 : hostPart.slice(0, end + 1);
	}
	const colon = hostPart.lastIndexOf(":");
	const host = colon >= 0 ? hostPart.slice(0, colon) : hostPart;
	return host === "" ? void 0 : host;
}
/**
* One service string with its userinfo removed, for everything that leaves
* this process. A tunnel service may carry `user:password@`, and the
* update-only write has to preserve that byte for byte — but an audit frame, a
* log line, or the settings card has no business showing a credential the
* operator put there for the origin.
* @param service - the rule's service string.
* @returns the same service with any `userinfo@` dropped.
*/
function redactServiceUserinfo(service) {
	const match = /^(https?:\/\/)([^/?#]*)([\s\S]*)$/.exec(service);
	if (match === null) return service;
	const scheme = match[1];
	const authority = match[2];
	const rest = match[3];
	const at = authority.lastIndexOf("@");
	return at < 0 ? service : `${scheme}${authority.slice(at + 1)}${rest}`;
}
/** Whether one dotted-quad segment is a decimal octet (0-255), not a sign or a space. */
function isIpv4Octet(segment) {
	return /^\d{1,3}$/.test(segment) && Number(segment) <= 255;
}
/**
* Whether one service authority host is a target this host may own: a loopback
* literal (any 127.0.0.0/8 address, `::1`, or `localhost`) or one of this
* machine's own LAN IPv4 addresses. A service pointing anywhere else — another
* machine, a DNS name, a NAS — is not this plugin's to retarget, and rewriting
* its port would break whatever service that address actually is.
* @param host - the authority host of the service (brackets kept for IPv6).
* @param lanHosts - this machine's LAN IPv4 addresses.
* @returns whether the service may be retargeted.
*/
function isRetargetableHost(host, lanHosts = []) {
	const name = (host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host).toLowerCase();
	if (name === "") return false;
	if (name === "localhost" || name === "::1") return true;
	const octets = name.split(".");
	if (octets.length === 4 && octets[0] === "127" && octets.every(isIpv4Octet)) return true;
	return lanHosts.some((candidate) => candidate.toLowerCase() === name);
}
/** The marker a stripped service string is replaced with, for the proof below. */
const STRIPPED_SERVICE = "\0wj-dsh-remote:ingress-service\0";
/**
* One document with the target rule's `service` string replaced by a marker.
* Two documents whose stripped forms are identical differ at that one key and
* nowhere else — which is the invariant the plan must prove before it writes.
* @param document - the tunnel configuration document.
* @param ruleIndex - the ingress rule the sync owns.
* @returns the canonical JSON of the stripped document.
*/
function withoutTargetService(document, ruleIndex) {
	const copy = structuredClone(document);
	const ingress = copy.ingress;
	if (Array.isArray(ingress)) {
		const rule = ingress[ruleIndex];
		if (isJsonObject$1(rule)) rule.service = STRIPPED_SERVICE;
	}
	return JSON.stringify(copy);
}
/**
* Plan one update-only ingress change against a document read from the API.
*
* The supported shape is a Cloudflare tunnel configuration: an object whose
* `ingress` is an array of rule objects, exactly one of which carries the
* target hostname, and whose last rule is a catch-all (no `hostname`). A
* document outside that shape — a missing `ingress`, a wildcard anywhere, a
* duplicated hostname, no catch-all, a rule that is not an object, a service
* that is not an http(s) origin, or a service whose host is not this machine —
* is a conflict and produces no document, so the caller cannot accidentally
* write. The two service strings the verdict reports are redacted of userinfo:
* they are audit facts, and the write itself is carried by the document.
* @param config - the `result.config` document read from the API.
* @param target - the hostname, the port, and this machine's own addresses.
* @returns unchanged (one read is enough), apply (the document to PUT), or a
*   conflict with the reason.
*/
function planIngressUpdate(config, target) {
	const conflict = (code, detail) => ({
		outcome: "conflict",
		code,
		hostname: target.hostname,
		detail
	});
	if (!isJsonObject$1(config)) return conflict("config-shape", "the tunnel configuration is not an object");
	const ingress = config.ingress;
	if (!Array.isArray(ingress)) return conflict("config-shape", "the tunnel configuration carries no ingress array");
	if (ingress.length === 0) return conflict("no-catch-all", "the ingress list is empty, so it has no catch-all rule");
	let matches = 0;
	let matchIndex;
	for (let index = 0; index < ingress.length; index += 1) {
		const rule = ingress[index];
		if (!isJsonObject$1(rule)) return conflict("rule-shape", `ingress rule ${String(index)} is not an object`);
		const hostname = rule.hostname;
		if (hostname === void 0) continue;
		if (typeof hostname !== "string") return conflict("rule-shape", `ingress rule ${String(index)} carries a hostname that is not a string`);
		if (hostname.includes("*")) return conflict("wildcard", `ingress rule ${String(index)} uses the wildcard hostname ${JSON.stringify(hostname)}, which this sync never matches`);
		if (hostname.toLowerCase() === target.hostname) {
			matches += 1;
			matchIndex = index;
		}
	}
	const last = ingress[ingress.length - 1];
	if (!isJsonObject$1(last) || typeof last.hostname === "string") return conflict("no-catch-all", "the last ingress rule carries a hostname, so the list has no catch-all");
	if (matches === 0) return conflict("missing", `no ingress rule names ${target.hostname}`);
	if (matches > 1 || matchIndex === void 0) return conflict("duplicate", `${String(matches)} ingress rules name ${target.hostname}, so this sync cannot tell which one it owns`);
	const rule = ingress[matchIndex];
	if (!isJsonObject$1(rule)) return conflict("rule-shape", `ingress rule ${String(matchIndex)} is not an object`);
	const service = rule.service;
	if (typeof service !== "string" || service === "") return conflict("service-shape", `ingress rule ${String(matchIndex)} carries no service string`);
	const serviceHost = serviceHostOf(service);
	if (serviceHost === void 0) return conflict("service-shape", `ingress rule ${String(matchIndex)} service ${JSON.stringify(redactServiceUserinfo(service))} is not an http(s) origin this sync can retarget`);
	if (!isRetargetableHost(serviceHost, target.allowedHosts ?? [])) return conflict("service-host", `ingress rule ${String(matchIndex)} points at ${JSON.stringify(serviceHost)}, which is neither loopback nor one of this machine's LAN addresses`);
	const next = serviceWithPort(service, target.port);
	if (next === void 0) return conflict("service-shape", `ingress rule ${String(matchIndex)} service ${JSON.stringify(redactServiceUserinfo(service))} is not an http(s) origin this sync can retarget`);
	if (next === service) return {
		outcome: "unchanged",
		hostname: target.hostname,
		ruleIndex: matchIndex,
		ruleCount: ingress.length,
		service: redactServiceUserinfo(service)
	};
	const document = structuredClone(config);
	const cloned = document.ingress[matchIndex];
	if (!isJsonObject$1(cloned)) return conflict("rule-shape", `ingress rule ${String(matchIndex)} is not an object`);
	cloned.service = next;
	if (withoutTargetService(config, matchIndex) !== withoutTargetService(document, matchIndex)) return conflict("config-shape", "the rewrite would touch a part of the document outside the target rule service");
	return {
		outcome: "apply",
		hostname: target.hostname,
		ruleIndex: matchIndex,
		ruleCount: ingress.length,
		from: redactServiceUserinfo(service),
		to: redactServiceUserinfo(next),
		document
	};
}
/**
* Read the tunnel configuration out of one API envelope. The API answers
* `{ success, result: { config: {...} }, errors }`; a body that shapes
* differently is reported, never guessed at.
* @param body - the parsed response body.
* @returns the config document, or undefined when the envelope carries none.
*/
function configOfEnvelope(body) {
	if (!isJsonObject$1(body)) return void 0;
	const result = body.result;
	if (!isJsonObject$1(result)) return void 0;
	const config = result.config;
	return isJsonObject$1(config) ? config : void 0;
}
/**
* The API's own error messages from one envelope, joined for the audit frame.
* Cloudflare answers 4xx/5xx with a populated `errors` array; the messages are
* safe to show (they name the credential's missing permission, never its value).
* @param body - the parsed response body.
* @returns a short joined summary, or undefined when the envelope carries none.
*/
function errorsOfEnvelope(body) {
	if (!isJsonObject$1(body)) return void 0;
	const errors = body.errors;
	if (!Array.isArray(errors)) return void 0;
	const messages = [];
	for (const entry of errors) {
		if (!isJsonObject$1(entry)) continue;
		const message = entry.message;
		if (typeof message === "string" && message !== "") messages.push(message);
	}
	return messages.length === 0 ? void 0 : messages.join(" ");
}
/**
* The default seam: one `fetch` round trip, and a hard refusal to send the
* account token outside the Cloudflare API even if a caller builds such a URL.
* @param request - the call to make.
* @returns the status and parsed body.
*/
const defaultIngressFetch = async (request) => {
	if (!request.url.startsWith(`https://api.cloudflare.com/`)) throw new Error("wj-dsh-remote: refusing to send the Cloudflare API token outside api.cloudflare.com");
	const response = await fetch(request.url, {
		method: request.method,
		headers: request.headers,
		...request.body !== void 0 ? { body: request.body } : {}
	});
	const text = await response.text();
	let body;
	if (text === "") body = void 0;
	else try {
		body = JSON.parse(text);
	} catch {
		body = text;
	}
	return {
		status: response.status,
		body
	};
};
/** Node timers. */
const nodeTimer$1 = {
	setTimeout: (fn, ms) => setTimeout(fn, ms),
	clearTimeout: (handle) => {
		clearTimeout(handle);
	}
};
/** Cap one audit detail so a chatty API message cannot bloat a status frame. */
function tidy(text) {
	return text.length <= 240 ? text : `${text.slice(0, 237)}...`;
}
/** The API's own messages as a parenthetical, when the envelope carries any. */
function errorsText(body) {
	const errors = errorsOfEnvelope(body);
	return errors === void 0 ? "" : ` (${tidy(errors)})`;
}
/**
* Two audit frames that describe the same state (the timestamp is not part of
* it). The pairing snapshot dedupe uses this, so a re-read that proves the same
* convergence never emits a second event.
* @param a - one frame.
* @param b - the other frame.
* @returns whether both describe the same state.
*/
function sameIngressFrame(a, b) {
	return a.state === b.state && a.hostname === b.hostname && a.port === b.port && a.service === b.service && a.previousService === b.previousService && a.ruleCount === b.ruleCount && a.ruleIndex === b.ruleIndex && a.changed === b.changed && a.code === b.code && a.detail === b.detail;
}
/**
* A non-reversible label for the account token, so the settle identity changes
* when the credential does without the token itself ever entering a key, a
* frame, or a log line. Truncated: 64 bits is far more than a local dedupe
* needs and a full digest would be a needless copy of the credential's shape.
* @param token - the account-level API token.
* @returns a truncated SHA-256 hex digest.
*/
function tokenDigest(token) {
	return createHash("sha256").update(token).digest("hex").slice(0, 16);
}
/**
* The identity a converged read is recorded under: the target, the tunnel, and
* a digest of the credential. A same-port save with a different token is a
* different identity and is read again; the same one is not read again.
* @param hostname - the matched public hostname.
* @param port - the bound port.
* @param accountId - the Cloudflare account id.
* @param tunnelId - the named tunnel id.
* @param token - the account-level API token (digested, never stored).
* @returns the settle key.
*/
function settleKeyOf(hostname, port, accountId, tunnelId, token) {
	return `${hostname}|${String(port)}|${accountId}|${tunnelId}|${tokenDigest(token)}`;
}
/** Which required settings are still missing (an explicit failure, not a retry). */
function missingConfig(input) {
	const missing = [];
	if (input.token === void 0 || input.token === "") missing.push("cfApiToken");
	if (input.accountId === void 0 || input.accountId === "") missing.push("cfAccountId");
	if (input.tunnelId === void 0 || input.tunnelId === "") missing.push("cfTunnelId");
	return missing;
}
/** One configured string, or undefined when it is missing or blank. */
function blankToUndefined(value) {
	if (value === void 0) return void 0;
	const trimmed = value.trim();
	return trimmed === "" ? void 0 : trimmed;
}
/**
* Normalize one web server port into a target or into nothing. A recompose pass
* can hand the plugin a half-read webServer whose port is `NaN` or
* `Infinity`; that is not a port, and treating it as one would either mint a
* `127.0.0.1:NaN` target or leave the caller waiting forever. The host reads
* the port through this, so a non-finite value takes exactly the path an
* unbound one does: the existing port-settle retry re-plans it.
* @param port - the live `ctx.webServer.port`.
* @returns the port, or undefined when it is not a finite number.
*/
function livePortOf(port) {
	return typeof port === "number" && Number.isFinite(port) ? port : void 0;
}
/**
* The one place resolved settings become a sync input, so "which switch turns
* this on" is testable without a cordis context. Three conditions, all
* required: the master switch, the ingress toggle, and the quick tunnel being
* off — a quick tunnel mints a new hostname per start and owns the public base,
* so that deployment has no named tunnel to update and the sync reads as off
* instead of editing an unrelated tunnel.
* @param value - the resolved settings.
* @param port - the bound web server port, undefined before the listener binds.
* @returns the input to schedule.
*/
function ingressInputOf(value, port) {
	return {
		enabled: value.enabled && value.ingressSync === true && value.autoTunnel !== true,
		hostname: hostnameOf$1(value.publicBaseUrl),
		port: livePortOf(port),
		token: blankToUndefined(value.cfApiToken),
		accountId: blankToUndefined(value.cfAccountId),
		tunnelId: blankToUndefined(value.cfTunnelId)
	};
}
/**
* Converge one named tunnel's ingress service onto this host's actual port.
*
* Scheduling is single-flight and generation-guarded: a later schedule (a
* settings save, a port settle) supersedes an in-flight run at its next
* checkpoint — before every request attempt, so a running backoff cannot
* outlive its target, and again immediately before the single PUT. Ports
* arrive late, and a half-read webServer can hand a non-finite number: neither
* one schedules anything, so no request is made and the caller's existing
* port-settle re-plan delivers the real port.
*/
var IngressSync = class {
	http;
	now;
	debounceMs;
	retryBaseMs;
	maxRetries;
	timer;
	onFrame;
	lanHosts;
	current;
	input;
	generation = 0;
	pending = false;
	debounce;
	/** The serialized run chain: one run at a time, queued schedules after it. */
	chain = Promise.resolve();
	/** Whether the chain currently holds a live run (a later schedule only queues). */
	running = false;
	/** Whether the sink has been told about a state yet (the first one always goes out). */
	emitted = false;
	/** The `hostname|port|account|tunnel|token-digest` a read last proved converged. */
	settledKey;
	/** Backoff waits in flight, so a dispose can cut them short. */
	waits = /* @__PURE__ */ new Set();
	disposed = false;
	/**
	* @param options - seams, timings, and the frame sink.
	*/
	constructor(options = {}) {
		this.http = options.fetch ?? defaultIngressFetch;
		this.now = options.now ?? (() => Date.now());
		this.debounceMs = options.debounceMs ?? 300;
		this.retryBaseMs = options.retryBaseMs ?? 500;
		this.maxRetries = options.maxRetries ?? 2;
		this.timer = options.timer ?? nodeTimer$1;
		this.onFrame = options.onFrame ?? (() => void 0);
		this.lanHosts = options.lanHosts ?? lanIPv4Addresses;
		this.current = {
			state: "off",
			at: this.now()
		};
	}
	/** The latest audit frame. */
	get frame() {
		return this.current;
	}
	/**
	* Ask the sync to converge on one input. Safe to call on every settings save
	* and every port settle: an already-converged target is a no-op, and an
	* unchanged schedule does not repeat its frame.
	* @param input - the switch, the target, and the credentials to use.
	*/
	schedule(input) {
		if (this.disposed) return;
		this.input = input;
		if (!input.enabled) {
			this.invalidate();
			this.publish({
				state: "off",
				at: this.now()
			});
			return;
		}
		if (input.hostname === void 0) {
			this.invalidate();
			this.publish({
				state: "failed",
				code: "hostname",
				detail: "ingress sync needs publicBaseUrl to name the fixed public hostname of the named tunnel",
				at: this.now()
			});
			return;
		}
		const port = input.port;
		if (typeof port !== "number" || !Number.isFinite(port)) {
			this.invalidate();
			this.publish({
				state: "waiting",
				hostname: input.hostname,
				at: this.now()
			});
			return;
		}
		const missing = missingConfig(input);
		if (missing.length > 0) {
			this.invalidate();
			this.publish({
				state: "failed",
				code: "not-configured",
				hostname: input.hostname,
				port,
				detail: `ingress sync is on but these settings are empty: ${missing.join(", ")}`,
				at: this.now()
			});
			return;
		}
		if (settleKeyOf(input.hostname, port, input.accountId ?? "", input.tunnelId ?? "", input.token ?? "") === this.settledKey && this.current.state === "applied") return;
		this.generation += 1;
		this.pending = true;
		this.publish({
			state: "waiting",
			hostname: input.hostname,
			port,
			at: this.now()
		});
		this.armDebounce();
	}
	/**
	* Await every run scheduled so far. A test seam: the host never awaits it,
	* and a synchronous timer double makes the whole chain settle immediately.
	* @returns the settled run chain.
	*/
	settled() {
		return this.chain;
	}
	/** Release the timers; an in-flight run finishes its checkpoints as no-ops. */
	dispose() {
		if (this.disposed) return;
		this.disposed = true;
		this.generation += 1;
		this.pending = false;
		this.input = void 0;
		this.settledKey = void 0;
		this.cancelDebounce();
		this.cancelWaits();
	}
	/**
	* Drop every claim this sync holds on a target: a newer generation (so an
	* in-flight run cannot write, settle, or report an applied frame), no queued
	* run, no converged identity, no pending debounce. Every branch of
	* {@link schedule} that ends up without a target calls this, so "there is
	* nothing to converge on" and "the switch is off" are one rule rather than
	* four that can drift apart.
	*/
	invalidate() {
		this.generation += 1;
		this.pending = false;
		this.settledKey = void 0;
		this.cancelDebounce();
	}
	armDebounce() {
		this.cancelDebounce();
		this.debounce = this.timer.setTimeout(() => {
			this.debounce = void 0;
			this.pump();
		}, this.debounceMs);
	}
	cancelDebounce() {
		if (this.debounce === void 0) return;
		this.timer.clearTimeout(this.debounce);
		this.debounce = void 0;
	}
	/**
	* Append one run to the serialized chain. The `running` flag is raised before
	* the link starts, so a schedule that lands while a run is in flight only
	* raises `pending` and the live loop picks it up with the newest generation
	* instead of stacking a second link that would read again after it settled.
	*/
	pump() {
		if (this.running) {
			this.pending = true;
			return;
		}
		this.running = true;
		this.chain = this.chain.then(async () => {
			try {
				if (this.disposed) return;
				do {
					this.pending = false;
					await this.run(this.generation);
				} while (this.pending && !this.disposed);
			} finally {
				this.running = false;
			}
		}).catch((error) => {
			console.warn(`wj-dsh-remote: ingress sync run failed (${error instanceof Error ? error.message : String(error)})`);
		});
	}
	/** One converge attempt toward the current target, superseded by any newer schedule. */
	async run(generation) {
		const input = this.input;
		if (this.disposed || generation !== this.generation) return;
		if (input === void 0 || !input.enabled) return;
		const hostname = input.hostname;
		const port = input.port;
		const token = input.token;
		const accountId = input.accountId;
		const tunnelId = input.tunnelId;
		if (hostname === void 0 || port === void 0) return;
		if (token === void 0 || accountId === void 0 || tunnelId === void 0) return;
		const url = ingressConfigUrl(accountId, tunnelId);
		const target = {
			hostname,
			port,
			allowedHosts: this.lanHosts()
		};
		const key = settleKeyOf(hostname, port, accountId, tunnelId, token);
		const audit = (extra) => ({
			hostname,
			port,
			...extra,
			at: this.now()
		});
		const read = await this.send("GET", url, token, generation);
		if (this.disposed || generation !== this.generation) return;
		if (!read.ok) {
			if (read.code === "stale" || read.code === "disposed") return;
			this.publish(audit({
				state: "failed",
				code: read.code,
				detail: tidy(read.detail)
			}));
			return;
		}
		const config = configOfEnvelope(read.response.body);
		if (config === void 0) {
			this.publish(audit({
				state: "failed",
				code: "config-shape",
				detail: tidy(`the Cloudflare API answered without a tunnel configuration${errorsText(read.response.body)}`)
			}));
			return;
		}
		const plan = planIngressUpdate(config, target);
		if (plan.outcome === "conflict") {
			this.publish(audit({
				state: "conflict",
				code: plan.code,
				detail: tidy(plan.detail)
			}));
			return;
		}
		if (plan.outcome === "unchanged") {
			this.converged(key, audit({
				state: "applied",
				changed: false,
				service: plan.service,
				ruleCount: plan.ruleCount,
				ruleIndex: plan.ruleIndex
			}));
			return;
		}
		if (this.disposed || generation !== this.generation) return;
		const write = await this.send("PUT", url, token, generation, { config: plan.document });
		if (this.disposed || generation !== this.generation) return;
		if (!write.ok) {
			if (write.code === "stale" || write.code === "disposed") return;
			const state = write.code === "write-rejected" ? "conflict" : "failed";
			this.publish(audit({
				state,
				code: write.code,
				detail: tidy(write.detail)
			}));
			return;
		}
		const verify = await this.send("GET", url, token, generation);
		if (this.disposed || generation !== this.generation) return;
		if (!verify.ok) {
			if (verify.code === "stale" || verify.code === "disposed") return;
			this.publish(audit({
				state: "failed",
				code: verify.code,
				detail: tidy(`the write succeeded but its verification read failed: ${verify.detail}`),
				service: plan.to,
				previousService: plan.from,
				ruleCount: plan.ruleCount,
				ruleIndex: plan.ruleIndex,
				changed: true
			}));
			return;
		}
		const verified = configOfEnvelope(verify.response.body);
		const check = verified === void 0 ? void 0 : planIngressUpdate(verified, target);
		if (check === void 0 || check.outcome !== "unchanged") {
			this.publish(audit({
				state: "conflict",
				code: "verify-mismatch",
				detail: tidy("the tunnel configuration read back does not hold the applied service; another writer may own this document, so it is not rewritten"),
				service: plan.to,
				previousService: plan.from,
				ruleCount: plan.ruleCount,
				ruleIndex: plan.ruleIndex,
				changed: true
			}));
			return;
		}
		this.converged(key, audit({
			state: "applied",
			changed: true,
			service: plan.to,
			previousService: plan.from,
			ruleCount: plan.ruleCount,
			ruleIndex: plan.ruleIndex
		}));
	}
	/** Record the converged target identity and publish the frame that says so. */
	converged(key, frame) {
		if (this.disposed) return;
		this.settledKey = key;
		this.publish(frame);
	}
	/**
	* Publish one frame, dropping a repeat that describes the same state. The
	* first publish always goes out, so a sink that starts from nothing learns
	* the current state even when it is the initial `off`.
	*/
	publish(frame) {
		if (this.disposed) return;
		if (this.emitted && sameIngressFrame(this.current, frame)) return;
		this.current = frame;
		this.emitted = true;
		this.onFrame(frame);
	}
	/**
	* One request with the bounded retry policy: 429, 5xx, and a network failure
	* are retried at most {@link DEFAULT_INGRESS_MAX_RETRIES} times; 401/403 and
	* any other 4xx are terminal, because repeating them cannot help.
	*
	* The run's generation is part of the request: it is checked before every
	* attempt, retries included, so a target superseded while a 429/5xx/network
	* backoff was running stops there instead of writing a document for a port
	* this host no longer serves. The answer is `stale` (or `disposed`) and the
	* caller drops it without publishing.
	*/
	async send(method, url, token, generation, body) {
		const headers = {
			authorization: `Bearer ${token}`,
			accept: "application/json"
		};
		if (body !== void 0) headers["content-type"] = "application/json";
		const payload = body === void 0 ? void 0 : JSON.stringify(body);
		let retries = 0;
		let code = "network";
		let detail = "the request could not be made";
		for (;;) {
			if (this.disposed) return {
				ok: false,
				code: "disposed",
				detail: "the sync was disposed"
			};
			if (generation !== this.generation) return {
				ok: false,
				code: "stale",
				detail: "a newer schedule superseded this request"
			};
			let response;
			try {
				response = await this.http({
					method,
					url,
					headers,
					...payload !== void 0 ? { body: payload } : {}
				});
			} catch (error) {
				response = void 0;
				code = "network";
				detail = error instanceof Error ? error.message : String(error);
			}
			if (response !== void 0) {
				const status = response.status;
				if (status === 401) return {
					ok: false,
					code: "unauthorized",
					detail: "the Cloudflare API rejected the token (401)"
				};
				if (status === 403) return {
					ok: false,
					code: "forbidden",
					detail: `the Cloudflare API refused this credential for the tunnel (403)${errorsText(response.body)}`
				};
				if (status < 400) return {
					ok: true,
					response
				};
				if (status !== 429 && status < 500) return {
					ok: false,
					code: method === "PUT" ? "write-rejected" : "http",
					detail: `the Cloudflare API answered ${String(status)}${errorsText(response.body)}`
				};
				code = "http";
				detail = `the Cloudflare API answered ${String(status)}${errorsText(response.body)}`;
			}
			if (retries >= this.maxRetries) return {
				ok: false,
				code,
				detail
			};
			retries += 1;
			await this.wait(this.retryBaseMs * 2 ** (retries - 1));
		}
	}
	/**
	* Wait one backoff step on the injected timer. The wait is tracked so a
	* dispose can release it at once: the interrupted run then wakes, sees the
	* dispose at its next attempt check, and stops instead of sleeping out a
	* backoff nobody is waiting for.
	* @param ms - how long the step lasts.
	* @returns a promise that settles when the step ends or is cancelled.
	*/
	wait(ms) {
		return new Promise((resolve) => {
			const entry = {
				handle: void 0,
				resolve
			};
			this.waits.add(entry);
			entry.handle = this.timer.setTimeout(() => {
				this.waits.delete(entry);
				resolve();
			}, ms);
		});
	}
	/** Release every pending backoff wait (dispose); the interrupted run aborts. */
	cancelWaits() {
		for (const entry of [...this.waits]) {
			this.waits.delete(entry);
			this.timer.clearTimeout(entry.handle);
			entry.resolve();
		}
	}
};
//#endregion
//#region src/device-id.ts
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
/** Unambiguous base32 alphabet (Crockford, lower-case). */
const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
/** File holding the pepper, relative to DSH_HOME. */
const PEPPER_FILE = "wj-dsh-remote-id-pepper";
/**
* Derive the public id of one device.
* @param pepper - per-install secret (32 random bytes).
* @param deviceId - the cookie value / session credential.
* @returns 12-character public identifier.
*/
function publicIdOf(pepper, deviceId) {
	const digest = createHmac("sha256", pepper).update(deviceId).digest();
	let bits = 0;
	let value = 0;
	let out = "";
	for (const byte of digest) {
		value = value << 8 | byte;
		bits += 8;
		while (bits >= 5 && out.length < 6) {
			out += ALPHABET[value >>> bits - 5 & 31];
			bits -= 5;
		}
		if (out.length === 6) break;
	}
	return out;
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
function loadIdPepper(home) {
	const file = join(home, PEPPER_FILE);
	try {
		const raw = readFileSync(file);
		if (raw.length >= 16) return raw;
	} catch {}
	const pepper = randomBytes(32);
	try {
		mkdirSync(dirname(file), { recursive: true });
		const tmp = `${file}.tmp.${process.pid}`;
		writeFileSync(tmp, pepper, { mode: 384 });
		renameSync(tmp, file);
	} catch {}
	return pepper;
}
//#endregion
//#region src/pairing.ts
/**
* Pairing state machine: one active one-time token, a device-session table,
* and presence tracking. Pure TypeScript with injected clock/randomness so
* the whole security semantics are unit-testable without cordis. The
* cordis-facing surfaces (routes, the api/gate listener) live next door.
*
* Security invariants:
* - One active token at a time; `issue()` replaces it, so a refreshed QR
*   immediately invalidates the previous link.
* - A token is a bearer credential for its whole window: it is refused only
*   when unknown, expired, or after `stop()`, and the same link may pair
*   repeatedly within that window (each accept mints a fresh device session).
*   Mobile flows routinely split across cookie contexts (camera preview to
*   in-app browser to the system browser), and the later context must be
*   able to complete its own pairing from the same link.
* - Tokens expire; `accept()` on an expired token is refused like an
*   unknown one (no oracle for validity).
* - `stop()` revokes every device session and clears the token, so paired
*   devices are cut off on their next gated request.
* - `revoke()` drops one device session; idle sessions older than
*   `idleExpireMs` are deleted on sweep, load, and the next gated request.
*/
/**
* Default idle-expiry window: 30 days without a heartbeat or a gated
* request. The reopen service worker refreshes lastSeenAt on every
* navigation it serves, so the window only runs out through genuine
* disuse; 30 days matches the browser-credential lifetimes the surrounding
* flow was built around, while the effective device lifetime stays shorter
* than the 365-day cookie because of this sweep. Override per deployment
* through the idleExpireMs config.
*/
const DEFAULT_IDLE_EXPIRE_MS = 720 * 60 * 60 * 1e3;
/** Cap on the persisted/displayed User-Agent string. */
const MAX_USER_AGENT_CHARS = 180;
/** Cap on a user-defined device name. */
const MAX_DEVICE_NAME_CHARS = 64;
/** Thrown by issue() for an address outside the sampled LAN literals. */
var UnknownLanAddressError = class extends Error {
	/**
	* @param address - the offending literal.
	*/
	constructor(address) {
		super(`wj-dsh-remote: unknown LAN address ${JSON.stringify(address)}`);
		this.name = "UnknownLanAddressError";
	}
};
/** Real clock/entropy: 32 random hex chars per token. */
const defaultClock = {
	now: () => Date.now(),
	randomToken: () => randomBytes(16).toString("hex")
};
/**
* The pairing state machine. Structural mutations issue/accept/stop/revoke
* and config updates (LAN bases, tunnel, posture) notify state listeners
* after the commit point that makes them true, and notification dedupes
* against the last emitted snapshot. Presence-only updates (touchDevice /
* heartbeat) just mark the store dirty and broadcast on the next sweep,
* which also surfaces time-driven transitions (a device aging offline)
* without any mutation.
*/
var PairingService = class {
	config;
	clock;
	fs;
	tokens = /* @__PURE__ */ new Map();
	devices = /* @__PURE__ */ new Map();
	listeners = /* @__PURE__ */ new Set();
	lastEmitted;
	stopped = false;
	tokenSerial = 0;
	/** LAN base URLs keyed by the advertised IP literal (interface order). */
	lanBases = /* @__PURE__ */ new Map();
	/** Public (tunneled) base URL, e.g. a Cloudflare Tunnel quick URL. */
	publicBase;
	/** Auto-tunnel status, while the auto-tunnel feature is active. */
	tunnelStatus;
	relayStatus;
	ingressStatus;
	posture;
	/** True when lastSeenAt changed since the last persist (flushed on sweep). */
	dirty = false;
	/**
	* @param config - tunables. The settings surface replaces the object (a
	* fresh literal) when a committed section changes; every operation reads
	* the current one.
	* @param clock - clock/entropy source (injectable for tests).
	*/
	constructor(config, clock = defaultClock, fs = {}) {
		this.config = config;
		this.clock = clock;
		this.fs = fs;
		this.loadPersisted();
	}
	/**
	* Restore device sessions persisted by a previous process run. A corrupt
	* or missing file is tolerated (an empty device table, never a throw) —
	* persistence is an availability convenience, not a security boundary.
	*
	* Every still-valid session is restored, deliberately without applying
	* `maxDevices`: the constructor runs with whatever cap the configuration
	* layer has delivered so far (the schema default until the saved settings
	* row is applied), and trimming here would permanently drop authorizations
	* the user never revoked — the trimmed table reaches disk on the next
	* heartbeat/sweep write. The cap is enforced where a device is admitted
	* (see `accept`), against the configuration in force at that moment.
	*/
	loadPersisted() {
		const file = this.config.devicesFile;
		if (file === void 0) return;
		try {
			const saved = JSON.parse(readFileSync(file, "utf8"));
			if (typeof saved !== "object" || saved === null) return;
			for (const [deviceId, session] of Object.entries(saved)) {
				if (typeof deviceId !== "string") continue;
				if (typeof session !== "object" || session === null) continue;
				const { createdAt, lastSeenAt, userAgent, name, publicId, level } = session;
				if (typeof createdAt !== "number" || typeof lastSeenAt !== "number") continue;
				const label = typeof userAgent === "string" ? sanitizeUserAgent(userAgent) : void 0;
				const customName = typeof name === "string" ? sanitizeDeviceName(name) : void 0;
				const savedPublicId = typeof publicId === "string" && /^[0-9a-z]{6}$/u.test(publicId) ? publicId : publicIdOf(this.config.idPepper, deviceId);
				const savedLevel = typeof level === "number" && Number.isInteger(level) && level >= 0 && level <= 9 ? level : this.config.defaultDeviceLevel ?? 0;
				this.devices.set(deviceId, {
					createdAt,
					lastSeenAt,
					publicId: savedPublicId,
					level: savedLevel,
					...label !== void 0 ? { userAgent: label } : {},
					...customName !== void 0 ? { name: customName } : {}
				});
			}
			if (this.evictIdle()) this.persistRevocation();
		} catch {}
	}
	/** Drop sessions whose lastSeenAt is older than idleExpireMs. */
	evictIdle() {
		const now = this.clock.now();
		const limit = this.config.idleExpireMs ?? 2592e6;
		let removed = false;
		for (const [id, session] of [...this.devices]) if (now - session.lastSeenAt > limit) {
			this.devices.delete(id);
			removed = true;
		}
		return removed;
	}
	/**
	* Write the current device table to the configured file. Called on the
	* mutation boundaries that change the set of live sessions (accept, stop,
	* revoke, idle eviction) and, throttled, from sweep() so lastSeenAt
	* survives a restart without a write per request.
	*
	* Device ids are session credentials (the gate authorizes requests by the
	* cookie's device id), so the file is written 0600 via a temp file and
	* atomic rename; a crash mid-write can never leave a half-written store.
	*/
	persist() {
		const file = this.config.devicesFile;
		if (file === void 0) return true;
		try {
			mkdirSync(dirname(file), { recursive: true });
			const temp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
			const payload = {};
			for (const [id, session] of this.devices) payload[id] = session;
			writeFileSync(temp, JSON.stringify(payload), { mode: 384 });
			renameSync(temp, file);
			this.dirty = false;
			return true;
		} catch (error) {
			console.error("wj-dsh-remote: failed to persist paired devices", error);
			return false;
		}
	}
	/**
	* Persist a table change that REVOKES access (stop, per-device revoke, idle
	* eviction). A failed write would leave the revoked session on disk, and
	* {@link loadPersisted} restores that file verbatim on the next start — the
	* device's still-valid cookie would authorize again after an explicit
	* revocation. When the write cannot be made durable, the stale store is
	* removed instead (a missing file already loads as an empty table), so the
	* failure costs a re-pair rather than silently undoing the revocation.
	*/
	persistRevocation() {
		if (this.persist()) return;
		const file = this.config.devicesFile;
		if (file === void 0) return;
		try {
			if (this.fs.removeFile !== void 0) this.fs.removeFile(file);
			else rmSync(file, { force: true });
			console.error("wj-dsh-remote: the device revocation could not be persisted; removed the stale device store so a restart cannot restore it");
		} catch (error) {
			console.error("wj-dsh-remote: the device revocation could not be persisted and the stale device store could not be removed", error);
		}
	}
	/** The default LAN base URL (the first interface; undefined when not LAN-reachable). */
	get lanBaseUrl() {
		return this.lanBases.values().next().value;
	}
	/** The LAN base URL for one specific literal (undefined when not constructible). */
	lanBaseUrlFor(address) {
		return this.lanBases.get(address);
	}
	/** The LAN IP literals QR links can be built from (interface order). */
	get lanAddresses() {
		return [...this.lanBases.keys()];
	}
	/** Set the LAN base URLs once the server bind is known (interface order). */
	setLanBases(entries) {
		this.lanBases = new Map(entries.map((entry) => [entry.address, entry.base]));
		this.notify();
	}
	/** The configured public (tunneled) base URL, when present. */
	get publicBaseUrl() {
		return this.publicBase;
	}
	/**
	* Set or clear the public base URL (a tunnel in front of this server). The
	* value is canonicalized to its origin: a trailing slash (what a browser
	* address-bar copy produces) or a path would mint a dead `//wj-pair-accept`
	* link, which WHATWG resolves as an authority rather than a path.
	*/
	setPublicBaseUrl(url) {
		this.publicBase = url === void 0 ? void 0 : canonicalBaseUrl(url);
		this.notify();
	}
	/** Set or clear the auto-tunnel status frame (undefined when the feature is off). */
	setTunnelStatus(status) {
		this.tunnelStatus = status;
		this.notify();
	}
	/** Set or clear the relay-registry status frame (undefined when not in play). */
	setRelayStatus(status) {
		this.relayStatus = status;
		this.notify();
	}
	/** Set or clear the ingress-sync status frame (undefined before it ever ran). */
	setIngressStatus(status) {
		this.ingressStatus = status;
		this.notify();
	}
	/** Set the latest /api posture probe result (see posture.ts). */
	setPosture(snapshot) {
		this.posture = snapshot;
		this.notify();
	}
	/**
	* Issue a fresh token, replacing (invalidating) any previous one. A
	* stopped service re-arms through this call (the panel's refresh button).
	* @param workspaceId - optional workspace the QR link should land in.
	* @param address - optional LAN IP literal the QR must be built from; the
	* default is the public base (when configured) or the first interface.
	* Unknown addresses are refused.
	* @returns the token secret and its expiry.
	* @throws {Error} when no reachable base exists (no non-loopback bind and
	* no public base) — callers surface this as the lan-required state instead
	* of minting an unusable QR.
	*/
	issue(workspaceId, address) {
		if (this.lanBases.size === 0 && this.publicBase === void 0) throw new Error("wj-dsh-remote: pairing requires a reachable bind (--host 0.0.0.0 or publicBaseUrl)");
		if (address !== void 0 && !this.lanBases.has(address)) throw new UnknownLanAddressError(address);
		const now = this.clock.now();
		const token = this.clock.randomToken();
		this.tokens.clear();
		this.stopped = false;
		this.tokenSerial += 1;
		this.tokens.set(token, {
			id: `t${this.tokenSerial}`,
			issuedAt: now,
			expiresAt: now + this.config.tokenTtlMs,
			...workspaceId !== void 0 ? { workspaceId } : {},
			...address !== void 0 ? { address } : {}
		});
		this.notify();
		return {
			token,
			expiresAt: now + this.config.tokenTtlMs
		};
	}
	/**
	* Redeem a token and bind a device session. The token is a bearer
	* credential for its whole window, not a single-use nonce: it is refused
	* only when unknown, past its expiry, or after stop(), and every successful
	* call — including a repeat within the same window — mints a fresh device
	* session (see the module doc for the mobile cookie-context rationale).
	* @param token - the token secret from the QR link.
	* @param userAgent - optional User-Agent header captured at accept.
	* @returns the new device id, or a refusal code.
	*/
	accept(token, userAgent) {
		const record = this.tokens.get(token);
		if (record === void 0 || this.stopped || this.clock.now() > record.expiresAt) return {
			ok: false,
			code: "invalid"
		};
		const deviceId = this.clock.randomToken();
		const now = this.clock.now();
		while (this.devices.size >= this.config.maxDevices) {
			let oldest;
			for (const [id, session] of this.devices) if (oldest === void 0 || session.createdAt < oldest.createdAt) oldest = {
				id,
				createdAt: session.createdAt
			};
			if (oldest === void 0) break;
			this.devices.delete(oldest.id);
		}
		const label = sanitizeUserAgent(userAgent);
		this.devices.set(deviceId, {
			createdAt: now,
			lastSeenAt: now,
			publicId: publicIdOf(this.config.idPepper, deviceId),
			level: this.config.defaultDeviceLevel ?? 0,
			...label !== void 0 ? { userAgent: label } : {}
		});
		this.persist();
		this.notify();
		return {
			ok: true,
			deviceId
		};
	}
	/**
	* Stop remote control: revoke every device session and clear the token.
	* The phone's next gated /api request 403s; the panel falls back to
	* stopped until a fresh QR is issued.
	*/
	stop() {
		this.tokens.clear();
		this.devices.clear();
		this.persistRevocation();
		this.stopped = true;
		this.notify();
	}
	/**
	* Revoke one paired device. The next gated request from that cookie is
	* refused; other sessions stay live. Unknown ids are a no-op.
	* @param deviceId - the cookie value of the device to drop.
	* @returns true when a live session was removed.
	*/
	revoke(deviceId) {
		if (this.stopped) return false;
		const target = this.devices.has(deviceId) ? deviceId : this.idOfPublicId(deviceId);
		if (target === void 0 || !this.devices.delete(target)) return false;
		this.persistRevocation();
		this.notify();
		return true;
	}
	/**
	* Set or clear one device's user-defined name. The label is display
	* metadata only — the device id stays the sole credential — so renaming
	* never widens or narrows what that cookie can reach. A blank name clears
	* the label and restores the User-Agent-derived fallback.
	* @param deviceId - the cookie value of the device to rename.
	* @param name - the new label (cleared when blank after sanitizing).
	* @returns true when a live session was renamed.
	*/
	rename(deviceId, name) {
		const resolved = this.devices.has(deviceId) ? deviceId : this.idOfPublicId(deviceId);
		const session = resolved === void 0 ? void 0 : this.liveSession(resolved);
		if (session === void 0) return false;
		const cleaned = sanitizeDeviceName(name);
		if (cleaned === void 0) delete session.name;
		else session.name = cleaned;
		this.persist();
		this.notify();
		return true;
	}
	/**
	* Collapse pairing records the operator identifies as one physical device:
	* keep the most recently active session and revoke the rest, so repeated
	* scans stop consuming `maxDevices` slots. The survivor keeps its own
	* name when it has one; otherwise it adopts a name from the records being
	* dropped, so collapsing never loses a label the operator typed.
	*
	* Pairing deliberately mints a session per accept (mobile cookie contexts
	* split), so this is an explicit operator action rather than an automatic
	* merge at accept: two different phones can present the same User-Agent,
	* and silently dropping one session would revoke a credential the user
	* never revoked.
	* @param deviceIds - the records to collapse (two or more).
	* @returns the surviving device id, or a refusal when the ids are not a
	*   same-User-Agent group of live sessions.
	*/
	mergeDuplicates(deviceIds) {
		if (this.stopped) return {
			ok: false,
			code: "unknown-device"
		};
		const ids = [...new Set(deviceIds.map((id) => this.devices.has(id) ? id : this.idOfPublicId(id) ?? id))];
		if (ids.length < 2) return {
			ok: false,
			code: "not-duplicates"
		};
		const sessions = [];
		for (const id of ids) {
			const session = this.devices.get(id);
			if (session === void 0) return {
				ok: false,
				code: "unknown-device"
			};
			sessions.push(session);
		}
		if (new Set(sessions.map((session) => session.userAgent ?? "")).size !== 1) return {
			ok: false,
			code: "not-duplicates"
		};
		let keep = 0;
		for (let index = 1; index < ids.length; index += 1) {
			const candidate = sessions[index];
			const current = sessions[keep];
			if (candidate.lastSeenAt > current.lastSeenAt || candidate.lastSeenAt === current.lastSeenAt && candidate.createdAt < current.createdAt) keep = index;
		}
		const survivor = sessions[keep];
		if (survivor.name === void 0) {
			const inherited = sessions.find((session) => session.name !== void 0)?.name;
			if (inherited !== void 0) survivor.name = inherited;
		}
		const keptId = ids[keep];
		for (const id of ids) if (id !== keptId) this.devices.delete(id);
		this.persistRevocation();
		this.notify();
		return {
			ok: true,
			deviceId: keptId
		};
	}
	/**
	* The api/gate path: record activity for a device id and report whether
	* the request may proceed. Unknown or revoked ids (including any device
	* after stop() or idle expiry) are refused.
	*
	* Presence refreshes are throttled on purpose: every gated request (and
	* the mobile SSE keepalive) lands here, so a broadcast per call would fan
	* a full snapshot out to every status stream on the hot path. The refresh
	* only updates lastSeenAt and marks the store dirty; the snapshot reaches
	* listeners at the next sweep() (structural changes notify immediately).
	* @param deviceId - the cookie value of the requesting device.
	* @returns true when the device session is live and was refreshed.
	*/
	touchDevice(deviceId) {
		const session = this.liveSession(deviceId);
		if (session === void 0) return false;
		session.lastSeenAt = this.clock.now();
		this.dirty = true;
		return true;
	}
	/** Explicit presence heartbeat (the phone's client sends these). */
	heartbeat(deviceId) {
		return this.touchDevice(deviceId);
	}
	/**
	* Periodic sweep: drop idle sessions, flush a dirty lastSeenAt, and
	* re-evaluate the derived snapshot (a device aging past the offline
	* window flips the phase to disconnected). Emits only when the snapshot
	* actually changed.
	*/
	sweep() {
		if (this.evictIdle()) this.persistRevocation();
		else if (this.dirty) this.persist();
		this.notify();
	}
	/** The current snapshot (fresh object per call — stable between emits). */
	snapshot() {
		const now = this.clock.now();
		const devices = [...this.devices.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt).map(([id, session]) => this.toDeviceSnapshot(id, session, now));
		const onlineCount = devices.filter((device) => device.online).length;
		const token = this.activeToken();
		return {
			phase: this.derivePhase(onlineCount, token !== void 0),
			lanAvailable: this.lanBases.size > 0,
			lanAddresses: [...this.lanBases.keys()],
			...this.publicBase !== void 0 ? { publicUrl: this.publicBase } : {},
			...this.tunnelStatus !== void 0 ? { tunnel: this.tunnelStatus } : {},
			...this.relayStatus !== void 0 ? { relay: this.relayStatus } : {},
			...this.ingressStatus !== void 0 ? { ingress: this.ingressStatus } : {},
			...this.posture !== void 0 ? { posture: this.posture } : {},
			...token !== void 0 ? {
				tokenId: token.record.id,
				tokenExpiresAt: token.record.expiresAt
			} : {},
			deviceCount: this.devices.size,
			onlineCount,
			devices
		};
	}
	/** Whether a cookie value names a currently live (non-idle) device session. */
	hasDevice(deviceId) {
		return this.liveSession(deviceId) !== void 0;
	}
	/** Public identity (publicId + level) of a live device, or undefined. */
	deviceIdentity(deviceId) {
		const session = this.liveSession(deviceId);
		return session === void 0 ? void 0 : {
			publicId: session.publicId,
			level: session.level
		};
	}
	/** Resolve a public id to its cookie id. */
	idOfPublicId(publicId) {
		for (const [id, session] of this.devices) if (session.publicId === publicId) return id;
	}
	/** Set one device's level (0..9). Returns false for an unknown public id. */
	setLevel(publicId, level) {
		const id = this.idOfPublicId(publicId);
		if (id === void 0) return false;
		const session = this.devices.get(id);
		if (session === void 0) return false;
		session.level = Math.max(0, Math.min(9, Math.trunc(level)));
		this.persist();
		this.notify();
		return true;
	}
	/**
	* Number of device sessions in the table, including idle ones whose idle
	* window has not been swept yet. Restore keeps every persisted session
	* (see `loadPersisted`), so this can exceed the configured cap until the
	* next `accept` trims the excess.
	*/
	deviceCount() {
		return this.devices.size;
	}
	/** Subscribe to snapshot changes (each emit passes a fresh snapshot). */
	onState(listener) {
		this.listeners.add(listener);
		return () => {
			this.listeners.delete(listener);
		};
	}
	activeToken() {
		for (const [token, record] of this.tokens) {
			if (this.stopped) return void 0;
			if (this.clock.now() > record.expiresAt) continue;
			return {
				token,
				record
			};
		}
	}
	/**
	* Return a live session, deleting it first when idle-expired. Side-effecting
	* so a stale cookie cannot pass the gate between sweeps.
	*/
	liveSession(deviceId) {
		if (this.stopped) return void 0;
		const session = this.devices.get(deviceId);
		if (session === void 0) return void 0;
		const limit = this.config.idleExpireMs ?? 2592e6;
		if (this.clock.now() - session.lastSeenAt > limit) {
			this.devices.delete(deviceId);
			this.persistRevocation();
			this.notify();
			return;
		}
		return session;
	}
	toDeviceSnapshot(_id, session, now) {
		return {
			publicId: session.publicId,
			level: session.level,
			createdAt: session.createdAt,
			lastSeenAt: session.lastSeenAt,
			online: this.isOnlineAt(session, now),
			...session.userAgent !== void 0 ? { userAgent: session.userAgent } : {},
			...session.name !== void 0 ? { name: session.name } : {}
		};
	}
	derivePhase(onlineCount, hasToken) {
		if (this.lanBases.size === 0 && this.publicBase === void 0) return "lan-required";
		if (this.stopped) return "stopped";
		if (onlineCount > 0) return "connected";
		if (this.devices.size > 0) return "disconnected";
		if (hasToken) return "waiting";
		return "stopped";
	}
	isOnlineAt(session, now) {
		return now - session.lastSeenAt <= this.config.offlineAfterMs;
	}
	notify() {
		const snapshot = this.snapshot();
		if (this.lastEmitted !== void 0 && snapshotsEqual(this.lastEmitted, snapshot)) return;
		this.lastEmitted = snapshot;
		for (const listener of this.listeners) try {
			listener(snapshot);
		} catch (error) {
			console.error("wj-dsh-remote: pairing state listener failed", error);
		}
	}
};
/** Structural equality over the snapshot's wire fields. */
function snapshotsEqual(a, b) {
	return a.phase === b.phase && a.lanAvailable === b.lanAvailable && sameStrings(a.lanAddresses, b.lanAddresses) && a.publicUrl === b.publicUrl && tunnelEqual(a.tunnel, b.tunnel) && relayEqual(a.relay, b.relay) && ingressEqual(a.ingress, b.ingress) && postureEqual(a.posture, b.posture) && a.tokenId === b.tokenId && a.tokenExpiresAt === b.tokenExpiresAt && a.deviceCount === b.deviceCount && a.onlineCount === b.onlineCount && devicesEqual(a.devices, b.devices);
}
/** Per-device roster equality (order is pairing time). */
function devicesEqual(a, b) {
	return a.length === b.length && a.every((device, index) => {
		const other = b[index];
		return other !== void 0 && device.publicId === other.publicId && device.level === other.level && device.createdAt === other.createdAt && device.lastSeenAt === other.lastSeenAt && device.online === other.online && device.userAgent === other.userAgent && device.name === other.name;
	});
}
/** Tunnel frame equality (undefined equals undefined; fields compared shallowly). */
function tunnelEqual(a, b) {
	return a === b || a !== void 0 && b !== void 0 && a.state === b.state && a.url === b.url && a.error === b.error;
}
/**
* Ingress frame equality: the audit state, not the timestamp. A re-read that
* proves the same convergence must not emit a second snapshot.
* @param a - one frame (or undefined).
* @param b - the other frame (or undefined).
* @returns whether both describe the same audit state.
*/
function ingressEqual(a, b) {
	if (a === b) return true;
	if (a === void 0 || b === void 0) return false;
	return sameIngressFrame(a, b);
}
/** Relay frame equality (same shape as the tunnel frame). */
function relayEqual(a, b) {
	return a === b || a !== void 0 && b !== void 0 && a.state === b.state && a.url === b.url && a.error === b.error;
}
/**
* Posture equality. A probe round can change this frame while every other field
* stays put — the common case, since the probe re-runs on a settings change and
* on a tunnel reaching running, and a quick-tunnel restart churns the probed
* host set. Leaving the frame out of the comparison suppressed those emits, so
* the loopback SSE stream and the desktop panel could sit on a stale "exposed"
* (or stale "clean") verdict for as long as the phase and roster stayed put.
*/
function postureEqual(a, b) {
	if (a === b) return true;
	if (!isPostureFrame(a) || !isPostureFrame(b)) return false;
	return a.checkedAt === b.checkedAt && hostsEqual(a.hosts, b.hosts);
}
/** Whether a value has the shape a posture frame is compared on. */
function isPostureFrame(value) {
	return typeof value === "object" && value !== null;
}
/**
* Per-host posture equality (a round's verdicts, in probe order). Tolerates a
* frame that is not the expected shape: this runs inside the emit path, outside
* the listener error containment, so a malformed snapshot handed in by another
* host-fiber caller must degrade to "changed" instead of throwing out of the
* setter that produced it.
*/
function hostsEqual(a, b) {
	if (a === b) return true;
	if (!Array.isArray(a) || !Array.isArray(b)) return false;
	return a.length === b.length && a.every((host, index) => {
		const other = b[index];
		return isPostureHost(host) && isPostureHost(other) && host.host === other.host && host.exposed === other.exposed;
	});
}
/** Whether a value has the shape one probed host is compared on. */
function isPostureHost(value) {
	return typeof value === "object" && value !== null;
}
/** Element-wise string list equality (interface order is meaningful). */
function sameStrings(a, b) {
	return a.length === b.length && a.every((value, index) => value === b[index]);
}
/**
* Canonical origin of a public base URL. An unparsable value is returned
* verbatim so the caller's malformed-base warning stays the single owner of
* that case.
* @param url - the configured public base.
*/
function canonicalBaseUrl(url) {
	try {
		return new URL(url).origin;
	} catch {
		return url;
	}
}
/** Strip control characters and cap the User-Agent stored with a session. */
function sanitizeUserAgent(raw) {
	if (raw === void 0) return void 0;
	return sanitizeLabel(raw, MAX_USER_AGENT_CHARS);
}
/**
* Strip control characters and cap a user-defined device name. A blank result
* clears the label (undefined), restoring the User-Agent-derived fallback.
* @param raw - the operator's input.
* @returns the cleaned label, or undefined when nothing visible remains.
*/
function sanitizeDeviceName(raw) {
	return sanitizeLabel(raw, MAX_DEVICE_NAME_CHARS);
}
/** Shared cleaner: collapse whitespace/control characters, cap, and blank-to-undefined. */
function sanitizeLabel(raw, max) {
	const cleaned = raw.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim();
	if (cleaned === "") return void 0;
	return cleaned.length <= max ? cleaned : cleaned.slice(0, max);
}
//#endregion
//#region src/dsh-home.ts
/**
* DSH_HOME resolution shared by the plugin family's Host halves: the
* environment override wins, the platform home fallback follows. Mirrors
* what dsh-pet and dsh-liangshen each used to implement locally.
*/
/** Expand a leading ~ (or ~user) in a path, platform-style. */
function expandHome(path, home = homedir()) {
	const j = home.startsWith("/") ? join$1 : join;
	if (path === "~") return home;
	if (path.startsWith("~/") || path.startsWith("~\\")) return j(home, path.slice(2));
	return path;
}
/**
* Resolve the DSH home directory.
* @param env - process environment to read DSH_HOME from.
* @param home - platform home directory fallback (test seam).
* @returns the absolute DSH home path.
*/
function resolveDshHome(env = process.env, home = homedir()) {
	const isPosix = home.startsWith("/");
	const j = isPosix ? join$1 : join;
	const isAbs = isPosix ? isAbsolute$1 : isAbsolute;
	const raw = env.DSH_HOME;
	if (raw !== void 0 && raw.trim() !== "") {
		const expanded = expandHome(raw.trim(), home);
		return isAbs(expanded) ? expanded : j(process.cwd(), expanded);
	}
	return j(home, ".dsh");
}
/** Resolve the DSH home directory from the live environment. */
function dshHome() {
	return resolveDshHome();
}
//#endregion
//#region src/loopback.ts
/** IPv4 127/8 predicate (four decimal octets, first == 127). */
function isIPv4Loopback(v4) {
	const parts = v4.split(".");
	return parts.length === 4 && parts[0] === "127" && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}
/** Whether a socket remote address names the loopback range (127/8, ::1, IPv4-mapped). */
function isLoopbackAddress(address) {
	if (address === void 0) return false;
	const normalized = address.toLowerCase();
	if (normalized === "::1") return true;
	if (normalized.startsWith("::ffff:")) return isIPv4Loopback(normalized.slice(7));
	return isIPv4Loopback(normalized);
}
/** Whether a normalized URL hostname names the loopback authority (localhost, [::1], 127/8). */
function isLoopbackHostname(hostname) {
	if (hostname === "localhost" || hostname === "[::1]") return true;
	return isIPv4Loopback(hostname);
}
/**
* Whether a reverse proxy stood between the client and this host: the request
* carries CF-Connecting-IP or X-Forwarded-For. Either header is stamped by a
* hop that forwards traffic, so the request did not originate on this machine.
* @param request - node HTTP request.
* @returns true when a forwarding header is present.
*/
function isProxiedRequest(request) {
	return request.headers["cf-connecting-ip"] !== void 0 || request.headers["x-forwarded-for"] !== void 0;
}
//#endregion
//#region src/gate.ts
/**
* Read one cookie value from a Cookie header.
* @param header - the raw Cookie header value (or undefined).
* @param name - the cookie name.
* @returns the value, or undefined when absent.
*/
function readCookie(header, name) {
	if (header === void 0) return void 0;
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq < 0) continue;
		if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
	}
}
/**
* The effective Host hostname of a request.
* @param request - node HTTP request.
* @returns the normalized hostname, or undefined when unparsable.
*/
function hostnameOf(request) {
	const host = request.headers.host;
	if (typeof host !== "string") return void 0;
	try {
		return new URL(`http://${host}`).hostname;
	} catch {
		return;
	}
}
/**
* Whether the request arrived at this process over a loopback upstream: a
* loopback socket and a loopback Host header, with the forwarding headers
* deliberately ignored. A reverse proxy (a Cloudflare tunnel, frp, nginx) dials
* 127.0.0.1:<port> and rewrites the Host to that upstream literal, so this is
* the shape of a tunneled request as much as of the desktop one.
*
* It answers "this process is reachable at a loopback authority", never "this
* request is the desktop": the desktop decision is {@link isLoopbackClient},
* which a forwarded request never satisfies. Only the fences that decide whether
* a Host is answerable at all (the pairing status view, the reachability beacon,
* the pairing entry pages) may be built on this predicate; every decision that
* hands out a credential or the desktop payload stays on {@link isLoopbackClient}
* (issue #1919 keeps #1906 shut: reachability for the visitor, payload and
* control plane for the desktop).
* @param request - node HTTP request.
* @returns true when the socket and the Host both name loopback.
*/
function isLoopbackUpstream(request) {
	const hostname = hostnameOf(request);
	if (hostname === void 0 || !isLoopbackHostname(hostname)) return false;
	const socket = request.socket;
	return isLoopbackAddress(socket?.remoteAddress);
}
/**
* Whether a request comes from the desktop loopback client: a loopback upstream
* ({@link isLoopbackUpstream}) reached with no forwarding header. This is the
* same decision the shared copy makes in `isLoopbackRequest` (sans the browser
* same-origin markers, which the /api/wj-pair routes apply separately through
* `isTrustedApiRequest`), and it carries the same proxy rule: a reverse proxy
* rewrites the Host to its own 127.0.0.1:<port> upstream and connects over
* loopback, so a request that arrives with CF-Connecting-IP or X-Forwarded-For
* is a forwarded one and is never the desktop (issue #1906). Every decision
* that grants the desktop payload or a control plane (the api/gate listener,
* the events stream, /api/wj-pair/issue, /api/wj-pair/stop, /api/wj-pair/revoke,
* /api/wj-pair/lan-bind) reads this predicate, so the rule holds for all of them.
* @param request - node HTTP request.
* @returns true for a local desktop request with no proxy in front of it.
*/
function isLoopbackClient(request) {
	if (isProxiedRequest(request)) return false;
	return isLoopbackUpstream(request);
}
/**
* Build the api/gate listener for one pairing service.
* @param service - the pairing service.
* @param requirePairingForLan - when false, non-loopback requests pass
* without a device cookie (the feature then only manages tokens/status;
* revocation of paired devices still holds). A function is re-read per
* request, so a settings edit takes effect without a restart. Defaults to true.
* @param enabled - when false, every non-loopback request is vetoed while
* loopback stays available. A function is re-read per request so the fence
* stays mounted for the plugin lifetime and disabling the plugin cannot open
* a LAN-exposed /api. Defaults to true.
* @returns the cordis waterfall listener: call `next()` to delegate,
* return false (without calling it) to veto with 403.
*/
function makeGateListener(service, requirePairingForLan = true, enabled = true) {
	return (request, _method, next) => {
		if (isLoopbackClient(request)) return next();
		if (!(typeof enabled === "function" ? enabled() : enabled)) return false;
		if (!(typeof requirePairingForLan === "function" ? requirePairingForLan() : requirePairingForLan)) return next();
		return isPairedDeviceRequest(service, request) ? next() : false;
	};
}
/**
* Whether a request carries a live, non-revoked paired-device cookie for
* this service. Sibling host routes outside /api (the right-panel
* /sidebar/* routes, etc.) use the same check via the remoteWebUiPairing service.
* @param service - the pairing service that owns the device table.
* @param request - the incoming HTTP request.
* @returns true when the cookie names a live session (and lastSeenAt was refreshed).
*/
function isPairedDeviceRequest(service, request) {
	const deviceId = readCookie(request.headers.cookie, service.config.cookieName);
	if (deviceId === void 0) return false;
	return service.touchDevice(deviceId);
}
//#endregion
//#region src/pairing-access.ts
/** Named lookup key sibling plugins pass to ctx.get. */
const REMOTE_WEB_UI_PAIRING = "remoteWebUiPairing";
/**
* Pairing identity for one HTTP request. Structural: consumers must not
* import this class, only the method shape.
*/
var RemoteWebUiPairing = class extends Service {
	check;
	/**
	* @param ctx - host plugin context.
	* @param check - live cookie + session predicate (re-read per request).
	*/
	constructor(ctx, check) {
		super(ctx, REMOTE_WEB_UI_PAIRING);
		this.check = check;
	}
	/**
	* Whether the request carries a live paired-device cookie.
	* @param request - the incoming HTTP request.
	* @returns true when the session is live and was refreshed.
	*/
	isPairedDevice(request) {
		return this.check(request);
	}
};
//#endregion
//#region src/http.ts
/** Default body cap for readJsonBody: 64 KiB. */
const DEFAULT_JSON_BODY_MAX_BYTES = 64 * 1024;
/** Family-default JSON response headers; callers may append or override. */
const JSON_HEADERS = {
	"content-type": "application/json; charset=utf-8",
	"referrer-policy": "no-referrer"
};
/**
* Lenient bounded body reader: parse a request body as JSON, or null on an
* empty body, invalid JSON, or a body past maxBytes (default 64 KiB).
* Overflow destroys the request instead of draining the remainder (no drain
* call, matching the current repo-wide behavior); callers must not keep
* reading the request afterwards. With objectOnly, non-JSON-object payloads
* also yield null.
*/
async function readJsonBody(req, opts = {}) {
	const maxBytes = opts.maxBytes ?? DEFAULT_JSON_BODY_MAX_BYTES;
	const chunks = [];
	let size = 0;
	for await (const chunk of req) {
		const buffer = chunk;
		size += buffer.length;
		if (size > maxBytes) {
			req.destroy();
			return null;
		}
		chunks.push(buffer);
	}
	const text = Buffer.concat(chunks).toString("utf8");
	if (text === "") return null;
	try {
		const parsed = JSON.parse(text);
		if (opts.objectOnly && !isJsonObject(parsed)) return null;
		return parsed;
	} catch {
		return null;
	}
}
/** Whether a value is a JSON object: typeof object, not null, not an array. */
function isJsonObject(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/**
* Request init that asks a remote origin for an uncompressed body.
*
* The DSH host boots `@deepseek-ai/dsh-http-proxy`, whose top-level import of
* the npm `undici` copy replaces the legacy `undici.globalDispatcher.1` slot
* Node's built-in `fetch()` reads. That cross-major wrapper drops the
* `content-encoding` header and automatic decompression, so a plain fetch
* resolves to raw gzip/brotli/zstd bytes — compressed noise no JSON or text
* consumer can read. Every host fetch that parses a remote body must request
* identity encoding. Caller headers survive; `accept-encoding` is forced to
* `identity` because a caller value has no decoder behind it in this host.
* @param init - the caller's request init (signal, headers, method, ...).
* @returns a copy with `accept-encoding: identity` merged in.
*/
function withIdentityEncoding(init = {}) {
	const headers = new Headers(init.headers);
	headers.set("accept-encoding", "identity");
	return {
		...init,
		headers
	};
}
/**
* Write one JSON response. Default headers are the family defaults
* (content-type and referrer-policy); caller headers are appended or
* override them.
*/
function writeJson(res, status, body, headers = {}) {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		...JSON_HEADERS,
		...headers
	});
	res.end(payload);
}
/**
* Build the grant table. Pure TypeScript with injected clock/randomness so the
* whole one-time semantics are unit-testable without a server.
*/
function createPairGrantStore(options = {}) {
	const ttlMs = options.ttlMs ?? 6e4;
	const now = options.now ?? (() => Date.now());
	const createGrant = options.createGrant ?? (() => randomBytes(32).toString("base64url"));
	const entries = /* @__PURE__ */ new Map();
	const purgeExpired = (at) => {
		for (const [grant, entry] of entries) if (entry.expiresAt <= at) entries.delete(grant);
	};
	return {
		issue(deviceId) {
			const issuedAt = now();
			purgeExpired(issuedAt);
			while (entries.size >= 256) {
				const oldest = entries.keys().next().value;
				if (oldest === void 0) break;
				entries.delete(oldest);
			}
			const grant = createGrant();
			const expiresAt = issuedAt + ttlMs;
			entries.set(grant, {
				deviceId,
				expiresAt
			});
			return {
				grant,
				expiresAt
			};
		},
		consume(grant) {
			if (grant === void 0 || grant === "") return void 0;
			const consumedAt = now();
			const entry = entries.get(grant);
			entries.delete(grant);
			purgeExpired(consumedAt);
			if (entry === void 0 || entry.expiresAt <= consumedAt) return void 0;
			return entry.deviceId;
		},
		peek(grant) {
			if (grant === void 0 || grant === "") return void 0;
			const at = now();
			const entry = entries.get(grant);
			if (entry === void 0) return void 0;
			if (entry.expiresAt <= at) {
				entries.delete(grant);
				return;
			}
			return entry.deviceId;
		},
		get size() {
			return entries.size;
		}
	};
}
//#endregion
//#region src/remote-methods.ts
/**
* Remote desktop channel constants — SDK-independent so tests and the
* client half can pin them without importing the host SDK graph.
*
* Access model on the 0.1.2-alpha.2 line: the host /api surface has no
* per-method privilege pin — the "configuration plane is local" behavior
* lives in the browser (client plugins branch on connection.isLoopback), and
* the paired remote desktop flips into host mode via the transport hook
* (ownsHost) while every call rides this gated channel as a loopback-shaped
* request. A paired device is therefore a full-control credential by
* design; the only paths that stay physically local are the control planes
* below (pairing control, self-update, plugin install/remove, host power).
*/
/** Gated mirror of same-origin fenced paths (`/wj-remote` + original pathname). */
const REMOTE_PREFIX$1 = "/wj-remote";
/** Connection-plugin method prefix under the gated channel. */
const REMOTE_API_PREFIX$1 = `${REMOTE_PREFIX$1}/api`;
/**
* Exact upgrade paths registered on webServer (the SDK matches upgrades by
* exact path, not prefix). Query strings ride on the request URL.
*/
const REMOTE_UPGRADE_PATHS = [
	{ mux: `${REMOTE_API_PREFIX$1}/remote.mux` }.mux,
	`${REMOTE_PREFIX$1}/sidebar/ws/terminal`,
	`${REMOTE_PREFIX$1}/sidebar/ws/agent-terminals`,
	`${REMOTE_PREFIX$1}/sidebar/ws/agent-opens`,
	`${REMOTE_API_PREFIX$1}/dsh-ssh/terminal`
];
/** Plugin-manager HTTP prefix: install/remove stay physically local. */
const PLUGIN_MANAGER_PATH = "/api/plugin-manager";
/**
* The cookieless device credential: the boot patch reads the device id from
* the /wj-pair-app URL, keeps it in sessionStorage, and attaches it to every
* gated HTTP call as this header (and to WebSocket upgrades as the `device`
* query parameter - WS handshakes cannot carry headers from the Web API).
* The channel gate accepts it exactly like the device cookie, so the mobile
* flow works even with browser cookies fully blocked; the cookie remains the
* primary credential on normal browsers.
*/
const REMOTE_DEVICE_HEADER = "x-wj-remote-device";
const REMOTE_DEVICE_QUERY = "device";
/**
* Path prefixes that stay physically local even for a paired device. A
* paired remote desktop may use the full host API (chat, sessions,
* settings, credentials, presets — it is a full-control credential), but it
* must not reach the machine-control planes: pairing control itself, the
* dsh-web self-update installer, and plugin install/remove.
*/
const LOCAL_ONLY_PREFIXES = ["/api/update", PLUGIN_MANAGER_PATH];
/**
* Header the channel stamps with the authenticated device id. The pairing
* handlers trust it only behind the channel's own loopback re-issue; client
* requests carrying it are stripped by the proxy.
*/
const REMOTE_ACTOR_HEADER = "x-wj-remote-actor";
/**
* Whether a paired inner path must stay physically local.
* @param innerPath - the rewritten inner path (e.g. `/api/session.list`).
* @returns a denial message, or undefined when the path may be proxied.
*/
function localOnlyDenial(innerPath) {
	for (const prefix of LOCAL_ONLY_PREFIXES) if (innerPath === prefix || innerPath.startsWith(`${prefix}/`)) return `${prefix.slice(1)} stays physically local and stays unreachable from a paired remote desktop`;
}
//#endregion
//#region src/remote-channel-rules.ts
/**
* The remote-channel rewrite contract as pure data (issue #987): both the
* browser patch (client/remote-channel.ts) and the parse-time boot patch
* (remote-channel-boot.ts, inlined into index.html by the host) decide from
* these tables, so the two can never drift apart.
* @module wj-dsh-remote/remote-channel-rules
*/
/** The gated mirror prefix (must match src/remote-methods.ts). */
const REMOTE_PREFIX = "/wj-remote";
/**
* The schemes that can deliver a page a remote party controls: the network
* transports, plus the documents a network page can mint. Every other scheme
* is registered and served by an application on this machine, so its page is
* the machine's own page whatever the application calls the scheme.
*
* The list is deliberately the *web* side rather than an allowlist of known
* desktop shells. The official DSH Desktop shell serves its Web GUI from
* `dsh-app://app/` (`location.hostname === 'app'`), which no hostname
* predicate can recognise; a scheme allowlist fixed that instance (#1682) but
* left the next shell — or a `file:` page — fenced behind a pairing page it
* can never complete, because a pairing link is reachable only over the
* network. Naming the web side instead makes an unknown application scheme
* local by construction.
*
* `blob:`, `data:`, `about:` and `filesystem:` stay on the web side: a
* network page mints those documents, so they must keep the fence.
*/
const WEB_PAGE_PROTOCOLS = [
	"http:",
	"https:",
	"blob:",
	"data:",
	"about:",
	"filesystem:"
];
/**
* The window global the device-gated app landing publishes to grant host mode.
* Set by the /wj-pair-app capture script, read by the parse-time boot patch: the
* transport hook (ownsHost) is server-granted, not asserted from the origin.
*/
const REMOTE_HOST_GRANT_GLOBAL = "__DSH_REMOTE_HOST_GRANT__";
/** The live rule set. */
const REMOTE_CHANNEL_RULES = {
	remotePrefix: REMOTE_PREFIX,
	apiPrefix: "/api/",
	pairPrefix: "/api/wj-pair/",
	updatePrefix: "/api/update/",
	settingsBridgePrefix: "/api/dsh-web-ui-settings",
	sidebarPrefix: "/sidebar/",
	gitPrefix: "/git/",
	petPrefix: "/pet/",
	wsPaths: [
		"/api/remote.mux",
		"/sidebar/ws/terminal",
		"/sidebar/ws/agent-terminals",
		"/sidebar/ws/agent-opens",
		"/api/dsh-ssh/terminal"
	],
	deviceHeader: REMOTE_DEVICE_HEADER,
	deviceKey: "wj-remote-device",
	deviceQuery: REMOTE_DEVICE_QUERY,
	uploadPath: "/api/session/uploadFileBinary",
	uploadHookGlobal: "__DSH_FILE_UPLOAD__",
	webProtocols: WEB_PAGE_PROTOCOLS,
	hostGrantGlobal: REMOTE_HOST_GRANT_GLOBAL
};
/** The window global the boot patch publishes its seat under. */
const REMOTE_CHANNEL_BOOT_GLOBAL = "__DSH_REMOTE_CHANNEL_BOOT__";
//#endregion
//#region src/lan-source.ts
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
const LAN_SOURCE_STORAGE_KEY = "dsh-remote-lan-source";
/**
* How recently a LAN hop must have been taken for a return to a non-LAN origin
* to read as "the hop did not stick". A phone that fails to load the LAN page
* re-scans the QR (which always names the public base) within seconds, and the
* landing then has to choose the public source instead of hopping again into
* the same black hole; a deliberate return much later is a fresh decision and
* re-probes.
*/
const LAN_SOURCE_RETRY_WINDOW_MS = 12e4;
/**
* Build the inline script that runs the source decision on the landing page.
* Reads every browser global through `window`, so a test can run it against
* one fake object (the same seam the parse-time boot patch uses).
* @param hop - the probe payload for this landing render.
* @returns the `<script>` element to splice into the landing's head.
*/
function appShellLanSwitchScript(hop) {
	return `<script>${"(function(){try{var w=window,loc=w.location;var P=" + JSON.stringify({
		key: LAN_SOURCE_STORAGE_KEY,
		candidates: hop.candidates,
		path: hop.path,
		ping: hop.pingPath,
		grant: hop.grant,
		timeout: 800,
		retry: LAN_SOURCE_RETRY_WINDOW_MS
	}) + ";var S=w.sessionStorage;P.sig=P.candidates.join(\",\");function rd(){try{var raw=S.getItem(P.key);if(typeof raw!==\"string\"||raw===\"\")return undefined;var d=JSON.parse(raw);if(typeof d!==\"object\"||d===null)return undefined;if(d.src!==\"lan\"&&d.src!==\"public\")return undefined;if(typeof d.sig!==\"string\"||typeof d.at!==\"number\")return undefined;return d}catch(e){return undefined}}function wr(d){try{S.setItem(P.key,JSON.stringify(d))}catch(e){}}function own(){for(var i=0;i<P.candidates.length;i++){if(P.candidates[i]===loc.origin)return true}return false}function go(base){try{loc.replace(base+P.path+\"?grant=\"+encodeURIComponent(P.grant))}catch(e){}}function probe(){if(typeof w.fetch!==\"function\")return;var settled=false;var timer=w.setTimeout(function(){finish(undefined)},P.timeout);function finish(base){if(settled)return;settled=true;try{w.clearTimeout(timer)}catch(e){}if(base===undefined){wr({src:\"public\",sig:P.sig,at:Date.now()});return}wr({src:\"lan\",sig:P.sig,base:base,at:Date.now()});go(base)}for(var i=0;i<P.candidates.length;i++){(function(base){var sent;try{sent=w.fetch(base+P.ping,{mode:\"no-cors\",cache:\"no-store\",credentials:\"omit\",referrerPolicy:\"no-referrer\"})}catch(e){sent=undefined}if(sent===undefined||typeof sent.then!==\"function\")return;sent.then(function(){finish(base)},function(){})})(P.candidates[i])}}var d=rd();if(own()){if(d===undefined||d.sig!==P.sig)wr({src:\"lan\",sig:P.sig,base:loc.origin,at:Date.now()});return}if(d!==undefined&&d.sig===P.sig){if(d.src===\"public\")return;if(Date.now()-d.at<P.retry){wr({src:\"public\",sig:P.sig,at:Date.now()});return}}probe()}catch(e){}})();"}<\/script>`;
}
//#endregion
//#region src/routes.ts
/**
* Whether one configured authority names the URL's authority: a port-less
* entry matches the hostname on any port, an exact `host:port` entry matches
* that authority verbatim (WHATWG normalization both sides). A malformed entry
* (a config or DSH_REMOTE_TRUSTED_HOSTS typo) contributes no trust instead of
* throwing out of the fence, so the valid entries are still consulted.
* @param entry - one `host` or `host:port` literal this surface serves.
* @param url - the parsed authority to match.
* @returns true when the entry names that authority.
*/
function matchesAuthority(entry, url) {
	let entryUrl;
	try {
		entryUrl = new URL(`http://${entry}`);
	} catch {
		return false;
	}
	return entryUrl.port === "" ? entryUrl.hostname === url.hostname : entryUrl.host === url.host;
}
/**
* Browser-trust fence for the /api/wj-pair routes, mirroring the connection
* package's internal fence semantics (Host/Origin based, DNS-rebinding and
* cross-site defense). The connection package no longer exports its trust
* predicate — the fence for the /api prefix lives inside the connection
* plugin — so the pairing routes, which must stay reachable from LAN phones
* ahead of the connection prefix route (exact routes match first), carry
* their own copy scoped to the literals the QR links advertise.
* @param request - the node HTTP request.
* @param trustedHosts - non-loopback authorities this surface serves: exact
* `host:port`, or port-less `host` matching any port.
* @returns true when the Host is ours (a loopback upstream or a trusted
* authority) and any attached browser markers are same-origin.
*/
function isTrustedApiRequest(request, trustedHosts) {
	if (!isTrustedHost(request, trustedHosts)) return false;
	if (request.headers["sec-fetch-site"] === "cross-site") return false;
	const origin = request.headers.origin;
	if (origin === void 0) return true;
	let originUrl;
	let hostUrl;
	try {
		originUrl = new URL(origin);
		hostUrl = new URL(`http://${request.headers.host ?? ""}`);
	} catch {
		return false;
	}
	if (originUrl.host === hostUrl.host) return true;
	if (!isProxiedRequest(request) || !isLoopbackUpstream(request)) return false;
	return trustedHosts.some((entry) => matchesAuthority(entry, originUrl));
}
/**
* Whether the request's Host is an authority this surface answers at all: a
* loopback upstream (the desktop, or a reverse proxy dialing the loopback
* literal) or a trusted entry (exact `host:port`, or port-less `host` matching
* any port). The browser-marker checks stay in {@link isTrustedApiRequest}: a
* pairing entry page is a navigation, and its authority is the token or device
* credential it carries, not who linked to it.
*
* This is reachability, not authorization: the desktop payload and every
* credential-bearing control plane ask {@link isLoopbackClient} (no forwarding
* header) instead, so a tunnel visitor becomes answerable without becoming the
* desktop (#1919 closes the reachability bug while #1906 keeps the leak shut).
* @param request - the node HTTP request.
* @param trustedHosts - non-loopback authorities this surface serves.
* @returns true when the Host is ours.
*/
function isTrustedHost(request, trustedHosts) {
	const host = request.headers.host;
	if (typeof host !== "string") return false;
	let hostUrl;
	try {
		hostUrl = new URL(`http://${host}`);
	} catch {
		return false;
	}
	return isLoopbackUpstream(request) || trustedHosts.some((entry) => matchesAuthority(entry, hostUrl));
}
/**
* Whether the request is a top-level document navigation — the shape every
* phone uses to open a pairing link. Browsers label it `Sec-Fetch-Mode:
* navigate` with `Sec-Fetch-Dest: document`; in-app browsers (WeChat, and
* anything else wrapping a WKWebView) additionally attach `Sec-Fetch-Site:
* cross-site` or an opaque `Origin: null`, which the API fence must keep
* refusing but which says nothing about a document navigation: the pairing
* token or the device id in the URL is what authorizes it.
* @param request - the node HTTP request.
* @returns true for a top-level document navigation.
*/
function isTopLevelDocumentNavigation(request) {
	return request.headers["sec-fetch-mode"] === "navigate" && request.headers["sec-fetch-dest"] === "document";
}
/**
* Test whether a hostname represents a private local-area network (RFC 1918 / ULA / mDNS / loopback).
* Supports pairing in container-bridged (Docker) or NAT-proxied topologies where the host
* machine's LAN IP or proxy domain differs from the container's internal sampled network interface.
*/
function isPrivateOrLocalHostname(hostname) {
	const normalized = hostname.toLowerCase().trim();
	if (normalized === "localhost" || normalized.endsWith(".local") || normalized.endsWith(".lan") || normalized.endsWith(".internal") || normalized.endsWith(".home.arpa")) return true;
	let ip = normalized;
	if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
	if (ip === "::1" || ip === "127.0.0.1") return true;
	if (ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80")) return true;
	const parts = ip.split(".").map(Number);
	if (parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
		const [a, b] = parts;
		if (a === 10) return true;
		if (a === 127) return true;
		if (a === 169 && b === 254) return true;
		if (a === 172 && b >= 16 && b <= 31) return true;
		if (a === 192 && b === 168) return true;
	}
	return false;
}
/**
* Validates that an incoming request is non-cross-site (rejects cross-site fetch metadata
* and ensures Origin matches Host when present).
*/
function isNonCrossSite(request) {
	if (request.headers["sec-fetch-site"] === "cross-site") return false;
	const host = request.headers.host;
	if (typeof host !== "string") return false;
	const origin = request.headers.origin;
	if (origin === void 0) return true;
	try {
		const originUrl = new URL(origin);
		const hostUrl = new URL(`http://${host}`);
		return originUrl.host === hostUrl.host;
	} catch {
		return false;
	}
}
/**
* The private-LAN fallback authority of a request: its Host header when the
* hostname is private/local (RFC 1918 / ULA / mDNS / loopback) and the
* browser markers are non-cross-site, else undefined. The accept paths and
* the lanFence fallback use this to serve container-bridged and reverse-proxy
* topologies whose Host is not among the advertised or configured authorities.
*/
function privateLanHostOf(request, navigation = false) {
	const host = request.headers.host;
	if (typeof host !== "string") return void 0;
	let hostName = "";
	try {
		hostName = new URL(`http://${host}`).hostname;
	} catch {
		return;
	}
	if (hostName === "" || !isPrivateOrLocalHostname(hostName)) return void 0;
	if (!(navigation && isTopLevelDocumentNavigation(request)) && !isNonCrossSite(request)) return void 0;
	return host;
}
/** Cap on pairing request bodies (tokens and workspace ids are tiny). */
const MAX_BODY_BYTES = 4096;
/**
* The rate-limit bucket key for one accept attempt (pure; unit-tested).
* A forwarded hop separates buckets behind the auto-tunnel (every internet
* client arrives from 127.0.0.1 there) — but only for loopback peers, since a
* direct LAN client can rotate the header freely. The caller passes the hop it
* trusts (the edge-appended LAST one; see rateLimitAccept), and the hop is
* truncated so one oversized header cannot mint a huge key.
* @param socketIp - the socket peer address.
* @param forwarded - the trusted XFF hop, already trimmed, if any.
* @param bucket - page (GET /wj-pair-accept) vs api (POST /api/wj-pair/accept).
*/
function acceptLimitKey(socketIp, forwarded, bucket) {
	if (isLoopbackAddress(socketIp) && forwarded !== void 0 && forwarded !== "") return `${bucket}|${socketIp}|${forwarded.slice(0, MAX_FORWARDED_KEY_CHARS)}`;
	return `${bucket}|${socketIp}`;
}
/** Longest forwarded hop kept in a bucket key (the header is caller-sized). */
const MAX_FORWARDED_KEY_CHARS = 64;
/**
* Hard cap on live accept buckets. The key is caller-influenced (a forwarded
* hop), so a rotating flood must not grow the table without bound: past the
* cap the oldest bucket is evicted, the same FIFO stance as
* {@link addBounded}. A legitimate client that loses its bucket merely starts
* a fresh window.
*/
const MAX_ACCEPT_BUCKETS = 1024;
/**
* Reasons a phone-facing entry page refused a request, logged once per shape
* so a real device failure is diagnosable from the host console without a
* debug build. Keyed by `reason|host|path`; bounded by construction (a handful
* of reasons, and only the first occurrence of each is printed).
*/
const loggedEntryRefusals = /* @__PURE__ */ new Set();
/**
* Log one entry-page refusal (first occurrence per shape) and cap the set.
* @param request - the refused request.
* @param path - the entry path that refused it.
* @param reason - why the fence refused.
*/
function logEntryRefusal(request, path, reason) {
	const key = `${reason}|${request.headers.host ?? ""}|${path}`;
	if (loggedEntryRefusals.has(key) || loggedEntryRefusals.size >= 64) return;
	loggedEntryRefusals.add(key);
	const markers = [
		`sec-fetch-site=${request.headers["sec-fetch-site"] ?? "-"}`,
		`sec-fetch-mode=${request.headers["sec-fetch-mode"] ?? "-"}`,
		`sec-fetch-dest=${request.headers["sec-fetch-dest"] ?? "-"}`,
		`origin=${request.headers.origin ?? "-"}`
	].join(" ");
	console.log(`wj-dsh-remote: refused ${path} from host ${request.headers.host ?? "-"} (${reason}; ${markers})`);
}
/**
* FIFO-bounded Set insert: past `max` entries the oldest one is evicted
* (a Set iterates in insertion order). The dynamic trusted-host table is fed
* by caller-controlled Host headers, so it must stay bounded; an evicted
* legitimate host re-adds itself on that device's next gated request.
*/
function addBounded(set, value, max) {
	if (set.has(value)) return;
	if (set.size >= max) {
		const oldest = set.values().next().value;
		if (oldest !== void 0) set.delete(oldest);
	}
	set.add(value);
}
/**
* The host authority of a configured public base URL, e.g. `foo.trycloudflare.com`
* from `https://foo.trycloudflare.com`. Undefined when the URL does not parse —
* a malformed config then simply contributes no fence entry (and the panel
* falls back to LAN-only URLs).
* @param url - the configured public base URL (or undefined).
* @returns the `host[:port]` authority the fence should trust.
*/
function publicHostOf(url) {
	if (url === void 0) return void 0;
	try {
		return new URL(url).host;
	} catch {
		return;
	}
}
/** Cookie lifetime: one year; revoked sessions die at the gate regardless. */
const COOKIE_MAX_AGE_SEC = 365 * 24 * 60 * 60;
/**
* The cookieless device credential: pass the device id from the /wj-pair-app
* URL into sessionStorage (and localStorage for tab reloads) before any app
* script runs - same key the boot patch and the channel gate read. The
* replaceState drops the one-time grant from the address bar and leaves the
* SPA on a path this plugin answers again; which path depends on the origin.
*
* A secure context registers the reopen service worker in the same breath,
* and that worker owns navigations to '/', so the SPA keeps its canonical
* root. A plain-HTTP LAN origin is never a secure context, so the worker
* cannot exist there and '/' falls through to the harness index gate the
* cookieless flow can never satisfy (issue #1867). The address bar therefore
* keeps the plugin-owned landing path, which re-validates the device
* credential on every reload and serves the bilingual re-pair page once the
* pairing is gone. Both targets are bare paths: the one-time grant never
* survives the rewrite, and no credential is ever left in the URL.
*/
const APP_DEVICE_STORAGE_KEY = "wj-remote-device";
function appShellCaptureScript(deviceId) {
	const safeId = JSON.stringify(deviceId);
	const grantGlobal = JSON.stringify(REMOTE_HOST_GRANT_GLOBAL);
	const reopenPath = JSON.stringify(PAIR_PATHS.appPage);
	const register = `try{if('serviceWorker' in navigator){navigator.serviceWorker.register(${JSON.stringify(PAIR_PATHS.appServiceWorker)},{scope:'/'}).catch(function(e){})}}catch(e){}`;
	return `<script>(function(){try{sessionStorage.setItem(${JSON.stringify(APP_DEVICE_STORAGE_KEY)},${safeId});}catch(e){}try{history.replaceState(null,'',window.isSecureContext?'/':${reopenPath})}catch(e){}try{window[${grantGlobal}]=true}catch(e){}${register}})()<\/script>`;
}
/**
* Patch the official index document with the device-capture script. The script
* goes immediately after the opening <head> tag, ahead of the harness-injected
* parse-time channel boot patch: that patch installs the transport host-mode
* hook only when this server-served marker is already set (see
* remote-channel-boot.ts), so host mode is granted by the device-gated landing
* instead of being asserted from the origin.
*
* A landing reached on a base other than the machine's own LAN origin also
* carries the source-decision script (lan-source.ts): the phone decides at
* connect time whether a LAN candidate answers, and switches its origin when
* one does. It runs after the capture script so the granted page is fully
* usable before the probe's outcome can move it.
* @param html - the official index document.
* @param deviceId - the device session this landing is being served for.
* @param hop - the LAN candidates to probe, when a switch is possible.
* @returns the patched document.
*/
function patchAppShell(html, deviceId, hop) {
	const script = appShellCaptureScript(deviceId) + (hop === void 0 ? "" : appShellLanSwitchScript(hop));
	const head = /<head[^>]*>/i.exec(html);
	if (head === null) return script + html;
	const end = head.index + head[0].length;
	return html.slice(0, end) + script + html.slice(end);
}
/**
* The reopen service worker served at PAIR_PATHS.appServiceWorker. A paired
* phone comes back to `/` from history, bookmarks, or tab restore; the
* harness fallback seat answers that navigation with its browser-auth 401,
* and the cookieless mobile flow never holds a browser-auth cookie. The
* worker owns navigations to `/` instead: network-first through /wj-pair-app
* (which validates the device cookie and refreshes its presence), the
* cached shell for offline opens, and a pass-through of the original
* request when the plugin no longer answers. A plain-HTTP LAN origin is
* never a secure context, so the worker cannot exist there; the capture
* script keeps the plugin-owned landing path in the address bar instead,
* and that landing re-validates the device credential on every reload.
*
* Kept as a plain string (same pattern as the capture script): it must load
* with no build step, run on every JS engine that ships service workers,
* and be assertable as source in tests. Bump SHELL_CACHE when the storage
* layout changes so old caches are pruned on activate.
*/
function appServiceWorkerScript() {
	return `'use strict';
var SHELL_CACHE = 'dsh-remote-shell-v1';
var SHELL_KEY = '/dsh-remote-shell';
var APP_URL = '/wj-pair-app';
self.addEventListener('install', function (event) {
  event.waitUntil(refreshShell().then(function () { return self.skipWaiting(); }));
});
self.addEventListener('activate', function (event) {
  event.waitUntil(self.caches.keys().then(function (names) {
    return Promise.all(names.map(function (name) {
      return name === SHELL_CACHE ? Promise.resolve() : self.caches.delete(name);
    }));
  }).then(function () { return self.clients.claim(); }));
});
self.addEventListener('fetch', function (event) {
  var request = event.request;
  if (request.method !== 'GET' || request.mode !== 'navigate') return;
  var path;
  try { path = new URL(request.url).pathname; } catch (error) { return; }
  if (path !== '/') return;
  event.respondWith(reopen(event));
});
/* Network-first: a live pairing gets the current shell (the /wj-pair-app check
   refreshes lastSeenAt, so every reopen also keeps the session alive); a
   refused shell passes the original navigation through for the harness's
   own response; an unreachable server falls back to the cached shell. */
function reopen(event) {
  var request = event.request;
  return fetch(APP_URL, { credentials: 'same-origin', cache: 'no-store' }).then(function (response) {
    if (!response.ok) return fetch(request);
    var copy = response.clone();
    event.waitUntil(self.caches.open(SHELL_CACHE).then(function (cache) {
      return cache.put(SHELL_KEY, copy);
    }));
    return response;
  }, function () {
    return self.caches.match(SHELL_KEY).then(function (cached) {
      return cached !== undefined ? cached : fetch(request);
    });
  });
}
/* Best-effort shell warm-up and refresh; never rejects. */
function refreshShell() {
  return fetch(APP_URL, { credentials: 'same-origin', cache: 'no-store' }).then(function (response) {
    if (!response.ok) return undefined;
    var copy = response.clone();
    return self.caches.open(SHELL_CACHE).then(function (cache) {
      return cache.put(SHELL_KEY, copy);
    });
  }, function () { return undefined; });
}`;
}
/**
* The dead-end guard for a failed /wj-pair-accept and for a dead reopen (the
* reopen service worker serves this page at `/` when the pairing no longer
* passes): a device without a live pairing has no harness browser-auth
* cookie, so a redirect to bare `/` would land on the harness browser-auth
* 401 page ("authentication required"), which reads like a broken server.
* Serve a plain bilingual explanation instead; an already-paired device (live
* device cookie, browser credential redeemed during its first scan) keeps
* the old behavior and is sent on to the app.
*/
function pairingFailurePage() {
	return [
		"<!doctype html><html><head><meta charset=\"utf-8\">",
		"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
		"<meta name=\"referrer\" content=\"no-referrer\">",
		"<title>Pairing link invalid</title></head>",
		"<body style=\"font-family:system-ui,sans-serif;padding:24px;max-width:32em;margin:0 auto;line-height:1.6\">",
		"<p><strong>配对已失效，或配对链接已过期。</strong></p>",
		"<p>请在桌面端打开远程控制面板，刷新二维码后重新扫码；重新配对后本机即可恢复访问。</p>",
		"<hr style=\"border:none;border-top:1px solid #ccc;margin:16px 0\">",
		"<p><strong>This pairing has expired or the link is no longer valid.</strong></p>",
		"<p>Open the remote panel on the desktop, refresh the QR code, and scan again — re-pairing restores access on this device.</p>",
		"</body></html>"
	].join("");
}
/** Route paths (exact matches under /api). */
const PAIR_PATHS = {
	issue: "/api/wj-pair/issue",
	me: "/api/wj-pair/me",
	level: "/api/wj-pair/level",
	accept: "/api/wj-pair/accept",
	stop: "/api/wj-pair/stop",
	revoke: "/api/wj-pair/revoke",
	rename: "/api/wj-pair/rename",
	merge: "/api/wj-pair/merge",
	heartbeat: "/api/wj-pair/heartbeat",
	status: "/api/wj-pair/status",
	events: "/api/wj-pair/events",
	lanBind: "/api/wj-pair/lan-bind",
	/** Top-level accept-and-redirect entry the QR link points at. */
	acceptPage: "/wj-pair-accept",
	/** The cookieless app landing: serves the official shell for a paired device. */
	appPage: "/wj-pair-app",
	/**
	* The landing page's LAN reachability beacon (lan-source.ts): an inert
	* no-cors GET target, so a probe proves the origin answers without touching
	* a credential or any state.
	*/
	ping: "/wj-pair-ping",
	/**
	* The reopen service worker (registered by the capture script). Root-level
	* path so its default script-directory scope already covers `/`.
	*/
	appServiceWorker: "/wj-pair-app.sw.js"
};
/**
* /api/wj-pair request payload contracts. Each POST endpoint validates its body
* against one of these instead of reaching into a hand-parsed object: the
* control-plane endpoints that carry no meaningful payload use the permissive
* pairActionPayloadSchema so their smoke calls keep working unchanged, while
* issue/accept enforce their optional/required fields. Unknown (extra) keys
* are tolerated exactly as the previous manual reads ignored them.
*/
const issuePayloadSchema = z$1.object({ address: z$1.string().min(1).optional() });
const acceptPayloadSchema = z$1.object({ token: z$1.string().default("") });
const revokePayloadSchema = z$1.object({ deviceId: z$1.string().min(1) });
const renamePayloadSchema = z$1.object({
	deviceId: z$1.string().min(1),
	/** The new label; an empty/blank string clears it (UA-derived fallback). */
	name: z$1.string()
});
const mergePayloadSchema = z$1.object({ 
/** Two or more pairing rows the operator grouped by User-Agent. */
deviceIds: z$1.array(z$1.string().min(1)).min(2).max(64) });
const pairActionPayloadSchema = z$1.object({}).passthrough();
/**
* Parse a pair request body through schema. A missing/empty, unparseable
* or non-object body (shared readJsonBody with objectOnly yields null for
* all of them) is treated as an empty object — the desktop stop/heartbeat
* send no body — and a value that fails the schema returns `undefined` so
* the caller can answer with the existing error shape.
*/
function parsePairPayload(schema, body) {
	const result = schema.safeParse(body ?? {});
	return result.success ? result.data : void 0;
}
/** The SSE fan-out for desktop panel status. */
var PairingEventsStream = class {
	streams = /* @__PURE__ */ new Set();
	/**
	* @param service - the pairing service whose snapshots are fanned out.
	*/
	constructor(service) {
		service.onState((snapshot) => {
			this.push(snapshot);
		});
	}
	/** Open one stream; the response is owned to completion. */
	open(req, res) {
		res.writeHead(200, {
			"content-type": "text/event-stream; charset=utf-8",
			"cache-control": "no-cache",
			connection: "keep-alive"
		});
		const stream = {
			res,
			closed: false
		};
		this.streams.add(stream);
		const close = () => {
			if (stream.closed) return;
			stream.closed = true;
			this.streams.delete(stream);
		};
		res.on("close", close);
		req.on("close", close);
	}
	/** Push one frame to every open stream (contained per stream). */
	push(snapshot) {
		const frame = `data: ${JSON.stringify({
			type: "state",
			...snapshot
		})}\n\n`;
		for (const stream of this.streams) try {
			stream.res.write(frame);
		} catch {
			stream.closed = true;
			this.streams.delete(stream);
		}
	}
	/** Stream count (tests/diagnostics). */
	get size() {
		return this.streams.size;
	}
};
/**
* The accepted {@link PairingSourcePreference} values, shared with the config
* schema so the patch that admits a value and the handler that reads it cannot
* drift apart.
*/
const PAIRING_SOURCE_OPTIONS = [
	"auto",
	"public",
	"lan"
];
/**
* The LAN origins a landing page served from one authority may hop to: every
* LAN base the service advertises except the authority serving the request
* (hopping to the current origin would be a no-op), normalized through `URL`
* so a default port compares equal to `location.origin`.
* @param lanBases - the advertised LAN base URLs, in interface order.
* @param currentOrigin - the origin serving the landing page.
* @returns the distinct candidate origins, in interface order.
*/
function lanSourceCandidates(lanBases, currentOrigin) {
	const origins = [];
	for (const base of lanBases) {
		let origin;
		try {
			origin = new URL(base).origin;
		} catch {
			continue;
		}
		if (origin === currentOrigin || origins.includes(origin)) continue;
		origins.push(origin);
	}
	return origins;
}
/**
* Build the /api/wj-pair route family.
* @param deps - service + fence inputs.
* @returns the exact routes to register on webServer.
*/
function makeRoutes(deps) {
	const { service, requirePairingForLan = true } = deps;
	const pairingRequired = () => typeof requirePairingForLan === "function" ? requirePairingForLan() : requirePairingForLan;
	/** The manual network override, re-read per request (default: automatic). */
	const sourcePreference = () => deps.pairingSource?.() ?? "auto";
	/**
	* Every authority this surface serves, as {@link isTrustedHost} wants them
	* (bare `host` or `host:port` literals). The LAN literals are re-read per
	* request: a hot rebind (the lan-bind toggle) updates them mid-process, and
	* both the fence and the reachability beacon must follow.
	*/
	const servedAuthorities = () => {
		const publicHost = publicHostOf(service.publicBaseUrl);
		const extraHosts = typeof deps.trustedHosts === "function" ? deps.trustedHosts() : deps.trustedHosts ?? [];
		return [
			...service.lanAddresses,
			...publicHost !== void 0 ? [publicHost] : [],
			...extraHosts,
			...dynamicTrustedHosts
		];
	};
	/** Every LAN base URL the service currently advertises, in interface order. */
	const lanBaseUrls = () => service.lanAddresses.map((address) => service.lanBaseUrlFor(address)).filter((base) => base !== void 0);
	/**
	* The origin a redirect may name: the authority the visitor actually
	* reached. That is the Host it presented - except when a proxy forwarded the
	* request and rewrote the Host to its own loopback upstream, where the
	* literal names the VISITOR's loopback rather than this host (issue #1919:
	* a phone following it would dial itself). Such a request is sent to the
	* configured public base, the only authority that visitor can reach; with no
	* public base configured there is nothing better to name, so the Host stays.
	*/
	const redirectOrigin = (req) => {
		if (isProxiedRequest(req) && isLoopbackUpstream(req) && service.publicBaseUrl !== void 0) try {
			return new URL(service.publicBaseUrl).origin;
		} catch {}
		return appOrigin(req);
	};
	const grants = deps.grants ?? createPairGrantStore();
	const events = new PairingEventsStream(service);
	const dynamicTrustedHosts = /* @__PURE__ */ new Set();
	/** Header the /wj-remote channel stamps with the authenticated device id. */
	const ACTOR_HEADER = "x-wj-remote-actor";
	/**
	* Resolve the caller: the channel's actor header names a live device (the
	* channel authenticated it), otherwise a direct loopback request is the
	* desktop and holds level 10. Anything else has no identity.
	*/
	const actorOf = (req) => {
		const forwarded = req.headers[ACTOR_HEADER];
		if (typeof forwarded === "string" && forwarded !== "") {
			const identity = service.deviceIdentity(forwarded);
			if (identity === void 0) return void 0;
			return {
				level: identity.level,
				deviceId: forwarded,
				publicId: identity.publicId,
				loopback: false
			};
		}
		if (isLoopbackClient(req) && isTrustedApiRequest(req, [])) return {
			level: 10,
			loopback: true
		};
	};
	/** Admit a caller at or above one level, answering 403 otherwise. */
	const requireLevel = (req, res, min) => {
		const actor = actorOf(req);
		if (actor === void 0 || actor.level < min) {
			writeJson(res, 403, {
				ok: false,
				code: "forbidden"
			});
			return;
		}
		return actor;
	};
	/** Resolve a panel-supplied device reference (public id or cookie id). */
	const targetIdOf = (reference) => service.idOfPublicId(reference) ?? (service.deviceIdentity(reference) !== void 0 ? reference : void 0);
	/**
	* Resolve a management target and enforce the level rule: the caller may
	* only act on devices strictly below its own level. Loopback is 10, so the
	* desktop can manage everything stored (0..9); a level-9 admin cannot touch
	* another 9 or a 10.
	*/
	const manageableId = (actor, reference, res) => {
		const id = targetIdOf(reference);
		const identity = id === void 0 ? void 0 : service.deviceIdentity(id);
		if (id === void 0 || identity === void 0) {
			writeJson(res, 404, {
				ok: false,
				code: "unknown-device"
			});
			return;
		}
		if (identity.level >= actor.level) {
			writeJson(res, 403, {
				ok: false,
				code: "level-too-high"
			});
			return;
		}
		return id;
	};
	/**
	* Phone-facing fence: loopback, the service's live LAN literals, configured
	* public host, extra trusted hosts, or dynamically paired hosts. `navigation`
	* relaxes the browser-marker checks for a top-level document navigation (the
	* pairing entry pages), never for an API or subresource request.
	*/
	const lanFence = (req, navigation = false) => {
		const combined = servedAuthorities();
		if (navigation && isTopLevelDocumentNavigation(req) ? isTrustedHost(req, combined) : isTrustedApiRequest(req, combined)) return true;
		const privateLanHost = privateLanHostOf(req, navigation);
		if (privateLanHost !== void 0) {
			const cookieDeviceId = readCookie(req.headers.cookie, service.config.cookieName);
			let queryDeviceId = null;
			let queryGrant;
			try {
				const params = new URL(req.url ?? "/", "http://pair.invalid").searchParams;
				queryDeviceId = params.get("device");
				queryGrant = params.get("grant") ?? void 0;
			} catch {}
			const granted = grants.peek(queryGrant);
			const deviceId = cookieDeviceId ?? queryDeviceId ?? granted ?? void 0;
			if (deviceId !== void 0 && service.hasDevice(deviceId)) {
				addBounded(dynamicTrustedHosts, privateLanHost, 64);
				return true;
			}
		}
		return false;
	};
	const requireMethod = (req, res, method) => {
		if (req.method === method) return true;
		res.writeHead(405);
		res.end();
		return false;
	};
	/** Per-source-IP accept rate limit (brute-force defense in depth). */
	const acceptAttempts = /* @__PURE__ */ new Map();
	const ACCEPT_MAX_ATTEMPTS = 10;
	const ACCEPT_WINDOW_MS = 3e4;
	/**
	* @param bucket - the POST /api/wj-pair/accept and the GET /wj-pair-accept flows
	*   count separately: a QR re-scan (page navigation) must not consume a
	*   brute-force budget that belongs to token guessing (and vice versa).
	*/
	/**
	* Drop expired buckets from the FRONT of the insertion-ordered table, then
	* FIFO-evict past the hard cap. The front always holds the oldest window
	* because a re-armed bucket is re-inserted at the tail, so this is amortized
	* O(1) per request: every iteration deletes an entry that was inserted once.
	* It replaces a full-table scan that ran on every pairing request once the
	* table passed 256 entries (and deleted nothing while all windows were
	* fresh).
	*/
	const pruneAcceptAttempts = (nowMs) => {
		while (acceptAttempts.size > 0) {
			const oldest = acceptAttempts.keys().next().value;
			if (oldest === void 0) break;
			const attempt = acceptAttempts.get(oldest);
			if (attempt !== void 0 && nowMs - attempt.windowStart <= ACCEPT_WINDOW_MS) break;
			acceptAttempts.delete(oldest);
		}
		while (acceptAttempts.size > MAX_ACCEPT_BUCKETS) {
			const oldest = acceptAttempts.keys().next().value;
			if (oldest === void 0) break;
			acceptAttempts.delete(oldest);
		}
	};
	const rateLimitAccept = (req, bucket) => {
		const socketIp = req.socket?.remoteAddress ?? "unknown";
		const hops = typeof req.headers["x-forwarded-for"] === "string" ? req.headers["x-forwarded-for"].split(",") : [];
		const ip = acceptLimitKey(socketIp, (hops[hops.length - 1] ?? "").trim(), bucket);
		const nowMs = Date.now();
		pruneAcceptAttempts(nowMs);
		const entry = acceptAttempts.get(ip);
		if (entry === void 0 || nowMs - entry.windowStart > ACCEPT_WINDOW_MS) {
			acceptAttempts.delete(ip);
			acceptAttempts.set(ip, {
				count: 1,
				windowStart: nowMs
			});
			return false;
		}
		entry.count += 1;
		return entry.count > ACCEPT_MAX_ATTEMPTS;
	};
	const handleIssue = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		if (requireLevel(req, res, 9) === void 0) return;
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		const payload = parsePairPayload(issuePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const { address } = payload;
		try {
			const { token, expiresAt } = service.issue(void 0, address);
			const preference = sourcePreference();
			const base = address !== void 0 ? service.lanBaseUrlFor(address) : preference === "lan" ? service.lanBaseUrl : preference === "public" ? service.publicBaseUrl : service.publicBaseUrl ?? service.lanBaseUrl;
			if (base === void 0) throw new Error("wj-dsh-remote: base unavailable");
			writeJson(res, 200, {
				ok: true,
				url: `${base}/wj-pair-accept?pair=${token}`,
				token,
				expiresAt,
				lanAddresses: service.lanAddresses,
				...service.publicBaseUrl !== void 0 ? { publicBaseUrl: service.publicBaseUrl } : {}
			});
		} catch (error) {
			const unknownAddress = error instanceof UnknownLanAddressError;
			writeJson(res, unknownAddress ? 400 : 409, {
				ok: false,
				code: unknownAddress ? "unknown-address" : "lan-required"
			});
		}
	};
	const handleAccept = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		const privateLanHost = privateLanHostOf(req);
		if (!lanFence(req) && privateLanHost === void 0) {
			writeJson(res, 403, {
				ok: false,
				code: "forbidden"
			});
			return;
		}
		if (rateLimitAccept(req, "api")) {
			writeJson(res, 429, {
				ok: false,
				code: "rate-limited"
			});
			return;
		}
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		const payload = parsePairPayload(acceptPayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const ua = req.headers["user-agent"];
		const result = service.accept(payload.token, typeof ua === "string" ? ua : void 0);
		if (!result.ok) {
			if (!lanFence(req)) {
				writeJson(res, 403, {
					ok: false,
					code: "forbidden"
				});
				return;
			}
			writeJson(res, 404, {
				ok: false,
				code: result.code
			});
			return;
		}
		if (privateLanHost !== void 0) addBounded(dynamicTrustedHosts, privateLanHost, 64);
		writeJson(res, 200, {
			ok: true,
			deviceId: result.deviceId
		}, { "set-cookie": [deviceCookie(req, service.config.cookieName, result.deviceId)] });
	};
	const handleStop = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		if (requireLevel(req, res, 10) === void 0) return;
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		if (parsePairPayload(pairActionPayloadSchema, body) === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		service.stop();
		writeJson(res, 200, { ok: true });
	};
	const handleRevoke = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		const actor = requireLevel(req, res, 9);
		if (actor === void 0) return;
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		const payload = parsePairPayload(revokePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const targetId = manageableId(actor, payload.deviceId, res);
		if (targetId === void 0) return;
		if (!service.revoke(targetId)) {
			writeJson(res, 404, {
				ok: false,
				code: "unknown-device"
			});
			return;
		}
		writeJson(res, 200, { ok: true });
	};
	/**
	* Rename one paired device. Loopback-only like revoke: the name is display
	* metadata, but the route still belongs to the desktop control plane (the
	* roster itself is only ever streamed there).
	*/
	const handleRename = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		const actor = requireLevel(req, res, 9);
		if (actor === void 0) return;
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		const payload = parsePairPayload(renamePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const targetId = manageableId(actor, payload.deviceId, res);
		if (targetId === void 0) return;
		if (!service.rename(targetId, payload.name)) {
			writeJson(res, 404, {
				ok: false,
				code: "unknown-device"
			});
			return;
		}
		writeJson(res, 200, { ok: true });
	};
	/**
	* Collapse duplicate pairing records the operator identified as one device.
	* The service keeps the most recently active row and revokes the rest, so
	* a merge frees `maxDevices` slots without the panel issuing several
	* independent revokes. The ids must name a same-User-Agent group.
	*/
	const handleMerge = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		const actor = requireLevel(req, res, 9);
		if (actor === void 0) return;
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		const payload = parsePairPayload(mergePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const mergeIds = [];
		for (const reference of payload.deviceIds) {
			const id = manageableId(actor, reference, res);
			if (id === void 0) return;
			mergeIds.push(id);
		}
		const merged = service.mergeDuplicates(mergeIds);
		if (!merged.ok) {
			writeJson(res, merged.code === "unknown-device" ? 404 : 409, {
				ok: false,
				code: merged.code
			});
			return;
		}
		writeJson(res, 200, {
			ok: true,
			deviceId: merged.deviceId
		});
	};
	const handleHeartbeat = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		if (!lanFence(req)) {
			writeJson(res, 403, {
				ok: false,
				code: "forbidden"
			});
			return;
		}
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		if (parsePairPayload(pairActionPayloadSchema, body) === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const deviceId = actorOf(req)?.deviceId ?? readCookie(req.headers.cookie, service.config.cookieName);
		if (deviceId === void 0 || !service.heartbeat(deviceId)) {
			writeJson(res, 401, {
				ok: false,
				code: "unpaired"
			});
			return;
		}
		writeJson(res, 200, { ok: true });
	};
	const handleStatus = async (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		const actor = requireLevel(req, res, 0);
		if (actor === void 0) return;
		const snapshot = service.snapshot();
		writeJson(res, 200, {
			ok: true,
			paired: true,
			requirePairingForLan: pairingRequired(),
			...snapshot,
			devices: actor.level >= 9 ? snapshot.devices : [],
			self: {
				level: actor.level,
				...actor.publicId !== void 0 ? { publicId: actor.publicId } : {},
				...actor.loopback ? { loopback: true } : {}
			}
		});
	};
	const handleMe = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		const actor = requireLevel(req, res, 0);
		if (actor === void 0) return;
		writeJson(res, 200, {
			ok: true,
			level: actor.level,
			...actor.publicId !== void 0 ? { publicId: actor.publicId } : {},
			loopback: actor.loopback
		});
	};
	/**
	* Change one device's level. Level 10 only (the loopback desktop); the
	* stored range is 0..9, so no remote device can ever become 10 and the
	* desktop stays the single super-admin.
	*/
	const handleLevel = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		if (requireLevel(req, res, 10) === void 0) return;
		const body = await readJsonBody(req, {
			maxBytes: MAX_BODY_BYTES,
			objectOnly: true
		});
		const record = typeof body === "object" && body !== null ? body : void 0;
		const publicId = typeof record?.publicId === "string" ? record.publicId : "";
		const level = typeof record?.level === "number" && Number.isInteger(record.level) ? record.level : -1;
		if (!/^[0-9a-z]{6}$/u.test(publicId) || level < 0 || level > 9) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		if (!service.setLevel(publicId, level)) {
			writeJson(res, 404, {
				ok: false,
				code: "unknown-device"
			});
			return;
		}
		writeJson(res, 200, { ok: true });
	};
	const handleEvents = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (requireLevel(req, res, 9) === void 0) return;
		events.open(req, res);
		events.push(service.snapshot());
	};
	/** LAN-bind facts for the settings card; loopback-only, read per request. */
	const handleLanBind = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (requireLevel(req, res, 9) === void 0) return;
		writeJson(res, 200, {
			ok: true,
			...deps.lanBindStatus?.() ?? {}
		});
	};
	/**
	* The QR entry: navigate here with ?pair=<token>. Sets the device cookie,
	* then redirects to the authenticated home (the connection service's
	* launch-token URL), so a LAN device that has never seen this authority
	* clears the browser-auth gate and boots the paired official UI in one
	* chain: /wj-pair-accept → /?token=<launch> → /. A device that is already
	* authenticated (or loopback) skips straight through the same way.
	*/
	const handleAcceptPage = async (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		const privateLanHost = privateLanHostOf(req, true);
		if (!lanFence(req, true) && privateLanHost === void 0) {
			logEntryRefusal(req, PAIR_PATHS.acceptPage, "untrusted-host");
			res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
			res.end("forbidden");
			return;
		}
		if (rateLimitAccept(req, "page")) {
			res.writeHead(429, { "content-type": "text/plain; charset=utf-8" });
			res.end("rate limited");
			return;
		}
		const token = new URL(req.url ?? "/", "http://pair.invalid").searchParams.get("pair") ?? "";
		const ua = req.headers["user-agent"];
		const result = token === "" ? {
			ok: false,
			code: "invalid"
		} : service.accept(token, typeof ua === "string" ? ua : void 0);
		if (!result.ok) {
			if (!lanFence(req, true)) {
				logEntryRefusal(req, PAIR_PATHS.acceptPage, "untrusted-host-after-invalid-token");
				res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
				res.end("forbidden");
				return;
			}
			const deviceId = readCookie(req.headers.cookie, service.config.cookieName);
			if (deviceId !== void 0 && service.hasDevice(deviceId)) {
				const { grant } = grants.issue(deviceId);
				res.writeHead(303, {
					location: `${redirectOrigin(req)}/wj-pair-app?grant=${encodeURIComponent(grant)}`,
					"cache-control": "no-store",
					"referrer-policy": "no-referrer"
				});
				res.end();
				return;
			}
			res.writeHead(200, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
				"referrer-policy": "no-referrer"
			});
			res.end(pairingFailurePage());
			return;
		}
		if (privateLanHost !== void 0) addBounded(dynamicTrustedHosts, privateLanHost, 64);
		const { grant } = grants.issue(result.deviceId);
		res.writeHead(303, {
			location: `${redirectOrigin(req)}/wj-pair-app?grant=${encodeURIComponent(grant)}`,
			"cache-control": "no-store",
			"referrer-policy": "no-referrer",
			"set-cookie": [deviceCookie(req, service.config.cookieName, result.deviceId)]
		});
		res.end();
	};
	/**
	* The cookieless app landing. A paired device (a one-time grant minted by
	* /wj-pair-accept, or a live pairing cookie on a reopen) receives the official
	* index shell patched with the device-capture script; the shell itself is
	* the official document and carries no data, so serving it needs only the
	* device credential.
	*/
	const handleAppPage = async (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (!lanFence(req, true)) {
			logEntryRefusal(req, PAIR_PATHS.appPage, "untrusted-host");
			res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
			res.end("forbidden");
			return;
		}
		if (rateLimitAccept(req, "page")) {
			res.writeHead(429, { "content-type": "text/plain; charset=utf-8" });
			res.end("rate limited");
			return;
		}
		const url = new URL(req.url ?? "/", "http://pair.invalid");
		const grantedDevice = grants.consume(url.searchParams.get("grant") ?? void 0);
		const cookieDevice = readCookie(req.headers.cookie, service.config.cookieName);
		const id = grantedDevice !== void 0 && service.touchDevice(grantedDevice) ? grantedDevice : cookieDevice !== void 0 && service.touchDevice(cookieDevice) ? cookieDevice : void 0;
		if (id === void 0) {
			res.writeHead(200, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
				"referrer-policy": "no-referrer"
			});
			res.end(pairingFailurePage());
			return;
		}
		const html = await deps.indexDocument?.(id).catch(() => void 0);
		if (html === void 0) {
			res.writeHead(502, {
				"content-type": "text/plain; charset=utf-8",
				"cache-control": "no-store"
			});
			res.end("remote device app unavailable");
			return;
		}
		res.writeHead(200, {
			"content-type": "text/html; charset=utf-8",
			"cache-control": "no-store",
			"referrer-policy": "no-referrer",
			"set-cookie": [deviceCookie(req, service.config.cookieName, id)]
		});
		res.end(patchAppShell(html, id, lanHop(req, id)));
	};
	/**
	* The LAN hop this landing may take, or undefined when there is nothing to
	* decide. Three conditions have to hold together: the automatic preference
	* (both overrides answer the question already — `lan` serves the QR from a
	* LAN origin, `public` forbids the move), at least one LAN candidate other
	* than this origin, and a fresh one-time grant for the target landing. The
	* grant is what lets the target origin serve the shell: the device cookie is
	* origin-scoped, so the LAN origin has no credential of its own, and the
	* grant table lives in this process regardless of which interface answered.
	* The candidate set is carried to the client as origins (lan-source.ts
	* compares them against `location.origin`).
	* @param req - the landing request (its authority is the current origin).
	* @param deviceId - the device session the landing is served for.
	* @returns the hop payload, or undefined when no switch is possible.
	*/
	const lanHop = (req, deviceId) => {
		if (sourcePreference() !== "auto") return void 0;
		const candidates = lanSourceCandidates(lanBaseUrls(), redirectOrigin(req));
		if (candidates.length === 0) return void 0;
		return {
			candidates,
			path: PAIR_PATHS.appPage,
			pingPath: PAIR_PATHS.ping,
			grant: grants.issue(deviceId).grant
		};
	};
	/**
	* The landing page's LAN reachability beacon: a 204 for a Host this plugin
	* serves, a 403 otherwise. It carries no credential and no state — a phone
	* that reaches it has proved the origin answers, which is all the source
	* decision needs, and the fence's browser-marker half is deliberately not
	* applied here: the probe is cross-site by construction (a page on the
	* public origin fetching a LAN origin), so the marker check would turn every
	* probe into the same 403 that means "not ours" and make the two
	* indistinguishable.
	*/
	const handlePing = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (!isTrustedHost(req, servedAuthorities())) {
			res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
			res.end();
			return;
		}
		res.writeHead(204, {
			"cache-control": "no-store",
			"referrer-policy": "no-referrer"
		});
		res.end();
	};
	/**
	* The reopen service worker script. Same phone-facing fence as the app
	* page but no rate limit and no device check: the script is inert logic
	* (no secrets, no data), and browsers re-fetch it on navigations for
	* update checks, which must not trip a brute-force budget. no-store keeps
	* the update check meaningful across deploys.
	*/
	const handleAppServiceWorker = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (!lanFence(req, true)) {
			res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
			res.end("forbidden");
			return;
		}
		res.writeHead(200, {
			"content-type": "text/javascript; charset=utf-8",
			"cache-control": "no-store",
			"service-worker-allowed": "/"
		});
		res.end(appServiceWorkerScript());
	};
	const routes = [
		{
			kind: "exact",
			path: PAIR_PATHS.issue,
			handler: handleIssue
		},
		{
			kind: "exact",
			path: PAIR_PATHS.me,
			handler: handleMe
		},
		{
			kind: "exact",
			path: PAIR_PATHS.level,
			handler: handleLevel
		},
		{
			kind: "exact",
			path: PAIR_PATHS.accept,
			handler: handleAccept
		},
		{
			kind: "exact",
			path: PAIR_PATHS.stop,
			handler: handleStop
		},
		{
			kind: "exact",
			path: PAIR_PATHS.revoke,
			handler: handleRevoke
		},
		{
			kind: "exact",
			path: PAIR_PATHS.rename,
			handler: handleRename
		},
		{
			kind: "exact",
			path: PAIR_PATHS.merge,
			handler: handleMerge
		},
		{
			kind: "exact",
			path: PAIR_PATHS.heartbeat,
			handler: handleHeartbeat
		},
		{
			kind: "exact",
			path: PAIR_PATHS.status,
			handler: handleStatus
		},
		{
			kind: "exact",
			path: PAIR_PATHS.events,
			handler: handleEvents
		}
	];
	if (deps.lanBindStatus !== void 0) routes.push({
		kind: "exact",
		path: PAIR_PATHS.lanBind,
		handler: handleLanBind
	});
	routes.push({
		kind: "exact",
		path: PAIR_PATHS.acceptPage,
		handler: handleAcceptPage
	});
	routes.push({
		kind: "exact",
		path: PAIR_PATHS.ping,
		handler: handlePing
	});
	if (deps.indexDocument !== void 0) {
		routes.push({
			kind: "exact",
			path: PAIR_PATHS.appPage,
			handler: handleAppPage
		});
		routes.push({
			kind: "exact",
			path: PAIR_PATHS.appServiceWorker,
			handler: handleAppServiceWorker
		});
	}
	return routes;
}
/**
* Whether the request reached this process over TLS. The harness itself serves
* plain HTTP; a tunnel edge terminates TLS and stamps `x-forwarded-proto`
* (the same signal {@link appOrigin} trusts when it rebuilds a redirect).
*/
function isHttpsRequest(req) {
	const forwarded = req.headers["x-forwarded-proto"];
	if (typeof forwarded === "string") {
		if (forwarded.split(",")[0]?.trim().toLowerCase() === "https") return true;
	}
	return req.socket.encrypted === true;
}
/**
* The device cookie for one request. `Secure` is added only when the request
* arrived over TLS: LAN pairing runs on plain HTTP, where a Secure cookie is
* simply dropped by the browser and the phone would silently lose its session.
*/
function deviceCookie(req, cookieName, deviceId) {
	const secure = isHttpsRequest(req) ? "; Secure" : "";
	return `${cookieName}=${deviceId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${String(COOKIE_MAX_AGE_SEC)}${secure}`;
}
/**
* The Host authority one request presented (https when a tunnel edge says so).
* It is the literal in the header, not necessarily an authority the visitor can
* reach: {@link makeRoutes} layers the public-base fallback over it for a Host a
* proxy rewrote to its loopback upstream.
*/
function appOrigin(req) {
	const origin = `http://${req.headers.host ?? "127.0.0.1"}`;
	return isHttpsRequest(req) ? origin.replace("http://", "https://") : origin;
}
//#endregion
//#region src/loopback-proxy.ts
/** WebSocket handshake headers forwarded to the loopback upstream. */
const WS_FORWARD_HEADERS = [
	"sec-websocket-key",
	"sec-websocket-version",
	"sec-websocket-extensions",
	"sec-websocket-protocol"
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
const REQUEST_HEADER_DENYLIST = /* @__PURE__ */ new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"expect",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"host",
	"sec-fetch-site",
	"origin",
	"referer",
	"cookie",
	"x-wj-remote-device",
	"forwarded",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-port",
	"x-forwarded-proto",
	"x-real-ip",
	"cf-connecting-ip",
	"accept-encoding",
	"range",
	"if-range"
]);
/**
* Prefixes the re-issue never carries: the browser fetch metadata
* (sec-fetch-*, sec-ch-*) describes the outer request, not this one.
*/
const REQUEST_HEADER_DENY_PREFIXES = ["sec-"];
/**
* Header names the caller nominated as hop-by-hop through its own Connection
* header (RFC 9110 7.6.1): whatever it names stops at this proxy too.
* @param connection - the outer request Connection header value.
* @returns the nominated names, lowercased.
*/
function nominatedHeaders(connection) {
	const nominated = /* @__PURE__ */ new Set();
	if (connection === void 0) return nominated;
	for (const value of Array.isArray(connection) ? connection : [connection]) for (const token of value.split(",")) {
		const name = token.trim().toLowerCase();
		if (name !== "") nominated.add(name);
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
function forwardedRequestHeaders(req, port, cookie, actor) {
	const nominated = nominatedHeaders(req.headers.connection);
	const headers = {};
	for (let index = 0; index + 1 < req.rawHeaders.length; index += 2) {
		const name = req.rawHeaders[index].toLowerCase();
		if (REQUEST_HEADER_DENYLIST.has(name) || nominated.has(name)) continue;
		if (REQUEST_HEADER_DENY_PREFIXES.some((prefix) => name.startsWith(prefix))) continue;
		const value = req.rawHeaders[index + 1];
		const previous = headers[name];
		headers[name] = previous === void 0 ? value : `${previous}, ${value}`;
	}
	headers.host = `127.0.0.1:${String(port)}`;
	headers["sec-fetch-site"] = "same-origin";
	if (cookie !== void 0) headers.cookie = cookie;
	delete headers[REMOTE_ACTOR_HEADER];
	if (actor !== void 0) headers[REMOTE_ACTOR_HEADER] = actor;
	return headers;
}
/** Response headers copied from the loopback upstream (no hop-by-hop). */
const HTTP_FORWARD_RESPONSE_HEADERS = [
	"content-type",
	"content-length",
	"content-disposition",
	"cache-control",
	"etag",
	"last-modified"
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
function proxyLoopbackHttp(req, res, port, upstreamPath, auth, actor) {
	Promise.resolve(auth?.ready()).catch(() => void 0).then((cookie) => {
		pipeLoopbackHttp(req, res, port, upstreamPath, auth, typeof cookie === "string" ? cookie : void 0, actor);
	});
}
function pipeLoopbackHttp(req, res, port, upstreamPath, auth, cookie, actor) {
	const headers = forwardedRequestHeaders(req, port, cookie, actor);
	const upstream = request({
		host: "127.0.0.1",
		port,
		path: upstreamPath,
		method: req.method,
		headers
	}, (upstreamRes) => {
		if (upstreamRes.statusCode === 401 && cookie !== void 0) auth?.invalidate();
		const out = {};
		for (const name of HTTP_FORWARD_RESPONSE_HEADERS) {
			const value = upstreamRes.headers[name];
			if (value !== void 0) out[name] = value;
		}
		res.writeHead(upstreamRes.statusCode ?? 502, out);
		upstreamRes.pipe(res);
		upstreamRes.on("error", () => {
			res.destroy();
		});
		res.on("close", () => {
			if (!upstreamRes.readableEnded) upstream.destroy();
		});
	});
	upstream.on("error", () => {
		if (!res.headersSent) {
			writeJson(res, 502, {
				ok: false,
				error: {
					code: "upstream-failure",
					message: "upstream request failed"
				}
			});
			return;
		}
		res.destroy();
	});
	req.on("error", () => {
		upstream.destroy();
	});
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
function proxyLoopbackUpgrade(req, socket, head, port, upstreamPath, cookie) {
	const lines = [
		`GET ${upstreamPath} HTTP/1.1`,
		`Host: 127.0.0.1:${String(port)}`,
		"Upgrade: websocket",
		"Connection: Upgrade"
	];
	if (cookie !== void 0) lines.push(`Cookie: ${cookie}`);
	for (const name of WS_FORWARD_HEADERS) {
		const value = req.headers[name];
		if (value === void 0) continue;
		lines.push(`${name}: ${Array.isArray(value) ? value.join(", ") : value}`);
	}
	const handshake = `${lines.join("\r\n")}\r\n\r\n`;
	const upstream = connect(port, "127.0.0.1");
	socket.setKeepAlive(true, 2e4);
	upstream.setKeepAlive(true, 2e4);
	const tearDown = () => {
		upstream.destroy();
		socket.destroy();
	};
	upstream.on("error", tearDown);
	socket.on("error", tearDown);
	upstream.on("close", () => {
		socket.destroy();
	});
	socket.on("close", () => {
		upstream.destroy();
	});
	upstream.on("connect", () => {
		upstream.write(handshake);
		if (head.length > 0) upstream.write(head);
		socket.pipe(upstream);
		upstream.pipe(socket);
	});
}
//#endregion
//#region src/remote-api.ts
const ALLOWED_METHODS = /* @__PURE__ */ new Set([
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"PATCH",
	"DELETE"
]);
/** Reject traversal and empty segments; allow plugin file-path characters. */
function isSafeSegment(segment) {
	if (segment === "") return false;
	let decoded;
	try {
		decoded = decodeURIComponent(segment);
	} catch {
		return false;
	}
	return decoded !== "." && decoded !== ".." && !decoded.includes("/") && !decoded.includes("\\") && !decoded.includes("\0");
}
/** One SDK-shaped error envelope (keeps the desktop client's parse path intact). */
function envelopeError(res, status, rpcId, code, message) {
	writeJson(res, status, {
		type: "server-response",
		rpcId,
		result: {
			ok: false,
			error: {
				code,
				message,
				details: { issues: [] }
			}
		}
	});
}
/**
* Map `/wj-remote/...` to the inner path, or undefined when the outer path is
* not a safe rewrite target.
*/
function innerPathOf(pathname) {
	if (pathname === "/wj-remote" || pathname === `/wj-remote/`) return void 0;
	if (!pathname.startsWith(`/wj-remote/`)) return void 0;
	const rest = pathname.slice(10);
	if (!rest.startsWith("/")) return void 0;
	const segments = rest.slice(1).split("/");
	if (segments.length === 0 || segments.some((segment) => !isSafeSegment(segment))) return;
	return rest;
}
/**
* Whether a paired inner path must stay physically local (delegates to the
* shared LOCAL_ONLY_PREFIXES table).
* @returns a denial message, or undefined when the path may be proxied.
*/
function loopbackOnlyDenial(innerPath) {
	return localOnlyDenial(innerPath);
}
/**
* Resolve a live device credential for a gated HTTP request: the pairing
* cookie first, then the cookieless header the boot patch attaches. Unknown
* or revoked ids are a no-op - a stale id never re-arms a device.
* @returns the touched device id, or undefined when neither credential is live.
*/
function pairedDeviceIdOf(req, service) {
	const cookieDevice = readCookie(req.headers.cookie, service.config.cookieName);
	const headerDevice = typeof req.headers["x-wj-remote-device"] === "string" ? req.headers[REMOTE_DEVICE_HEADER] : void 0;
	const id = cookieDevice ?? headerDevice;
	if (id === void 0) return void 0;
	return service.touchDevice(id) ? id : void 0;
}
/**
* Build the remote desktop channel HTTP routes.
* @param deps - pairing service + local port + inner credential.
* @returns the routes to register on webServer.
*/
function makeRemoteApiRoutes(deps) {
	const { service } = deps;
	const handler = (req, res) => {
		const paired = pairedDeviceIdOf(req, service);
		if (paired === void 0) {
			req.resume();
			envelopeError(res, 403, "invalid-request", "unpaired", "this device is not paired with the desktop");
			return;
		}
		const method = req.method ?? "GET";
		if (!ALLOWED_METHODS.has(method)) {
			req.resume();
			res.writeHead(405).end();
			return;
		}
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		const inner = innerPathOf(url.pathname);
		if (inner === void 0) {
			req.resume();
			res.writeHead(404).end();
			return;
		}
		const denied = loopbackOnlyDenial(inner);
		if (denied !== void 0) {
			req.resume();
			envelopeError(res, 403, "invalid-request", "forbidden", denied);
			return;
		}
		const port = deps.port();
		if (port === void 0) {
			req.resume();
			envelopeError(res, 503, "invalid-request", "port-unbound", "the local web server port is not bound yet; retry shortly");
			return;
		}
		proxyLoopbackHttp(req, res, port, `${inner}${url.search}`, deps.auth, paired);
	};
	return [{
		kind: "prefix",
		path: REMOTE_PREFIX$1,
		handler
	}];
}
/**
* Map one outer upgrade URL onto the loopback path, dropping the cookieless
* device credential on the way in.
*
* The outer handshake carries the device id as `?device=<id>` because WebSocket
* handshakes cannot carry headers from the Web API. That id is a live session
* credential — it opens the full host API through this same channel — and the
* inner leg is a request the rest of the loopback origin sees (on a WebSocket
* leg, a raw handshake request line written to a loopback socket), so forwarding
* it handed a working credential to every other observer of the local port for
* no benefit: the gate above has already authenticated the caller, and no
* upstream route reads the parameter (the gateway mux matches on path alone).
* The rest of the query rides through unchanged, so a caller's own parameters
* still reach the upstream.
*/
function upgradeInnerPath(reqUrl, fallbackPath) {
	if (reqUrl === void 0 || reqUrl === "") return fallbackPath;
	let url;
	try {
		url = new URL(reqUrl, "http://127.0.0.1");
	} catch {
		return fallbackPath;
	}
	const inner = innerPathOf(url.pathname);
	if (inner === void 0) return fallbackPath;
	url.searchParams.delete(REMOTE_DEVICE_QUERY);
	return `${inner}${url.search}`;
}
/**
* Build the WebSocket upgrade routes for the event streams and known plugin
* sockets. webServer matches upgrades by exact path.
* @param deps - pairing service + local port + live pairing policy.
* @returns the upgrade routes to register on webServer.
*/
function makeRemoteApiUpgradeRoutes(deps) {
	const { service } = deps;
	const handlerFor = (fallbackPath) => (req, socket, head) => {
		let queryDevice;
		try {
			queryDevice = new URL(req.url ?? "/", "http://127.0.0.1").searchParams.get("device") ?? void 0;
		} catch {}
		if ((pairedDeviceIdOf(req, service) ?? (queryDevice !== void 0 && service.touchDevice(queryDevice) ? queryDevice : void 0)) === void 0) {
			socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
			socket.destroy();
			return;
		}
		const port = deps.port();
		if (port === void 0) {
			socket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
			socket.destroy();
			return;
		}
		const inner = upgradeInnerPath(req.url, fallbackPath);
		if (loopbackOnlyDenial(inner.split("?")[0] ?? inner) !== void 0) {
			socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
			socket.destroy();
			return;
		}
		Promise.resolve(deps.auth?.ready()).catch(() => void 0).then((cookie) => {
			if (socket.destroyed) return;
			proxyLoopbackUpgrade(req, socket, head, port, inner, typeof cookie === "string" ? cookie : void 0);
		});
	};
	return REMOTE_UPGRADE_PATHS.map((path) => ({
		path,
		handler: handlerFor(path.slice(10))
	}));
}
//#endregion
//#region src/remote-presence-pet.ts
/** Default restore grace: the presence sweep flips a device offline after
* ~25 s, and a phone that was briefly backgrounded should not flicker the
* pet; 2 minutes keeps the restore stable. */
const DEFAULT_RESTORE_AFTER_MS = 12e4;
const nodeTimers = {
	setTimeout,
	clearTimeout
};
/**
* Start the presence link. Returns the disposer (withdraws the state
* subscription and cancels a pending restore).
* @param deps - pairing stream + pet seam (+ test seams).
*/
function startRemotePresencePet(deps) {
	const restoreAfterMs = deps.restoreAfterMs ?? DEFAULT_RESTORE_AFTER_MS;
	const timers = deps.timers ?? nodeTimers;
	let previousOnline = false;
	let hiddenByRemote = false;
	let restoreTimer;
	let disposed = false;
	const clearRestore = () => {
		if (restoreTimer !== void 0) {
			timers.clearTimeout(restoreTimer);
			restoreTimer = void 0;
		}
	};
	const scheduleRestore = () => {
		clearRestore();
		restoreTimer = timers.setTimeout(() => {
			restoreTimer = void 0;
			restoreAfterTick();
		}, restoreAfterMs);
	};
	const restoreAfterTick = () => {
		if (disposed || !hiddenByRemote) return;
		const pet = deps.pet();
		if (pet === void 0) return;
		hiddenByRemote = false;
		pet.setVisible(true).catch(() => {});
	};
	const hideForRemote = () => {
		if (hiddenByRemote) return;
		const pet = deps.pet();
		if (pet === void 0) return;
		pet.state().then((value) => {
			if (disposed || hiddenByRemote) return;
			if (value.display?.visible !== true) return;
			hiddenByRemote = true;
			return pet.setVisible(false).catch(() => {
				hiddenByRemote = false;
			});
		}, () => {});
	};
	const handle = (snapshot) => {
		const online = snapshot.phase === "connected" && snapshot.onlineCount > 0;
		if (online && !previousOnline) {
			cancelRestoreAndClear();
			hideForRemote();
		} else if (!online && previousOnline) scheduleRestore();
		previousOnline = online;
	};
	const cancelRestoreAndClear = () => {
		clearRestore();
	};
	const unsubscribe = deps.onState(handle);
	return () => {
		disposed = true;
		unsubscribe();
		clearRestore();
	};
}
//#endregion
//#region src/posture.ts
/**
* Build the forged Host values to probe: the public base authority (host or
* host:port as written in the URL) plus every LAN base literal.
* @param publicBaseUrl - the configured public base URL (or undefined).
* @param lanAddresses - the LAN interface addresses the QR advertises.
* @param port - the local webServer port (LAN hosts are probed as host:port).
* @returns Host header values, de-duplicated.
*/
function postureTargets(publicBaseUrl, lanAddresses, port) {
	const targets = [];
	if (publicBaseUrl !== void 0) try {
		const url = new URL(publicBaseUrl);
		const authority = url.port === "" ? url.hostname : `${url.hostname}:${url.port}`;
		if (authority !== "") targets.push(authority);
	} catch {}
	for (const address of lanAddresses) targets.push(`${address}:${String(port)}`);
	return [...new Set(targets)];
}
const defaultRequest = (options, onStatus) => {
	const request = http.request(options, (response) => {
		onStatus(response.statusCode ?? 0);
	});
	request.on("error", () => {
		onStatus(0);
	});
	return request;
};
/**
* Probe one forged Host against the local `/api` fence.
* @param port - the local webServer port.
* @param hostHeader - the Host header to forge.
* @param request - transport seam.
* @param timeoutMs - give up after this long (counts as not exposed; the
* fence being unreachable is not evidence it is open).
* @returns true when the probe got past the fence.
*/
async function probeHost(port, hostHeader, request, timeoutMs) {
	return await new Promise((resolve) => {
		let settled = false;
		const finish = (exposed) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			handle.destroy();
			resolve(exposed);
		};
		const handle = request({
			host: "127.0.0.1",
			port,
			method: "POST",
			path: "/api/session.list",
			headers: {
				host: hostHeader,
				"content-type": "application/json"
			},
			timeout: timeoutMs
		}, (status) => {
			finish(status !== 403 && status !== 401);
		});
		const timer = setTimeout(() => {
			finish(false);
		}, timeoutMs + 1e3);
		handle.on("error", () => {
			finish(false);
		});
		handle.end("{}");
	});
}
/**
* Run one posture probe round.
* @returns the snapshot for this round.
*/
async function probePosture(options) {
	const { port, targets } = options;
	const request = options.request ?? defaultRequest;
	const timeoutMs = options.timeoutMs ?? 3e3;
	const now = options.now ?? (() => Date.now());
	const hosts = [];
	for (const target of targets) hosts.push({
		host: target,
		exposed: await probeHost(port, target, request, timeoutMs)
	});
	return {
		checkedAt: now(),
		hosts
	};
}
/**
* Reserve an advertised-target key so a second trigger with the same set
* does not overlap an in-flight round. Pair with {@link releasePostureKey}
* on failure — otherwise that key never retries.
*/
function claimPostureKey(current, key) {
	if (current === key) return {
		run: false,
		next: current
	};
	return {
		run: true,
		next: key
	};
}
/**
* Drop a failed in-flight key so the next trigger re-probes the same targets.
* A newer key that started meanwhile is left alone.
*/
function releasePostureKey(current, attempted) {
	return current === attempted ? void 0 : current;
}
//#endregion
//#region src/firewall.ts
/**
* Host firewall management for the LAN bind toggle: while LAN access is on,
* keep one inbound allow rule for the bound port; when it turns off, remove
* the rule. Windows manages the Windows Defender Firewall rule via netsh;
* Linux uses the first available manager among firewalld / ufw / iptables.
* On every other platform (macOS included) the plugin reports the firewall
* as unmanaged: the port usually needs no rule there, and managing pf or the
* application firewall is out of scope for a distributable plugin.
*
* Ported from the dsh-LAN reference implementation (MIT), adapted to this
* package's structure and test seams.
*/
/** Rule name shared by every backend so re-runs recreate the same rule. */
const FIREWALL_RULE_NAME = "wj-dsh-remote (auto)";
/** Production runner: spawn without a shell, capture text, 20s timeout. */
const spawnRunner = (cmd, args) => {
	const result = spawnSync(cmd, args, {
		shell: false,
		encoding: "utf8",
		windowsHide: process.platform === "win32",
		timeout: 2e4
	});
	return {
		ok: result.status === 0,
		out: result.stdout ?? "",
		err: result.stderr ?? "",
		missing: result.error !== void 0
	};
};
function netshBackend(run) {
	const show = () => {
		const result = run("netsh", [
			"advfirewall",
			"firewall",
			"show",
			"rule",
			`name=${FIREWALL_RULE_NAME}`,
			"verbose"
		]);
		return result.ok && result.out.includes("wj-dsh-remote (auto)");
	};
	return {
		label: "netsh",
		ruleExists: show,
		addRule: (port) => run("netsh", [
			"advfirewall",
			"firewall",
			"add",
			"rule",
			`name=${FIREWALL_RULE_NAME}`,
			"dir=in",
			"action=allow",
			"protocol=TCP",
			`localport=${String(port)}`,
			"profile=private,domain"
		]).ok,
		removeRule: () => {
			if (!show()) return true;
			return run("netsh", [
				"advfirewall",
				"firewall",
				"delete",
				"rule",
				`name=${FIREWALL_RULE_NAME}`
			]).ok;
		}
	};
}
function firewalldBackend(run) {
	return {
		label: "firewalld",
		ruleExists: (port) => run("firewall-cmd", [
			"--permanent",
			"--query-port",
			`${String(port)}/tcp`
		]).ok,
		addRule: (port) => {
			const add = run("firewall-cmd", [
				"--permanent",
				"--add-port",
				`${String(port)}/tcp`
			]);
			const reload = run("firewall-cmd", ["--reload"]);
			return add.ok && reload.ok;
		},
		removeRule: (port) => {
			const del = run("firewall-cmd", [
				"--permanent",
				"--remove-port",
				`${String(port)}/tcp`
			]);
			const reload = run("firewall-cmd", ["--reload"]);
			return del.ok && reload.ok;
		}
	};
}
function ufwBackend(run) {
	return {
		label: "ufw",
		ruleExists: (port) => {
			const result = run("ufw", ["status"]);
			return result.ok && new RegExp(`(^|\\s)${String(port)}/tcp\\s+ALLOW`, "i").test(result.out);
		},
		addRule: (port) => run("ufw", ["allow", `${String(port)}/tcp`]).ok,
		removeRule: (port) => run("ufw", [
			"delete",
			"allow",
			`${String(port)}/tcp`
		]).ok
	};
}
function iptablesBackend(run) {
	const rule = (port) => [
		"INPUT",
		"-p",
		"tcp",
		"--dport",
		String(port),
		"-j",
		"ACCEPT"
	];
	return {
		label: "iptables",
		ruleExists: (port) => run("iptables", ["-C", ...rule(port)]).ok,
		addRule: (port) => run("iptables", ["-A", ...rule(port)]).ok,
		removeRule: (port) => run("iptables", ["-D", ...rule(port)]).ok
	};
}
function toolAvailable(run, cmd) {
	try {
		return run(cmd, ["--version"]).missing !== true;
	} catch {
		return false;
	}
}
/**
* Detect the platform firewall manager. Returns undefined when the platform
* has no supported manager (macOS, unknown Linux without tools): the port
* then usually needs no rule and the UI reports "unmanaged".
*/
function detectFirewallBackend(platform, run = spawnRunner) {
	if (platform === "win32") return netshBackend(run);
	if (platform !== "linux") return void 0;
	if (toolAvailable(run, "firewall-cmd")) {
		if (run("firewall-cmd", ["--state"]).ok) return firewalldBackend(run);
	}
	if (toolAvailable(run, "ufw")) return ufwBackend(run);
	if (toolAvailable(run, "iptables")) return iptablesBackend(run);
}
let cachedBackend;
/** Cached detection for the running platform (per process). */
function firewallBackend() {
	const platform = process.platform;
	if (cachedBackend === void 0 || cachedBackend.platform !== platform) cachedBackend = {
		platform,
		backend: detectFirewallBackend(platform)
	};
	return cachedBackend.backend;
}
/**
* Delete-and-add: recreating the rule is idempotent and locale-proof (netsh
* output is localized, so parsing the live rule's port is fragile; the Linux
* backends follow the same recreate pattern).
*/
function ensureFirewallRule(port) {
	invalidateFirewallSummary();
	const backend = firewallBackend();
	if (backend === void 0) return true;
	backend.removeRule(port);
	return backend.addRule(port);
}
function removeFirewallRule(port) {
	invalidateFirewallSummary();
	const backend = firewallBackend();
	if (backend === void 0) return true;
	return backend.removeRule(port);
}
/**
* Human-readable firewall state for the status endpoint. A missing backend
* means the platform has nothing to manage; detection stays at the call site
* so an explicit undefined cannot silently re-probe the real OS mid-test.
*/
function computeFirewallSummary(port, lanEnabled, backend) {
	if (backend === void 0) return {
		ok: true,
		managed: false
	};
	return {
		ok: lanEnabled ? backend.ruleExists(port) : !backend.ruleExists(port),
		managed: true,
		note: backend.label
	};
}
let summaryCache;
/** Forget the cached summary (rule mutations call this). */
function invalidateFirewallSummary() {
	summaryCache = void 0;
}
/**
* The settings card polls this every ten seconds; the probes are blocking
* spawnSync subprocesses on managed platforms, so short-TTL memoization
* keeps one poll from freezing the host event loop per request.
*/
function firewallSummary(port, lanEnabled) {
	const key = `${String(port)}|${lanEnabled ? "1" : "0"}`;
	const now = Date.now();
	if (summaryCache !== void 0 && summaryCache.key === key && now - summaryCache.at < 3e4) return summaryCache.value;
	const value = computeFirewallSummary(port, lanEnabled, firewallBackend());
	summaryCache = {
		key,
		at: now,
		value
	};
	return value;
}
//#endregion
//#region src/lan-bind.ts
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
/** Profile names safe to interpolate into the patch path: one path segment, no traversal. */
const PROFILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const LAN_BIND_BLOCK_BEGIN = "# --- wj-dsh-remote lan-bind block (managed - do not edit) ---";
const LAN_BIND_BLOCK_END = "# --- end wj-dsh-remote lan-bind block ---";
/**
* The absolute path of the profile patch file this toggle manages. The value
* is config-controlled (and the runtime/environment fallbacks bypass schema
* validation entirely), so the path is guarded twice: the profile must be a
* single safe path segment, and the resolved file must stay under the
* profiles directory.
*/
function profilePatchFile(profile, home = dshHome()) {
	if (!PROFILE_PATTERN.test(profile)) throw new Error(`wj-dsh-remote: unsafe lan-bind profile ${JSON.stringify(profile)}`);
	const file = resolve(join(home, "profiles", profile, "cordis.patch.yml"));
	const root = resolve(join(home, "profiles")) + sep;
	if (!file.startsWith(root)) throw new Error(`wj-dsh-remote: lan-bind profile ${JSON.stringify(profile)} escapes the profiles directory`);
	return file;
}
function readPatchContent(file) {
	if (!existsSync(file)) return "";
	return readFileSync(file, "utf8");
}
/**
* Split a block-sequence region into its top-level items. Only a column-0 `-`
* starts an item: that is the shape every writer of this file produces - the
* managed block itself and the YAML document API's block-style re-emission.
* @param region - text between two line boundaries.
* @returns the items in source order; text outside them is not returned.
*/
function blockItems(region) {
	const items = [];
	let start = -1;
	let offset = 0;
	for (const line of region.split("\n")) {
		if (line.startsWith("- ") || line === "-") {
			if (start !== -1) items.push({
				start,
				end: offset,
				text: region.slice(start, offset)
			});
			start = offset;
		}
		offset += line.length + 1;
	}
	if (start !== -1) items.push({
		start,
		end: region.length,
		text: region.slice(start)
	});
	return items;
}
/**
* Whether one top-level item is the webserver row this plugin's block owns.
* The row id is the whole signal: the markers declare everything inside them
* managed, our block always writes `- id: webserver`, and a same-id row later
* in the patch replaces this one wholesale anyway - so an id-webserver row
* found inside our markers is this plugin's row (a hand-truncated block may
* have lost its `name` line).
* @param item - one top-level item's text.
* @returns true when the item is the managed webserver row.
*/
function isManagedWebserverItem(item) {
	return /^- id:\s*['"]?webserver['"]?[ \t]*(?:\r?\n|$)/.test(item);
}
/**
* The text between a block's BEGIN and END markers: from the character after
* the BEGIN line's terminator to the start of the END marker's line (or to
* the end of the content without an END marker).
* @param content - the patch file text.
* @param begin - index of the BEGIN marker.
* @param end - index of the END marker, or -1 when the block is unterminated.
* @returns the region's text.
*/
function managedRegion(content, begin, end) {
	const newlineAfterBegin = content.indexOf("\n", begin);
	const innerStart = newlineAfterBegin === -1 ? content.length : newlineAfterBegin + 1;
	const endLineStart = end === -1 ? content.length : content.lastIndexOf("\n", end - 1) + 1;
	return content.slice(innerStart, Math.max(innerStart, endLineStart));
}
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
function stripManagedBlock(content) {
	let text = content;
	for (;;) {
		const begin = text.indexOf(LAN_BIND_BLOCK_BEGIN);
		if (begin === -1) return text;
		const end = text.indexOf(LAN_BIND_BLOCK_END, begin);
		const blockStart = text.lastIndexOf("\n", begin - 1) + 1;
		const newlineAfterEnd = end === -1 ? -1 : text.indexOf("\n", end);
		const resumeAt = end === -1 ? text.length : newlineAfterEnd === -1 ? text.length : newlineAfterEnd + 1;
		const region = managedRegion(text, begin, end);
		let kept = "";
		let cursor = 0;
		for (const item of blockItems(region)) {
			if (!isManagedWebserverItem(item.text)) continue;
			kept += region.slice(cursor, item.start);
			cursor = item.end;
		}
		kept += region.slice(cursor);
		text = text.slice(0, blockStart) + kept + text.slice(resumeAt);
	}
}
/**
* Parse the block's pinned bind out of patch content. A block whose values
* were hand-edited reports the literals as-is so the card can surface them
* instead of silently claiming one of the two known states.
*/
function managedBindOf(content) {
	const begin = content.indexOf(LAN_BIND_BLOCK_BEGIN);
	if (begin === -1) return void 0;
	const region = managedRegion(content, begin, content.indexOf(LAN_BIND_BLOCK_END, begin));
	const items = blockItems(region).filter((item) => isManagedWebserverItem(item.text));
	const scope = items.length > 0 ? items.map((item) => item.text).join("") : region;
	const hostMatch = /host:\s*'([^']+)'/.exec(scope);
	const portMatch = /port:\s*(\d+)/.exec(scope);
	return {
		host: hostMatch?.[1] ?? "",
		port: portMatch !== null ? Number(portMatch[1]) : void 0
	};
}
/** File-level state of a patch file a previous version wrote to. */
function lanBindState(profile, home = dshHome()) {
	const state = managedBindOf(readPatchContent(profilePatchFile(profile, home)));
	if (state === void 0) return { blockPresent: false };
	return {
		blockPresent: true,
		host: state.host,
		port: state.port
	};
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
function removeManagedBlock(profile, home = dshHome()) {
	const file = profilePatchFile(profile, home);
	if (!existsSync(file)) return {
		removed: false,
		host: void 0,
		port: void 0
	};
	const content = readFileSync(file, "utf8");
	const state = managedBindOf(content);
	const stripped = stripManagedBlock(content);
	if (stripped === content) return {
		removed: false,
		host: void 0,
		port: void 0
	};
	const mode = statSync(file).mode & 511;
	mkdirSync(dirname(file), { recursive: true });
	const temp = `${file}.wj-dsh-remote-tmp-${process.pid.toString(36)}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
	writeFileSync(temp, stripped, { mode });
	renameSync(temp, file);
	return {
		removed: true,
		host: state?.host,
		port: state?.port
	};
}
//#endregion
//#region src/lan-forward.ts
/**
* The LAN edge the lan-bind toggle owns (issue #1917).
*
* The toggle used to pin the LAN address into the profile's webserver row. That
* row is the only place the harness takes its bind from, and rewriting it
*   - replaced the official row's whole config (so the row's own
*     `host: !!js ctx.webStartup.host ?? '127.0.0.1'` expression and the CLI
*     `--host`/`--port` never reached it), and
*   - the profile patch is watched by the Host's HMR config watcher, so the
*     write recomposed the running process and rebound the live listener.
*
* This module keeps the host bound to loopback and gives LAN clients their own
* listener: a forwarder on the machine's LAN address, on the same port, that
* re-issues every request (HTTP and WebSocket upgrade alike) to
* `127.0.0.1:<port>`. Two consequences are load-bearing:
*
* 1. The upstream leg is loopback, so the socket alone would read as "the
*    desktop". The forwarder therefore DROPS whatever Host the client sent and
*    stamps the LAN authority it was reached at, plus `X-Forwarded-For`. Every
*    fence that decides "is this the desktop" (`isLoopbackClient`, the pairing
*    gate, the `/wj-remote` gate) then keeps refusing the forwarded request, while
*    the phone-facing fences still match the LAN authority the QR advertises.
* 2. A bind that cannot be taken (address gone after a network change, port
*    taken) only loses the LAN edge: the loopback listener is never touched, so
*    the host cannot be bricked and the failure is reported on the status
*    frame.
*
* Nothing here writes a file: the forwarder is runtime state, so a network
* change needs no profile edit and no restart.
*
* @module wj-dsh-remote/lan-forward
*/
/** The upstream the forwarder re-issues to: the process's own loopback listener. */
const FORWARD_UPSTREAM_HOST = "127.0.0.1";
/**
* Headers that describe one hop rather than the request. They are rebuilt for
* each leg so a keep-alive or upgrade marker from the client never leaks into
* the loopback leg (and vice versa on the response).
*/
const HOP_BY_HOP = /* @__PURE__ */ new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade"
]);
/**
* Headers the forwarder owns: a client-supplied value is discarded, never
* appended to, so a LAN client cannot claim to be the desktop by forging them.
*/
const REWRITTEN = /* @__PURE__ */ new Set([
	"host",
	"x-forwarded-for",
	"x-forwarded-proto",
	"x-forwarded-host",
	"cf-connecting-ip"
]);
/** The idle state: nothing bound, nothing failed. */
const IDLE_FORWARD_STATE = {
	listening: false,
	address: void 0,
	port: void 0,
	upstreamPort: void 0,
	error: void 0
};
/**
* The `Host` authority a listener at `address:port` is reached at. IPv6
* literals are bracketed like any URL authority.
* @param address - the listen address (a literal).
* @param port - the listen port.
* @returns the authority text a request to that listener carries.
*/
function authorityOf(address, port) {
	return `${address.includes(":") ? `[${address}]` : address}:${String(port)}`;
}
/**
* The headers the loopback leg carries for one request: the client's own
* headers minus the hop-by-hop and forwarder-owned ones, plus the LAN authority
* the client actually reached and its address.
* @param request - the request as it arrived on the LAN listener.
* @param authority - the LAN authority the forwarder listens at.
* @param clientAddress - the client's socket address, when readable.
* @returns the headers for the loopback request.
*/
function forwardedHeaders(request, authority, clientAddress) {
	const headers = {};
	for (const [name, value] of Object.entries(request.headers)) {
		if (value === void 0) continue;
		const lower = name.toLowerCase();
		if (HOP_BY_HOP.has(lower) || REWRITTEN.has(lower)) continue;
		headers[lower] = Array.isArray(value) ? value.join(", ") : value;
	}
	headers.host = authority;
	if (clientAddress !== void 0 && clientAddress !== "") headers["x-forwarded-for"] = clientAddress;
	headers["x-forwarded-proto"] = "http";
	return headers;
}
/**
* Rebuild a WebSocket handshake for the loopback leg. The client's own headers
* travel through verbatim (so `Sec-WebSocket-*` and any application protocol
* survive) except the ones the forwarder owns.
* @param request - the upgrade request as it arrived on the LAN listener.
* @param authority - the LAN authority the forwarder listens at.
* @param clientAddress - the client's socket address, when readable.
* @returns the handshake request head to write on the loopback leg.
*/
function forwardedHandshake(request, authority, clientAddress) {
	const lines = [`${request.method ?? "GET"} ${request.url ?? "/"} HTTP/1.1`];
	const raw = request.rawHeaders;
	for (let index = 0; index + 1 < raw.length; index += 2) {
		const name = raw[index] ?? "";
		const lower = name.toLowerCase();
		if (REWRITTEN.has(lower)) continue;
		lines.push(`${name}: ${raw[index + 1] ?? ""}`);
	}
	lines.push(`Host: ${authority}`);
	if (clientAddress !== void 0 && clientAddress !== "") lines.push(`X-Forwarded-For: ${clientAddress}`);
	lines.push("X-Forwarded-Proto: http");
	return `${lines.join("\r\n")}\r\n\r\n`;
}
/** One listener, its live connections, and its last bind outcome. */
var LanForwarder = class {
	server;
	config;
	state = IDLE_FORWARD_STATE;
	/** Every socket this forwarder opened on either leg. */
	sockets = /* @__PURE__ */ new Set();
	/** Every in-flight loopback request, so a teardown cannot leave one running. */
	upstreams = /* @__PURE__ */ new Set();
	/** What the forwarder is doing right now. */
	snapshot() {
		return this.state;
	}
	/**
	* Bind the LAN listener, or report why it could not be bound.
	*
	* Never throws: a bind failure is the ordinary outcome after a network change
	* (the address is gone) or a port collision, and the loopback listener must
	* keep serving regardless.
	* @param address - the LAN address to listen on.
	* @param port - the port to listen on (the web server's own port).
	* @param upstreamPort - the loopback port to re-issue to; defaults to `port`.
	* @returns the settled state.
	*/
	start(address, port, upstreamPort = port) {
		if (this.config !== void 0 && this.state.listening && this.config.address === address && this.config.port === port && this.config.upstreamPort === upstreamPort) return Promise.resolve(this.state);
		return this.stop().then(() => this.bind(address, port, upstreamPort));
	}
	bind(address, port, upstreamPort) {
		let authority = authorityOf(address, port);
		const server = createServer((request, response) => {
			this.forwardHttp(request, response, upstreamPort, authority);
		});
		server.on("upgrade", (request, socket, head) => {
			this.forwardUpgrade(request, socket, head, upstreamPort, authority);
		});
		server.on("connection", (socket) => {
			this.sockets.add(socket);
			socket.on("close", () => {
				this.sockets.delete(socket);
			});
		});
		this.server = server;
		this.config = {
			address,
			port,
			upstreamPort
		};
		return new Promise((resolve) => {
			let settled = false;
			const settle = (next) => {
				if (settled) return;
				settled = true;
				this.state = next;
				resolve(next);
			};
			server.on("error", (error) => {
				const reason = error.code === void 0 ? error.message : `${error.code}: ${error.message}`;
				if (this.server === server) {
					this.server = void 0;
					this.config = void 0;
				}
				this.releaseSockets();
				settle({
					listening: false,
					address,
					port,
					upstreamPort,
					error: reason
				});
				if (!server.listening) return;
				server.close(() => void 0);
			});
			server.listen(port, address, () => {
				const bound = server.address();
				const boundPort = typeof bound === "object" && bound !== null ? bound.port : port;
				const boundAddress = typeof bound === "object" && bound !== null ? bound.address : address;
				authority = authorityOf(boundAddress, boundPort);
				this.config = {
					address: boundAddress,
					port: boundPort,
					upstreamPort
				};
				settle({
					listening: true,
					address: boundAddress,
					port: boundPort,
					upstreamPort,
					error: void 0
				});
			});
		});
	}
	/**
	* Close the LAN listener and every connection it opened, then resolve once the
	* port is released. Safe to call when nothing is bound.
	*/
	stop() {
		const server = this.server;
		this.server = void 0;
		this.config = void 0;
		this.releaseSockets();
		this.state = IDLE_FORWARD_STATE;
		if (server === void 0) return Promise.resolve();
		return new Promise((resolve) => {
			server.close(() => {
				resolve();
			});
			server.closeAllConnections?.();
		});
	}
	releaseSockets() {
		for (const upstream of this.upstreams) upstream.destroy();
		this.upstreams.clear();
		for (const socket of this.sockets) socket.destroy();
		this.sockets.clear();
	}
	trackUpstream(upstream) {
		this.upstreams.add(upstream);
		upstream.on("close", () => {
			this.upstreams.delete(upstream);
		});
	}
	forwardHttp(request$1, response, upstreamPort, authority) {
		const upstream = request({
			host: FORWARD_UPSTREAM_HOST,
			port: upstreamPort,
			method: request$1.method,
			path: request$1.url,
			headers: forwardedHeaders(request$1, authority, request$1.socket.remoteAddress)
		}, (upstreamResponse) => {
			const headers = {};
			for (const [name, value] of Object.entries(upstreamResponse.headers)) {
				if (value === void 0 || HOP_BY_HOP.has(name.toLowerCase())) continue;
				headers[name] = value;
			}
			response.writeHead(upstreamResponse.statusCode ?? 502, headers);
			upstreamResponse.pipe(response);
			upstreamResponse.on("error", () => {
				response.destroy();
			});
			response.on("close", () => {
				if (!upstreamResponse.readableEnded) upstream.destroy();
			});
		});
		this.trackUpstream(upstream);
		upstream.on("error", () => {
			if (response.headersSent) {
				response.destroy();
				return;
			}
			response.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
			response.end("wj-dsh-remote: the LAN forwarder could not reach the loopback listener\n");
		});
		request$1.on("error", () => {
			upstream.destroy();
		});
		request$1.pipe(upstream);
	}
	forwardUpgrade(request, socket, head, upstreamPort, authority) {
		const upstream = connect(upstreamPort, FORWARD_UPSTREAM_HOST);
		this.sockets.add(upstream);
		const tearDown = () => {
			this.sockets.delete(upstream);
			upstream.destroy();
			socket.destroy();
		};
		upstream.on("error", tearDown);
		socket.on("error", tearDown);
		upstream.on("close", () => {
			socket.destroy();
		});
		socket.on("close", () => {
			upstream.destroy();
		});
		upstream.on("connect", () => {
			upstream.write(forwardedHandshake(request, authority, request.socket.remoteAddress));
			if (head.length > 0) upstream.write(head);
			socket.pipe(upstream);
			upstream.pipe(socket);
		});
	}
};
//#endregion
//#region src/tunnel-plan.ts
/**
* Pure planner for the settings-sync tunnel branch: given the resolved
* settings slice, decide which tunnel mode runs and with what target. Kept
* free of cordis types so the precedence matrix is unit-testable without a
* host context.
*/
/** Whether a configured public base is a parseable http(s) URL with a host. */
function isHttpUrl(value) {
	try {
		const url = new URL(value);
		return (url.protocol === "http:" || url.protocol === "https:") && url.hostname !== "";
	} catch {
		return false;
	}
}
/**
* Decide the tunnel mode and target from one resolved settings value.
* Precedence: the quick tunnel wins when `autoTunnel` is on (anything else
* configured is reported as ignored); the named tunnel runs only with a
* token AND a valid public hostname (the token does not carry the hostname,
* so the QR base and the fence trust would have no source without it);
* otherwise no tunnel and the manual public base applies.
*
* The quick target URL names the local webServer port, so a plan made before
* the listener binds cannot be quick: it comes back `off` and the caller —
* which can observe the port settle — re-plans. The planner itself never
* emits an `http://127.0.0.1:undefined` target.
* @param value - the resolved settings slice that drives the tunnel.
* @param port - the local webServer port the tunnel forwards to (undefined
*   before the listener binds).
*/
function tunnelPlanOf(value, port) {
	if (value.autoTunnel === true) {
		if (port === void 0) return { mode: "off" };
		const ignored = [];
		if (value.tunnelToken !== void 0 && value.tunnelToken !== "") ignored.push("tunnelToken");
		if (value.publicBaseUrl !== void 0 && value.publicBaseUrl !== "") ignored.push("publicBaseUrl");
		return {
			mode: "quick",
			targetUrl: `http://127.0.0.1:${String(port)}`,
			ignored
		};
	}
	if (value.tunnelToken !== void 0 && value.tunnelToken !== "") {
		if (value.publicBaseUrl !== void 0 && isHttpUrl(value.publicBaseUrl)) return {
			mode: "named",
			token: value.tunnelToken,
			publicUrl: value.publicBaseUrl
		};
		return { mode: "off" };
	}
	return { mode: "off" };
}
const RELAY_UNREGISTER_URL = "https://dsh-market.com/api/relay/unregister";
/**
* The public origin template: one stable single-label subdomain per
* registration id. Single label on purpose — Universal SSL covers exactly
* one subdomain level, so a two-level hostname would get no certificate.
*/
const RELAY_BASE_SUFFIX = ".dsh-market.com";
const RELAY_ID_RE = /^[a-z0-9]{16}$/;
const RELAY_SECRET_RE = /^[A-Za-z0-9_-]{43}$/;
/** Registry storage layout: one file per profile under the relay directory. */
function relayIdentityFile(profile, home = dshHome()) {
	if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(profile)) throw new Error(`relay registry: profile ${JSON.stringify(profile)} is not a safe path segment`);
	return join(home, "wj-dsh-remote-registry", `${profile}.json`);
}
/** Generate one identity pair (id: 8-byte hex slug; secret: 32-byte base64url). */
function generateRelayIdentity(random = randomBytes) {
	return {
		id: random(8).toString("hex"),
		secret: random(32).toString("base64url"),
		fresh: true
	};
}
/**
* Load (or lazily mint) the per-profile relay identity. The file is written
* owner-only on first mint; a corrupt file is reminted (the phone then
* re-pairs once — the same cost as losing the devices file).
*/
function loadRelayIdentity(profile, home = dshHome(), random = randomBytes) {
	const file = relayIdentityFile(profile, home);
	try {
		if (existsSync(file)) {
			const parsed = JSON.parse(readFileSync(file, "utf8"));
			if (typeof parsed.id === "string" && RELAY_ID_RE.test(parsed.id) && typeof parsed.secret === "string" && RELAY_SECRET_RE.test(parsed.secret)) return {
				id: parsed.id,
				secret: parsed.secret
			};
			console.warn(`relay registry: ${file} is malformed — reminting the identity (paired devices must scan the QR once more)`);
		}
	} catch (error) {
		console.warn(`relay registry: could not read ${file} (${error instanceof Error ? error.message : String(error)}) — reminting`);
	}
	const identity = generateRelayIdentity(random);
	mkdirSync(dirname(file), { recursive: true });
	writeFileSync(file, JSON.stringify({
		id: identity.id,
		secret: identity.secret
	}, null, 2) + "\n", { mode: 384 });
	return identity;
}
/** Build the registration request body for one identity + tunnel target. */
function registrationBody(identity, target) {
	return JSON.stringify({
		id: identity.id,
		secret: identity.secret,
		new_secret: identity.fresh === true ? identity.secret : void 0,
		target
	});
}
/** Best-effort removal of the mapping (used on disable; errors are swallowed). */
async function unregisterRelay(identity, endpoint = RELAY_UNREGISTER_URL, fetchFn = fetch) {
	await fetchFn(endpoint, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			id: identity.id,
			secret: identity.secret
		})
	});
}
/**
* The stable relay base for one identity — the origin the QR and the phone
* bookmark use while (or after) the registration is accepted.
*/
function relayBaseOf(identity) {
	return `https://${identity.id}${RELAY_BASE_SUFFIX}`;
}
/**
* Registration loop with capped exponential backoff. Re-registration happens
* on every tunnel start (the quick URL can change after a crash-restart);
* failures retry with backoff and surface the last error to the card.
*/
var RelayRegistrar = class {
	identity;
	setState;
	options;
	timer;
	attempts = 0;
	lastError;
	disposed = false;
	constructor(identity, setState, options = {}) {
		this.identity = identity;
		this.setState = setState;
		this.options = options;
	}
	/** The stable relay base for the QR while registered. */
	get baseUrl() {
		return relayBaseOf(this.identity);
	}
	/** The last registration failure detail (undefined while healthy). */
	get error() {
		return this.lastError;
	}
	/** Push one tunnel target; resolves the stable base once accepted. */
	async announce(target) {
		if (this.disposed) return void 0;
		if (this.timer !== void 0) {
			clearTimeout(this.timer);
			this.timer = void 0;
		}
		this.setState({ state: "registering" });
		try {
			const response = await (this.options.fetchFn ?? fetch)(this.options.registerUrl ?? "https://dsh-market.com/api/relay/register", {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: registrationBody(this.identity, target)
			});
			if (!response.ok) {
				const detail = await response.json().catch(() => void 0);
				const error = detail && typeof detail.error === "string" ? detail.error : `HTTP ${String(response.status)}`;
				throw new Error(error);
			}
			this.identity.fresh = false;
			this.attempts = 0;
			this.lastError = void 0;
			this.setState({
				state: "running",
				url: this.baseUrl
			});
			return this.baseUrl;
		} catch (error) {
			this.lastError = error instanceof Error ? error.message : String(error);
			if (this.lastError === "invalid-params" && this.identity.fresh !== true) this.identity.fresh = true;
			this.setState({
				state: "failed",
				error: this.lastError
			});
			this.scheduleRetry(target);
			return;
		}
	}
	/** Best-effort removal of the registry row (the relay toggle turned off). */
	async unregister() {
		await unregisterRelay(this.identity, this.options.unregisterUrl, this.options.fetchFn);
	}
	scheduleRetry(target) {
		if (this.disposed) return;
		const base = this.options.baseDelayMs ?? 5e3;
		const max = this.options.maxDelayMs ?? 6e4;
		const delay = Math.min(base * 2 ** this.attempts, max);
		this.attempts += 1;
		const timerFn = this.options.timerFn ?? ((fn, ms) => {
			const timer = setTimeout(fn, ms);
			timer.unref?.();
			return timer;
		});
		this.timer = timerFn(() => {
			this.timer = void 0;
			this.announce(target);
		}, delay);
	}
	/** Stop retrying and clear the card state (tunnel stopped or disabled). */
	dispose() {
		this.disposed = true;
		if (this.timer !== void 0) {
			clearTimeout(this.timer);
			this.timer = void 0;
		}
		this.setState({ state: "off" });
	}
};
/** Build the claim body (an absent value is omitted, never sent as null). */
function relayClaimBody(request) {
	return JSON.stringify({
		id: request.id,
		secret: request.secret,
		new_secret: request.newSecret,
		origin: { port: request.port },
		plugin: request.pluginVersion === void 0 ? void 0 : { version: request.pluginVersion }
	});
}
/** The tunnel of one accepted claim, or undefined when it carries none. */
function relayTunnelOf(value) {
	if (typeof value !== "object" || value === null) return void 0;
	const tunnel = value;
	if (typeof tunnel.id !== "string" || tunnel.id === "") return void 0;
	if (typeof tunnel.token !== "string" || tunnel.token === "") return void 0;
	return {
		id: tunnel.id,
		token: tunnel.token
	};
}
/** The CNAME target of one accepted claim, or undefined when it carries none. */
function relayDnsTargetOf(value) {
	if (typeof value !== "object" || value === null) return void 0;
	const target = value.target;
	return typeof target === "string" && target !== "" ? target : void 0;
}
/** One lease read back from an accepted claim, or undefined for a bad shape. */
function relayClaimOf(value) {
	if (typeof value !== "object" || value === null) return void 0;
	const body = value;
	const mode = body.mode;
	if (mode !== "named" && mode !== "quick" && mode !== "bridge") return void 0;
	if (typeof body.hostname !== "string" || body.hostname === "") return void 0;
	const tunnel = relayTunnelOf(body.tunnel);
	const target = relayDnsTargetOf(body.dns);
	if (mode !== "bridge" && (tunnel === void 0 || target === void 0)) return void 0;
	const bridge = relayBridgeGrantOf(body.bridge);
	return {
		mode,
		...tunnel === void 0 ? {} : { tunnel },
		hostname: body.hostname,
		...target === void 0 ? {} : { dns: { target } },
		...bridge === void 0 ? {} : { bridge }
	};
}
/** The bridge grant of one accepted lease, or undefined when it carries none. */
function relayBridgeGrantOf(value) {
	if (typeof value !== "object" || value === null) return void 0;
	const grant = value;
	if (typeof grant.endpoint !== "string" || grant.endpoint === "") return void 0;
	if (typeof grant.instance !== "string" || grant.instance === "") return void 0;
	if (grant.credential !== "lease-secret") return void 0;
	return {
		endpoint: grant.endpoint,
		instance: grant.instance,
		credential: "lease-secret"
	};
}
/** The error code and retry hint of a refused claim. */
function refusalOf(status, detail) {
	const body = typeof detail === "object" && detail !== null ? detail : {};
	const error = typeof body.error === "string" ? body.error : "http-" + String(status);
	const retryAfterMs = typeof body.retryAfterMs === "number" && Number.isFinite(body.retryAfterMs) ? body.retryAfterMs : void 0;
	return retryAfterMs === void 0 ? {
		ok: false,
		status,
		error
	} : {
		ok: false,
		status,
		error,
		retryAfterMs
	};
}
/**
* Claim one lease. A transport failure is graded like `502 cf-api-unavailable`
* (status 0) so the caller retries on the same path as a refused upstream.
* @param request - the lease to refresh.
* @param options - endpoint and fetch seams (defaults are the real ones).
*/
async function claimRelayLease(request, options = {}) {
	const fetchFn = options.fetchFn ?? fetch;
	let response;
	try {
		response = await fetchFn(options.url ?? "https://dsh-market.com/api/relay/claim", {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: relayClaimBody(request)
		});
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		return {
			ok: false,
			status: 0,
			error: detail === "" ? "network-error" : detail
		};
	}
	const detail = await response.json().catch(() => void 0);
	if (!response.ok) return refusalOf(response.status, detail);
	const claim = relayClaimOf(detail);
	return claim === void 0 ? {
		ok: false,
		status: response.status,
		error: "invalid-response"
	} : {
		ok: true,
		claim
	};
}
/**
* Release one lease (the plugin's offline action: toggle off, profile
* unmount). Best-effort — a release that never lands only leaves the row
* marked active, which the 90-day GC recovers.
*/
async function releaseRelayLease(identity, options = {}) {
	await (options.fetchFn ?? fetch)(options.url ?? "https://dsh-market.com/api/relay/release", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			id: identity.id,
			secret: identity.secret
		})
	});
}
/**
* Grade one failed claim into a retry decision.
*
* `403 auth-failed` is terminal: the id belongs to another secret and no
* number of retries can take it back. Everything else retries on a capped
* exponential backoff, with the control plane's own `retryAfterMs` (a 502
* names it) raising the floor so a retry cannot land inside a known outage.
* @param outcome - the refused attempt.
* @param attempt - how many attempts already failed (0 for the first).
* @param options - backoff bounds (defaults are the shipped ones).
*/
function relayClaimRetryOf(outcome, attempt, options = {}) {
	const base = options.baseDelayMs ?? 5e3;
	const max = options.maxDelayMs ?? 6e4;
	if (outcome.status === 403) return {
		retry: false,
		delayMs: 0,
		refreshIdentity: false
	};
	const backoff = Math.min(base * 2 ** attempt, max);
	return {
		retry: true,
		delayMs: Math.min(Math.max(backoff, outcome.retryAfterMs ?? 0), max),
		refreshIdentity: outcome.error === "invalid-params" || outcome.error === "unknown-id"
	};
}
/** Liveness poll interval while that grace elapses. */
const ORPHAN_POLL_STEP_MS = 100;
/** The record file this plugin owns: `$DSH_HOME/wj-dsh-remote-tunnel-child.json`. */
function tunnelChildRecordFile(home = dshHome()) {
	return join(home, "wj-dsh-remote-tunnel-child.json");
}
/**
* Read one record, ignoring a file that cannot identify a child (`pid` and
* `command` absent or malformed): only a well-formed record may ever lead to a
* signal.
* @param file - the record file.
* @returns the record, or undefined when there is none to trust.
*/
function readTunnelChildRecord(file) {
	try {
		if (!existsSync(file)) return void 0;
		const parsed = JSON.parse(readFileSync(file, "utf8"));
		if (typeof parsed.pid !== "number" || !Number.isInteger(parsed.pid) || parsed.pid <= 0) return void 0;
		if (typeof parsed.command !== "string" || parsed.command === "") return void 0;
		if (typeof parsed.ownerPid !== "number" || !Number.isInteger(parsed.ownerPid) || parsed.ownerPid <= 0) return void 0;
		return {
			pid: parsed.pid,
			command: parsed.command,
			ownerPid: parsed.ownerPid,
			recordedAt: typeof parsed.recordedAt === "string" ? parsed.recordedAt : ""
		};
	} catch {
		return;
	}
}
/**
* Write one record owner-only, creating the DSH home when it is missing.
* @param file - the record file.
* @param record - what to record about the spawned child.
*/
function recordTunnelChild(file, record) {
	mkdirSync(dirname(file), { recursive: true });
	writeFileSync(file, JSON.stringify(record, null, 2) + "\n", { mode: 384 });
}
/** Drop one record; an absent file is not an error. */
function clearTunnelChildRecord(file) {
	rmSync(file, { force: true });
}
/**
* Whether a pid is still in the process table. `EPERM` means the process
* exists but belongs to another user, which still counts as alive.
* @param pid - the pid to probe.
* @returns whether the pid exists.
*/
function processAlive(pid) {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return error.code === "EPERM";
	}
}
/**
* Read one pid's exact command line: `/proc/<pid>/cmdline` on Linux,
* `ps -ww -o command=` elsewhere. Arguments are joined with single spaces in
* both cases, which is exactly how a recorded argv is stored.
* @param pid - the pid to read.
* @returns the command line, or undefined when it cannot be read.
*/
async function processCommandLine(pid) {
	if (process.platform === "linux") try {
		return parseProcCommandLine(readFileSync(`/proc/${String(pid)}/cmdline`, "utf8"));
	} catch {
		return;
	}
	return await psCommandLine(pid);
}
/**
* Turn one `/proc/<pid>/cmdline` read (argv, NUL-separated, usually with a
* trailing NUL) into the line `ps` prints, so both platforms compare against
* the same recorded shape.
* @param raw - the raw `/proc/<pid>/cmdline` text.
* @returns the joined command line, or undefined for an empty file.
*/
function parseProcCommandLine(raw) {
	const argv = raw.split("\0").filter((part) => part !== "");
	return argv.length === 0 ? void 0 : argv.join(" ");
}
/** The `ps` fallback (unlimited width, so a long cloudflared line is not cut). */
function psCommandLine(pid) {
	return new Promise((resolvePromise) => {
		execFile("ps", [
			"-ww",
			"-p",
			String(pid),
			"-o",
			"command="
		], { maxBuffer: 1 << 20 }, (error, stdout) => {
			if (error !== null) {
				resolvePromise(void 0);
				return;
			}
			const line = stdout.replace(/\s+$/, "");
			resolvePromise(line === "" ? void 0 : line);
		});
	});
}
/** Signal one recorded pid, ignoring a child that is already gone. */
function nodeSignal(pid, signal) {
	try {
		process.kill(pid, signal);
	} catch {}
}
/** Node timers. */
function nodeWait(ms) {
	return new Promise((resolvePromise) => {
		setTimeout(resolvePromise, ms);
	});
}
/**
* Wait up to `graceMs` for a signalled pid to disappear, polling so a child
* that exits at once does not cost the whole grace.
* @returns whether the pid is gone.
*/
async function waitForGone(pid, alive, wait, graceMs) {
	if (graceMs <= 0) return !alive(pid);
	const step = Math.min(ORPHAN_POLL_STEP_MS, graceMs);
	for (let elapsed = 0; elapsed < graceMs; elapsed += step) {
		if (!alive(pid)) return true;
		await wait(step);
	}
	return !alive(pid);
}
/**
* Settle one recorded leftover: reap exactly the recorded child when it is
* still the process that record describes, and leave every other process
* strictly alone.
* @param file - the record file.
* @param seams - process-table and signal seams (defaults read the real table).
* @returns which way the record was settled.
*/
async function reapRecordedTunnelChild(file, seams = {}) {
	const record = readTunnelChildRecord(file);
	if (record === void 0) {
		clearTunnelChildRecord(file);
		return "none";
	}
	const alive = seams.alive ?? processAlive;
	const command = seams.command ?? processCommandLine;
	if (!alive(record.pid) || await command(record.pid) !== record.command) {
		clearTunnelChildRecord(file);
		return "stale";
	}
	if (record.ownerPid === process.pid || alive(record.ownerPid)) return "owned";
	const signal = seams.signal ?? nodeSignal;
	const wait = seams.wait ?? nodeWait;
	const graceMs = seams.graceMs ?? 3e3;
	signal(record.pid, "SIGTERM");
	if (!await waitForGone(record.pid, alive, wait, graceMs)) signal(record.pid, "SIGKILL");
	clearTunnelChildRecord(file);
	return "reaped";
}
/**
* Build the file-backed crash-recovery guard the tunnel manager uses: the
* record lives at {@link tunnelChildRecordFile} unless a file is given.
* @param options - record file and process seams (all optional).
* @returns the guard.
*/
function createTunnelChildGuard(options = {}) {
	const file = () => options.file ?? tunnelChildRecordFile();
	return {
		async reap() {
			return await reapRecordedTunnelChild(file(), options);
		},
		record(child) {
			const pid = child?.pid;
			const argv = child?.spawnargs;
			if (pid === void 0 || argv === void 0 || argv.length === 0) return false;
			try {
				recordTunnelChild(file(), {
					pid,
					command: argv.join(" "),
					ownerPid: process.pid,
					recordedAt: (/* @__PURE__ */ new Date()).toISOString()
				});
				return true;
			} catch (error) {
				console.warn(`wj-dsh-remote: could not record the tunnel child (${error instanceof Error ? error.message : String(error)})`);
				return false;
			}
		},
		clear() {
			try {
				clearTunnelChildRecord(file());
			} catch {}
		}
	};
}
//#endregion
//#region src/tunnel.ts
/**
* Auto-tunnel manager: spawns a Cloudflare tunnel through the `cloudflared`
* npm package — its postinstall downloads the platform binary and the
* readiness policy below validates it and re-fetches when it cannot run (the
* desktop payload stages one tree for every shipped OS/arch), so no
* user-side tooling is involved — surfaces the public URL, and restarts the
* process after unexpected exits with exponential backoff. Two modes: the
* accountless quick tunnel (`https://xxx.trycloudflare.com`, hostname minted
* per start) and an account named tunnel (`cloudflared tunnel run --token`,
* fixed public hostname — the mode that lets a paired phone keep its
* bookmark and pairing cookie across restarts).
*
* The cloudflared package's Tunnel is a thin spawn wrapper; this manager
* owns the lifecycle policy (binary readiness, URL timeout, restart
* backoff, and the public-URL readiness watchdog) around it. All seams — the
* tunnel factory, binary readiness, the URL probe, timers — are injectable
* so the whole lifecycle is unit-testable without a real binary or network.
*
* 'running' is not a terminal state: the connector can lose its edge
* registration while the process keeps living, which leaves a hostname that
* no longer resolves. The watchdog below probes the public URL of a running
* tunnel and reuses the crash-restart path when it stops answering, so the
* relay is re-registered against a freshly minted URL instead of proxying a
* dead one (issue #1723).
*
* A host crash is the one exit the manager cannot cover in-process: the child
* is reparented and keeps running, holding a hostname nobody serves. Every
* spawn is therefore recorded under the DSH home (pid plus its exact command
* line) and the record is dropped when that child is stopped, so the next
* start reaps exactly the child a dead host left behind — see
* ./tunnel-orphan.ts.
*/
/** Compare two targets for the start idempotence check. */
function sameTarget(left, right) {
	if (left === void 0) return false;
	return JSON.stringify(left) === JSON.stringify(right);
}
/**
* Wrap a named-tunnel process so it fits the quick-tunnel handle shape: the
* fixed public URL is reported through the same `url` event once the first
* edge connection registers (cloudflared fires `connected` per connection,
* so only the first is taken), and exit/error pass through. The manager's
* URL timeout, crash-restart backoff, and stop semantics then stay fully
* mode-agnostic.
* @param inner - the running named-tunnel process.
* @param publicUrl - the fixed public hostname ingress maps to this server.
* @returns a handle emitting `url` once the tunnel is reachable.
*/
function namedTunnelHandle(inner, publicUrl) {
	const handle = new EventEmitter();
	let registered = false;
	const onConnected = () => {
		if (registered) return;
		registered = true;
		handle.emit("url", publicUrl);
	};
	const onExit = (code, signal) => {
		handle.emit("exit", code, signal);
	};
	const onError = (value) => {
		handle.emit("error", value);
	};
	inner.on("connected", onConnected);
	inner.on("exit", onExit);
	inner.on("error", onError);
	if (inner.process !== void 0) handle.process = inner.process;
	handle.stop = () => {
		inner.off("connected", onConnected);
		inner.off("exit", onExit);
		inner.off("error", onError);
		return inner.stop();
	};
	return handle;
}
/**
* Probe one public tunnel URL from the host. Resolves true when the URL is
* served (any HTTP answer below 500 — a harness without credentials answers
* 401/403, which is a healthy round trip), false for a DNS failure, a refused
* connection, a timeout, or a Cloudflare 5xx (530 "Origin DNS error" / 1033)
* — the shapes a tunnel that lost its edge registration produces.
*
* The probe must never reject: the watchdog reads a rejection as a dead
* tunnel and restarts on it, so a local programming error would otherwise
* recycle working tunnels forever.
* @param url - the tunnel's public URL.
* @param timeoutMs - how long one probe may take.
* @returns whether the URL answered as a live origin.
*/
async function probeTunnelUrl(url, timeoutMs) {
	const controller = new AbortController();
	const timer = setTimeout(() => {
		controller.abort();
	}, timeoutMs);
	try {
		const response = await fetch(url, {
			method: "GET",
			redirect: "manual",
			cache: "no-store",
			signal: controller.signal
		});
		await response.body?.cancel().catch(() => void 0);
		return response.status < 500;
	} catch {
		return false;
	} finally {
		clearTimeout(timer);
	}
}
/** Default probe: the real network round trip. */
async function defaultProbe(url, timeoutMs) {
	return await probeTunnelUrl(url, timeoutMs);
}
/** Time box for the `--version` probe that validates a staged binary. */
const BINARY_PROBE_TIMEOUT_MS = 1e4;
/**
* Probe whether the binary at `path` actually executes on this machine. The
* desktop payload stages one dependency tree for every shipped OS/arch, so a
* binary can exist with the wrong architecture (the arm64 darwin
* `bin/cloudflared` on an x64 mac); existence alone must not skip the
* reinstall.
*/
function binaryRuns(executable) {
	return new Promise((resolvePromise) => {
		const child = spawn(executable, ["--version"], { stdio: "ignore" });
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
			resolvePromise(false);
		}, BINARY_PROBE_TIMEOUT_MS);
		child.once("error", () => {
			clearTimeout(timer);
			resolvePromise(false);
		});
		child.once("exit", (code) => {
			clearTimeout(timer);
			resolvePromise(code === 0);
		});
	});
}
/**
* Build the default readiness policy over a binary path: skip when the
* binary has already proven runnable in this process, validate an existing
* file before trusting it (a stale or wrong-arch binary must not disable
* the reinstall), and re-fetch the current platform binary otherwise.
*/
function createBinaryReadiness(executable, seams = {}) {
	const exists = seams.exists ?? existsSync;
	const runs = seams.runs ?? binaryRuns;
	const installBinary = seams.install ?? install;
	const validated = /* @__PURE__ */ new Set();
	let installs = 0;
	let lastFailure;
	return async () => {
		if (validated.has(executable)) return;
		if (installs >= 3 && lastFailure !== void 0) throw lastFailure;
		if (exists(executable) && await runs(executable)) {
			validated.add(executable);
			return;
		}
		installs += 1;
		try {
			await installBinary(executable);
			if (!await runs(executable)) throw new Error(`the cloudflared binary at ${executable} still does not run after the reinstall`);
		} catch (error) {
			lastFailure = error instanceof Error ? error : new Error(String(error));
			throw lastFailure;
		}
		validated.add(executable);
	};
}
/** The readiness policy the manager uses by default: the package's real binary path. */
const defaultBinaryReadiness = createBinaryReadiness(bin);
/** Default binary readiness: keep a working platform binary at `bin`. */
async function defaultEnsureBinary() {
	await defaultBinaryReadiness();
}
/** The flags every tunnel mode shares (see the quick factory comment). */
const SHARED_TUNNEL_FLAGS = {
	"--no-autoupdate": true,
	"--protocol": "http2"
};
/**
* Spawn flags for one quick target. `originHostHeader` stamps the Host the
* local webserver sees: the plugin's phone-facing fence trusts the configured
* public host (the stable relay origin, Host-bound) and the harness
* browser-auth binds cookies to the Host authority, while the Workers relay
* cannot control the origin-side Host at all (fetch forces it to the URL
* authority) — so the connector must restamp it with the stable origin.
*/
function quickTunnelFlags(originHostHeader) {
	return originHostHeader === void 0 ? { ...SHARED_TUNNEL_FLAGS } : {
		...SHARED_TUNNEL_FLAGS,
		"--http-host-header": originHostHeader
	};
}
/**
* Command-line arguments for a named tunnel. The account token is deliberately
* NOT part of the argv: `--token <t>` would expose an account credential to any
* local user through ps/proc for the whole tunnel lifetime, while the flag's own
* environment variable (TUNNEL_TOKEN, see cloudflared's tunnel run flags) is not
* readable that way. Note: `--no-autoupdate` and `--protocol` are flags for the
* `tunnel` command and must appear BEFORE the `run` subcommand. Putting them
* after `run` causes cloudflared to exit immediately with "flag provided but not
* defined: -no-autoupdate" (issues #1432, #1433).
*/
function namedTunnelArgs() {
	return [
		"tunnel",
		"--no-autoupdate",
		"--protocol",
		"http2",
		"run"
	];
}
/**
* Run one spawn call with TUNNEL_TOKEN set, restoring the previous value
* afterwards. The cloudflared package's Tunnel spawns with the inherited
* environment inside its constructor, so the variable only has to exist for
* that call; the child keeps its own copy of the environment.
* @param token - the named-tunnel token.
* @param spawnTunnel - the call that creates the child process.
* @returns whatever the spawn call returns.
*/
function withTunnelTokenEnv(token, spawnTunnel) {
	const previous = process.env.TUNNEL_TOKEN;
	process.env.TUNNEL_TOKEN = token;
	try {
		return spawnTunnel();
	} finally {
		if (previous === void 0) delete process.env.TUNNEL_TOKEN;
		else process.env.TUNNEL_TOKEN = previous;
	}
}
/** Spawn one named tunnel without putting its token in the child's argv. */
function spawnNamedTunnel(token) {
	return withTunnelTokenEnv(token, () => new Tunnel(namedTunnelArgs()));
}
/** Default factory: the cloudflared package's quick and named tunnels. */
function defaultFactory(target) {
	if (target.kind === "quick") return Tunnel.quick(target.targetUrl, quickTunnelFlags(target.originHostHeader));
	return namedTunnelHandle(spawnNamedTunnel(target.token), target.publicUrl);
}
/** Node timers. */
const nodeTimer = {
	setTimeout,
	clearTimeout
};
/**
* Own the lifecycle of one auto-tunnel: start/stop, URL surfacing, and
* crash-restart backoff.
*/
var TunnelManager = class {
	factory;
	ensureBinary;
	urlTimeoutMs;
	restartBaseMs;
	restartMaxMs;
	timer;
	probe;
	healthCheckIntervalMs;
	healthCheckFailures;
	probeTimeoutMs;
	orphan;
	phase = "stopped";
	url;
	error;
	target;
	handle;
	urlTimer;
	restartTimer;
	healthTimer;
	healthFailures = 0;
	attempts = 0;
	recordedChild = false;
	generation = 0;
	stopping = false;
	urlListeners = /* @__PURE__ */ new Set();
	phaseListeners = /* @__PURE__ */ new Set();
	/**
	* @param options - seams; defaults spawn the real quick tunnel.
	*/
	constructor(options = {}) {
		this.factory = options.factory ?? defaultFactory;
		this.ensureBinary = options.ensureBinary ?? defaultEnsureBinary;
		this.urlTimeoutMs = options.urlTimeoutMs ?? 3e4;
		this.restartBaseMs = options.restartBaseMs ?? 5e3;
		this.restartMaxMs = options.restartMaxMs ?? 6e4;
		this.timer = options.timer ?? nodeTimer;
		this.probe = options.probe ?? defaultProbe;
		this.healthCheckIntervalMs = options.healthCheckIntervalMs ?? 6e4;
		this.healthCheckFailures = options.healthCheckFailures ?? 2;
		this.probeTimeoutMs = options.probeTimeoutMs ?? 1e4;
		this.orphan = options.orphan ?? createTunnelChildGuard();
	}
	/** The current status frame. */
	get info() {
		return {
			phase: this.phase,
			...this.url !== void 0 ? { url: this.url } : {},
			...this.error !== void 0 ? { error: this.error } : {}
		};
	}
	/**
	* Start (or keep) a tunnel toward `target`. Restarting with a different
	* target tears the old tunnel down first; restarting with the same target
	* while running is a no-op. A string is the quick mode's local target URL.
	*
	* In quick mode the URL surfaces when cloudflared mints the ephemeral
	* trycloudflare hostname; in named mode the fixed `publicUrl` surfaces
	* once the first edge connection registers (see {@link namedTunnelHandle}).
	* @param target - what to run (a string means quick toward that local URL).
	*/
	start(target) {
		const resolved = typeof target === "string" ? {
			kind: "quick",
			targetUrl: target
		} : target;
		if (sameTarget(this.target, resolved) && (this.phase === "starting" || this.phase === "running")) return;
		this.teardown();
		this.stopping = false;
		this.target = resolved;
		this.attempts = 0;
		this.generation += 1;
		this.attempt();
	}
	/** Stop the tunnel for good: no restarts, no state. */
	stop() {
		this.teardown();
		this.stopping = false;
		this.target = void 0;
		this.setPhase("stopped");
	}
	/** Alias of {@link stop} for plugin-effect disposal. */
	dispose() {
		this.stop();
	}
	/** Subscribe to minted tunnel URLs (fire-and-forget duplicates dropped). */
	onUrl(listener) {
		this.urlListeners.add(listener);
		return () => {
			this.urlListeners.delete(listener);
		};
	}
	/** Subscribe to every phase change. */
	onPhase(listener) {
		this.phaseListeners.add(listener);
		return () => {
			this.phaseListeners.delete(listener);
		};
	}
	attempt() {
		if (this.stopping || this.target === void 0) return;
		const gen = this.generation;
		this.setPhase("starting");
		this.handle = void 0;
		this.url = void 0;
		this.error = void 0;
		this.ensureBinary().then(async () => {
			await this.reapLeftoverChild();
			if (this.stopping || this.target === void 0 || gen !== this.generation) return;
			const handle = this.factory(this.target);
			this.handle = handle;
			this.recordedChild = this.orphan.record(handle.process);
			this.urlTimer = this.timer.setTimeout(() => {
				this.fail("timed out waiting for the tunnel URL");
			}, this.urlTimeoutMs);
			handle.on("url", (value) => {
				if (this.handle !== handle) return;
				this.handleUrl(value);
			});
			handle.on("exit", () => {
				if (this.handle !== handle) return;
				this.handleExit();
			});
			handle.on("error", (value) => {
				if (this.handle !== handle || this.phase !== "starting") return;
				this.error = value instanceof Error ? value.message : String(value);
			});
		}).catch((value) => {
			if (this.stopping || this.target === void 0 || gen !== this.generation) return;
			const message = value instanceof Error ? value.message : String(value);
			this.fail(`could not obtain the cloudflared binary: ${message}`);
		});
	}
	handleUrl(value) {
		if (this.urlTimer !== void 0) {
			this.timer.clearTimeout(this.urlTimer);
			this.urlTimer = void 0;
		}
		this.url = value;
		this.error = void 0;
		this.attempts = 0;
		this.setPhase("running");
		this.startHealthWatch(value);
		for (const listener of this.urlListeners) try {
			listener(value);
		} catch {}
	}
	/**
	* Watch the readiness of a running tunnel. cloudflared can keep its process
	* (and its metrics port) alive while every edge connection is gone, leaving
	* a minted hostname that no longer resolves: the manager used to report
	* 'running' forever and the relay kept forwarding to that dead address, so
	* the phone hit Cloudflare 1016 instead of the relay's offline page
	* (issue #1723). A bounded number of consecutive probe failures ends the
	* attempt through the ordinary fail/backoff path, which mints a new URL and
	* re-announces the relay.
	*/
	startHealthWatch(url) {
		this.stopHealthWatch();
		if (this.stopping || this.phase !== "running") return;
		if (this.healthCheckIntervalMs <= 0 || this.healthCheckFailures <= 0) return;
		this.healthFailures = 0;
		const schedule = () => {
			this.healthTimer = this.timer.setTimeout(() => {
				this.healthTimer = void 0;
				this.healthCheck(url);
			}, this.healthCheckIntervalMs);
		};
		schedule();
	}
	/** One probe round of the running tunnel's public URL. */
	async healthCheck(url) {
		if (this.stopping || this.phase !== "running" || this.url !== url) return;
		let alive = false;
		try {
			alive = await this.probe(url, this.probeTimeoutMs);
		} catch {
			alive = false;
		}
		if (this.stopping || this.phase !== "running" || this.url !== url) return;
		if (alive) this.healthFailures = 0;
		else {
			this.healthFailures += 1;
			if (this.healthFailures >= this.healthCheckFailures) {
				this.fail("the tunnel stopped answering on its public URL");
				return;
			}
		}
		this.healthTimer = this.timer.setTimeout(() => {
			this.healthTimer = void 0;
			this.healthCheck(url);
		}, this.healthCheckIntervalMs);
	}
	/** Cancel the readiness watchdog (teardown, restart, stop). */
	stopHealthWatch() {
		if (this.healthTimer !== void 0) {
			this.timer.clearTimeout(this.healthTimer);
			this.healthTimer = void 0;
		}
		this.healthFailures = 0;
	}
	handleExit() {
		if (this.stopping) return;
		this.fail("the tunnel process exited unexpectedly");
	}
	fail(message) {
		if (this.stopping) return;
		this.url = void 0;
		this.error = message;
		this.stopHandle();
		if (this.urlTimer !== void 0) {
			this.timer.clearTimeout(this.urlTimer);
			this.urlTimer = void 0;
		}
		this.stopHealthWatch();
		this.setPhase("failed");
		this.attempts += 1;
		const delay = Math.min(this.restartBaseMs * 2 ** (this.attempts - 1), this.restartMaxMs);
		this.restartTimer = this.timer.setTimeout(() => {
			this.restartTimer = void 0;
			this.attempt();
		}, delay);
	}
	/**
	* Reap the child a crashed host recorded (see ./tunnel-orphan.ts). A failed
	* recovery only loses the cleanup, so it must never fail the attempt.
	*/
	async reapLeftoverChild() {
		try {
			await this.orphan.reap();
		} catch (error) {
			console.warn(`wj-dsh-remote: could not clear a leftover tunnel child (${error instanceof Error ? error.message : String(error)})`);
		}
	}
	/**
	* Stop the current child and drop its crash-recovery record: the process the
	* record describes is gone, so a later start must not reap it again (and a
	* healthy host never reaps its own live child).
	*/
	stopHandle() {
		if (this.handle === void 0) return;
		const handle = this.handle;
		this.handle = void 0;
		try {
			handle.stop();
		} finally {
			if (this.recordedChild) {
				this.recordedChild = false;
				this.orphan.clear();
			}
		}
	}
	/** Stop the current process and cancel every pending timer (no phase change). */
	teardown() {
		this.stopping = true;
		this.stopHealthWatch();
		if (this.urlTimer !== void 0) {
			this.timer.clearTimeout(this.urlTimer);
			this.urlTimer = void 0;
		}
		if (this.restartTimer !== void 0) {
			this.timer.clearTimeout(this.restartTimer);
			this.restartTimer = void 0;
		}
		this.stopHandle();
	}
	setPhase(phase) {
		this.phase = phase;
		const info = this.info;
		for (const listener of this.phaseListeners) try {
			listener(info);
		} catch {}
	}
};
//#endregion
//#region src/relay-connector.ts
/**
* The relay's two connectors. The quick tunnel keeps serving every instance
* that has not migrated, and the named connector is established beside it on
* the same relay hostname and left idle while the wildcard Worker route still
* shadows the CNAME. The control plane's `mode` names the connector the phone
* is meant to be served from; nothing here switches the edge — it only keeps
* both sides up, so a server-side flip needs no plugin restart and a rollback
* is the same flip back.
*/
/**
* The crash-recovery record slot the idle named connector owns. Kept apart
* from the quick connector's slot so each connector's leftover child is reaped
* by the start that belongs to it instead of overwriting its sibling's record.
*/
function namedTunnelChildRecordFile(home = dshHome()) {
	return join(home, "wj-dsh-remote-tunnel-child-named.json");
}
/**
* Read this plugin's own version from its package manifest (the claim reports
* it so the migration can measure adoption by released version).
* @returns the version, or undefined when the manifest cannot be read.
*/
function readPluginVersion() {
	try {
		const parsed = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
		return typeof parsed.version === "string" && parsed.version !== "" ? parsed.version : void 0;
	} catch {
		return;
	}
}
/**
* The dedupe key of one claim trigger: the local origin port plus the quick
* tunnel URL the start reported. A settings sync re-runs the tunnel plan with
* the same key; a tunnel restart mints a new quick URL and therefore claims
* again (which is also what keeps the lease's `last_seen_at` inside the cron
* GC's TTL).
* @param port - the bound web server port, or undefined before it settles.
* @param target - the quick tunnel URL, or undefined while none is minted.
* @returns the key, or undefined when there is nothing to claim yet.
*/
function relayClaimKeyOf(port, target) {
	if (port === void 0) return void 0;
	return String(port) + "|" + (target ?? "");
}
/**
* Build the named connector the relay keeps beside the quick tunnel.
*
* Health probing is off on purpose: while the wildcard Worker route answers
* the relay hostname, a probe of the idle connector's public URL sees the
* Worker's offline page and would declare a healthy connector dead, restarting
* it forever (the failure mode issue #1723 fixed for the quick tunnel).
* @param options - an existing manager (tests); defaults spawn the real one.
*/
function createNamedRelayConnector(options = {}) {
	const manager = options.manager ?? new TunnelManager({
		healthCheckIntervalMs: 0,
		orphan: createTunnelChildGuard({ file: namedTunnelChildRecordFile() })
	});
	return {
		start(token, hostname) {
			manager.start({
				kind: "named",
				token,
				publicUrl: "https://" + hostname
			});
		},
		stop() {
			manager.stop();
		},
		get info() {
			return manager.info;
		}
	};
}
/**
* Own the lease half of the relay: claim it on every tunnel start, bring the
* named connector up beside the quick one, and retry a failed claim with a
* capped backoff while the quick connector keeps serving.
*/
var RelayConnectorPair = class {
	identity;
	options;
	stateValue = { state: "idle" };
	leaseValue;
	attempts = 0;
	timer;
	disposed = false;
	constructor(identity, options = {}) {
		this.identity = identity;
		this.options = options;
	}
	/** The lease half's current state. */
	get state() {
		return this.stateValue;
	}
	/** The connector the phone is served from, for the last accepted lease. */
	get served() {
		return this.leaseValue?.mode;
	}
	/** The last accepted lease (undefined until one lands). */
	get lease() {
		return this.leaseValue;
	}
	/**
	* Claim one lease and start (or restart) the named connector for it. A
	* refusal is graded into a retry and never tears down the quick connector:
	* the instance keeps the origin the registry already gave it.
	* @param input - the local origin port and the reporting plugin version.
	* @returns the accepted lease, or undefined when the attempt did not land.
	*/
	async start(input) {
		if (this.disposed) return void 0;
		this.clearTimer();
		this.setState({ state: "claiming" });
		const claimFn = this.options.claim ?? ((request) => claimRelayLease(request));
		let outcome;
		try {
			outcome = await claimFn({
				id: this.identity.id,
				secret: this.identity.secret,
				newSecret: this.identity.fresh === true ? this.identity.secret : void 0,
				port: input.port,
				pluginVersion: input.pluginVersion
			});
		} catch (error) {
			outcome = {
				ok: false,
				status: 0,
				error: error instanceof Error ? error.message : String(error)
			};
		}
		if (this.disposed) return void 0;
		if (outcome.ok) {
			this.identity.fresh = false;
			this.attempts = 0;
			this.leaseValue = outcome.claim;
			this.startNamed(outcome.claim);
			this.startBridge(outcome.claim, input.port);
			this.setState({
				state: "claimed",
				mode: outcome.claim.mode,
				hostname: outcome.claim.hostname
			});
			return outcome.claim;
		}
		this.setState({
			state: "failed",
			error: outcome.error
		});
		const retry = relayClaimRetryOf(outcome, this.attempts, {
			baseDelayMs: this.options.baseDelayMs,
			maxDelayMs: this.options.maxDelayMs
		});
		if (retry.refreshIdentity) this.identity.fresh = true;
		if (retry.retry) this.scheduleRetry(input, retry.delayMs);
	}
	/**
	* The plugin's offline action (toggle off, profile unmount): release the
	* lease and stop the idle connector. Never retires — the hostname is the
	* phone's bookmark, and the tunnel behind it survives.
	*/
	async release() {
		const releaseFn = this.options.release ?? ((identity) => releaseRelayLease(identity));
		try {
			await releaseFn(this.identity);
		} catch {}
		this.stopNamed();
	}
	/** Stop retrying and drop the connector (the relay half was disposed). */
	dispose() {
		this.disposed = true;
		this.clearTimer();
		this.stopNamed();
		this.setState({ state: "idle" });
	}
	startNamed(claim) {
		const startNamed = this.options.startNamed;
		if (startNamed === void 0 || claim.tunnel === void 0) return;
		try {
			startNamed(claim.tunnel.token, claim.hostname);
		} catch (error) {
			console.warn("wj-dsh-remote: the named connector could not start (" + (error instanceof Error ? error.message : String(error)) + ")");
		}
	}
	stopNamed() {
		try {
			this.options.stopNamed?.();
		} catch {}
		try {
			this.options.stopBridge?.();
		} catch {}
	}
	/** Bring the bridge connector up for one accepted lease, if it carries one. */
	startBridge(claim, port) {
		const startBridge = this.options.startBridge;
		if (startBridge === void 0 || claim.bridge === void 0) return;
		try {
			startBridge({
				claim,
				identity: this.identity,
				port
			});
		} catch (error) {
			console.warn("wj-dsh-remote: the bridge connector could not start (" + (error instanceof Error ? error.message : String(error)) + ")");
		}
	}
	scheduleRetry(input, delayMs) {
		if (this.disposed) return;
		this.attempts += 1;
		const timerFn = this.options.timerFn ?? ((fn, ms) => {
			const timer = setTimeout(fn, ms);
			timer.unref?.();
			return timer;
		});
		this.timer = timerFn(() => {
			this.timer = void 0;
			this.start(input);
		}, delayMs);
		this.timer.unref?.();
	}
	clearTimer() {
		if (this.timer === void 0) return;
		clearTimeout(this.timer);
		this.timer = void 0;
	}
	setState(state) {
		this.stateValue = state;
		try {
			this.options.onState?.(state);
		} catch {}
	}
};
//#endregion
//#region src/relay-bridge-connector.ts
/**
* The bridge connector: the plugin side of the relay bridge, grown from the
* shadow-flight probe (`probe/relay-bridge/connector.mjs`).
*
* It dials the instance's Durable Object meeting point over WSS and serves
* every stream the object multiplexes onto that one socket -- HTTP requests
* with streamed bodies and responses, and the phone's own WebSocket upgrades.
*
* Two rules are not negotiable here:
*
*  1. The credential is the relay identity's own long-lived id and secret, sent
*     in the upgrade's `authorization` header so it never appears in a URL. A
*     dropped socket is re-dialed with the same credential; the object replaces
*     the socket it already holds, so a reconnect needs no new ticket and no
*     new instance.
*  2. The connector never invents the `Host` it sends upstream. It carries the
*     public origin the phone dialed -- the object reads it from the request
*     URL and puts it in the frame, and the fallback is this instance's claimed
*     relay hostname. It never substitutes the loopback authority it dials: the
*     host's local control plane (`/wj-remote-bridge/pair/token`, `/api/wj-pair/*`,
*     `/api/update/*`, `/api/plugin-manager`) is gated on the socket address
*     AND a loopback Host, so rewriting this header would publish that control
*     plane on the public origin.
*
* Frames mirror `market/worker/src/relay-bridge.js`: control frames are JSON
* text, payload frames are `[kind:u8][streamId:u32be][payload]`.
*/
/** The upgrade carries the lease secret here, never in the URL. */
const BRIDGE_AUTH_HEADER = "authorization";
/** Response frames this connector will not forward upstream. */
const BRIDGE_HOP_BY_HOP = /* @__PURE__ */ new Set([
	"host",
	"connection",
	"keep-alive",
	"transfer-encoding",
	"upgrade",
	"sec-websocket-key",
	"sec-websocket-version",
	"sec-websocket-extensions",
	"sec-websocket-accept",
	"cf-connecting-ip",
	"cf-ipcountry",
	"cf-visitor",
	"cf-ray",
	"cf-ipcity",
	"x-forwarded-for",
	"x-forwarded-proto",
	"x-real-ip"
]);
const HTTP_BODY = 1;
const WS_BINARY = 2;
const WS_TEXT = 3;
function headerPairs(raw) {
	const pairs = [];
	if (!Array.isArray(raw)) return pairs;
	for (const entry of raw) {
		if (!Array.isArray(entry) || entry.length !== 2) continue;
		const [name, value] = entry;
		if (typeof name !== "string" || typeof value !== "string") continue;
		pairs.push([name, value]);
	}
	return pairs;
}
/** The upgrade URL one instance dials (the id is not a secret). */
function relayBridgeDialUrl(endpoint, id) {
	const url = new URL(endpoint);
	url.searchParams.set("id", id);
	return url.href;
}
/**
* The `Host` one bridged request travels with.
* @param frameHost - the public origin the object read from the request URL.
* @param hostname - this instance's claimed relay hostname.
* @returns a public origin, never the upstream authority this connector dials.
*/
function bridgeUpstreamHost(frameHost, hostname) {
	if (typeof frameHost === "string" && frameHost !== "") return frameHost;
	return hostname;
}
/**
* The upstream headers of one bridged request: the phone's own, minus the hops
* this transport owns, with the public `Host` put back explicitly.
*/
function bridgeUpstreamHeaders(frameHeaders, host) {
	const headers = {};
	for (const [name, value] of headerPairs(frameHeaders)) {
		if (BRIDGE_HOP_BY_HOP.has(name.toLowerCase())) continue;
		headers[name] = value;
	}
	headers.host = host;
	return headers;
}
/** The headers of the bridge socket's own upgrade. */
function bridgeUpgradeHeaders(endpoint, secret) {
	return {
		host: new URL(endpoint).host,
		connection: "Upgrade",
		upgrade: "websocket",
		"sec-websocket-key": randomBytes(16).toString("base64"),
		"sec-websocket-version": "13",
		[BRIDGE_AUTH_HEADER]: "Bearer " + secret
	};
}
function encodeChunk(kind, id, payload) {
	const bytes = new Uint8Array(5 + payload.byteLength);
	bytes[0] = kind;
	new DataView(bytes.buffer).setUint32(1, id >>> 0);
	bytes.set(payload, 5);
	return bytes;
}
function decodeChunk(data) {
	if (data.byteLength < 5) return void 0;
	return {
		kind: data[0],
		id: new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(1),
		payload: data.subarray(5)
	};
}
/** One client frame, masked as RFC 6455 requires of the dialing side. */
function encodeBridgeFrame(opcode, payload) {
	const length = payload.byteLength;
	const head = length < 126 ? 6 : length < 65536 ? 8 : 14;
	const bytes = new Uint8Array(head + length);
	bytes[0] = 128 | opcode;
	if (length < 126) bytes[1] = 128 | length;
	else if (length < 65536) {
		bytes[1] = 254;
		bytes[2] = length >>> 8 & 255;
		bytes[3] = length & 255;
	} else {
		bytes[1] = 255;
		new DataView(bytes.buffer).setUint32(2, 0);
		new DataView(bytes.buffer).setUint32(6, length);
	}
	const mask = randomBytes(4);
	bytes.set(mask, head - 4);
	for (let index = 0; index < length; index += 1) bytes[head + index] = payload[index] ^ mask[index % 4];
	return bytes;
}
/**
* A frame reader for the connector's own client side, reassembling fragmented
* messages and unmasking nothing: only servers send unmasked frames here.
*/
function createBridgeFrameParser(onFrame) {
	let buffer = Buffer.alloc(0);
	let continuation = null;
	let continuationOpcode = 1;
	return (incoming) => {
		buffer = buffer.length === 0 ? incoming : Buffer.concat([buffer, incoming]);
		for (;;) {
			if (buffer.length < 2) return;
			const fin = (buffer[0] & 128) !== 0;
			const opcode = buffer[0] & 15;
			const masked = (buffer[1] & 128) !== 0;
			let length = buffer[1] & 127;
			let offset = 2;
			if (length === 126) {
				if (buffer.length < 4) return;
				length = buffer.readUInt16BE(2);
				offset = 4;
			} else if (length === 127) {
				if (buffer.length < 10) return;
				length = Number(buffer.readBigUInt64BE(2));
				offset = 10;
			}
			const maskAt = offset;
			if (masked) offset += 4;
			if (buffer.length < offset + length) return;
			let payload = Buffer.from(buffer.subarray(offset, offset + length));
			if (masked) {
				const mask = buffer.subarray(maskAt, maskAt + 4);
				for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
			}
			buffer = buffer.subarray(offset + length);
			if (opcode === 0) {
				continuation = continuation === null ? payload : Buffer.concat([continuation, payload]);
				if (!fin) continue;
				onFrame({
					opcode: continuationOpcode,
					payload: continuation
				});
				continuation = null;
				continue;
			}
			if ((opcode === 1 || opcode === 2) && !fin) {
				continuation = payload;
				continuationOpcode = opcode;
				continue;
			}
			onFrame({
				opcode,
				payload
			});
		}
	};
}
/** Where the connector records its state (`$DSH_HOME/wj-dsh-remote-relay-bridge.json`). */
function relayBridgeStateFile(home = dshHome()) {
	return join(home, "wj-dsh-remote-relay-bridge.json");
}
/**
* Record one connector state. Best effort on purpose: a home that cannot be
* written must never take the socket down with it.
* @param file - the record path (see `relayBridgeStateFile`).
* @param record - the state and the lease it belongs to.
*/
function writeRelayBridgeState(file, record) {
	try {
		mkdirSync(dirname(file), { recursive: true });
		const staged = file + ".tmp";
		writeFileSync(staged, JSON.stringify(record, null, 2) + "\n", { mode: 384 });
		renameSync(staged, file);
	} catch {}
}
/**
* The connector itself: one socket to the object, one upstream request or
* WebSocket per stream id, and a reconnect that keeps the same credential.
*/
var RelayBridgeConnector = class {
	socket;
	parser;
	timer;
	stateValue = { state: "idle" };
	attempts = 0;
	disposed = false;
	requests = /* @__PURE__ */ new Map();
	peers = /* @__PURE__ */ new Map();
	options;
	constructor(options) {
		this.options = options;
	}
	/** The connector's current state. */
	get state() {
		return this.stateValue;
	}
	/** Whether a bridge socket is attached right now. */
	get connected() {
		return this.socket !== void 0;
	}
	/** Dial the object (or schedule the next attempt if the dial fails). */
	start() {
		if (this.disposed) return;
		this.clearTimer();
		this.teardown();
		this.setState({ state: "dialing" });
		this.dial();
	}
	/** Close the socket and stop retrying (the relay half was disposed). */
	stop() {
		this.disposed = true;
		this.clearTimer();
		this.teardown();
		this.setState({ state: "idle" });
	}
	dial() {
		const { endpoint, id, secret } = this.options;
		const url = relayBridgeDialUrl(endpoint, id);
		const target = new URL(url);
		const request = (target.protocol === "wss:" ? https : http).request({
			host: target.hostname,
			port: target.port === "" ? target.protocol === "wss:" ? 443 : 80 : Number(target.port),
			path: target.pathname + target.search,
			method: "GET",
			headers: bridgeUpgradeHeaders(endpoint, secret)
		});
		request.on("upgrade", (response, socket, head) => {
			if (response.statusCode !== 101) {
				socket.destroy();
				this.fail("upgrade answered " + String(response.statusCode));
				return;
			}
			this.attach(socket, head);
		});
		request.on("response", (response) => {
			response.resume();
			this.fail("refused with " + String(response.statusCode));
		});
		request.on("error", (error) => {
			this.fail(error.message);
		});
		request.end();
	}
	attach(socket, head) {
		this.socket = socket;
		this.attempts = 0;
		this.parser = createBridgeFrameParser((frame) => {
			this.onBridgeFrame(frame);
		});
		socket.on("data", (incoming) => {
			this.parser?.(incoming);
		});
		socket.on("error", () => void 0);
		socket.on("close", () => {
			if (this.socket !== socket) return;
			this.socket = void 0;
			this.teardown();
			this.fail("socket closed");
		});
		if (head.length > 0) this.parser(head);
		this.setState({
			state: "connected",
			instance: this.options.id
		});
	}
	/** Send one control frame: a text frame, which is how the object tells a
	* control frame from a payload chunk. */
	sendText(text) {
		this.write(1, Buffer.from(text));
	}
	/** Send one payload frame: a binary frame carrying a chunk. */
	sendChunk(bytes) {
		this.write(2, Buffer.from(bytes));
	}
	write(opcode, body) {
		const socket = this.socket;
		if (socket === void 0 || socket.destroyed) return;
		socket.write(encodeBridgeFrame(opcode, body));
	}
	onBridgeFrame(frame) {
		if (frame.opcode === 8) {
			this.socket?.destroy();
			return;
		}
		if (frame.opcode === 9) {
			this.socket?.write(encodeBridgeFrame(10, frame.payload));
			return;
		}
		if (frame.opcode === 1) {
			this.onControl(frame.payload.toString("utf8"));
			return;
		}
		if (frame.opcode !== 2) return;
		const chunk = decodeChunk(frame.payload);
		if (chunk === void 0) return;
		if (chunk.kind === HTTP_BODY) {
			this.requests.get(chunk.id)?.write(Buffer.from(chunk.payload));
			return;
		}
		const peer = this.peers.get(chunk.id);
		if (peer === void 0) return;
		if (chunk.kind === WS_TEXT) peer.text(Buffer.from(chunk.payload).toString("utf8"));
		if (chunk.kind === WS_BINARY) peer.binary(Buffer.from(chunk.payload));
	}
	onControl(raw) {
		let frame;
		try {
			frame = JSON.parse(raw);
		} catch {
			return;
		}
		const id = typeof frame.id === "number" ? frame.id : -1;
		switch (frame.t) {
			case "req":
				this.startHttp(id, frame);
				return;
			case "end":
				this.requests.get(id)?.end();
				return;
			case "ws-open":
				this.openSocket(id, frame);
				return;
			case "ws-close":
				this.peers.get(id)?.close(typeof frame.code === "number" ? frame.code : 1e3, String(frame.reason ?? ""));
				this.peers.delete(id);
				return;
			case "close": {
				const peer = this.peers.get(id);
				if (peer !== void 0) {
					this.peers.delete(id);
					peer.close(1e3, String(frame.reason ?? "closed"));
					return;
				}
				const request = this.requests.get(id);
				if (request !== void 0) {
					this.requests.delete(id);
					request.destroy();
				}
				return;
			}
			default:
		}
	}
	/** Start one upstream HTTP request for a bridged stream. */
	startHttp(id, frame) {
		const upstream = new URL(this.options.upstream);
		const method = typeof frame.method === "string" ? frame.method : "GET";
		const path = typeof frame.url === "string" && frame.url !== "" ? frame.url : "/";
		const host = bridgeUpstreamHost(frame.host, this.options.hostname);
		const request = http.request({
			host: upstream.hostname,
			port: upstream.port === "" ? 80 : Number(upstream.port),
			path,
			method,
			headers: bridgeUpstreamHeaders(frame.headers, host)
		}, (response) => {
			this.requests.delete(id);
			this.sendText(JSON.stringify({
				t: "res",
				id,
				status: response.statusCode,
				statusText: response.statusMessage ?? "",
				headers: rawHeaderPairs(response.rawHeaders)
			}));
			response.on("data", (chunk) => {
				this.sendChunk(encodeChunk(HTTP_BODY, id, chunk));
			});
			response.on("end", () => {
				this.sendText(JSON.stringify({
					t: "fin",
					id
				}));
			});
			response.on("error", (error) => {
				this.sendText(JSON.stringify({
					t: "fail",
					id,
					message: error.message
				}));
			});
		});
		request.on("error", (error) => {
			this.requests.delete(id);
			this.sendText(JSON.stringify({
				t: "fail",
				id,
				message: error.message
			}));
		});
		this.requests.set(id, request);
	}
	/** Open one upstream WebSocket for a phone's upgrade. */
	async openSocket(id, frame) {
		const upstream = new URL(this.options.upstream);
		const host = bridgeUpstreamHost(frame.host, this.options.hostname);
		const headers = bridgeUpstreamHeaders(frame.headers, host);
		headers.connection = "Upgrade";
		headers.upgrade = "websocket";
		headers["sec-websocket-key"] = randomBytes(16).toString("base64");
		headers["sec-websocket-version"] = "13";
		try {
			const dialed = await new Promise((resolve, reject) => {
				const request = http.request({
					host: upstream.hostname,
					port: upstream.port === "" ? 80 : Number(upstream.port),
					path: typeof frame.url === "string" && frame.url !== "" ? frame.url : "/",
					method: "GET",
					headers
				});
				request.on("upgrade", (response, socket, head) => {
					resolve({
						socket,
						head
					});
				});
				request.on("response", (response) => {
					response.resume();
					reject(/* @__PURE__ */ new Error("upstream answered " + String(response.statusCode) + " instead of 101"));
				});
				request.on("error", (error) => {
					reject(error);
				});
				request.end();
			});
			this.sendText(JSON.stringify({
				t: "ws-accept",
				id
			}));
			const peer = {
				socket: dialed.socket,
				closed: false,
				close: (code, reason) => {
					if (peer.closed) return;
					peer.closed = true;
					const text = Buffer.from(reason);
					const payload = Buffer.alloc(2 + text.length);
					payload.writeUInt16BE(code, 0);
					text.copy(payload, 2);
					try {
						dialed.socket.write(encodeBridgeFrame(8, payload));
					} catch {}
					dialed.socket.destroy();
				},
				text: (body) => {
					if (!peer.closed) dialed.socket.write(encodeBridgeFrame(1, Buffer.from(body)));
				},
				binary: (body) => {
					if (!peer.closed) dialed.socket.write(encodeBridgeFrame(2, body));
				}
			};
			const parse = createBridgeFrameParser((incoming) => {
				if (incoming.opcode === 1) {
					this.sendChunk(encodeChunk(WS_TEXT, id, incoming.payload));
					return;
				}
				if (incoming.opcode === 2) {
					this.sendChunk(encodeChunk(WS_BINARY, id, incoming.payload));
					return;
				}
				if (incoming.opcode === 8) {
					const code = incoming.payload.length >= 2 ? incoming.payload.readUInt16BE(0) : 1005;
					const reason = incoming.payload.length > 2 ? incoming.payload.subarray(2).toString("utf8") : "";
					this.peers.delete(id);
					peer.closed = true;
					dialed.socket.destroy();
					this.sendText(JSON.stringify({
						t: "ws-close",
						id,
						code,
						reason
					}));
					return;
				}
				if (incoming.opcode === 9) dialed.socket.write(encodeBridgeFrame(10, incoming.payload));
			});
			dialed.socket.on("data", parse);
			dialed.socket.on("error", () => void 0);
			dialed.socket.on("close", () => {
				if (!this.peers.delete(id)) return;
				if (peer.closed) return;
				peer.closed = true;
				this.sendText(JSON.stringify({
					t: "ws-close",
					id,
					code: 1006,
					reason: "upstream-closed"
				}));
			});
			this.peers.set(id, peer);
			if (dialed.head.length > 0) parse(dialed.head);
		} catch (error) {
			this.sendText(JSON.stringify({
				t: "ws-fail",
				id,
				message: error instanceof Error ? error.message : String(error)
			}));
		}
	}
	/** Report one failed dial and retry with the same credential. */
	fail(error) {
		if (this.disposed) return;
		this.setState({
			state: "failed",
			error
		});
		this.scheduleRetry();
	}
	scheduleRetry() {
		if (this.disposed) return;
		const base = this.options.baseDelayMs ?? 1e3;
		const max = this.options.maxDelayMs ?? 3e4;
		const delay = Math.min(base * 2 ** this.attempts, max);
		this.attempts += 1;
		const timerFn = this.options.timerFn ?? ((fn, ms) => {
			const timer = setTimeout(fn, ms);
			timer.unref?.();
			return timer;
		});
		this.timer = timerFn(() => {
			this.timer = void 0;
			this.dial();
		}, delay);
		this.timer.unref?.();
	}
	clearTimer() {
		if (this.timer === void 0) return;
		clearTimeout(this.timer);
		this.timer = void 0;
	}
	/** Drop every stream this socket carried: the object re-opens them. */
	teardown() {
		for (const [id, request] of this.requests) {
			this.requests.delete(id);
			request.destroy();
		}
		for (const [id, peer] of this.peers) {
			this.peers.delete(id);
			peer.close(1e3, "connector-closed");
		}
	}
	setState(state) {
		this.stateValue = state;
		try {
			this.options.onState?.(state);
		} catch {}
	}
};
/**
* Build the runner the relay pair drives: one connector per accepted lease,
* rebuilt when a later claim names a different endpoint, and stopped with the
* relay half. The bridge keeps its socket up while the instance's mode is
* quick, so a server-side flip needs no plugin restart.
* @param options - a state observer (logs and the on-disk record).
*/
function createRelayBridgeRunner(options = {}) {
	const stateFile = options.stateFile === void 0 ? relayBridgeStateFile() : options.stateFile;
	const now = options.now ?? (() => (/* @__PURE__ */ new Date()).toISOString());
	let connector;
	let lease;
	const observe = (state) => {
		const target = lease;
		if (stateFile !== null) writeRelayBridgeState(stateFile, {
			state: state.state,
			instance: target?.instance ?? "none",
			hostname: target?.hostname ?? "none",
			endpoint: target?.endpoint ?? "none",
			upstream: target?.upstream ?? "none",
			at: now(),
			...state.state === "failed" ? { error: state.error } : {}
		});
		options.onState?.(state);
	};
	return {
		start(start) {
			const grant = start.claim.bridge;
			if (grant === void 0) return;
			connector?.stop();
			lease = {
				instance: start.identity.id,
				hostname: start.claim.hostname,
				endpoint: grant.endpoint,
				upstream: "http://127.0.0.1:" + String(start.port)
			};
			connector = new RelayBridgeConnector({
				endpoint: lease.endpoint,
				id: start.identity.id,
				secret: start.identity.secret,
				hostname: lease.hostname,
				upstream: lease.upstream,
				onState: observe
			});
			connector.start();
		},
		stop() {
			connector?.stop();
			connector = void 0;
		},
		get state() {
			return connector?.state ?? { state: "idle" };
		}
	};
}
/** Flatten a node raw header array into frame pairs. */
function rawHeaderPairs(raw) {
	const pairs = [];
	for (let index = 0; index + 1 < raw.length; index += 2) pairs.push([raw[index], raw[index + 1]]);
	return pairs;
}
//#endregion
//#region src/host-bind-capability.ts
/**
* What the installed webserver accepts as a bind address, plus the address
* classes the LAN-bind decision needs (issue #1893).
*
* The managed LAN-bind block used to pin `host: '0.0.0.0'`. Since
* `@deepseek-ai/dsh-host-webserver@0.2.1-rc.2` the webserver `Config` schema
* rejects the unspecified (wildcard) address, so such a block is refused at
* config validation and every later `dsh web` start fails. This module is the
* one place that asks the installed package instead of assuming, and the block
* planner reads its answer.
*
* The value import below is a devDependency of this package and stays external
* in the published bundle (see the package tsdown config's libExternal): the
* host process resolves it from the profile tree, which is exactly the module
* it is about to compose. A host this module cannot interrogate is never
* assumed permissive - every failure path answers "no wildcard", because an
* unreadable package must not make the block pin a literal that refuses to
* boot.
*
* @module wj-dsh-remote/host-bind-capability
*/
/** The bind value this probe validates: the wildcard literal and a fixed port. */
const PROBE_BIND = {
	host: "0.0.0.0",
	port: 3080
};
/**
* Whether a value can hold a `Config` factory. The package exports the
* WebServer class itself, a namespace object holding it, and a default export;
* a class is a function, so both kinds count.
*/
function isHolder(value) {
	return typeof value === "object" && value !== null || typeof value === "function";
}
/**
* The schema factory of whatever module shape was loaded. The package exposes
* `WebServer` both as a named export and as the default, and the default may
* itself be a namespace, so the lookup walks those two links. Anything without
* a callable `Config` is treated as an unusable shape.
* @param moduleNamespace - the loaded module object (or any nested holder).
* @returns the schema factory, or undefined when the shape is unusable.
*/
function configSchemaOf(moduleNamespace) {
	const seen = /* @__PURE__ */ new Set();
	const queue = [moduleNamespace];
	while (queue.length > 0) {
		const current = queue.shift();
		if (!isHolder(current) || seen.has(current)) continue;
		seen.add(current);
		let config;
		try {
			config = current.Config;
		} catch {
			continue;
		}
		if (typeof config === "function") return config;
		try {
			const holder = current;
			queue.push(holder.default, holder.WebServer);
		} catch {}
	}
}
/**
* Validate the wildcard bind against one schema factory.
* @param configOf - the schema factory to interrogate (undefined = unusable shape).
* @returns true only when the schema accepts the wildcard bind.
*/
function probeWildcardBindSupport(configOf) {
	if (typeof configOf !== "function") return false;
	try {
		configOf({
			host: PROBE_BIND.host,
			port: PROBE_BIND.port
		});
		return true;
	} catch {
		return false;
	}
}
/**
* Memoized answers, keyed by the schema factory itself: the installed module
* hands over the same function every call, so the schema is interrogated once
* per process, and an injected factory answers per factory.
*/
const probeAnswers = /* @__PURE__ */ new WeakMap();
/**
* Whether the host this plugin runs on accepts the wildcard bind. Grounded in
* the installed package's own schema, so it cannot drift away from the host
* whatever the version is called; false when the package cannot be read.
* @param configOf - schema factory override (test seam); by default the
* installed package's own `WebServer.Config`.
* @returns true only when the wildcard bind validates.
*/
function wildcardBindSupported(configOf) {
	const factory = configOf ?? configSchemaOf(webserver);
	if (typeof factory !== "function") return false;
	const cached = probeAnswers.get(factory);
	if (cached !== void 0) return cached;
	const supported = probeWildcardBindSupport(factory);
	probeAnswers.set(factory, supported);
	return supported;
}
/**
* The host package's own predicate, when it exports a callable one.
* @param name - the exported predicate's name.
* @param host - the bind value to classify.
* @returns its verdict, or undefined when the package cannot answer.
*/
function hostPredicate(name, host) {
	try {
		const fn = webserver[name];
		if (typeof fn !== "function") return void 0;
		return fn(host) === true;
	} catch {
		return;
	}
}
/** Local fallback for the wildcard classes: IPv4 any, IPv6 any, mapped IPv4 any. */
function localWildcard(token) {
	return token === "0.0.0.0" || token === "::" || token === "0:0:0:0:0:0:0:0" || token === "::ffff:0.0.0.0";
}
/** Local fallback for the loopback classes: 127/8, ::1, mapped and expanded forms. */
function localLoopback(token) {
	if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(token)) return true;
	if (token === "::1" || token === "0:0:0:0:0:0:0:1") return true;
	return /^::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(token);
}
/** Local fallback for an IPv4 literal (the only address class a URL base can be built from bare). */
function isIPv4Literal(token) {
	const parts = token.split(".");
	if (parts.length !== 4) return false;
	return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}
/**
* Whether a bind value asks for every interface at once.
* @param host - the bind value (absent while a recompose pass has not settled).
* @returns true for the wildcard classes.
*/
function isWildcardLiteral(host) {
	if (typeof host !== "string" || host === "") return false;
	return hostPredicate("isWildcardHost", host) ?? localWildcard(host.trim().toLowerCase());
}
/**
* Whether a bind value names this machine only, so no other device can dial
* it: the loopback literals of the host package (127/8, ::1 and their mapped
* forms), the `localhost` token the schema refuses as a literal, and an absent
* bind. A hostname is treated by the host package's own verdict, not guessed.
* @param host - the bind value (absent while a recompose pass has not settled).
* @returns true when nothing off this machine can reach the listener.
*/
function isLoopbackBind(host) {
	if (typeof host !== "string") return true;
	const token = host.trim().toLowerCase();
	if (token === "" || token === "localhost") return true;
	return hostPredicate("isLoopbackHost", host) ?? localLoopback(token);
}
/**
* The URL authority a concrete bind literal is expressed by. The host package
* owns the canonical form (mapped loopback collapses to dotted quad, IPv6 gets
* bracketed, a non-loopback zone id has no URL form).
* @param host - a concrete bind literal.
* @returns the URL host, or undefined when the literal has no URL form.
*/
function bindUrlHostOf(host) {
	try {
		const fn = webserver.bindUrlHost;
		if (typeof fn === "function") return fn(host);
	} catch {}
	return isIPv4Literal(host.trim().toLowerCase()) ? host : void 0;
}
//#endregion
//#region src/lan-bind-plan.ts
/**
* Pure decision helpers shared by the lan-bind sync path (index.ts) and the
* status path (lanBindStatus). Extracted so the LAN-edge plan and the firewall
* re-apply gate have one implementation and direct unit coverage.
*
* Since issue #1917 the plugin owns no bind: the host stays on loopback and LAN
* reachability comes from the forwarder in lan-forward.ts, so the only decision
* left here is which LAN address (if any) that forwarder may listen on.
*/
/**
* The LAN address the forwarder may listen on, or the reason it must not.
*
* The order is: the toggle off keeps LAN off; a non-loopback `--host` means the
* operator asked the HOST to bind the network itself, so the forwarder yields
* the port instead of fighting it for the same address:port (issue #1917);
* otherwise this machine's first LAN candidate. A host with no LAN IPv4 address
* has nothing to listen on, which the caller reports instead of failing.
*
* Only a concrete interface address is ever returned: the wildcard would
* collide with the loopback listener on the same port, and a forwarder bound to
* `0.0.0.0` would additionally answer the loopback port a second time.
* @param lanBind - the toggle value.
* @param startupHost - the CLI-provided bind host, when given.
* @param capability - the sampled interface candidates.
* @returns the address to listen on, or the reason there is none.
*/
function forwardPlanOf(lanBind, startupHost, capability) {
	if (lanBind !== true) return {
		host: void 0,
		reason: "off"
	};
	if (typeof startupHost === "string" && startupHost !== "" && isLanReachableBind(startupHost)) return {
		host: void 0,
		reason: "host-bind"
	};
	const host = capability.candidates[0];
	return host === void 0 ? {
		host: void 0,
		reason: "no-address"
	} : {
		host,
		reason: void 0
	};
}
/**
* The reachability decision behind the QR bases, the status `lanUrls`, the
* firewall summary and the boot's LAN warning: a bind that is not loopback is
* reachable from another device, whatever literal it names. Equality with the
* wildcard is deliberately not the test - on a host that refuses wildcard
* binds the only LAN bind is a concrete interface address.
* @param host - the block host or the live bind (absent before it settles).
* @returns true when another device could dial the listener.
*/
function isLanReachableBind(host) {
	return !isLoopbackBind(host);
}
/**
* The profile whose `cordis.patch.yml` the LAN bind toggle manages. An
* explicit `profile` config wins; otherwise the launched profile the Host
* publishes is authoritative, because the DSH Desktop client boots the
* `desktop` profile without exporting `DSH_PROFILE` — an environment-only
* fallback edited `profiles/web` there, so the toggle looked applied while
* the running host never followed the block.
* @param configured - the explicit `profile` plugin config, when set.
* @param launched - the launched profile name the Host published, when available.
* @param env - the DSH_PROFILE environment value, when set.
*/
function resolveManagedProfile(configured, launched, env) {
	return configured ?? launched ?? env ?? "web";
}
/**
* Whether the firewall rule must be (re)applied: only when the toggle or the
* bound port moved since the last application. Keeps unrelated settings
* saves from spawning netsh/firewall-cmd delete+add churn.
* @param previous - the state applied earlier by this process, if any.
* @param next - the state the settings now ask for, if derivable.
*/
function firewallActionNeeded(previous, next) {
	if (next === void 0) return false;
	if (previous === void 0) return true;
	return previous.enabled !== next.enabled || previous.port !== next.port;
}
//#endregion
//#region src/inner-auth.ts
/** The harness browser-auth cookie name prefix (see dsh-client-connection). */
const BROWSER_AUTH_COOKIE_PREFIX = "dsh-auth-";
/**
* Build the inner-auth handle.
* @param launchUrl - the launch-token URL for the inner loopback authority
*   (the connection service's authenticatedUrl of `http://127.0.0.1:<port>/`),
*   or undefined when the connection service or port is unavailable.
* @param fetchImpl - injectable fetch (tests).
*/
function createInnerAuth(launchUrl, fetchImpl = fetch) {
	let cached;
	let inflight;
	const redeem = async () => {
		const url = launchUrl();
		if (url === void 0) return void 0;
		try {
			const raw = (await fetchImpl(url, { redirect: "manual" })).headers.get("set-cookie");
			if (raw === null) return void 0;
			const entry = raw.split(",").map((part) => part.trim()).find((part) => part.startsWith(BROWSER_AUTH_COOKIE_PREFIX));
			if (entry === void 0) return void 0;
			const pair = entry.split(";")[0]?.trim();
			return pair !== void 0 && pair.includes("=") ? pair : void 0;
		} catch {
			return;
		}
	};
	return {
		ready() {
			if (cached !== void 0) return Promise.resolve(cached);
			inflight ??= redeem().then((value) => {
				if (value !== void 0) cached = value;
				inflight = void 0;
				return value;
			}, () => {
				inflight = void 0;
			});
			return inflight;
		},
		invalidate() {
			cached = void 0;
		}
	};
}
//#endregion
//#region src/public-base.ts
/**
* The public base the pairing fence trusts while a tunnel is not running
* (issue #1547).
*
* The fence reads exactly one public host: `service.publicBaseUrl`. Dropping
* it the instant the tunnel leaves `running` makes every public request from
* the address still printed in the QR code answer 403 — including
* `/api/wj-pair/status`, which exists to be callable before pairing. Two of the
* three tunnel modes never lose their host: a named tunnel keeps its fixed
* dashboard hostname, and a registered relay keeps its stable subdomain. A
* quick tunnel does mint a new hostname on restart, so its previous host is
* kept only for a bounded grace window: Cloudflare's edge can still deliver a
* connection the phone already opened, and a mobile network reconnects
* constantly, so an instant drop turns the phone's retry into a silent 403.
* @module wj-dsh-remote/public-base
*/
/** How long a quick-tunnel host stays trusted after the tunnel stops running. */
const PUBLIC_BASE_GRACE_MS = 6e4;
/**
* Owns the trusted public base across tunnel and relay transitions.
*
* The keeper never decides on its own to widen trust: it only postpones
* dropping an address the operator (named/relay) or the tunnel (quick) had
* already published, and it forgets it once the tunnel comes back with the
* address that actually serves the QR.
*/
var PublicBaseKeeper = class {
	onChange;
	graceMs;
	mode = "off";
	tunnelUrl;
	relayUrl;
	graceTimer;
	/**
	* @param onChange - receives the base the fence should trust from now on.
	* @param graceMs - how long a quick-tunnel host outlives its tunnel.
	*/
	constructor(onChange, graceMs = PUBLIC_BASE_GRACE_MS) {
		this.onChange = onChange;
		this.graceMs = graceMs;
	}
	/** The base a fresh fence read should trust: the stable relay origin wins. */
	current() {
		return this.relayUrl ?? this.tunnelUrl;
	}
	/** The mode that currently owns the public base. */
	setMode(mode) {
		this.mode = mode;
	}
	/** The last quick-tunnel URL, for callers that must announce it downstream. */
	quickUrl() {
		return this.tunnelUrl;
	}
	/** A relay registration result; undefined withdraws the stable origin. */
	setRelay(url) {
		this.relayUrl = url;
		this.emit();
	}
	/** The tunnel reported a live URL: it supersedes any pending grace. */
	markRunning(url) {
		this.cancelGrace();
		this.tunnelUrl = url;
		this.emit();
	}
	/**
	* The tunnel left `running` (starting again, or failed). A named tunnel's
	* fixed hostname stays trusted; a quick tunnel's previous host stays
	* trusted for the grace window, then is dropped if nothing replaced it.
	*/
	markReconnecting() {
		if (this.mode === "named") return;
		this.startGrace();
	}
	/** Re-publish the current base after a branch change that did not move it. */
	refresh() {
		this.emit();
	}
	/** Forget everything (teardown, or a mode change that stops the tunnel). */
	reset() {
		this.cancelGrace();
		this.tunnelUrl = void 0;
		this.relayUrl = void 0;
		this.emit();
	}
	/** Cancel the pending grace timer; the keeper keeps its last base. */
	dispose() {
		this.cancelGrace();
	}
	startGrace() {
		if (this.tunnelUrl === void 0) return;
		if (this.graceTimer !== void 0) return;
		this.graceTimer = setTimeout(() => {
			this.graceTimer = void 0;
			this.tunnelUrl = void 0;
			this.emit();
		}, this.graceMs);
	}
	cancelGrace() {
		if (this.graceTimer === void 0) return;
		clearTimeout(this.graceTimer);
		this.graceTimer = void 0;
	}
	emit() {
		this.onChange(this.current());
	}
};
//#endregion
//#region src/mount-once.ts
/**
* Host single-instance guard shared by the plugin family. The family bundle
* (dsh-web-all / dsh-skins) namespaces every child row id (web-ui-*), so
* the loader accepts a standalone install of the same package side by side;
* without this guard the second instance would still re-register the same
* webserver routes, tools, settings namespaces, and system-prompt sections
* and fail the boot. mountOnce makes a mount of an already-mounted package a
* no-op for as long as the first instance lives (the browser half is already
* deduped by package name in the client module host).
*
* A no-op is only safe while the holder is ALIVE. The holder can be disposed
* long after the refused mount ran its course: the Host reloads a profile by
* creating the new loader entries before the old ones are torn down (a
* plugin-manager enable/disable/install write, a settings-driven row reload,
* HMR), so the new aggregate shell entry mounts its family plugin while the
* previous entry still owns the name. Dropping that refused mount lost the
* plugin for good - the previous entry then disposed its own mount, releasing
* the name with nobody left to take it, and the family row stayed listed as
* active while its host routes 404ed (the task-board panel showed
* "board.hostError.notMounted", no degraded record appeared, and only a Host
* restart recovered it).
*
* The refused mount is therefore QUEUED, not dropped, and replayed the moment
* the holder releases the name - if the waiting fiber is still alive then. The
* single-instance guarantee is unchanged: exactly one mount is live per
* package name, and the replay re-enters the guard so a later mount still
* dedupes against it.
*
* The registry rides a global symbol so two module instances of the same
* package (npm copy vs repository link) still share one verdict. That symbol
* is a CROSS-REPOSITORY contract, not this file's private state: the four
* satellite packages (dsh-skins / dsh-pet / dsh-presets /
* dsh-community-plugins) are separate repositories carrying their own copy of
* this guard, rebuilt on their own schedule, so the value under `MOUNTED`
* must keep the shape every published copy reads (a `Set` of package names
* with `has`/`add`/`delete`). The wait queues this guard added therefore live
* under their own additive key, and the registry reads back a `Set` even when
* some other build left a different value there. Changing `MOUNTED`'s shape
* in place broke that contract once: a satellite's legacy copy created a
* `Set`, the family's new copy read it as a `Map`, and every family row
* mounted after it failed with "claims.get is not a function".
*
* cordis `ctx.effect` runs its callback immediately and treats the callback's
* return value as the fiber disposer, so the unmarker is returned, not run.
*/
/** Published cross-repository contract: package names currently mounted. */
const MOUNTED = Symbol.for("dsh-web.mounted-plugins");
/** Additive key this guard owns: refused mounts waiting for the name. */
const WAITERS = Symbol.for("dsh-web.mounted-plugins.waiters");
/**
* The shared name registry, always a `Set` whatever another build stored here:
* a foreign value (an interim shape, a hand-written global) must not take every
* family plugin down with it.
* @returns the process-wide set of mounted package names.
*/
function mountedSet() {
	const registry = globalThis;
	const existing = registry[MOUNTED];
	if (existing instanceof Set) return existing;
	const created = /* @__PURE__ */ new Set();
	registry[MOUNTED] = created;
	return created;
}
/** Queue per package name for mounts refused while a holder was alive. */
function mountWaiters() {
	const registry = globalThis;
	return registry[WAITERS] ??= /* @__PURE__ */ new Map();
}
/**
* Wrap a cordis plugin apply so the package runs at most once per process.
* The first mount registers normally and releases the name when its fiber
* disposes; a mount refused while that name is held waits for the release and
* then runs, unless its own fiber disposes first.
* @param packageName - npm package identity shared by every install source.
* @param fn - the original plugin apply.
* @returns an apply of the same shape.
*/
function mountOnce(packageName, fn) {
	const mount = (...args) => {
		const mounted = mountedSet();
		const ctx = args[0];
		if (mounted.has(packageName)) {
			const waiters = mountWaiters();
			const queue = waiters.get(packageName) ?? [];
			let alive = true;
			const pending = { run: () => {
				if (alive) mount(...args);
			} };
			ctx?.effect?.(() => () => {
				alive = false;
				const index = queue.indexOf(pending);
				if (index >= 0) queue.splice(index, 1);
			});
			queue.push(pending);
			waiters.set(packageName, queue);
			return;
		}
		mounted.add(packageName);
		ctx?.effect?.(() => () => {
			mounted.delete(packageName);
			const waiters = mountWaiters();
			const queue = waiters.get(packageName);
			if (queue === void 0) return;
			waiters.delete(packageName);
			for (const waiter of queue.splice(0)) queueMicrotask(() => {
				waiter.run();
			});
		});
		return fn(...args);
	};
	return mount;
}
//#endregion
//#region src/detached-work.ts
/**
* Run one piece of work outside the caller's async context.
*
* A Host mutation that runs inside `hmr.runExclusive` marks the running async
* context with an AsyncLocalStorage store. Side effects on that path that write
* a file the HMR config watcher refreshes from - `cordis.patch.yml` above all -
* must not run under that mark, or the watcher's refresh re-enters the
* exclusive transaction and is refused with "HMR transactions cannot be nested"
* (#1751, #1754, #1816).
*
* Deferring is NOT enough, and the earlier belt that this one replaces was
* built on a disproven premise: Node propagates an AsyncLocalStorage store into
* `setImmediate`, into `node:timers`, into promise continuations, and into any
* AsyncResource scoped to the current async id. Measured on Node 24:
*
* ```
* als.run(true, () => setImmediate(() => als.getStore()))   // -> true
* ```
*
* What DOES start clean is an AsyncResource whose `triggerAsyncId` is not the
* transaction. A resource created once at module scope - that is, before any
* transaction existed - carries no store, and everything it schedules inherits
* that emptiness rather than the caller's mark:
*
* ```
* const detached = new AsyncResource('...')      // module scope
* als.run(true, () => detached.runInAsyncScope(() => setImmediate(() => als.getStore())))
* // -> undefined
* ```
*
* @module dsh-web-shared/host/detached-work
*/
/**
* The escape hatch, created at module scope on purpose: a resource built while
* a transaction is running would capture that transaction, so this single
* instance is the only one the module ever needs. It carries no context of its
* own, so every job run through it starts from the process's root context.
*/
const DETACHED = new AsyncResource("dsh-web:detached-work", { triggerAsyncId: 0 });
/**
* Run `work` outside the caller's AsyncLocalStorage context.
*
* The call itself is synchronous - this schedules, it does not defer. Work that
* must not block the caller should schedule its own `setImmediate` inside
* `work`, which then also starts clean because it inherits this resource's
* empty context rather than the caller's.
*
* @param work - the side effect to detach from the caller's async context.
* @returns whatever `work` returns.
*/
function runDetached(work) {
	return DETACHED.runInAsyncScope(work);
}
//#endregion
//#region src/remote-channel-boot.ts
/**
* Parse-time remote-channel boot patch (issue #987): the browser-half patch
* (client/remote-channel.ts) installs when this plugin's boot entry runs,
* but `dsh-client-connection` boots earlier and opens its event streams
* unrewritten — on a non-loopback origin the SDK fence rejects them and the
* workspace list never loads. The host therefore inlines this classic script
* right after the opening <head> tag (webserver/index-inject), so the
* fetch/WebSocket/EventSource/src rewrite is active before ANY boot entry
* executes. The plugin's client apply later adopts the installed seat
* (hooks + pending unpaired signal) instead of patching twice.
*
* The rewrite decisions are generated from REMOTE_CHANNEL_RULES, the same
* data the browser patch consumes — the two cannot drift apart. On this
* 0.1.2-alpha.2 line the "configuration plane is local" behavior lives in
* the browser (client plugins branch on connection.isLoopback), so the
* script also flips the official UI into host mode by installing the
* transport hook `__DSH_TRANSPORT__ = { ownsHost: true }` before the
* connection plugin reads it: the paired remote desktop gets the full
* settings/credentials/presets surface, and every call still rides the
* gated /remote channel. Host mode is server-granted, not origin-asserted:
* the hook is installed only when the device-gated app landing (/wj-pair-app)
* published the grant marker (REMOTE_HOST_GRANT_GLOBAL) ahead of this
* script, so a shell served to an unpaired browser - a fence-open
* deployment - never presents itself as the machine owner. It finally
* publishes the official pre-Cordis
* upload hook (`__DSH_FILE_UPLOAD__`), because the background upload
* transport otherwise runs inside a Web Worker whose own globals the
* main-thread rewrite cannot reach (issue #1580). The script self-skips on
* loopback origins and never throws.
* @module wj-dsh-remote/remote-channel-boot
*/
/**
* Build the inline boot script. The result contains no `<\/script` sequence
* (the injection contract) and installs a {@link RemoteChannelBootSeat} on
* the window global.
*/
function buildRemoteChannelBootScript(rules = REMOTE_CHANNEL_RULES) {
	const json = JSON.stringify(rules);
	const seat = JSON.stringify(REMOTE_CHANNEL_BOOT_GLOBAL);
	return "(function(){try{var w=window,loc=w.location,h=loc.hostname;var R=" + json + ";if(h==='localhost'||h==='::1'||h==='[::1]'||/^127(\\.\\d{1,3}){3}$/.test(h))return;var pr=loc.protocol;if(typeof pr===\"string\"&&pr!==\"\"&&R.webProtocols.indexOf(pr)===-1)return;try{if(w.__DSH_TRANSPORT__&&w.__DSH_TRANSPORT__.ownsHost===true&&h.indexOf(\".\")===-1&&h.indexOf(\":\")===-1)return}catch(e){}try{if(w[R.hostGrantGlobal]===true){if(w.__DSH_TRANSPORT__===undefined)w.__DSH_TRANSPORT__={};w.__DSH_TRANSPORT__.ownsHost=true}}catch(e){}function rdv(){try{return w.sessionStorage.getItem(R.deviceKey)}catch(e){return null}}function att(init){var dv=rdv();if(dv===null)return init;var h=init&&init.headers;if(typeof Headers!==\"undefined\"&&h instanceof Headers){try{h.set(R.deviceHeader,dv)}catch(e){}return init}if(typeof h===\"object\"&&h!==null){var o={};for(var k in h)o[k]=h[k];o[R.deviceHeader]=dv;return Object.assign({},init,{headers:o})}return init}function sf(p){if(p.indexOf(R.updatePrefix)===0)return false;if(p===R.settingsBridgePrefix||p.indexOf(R.settingsBridgePrefix+\"/\")===0)return false;if(p.indexOf(R.apiPrefix)===0)return true;if(p.indexOf(R.sidebarPrefix)===0||p===\"/sidebar\")return true;if(p.indexOf(R.gitPrefix)===0||p===\"/git\")return true;if(p.indexOf(R.petPrefix)===0||p===\"/pet\")return true;/*wj-adapters:start*/if(/^\\/dsh-market\\/(?:registry|status|installed|updates|updates\\/summary|find-compatible|discovery-compatibility|snapshots|logs|presets|bundle-order|groups|check|changelog|build-env|channel|entry-visibility|sidebar-entry|favorite|note|github-proxy|api\\/v1\\/capabilities)(?:\\/|$)/.test(p))return true;/*wj-adapters:end*/return false}function sw(p){return R.wsPaths.indexOf(p)!==-1}function rp(p){return R.remotePrefix+p}function so(u){return u.origin===loc.origin}function rr(raw){var u;try{u=new URL(raw,loc.href)}catch(e){return raw}if(u.origin!==loc.origin)return raw;if(!sf(u.pathname))return raw;u.pathname=rp(u.pathname);if(raw.charAt(0)===\"/\"&&raw.charAt(1)!==\"/\")return u.pathname+u.search+u.hash;return u.href}function uc(v){if(typeof v!==\"object\"||v===null)return undefined;var n=v.result;if(typeof n===\"object\"&&n!==null){var e=n.error;if(typeof e===\"object\"&&e!==null&&typeof e.code===\"string\")return e.code}var t=v.error;if(typeof t===\"object\"&&t!==null&&typeof t.code===\"string\")return t.code;return undefined}var seat={onUnpaired:null,onPaired:null,pendingUnpaired:false,restore:function(){}};function denied(res){if(res.status!==403)return false;return res.clone().json().then(function(b){return uc(b)===\"unpaired\"}).catch(function(){return false})}function signal(unpaired){if(unpaired){if(seat.onUnpaired)seat.onUnpaired();else seat.pendingUnpaired=true}else{seat.pendingUnpaired=false;if(seat.onPaired)seat.onPaired()}}var of=w.fetch;w.fetch=function(input,init){var raw=typeof input===\"string\"||input instanceof URL?input.toString():input.url;var url=new URL(raw,loc.href);if(so(url)&&sf(url.pathname)){var next=new URL(url);next.pathname=rp(url.pathname);var target=typeof input===\"string\"||input instanceof URL?next.toString():new Request(next,input);return Promise.resolve(of.call(w,target,att(init))).then(function(res){void Promise.resolve(denied(res)).then(signal);return res})}return of.call(w,input,init)};var OW=w.WebSocket;w.WebSocket=function(url,protocols){var p=new URL(url.toString(),loc.href);var o=p.protocol===\"wss:\"?\"https://\"+p.host:p.protocol===\"ws:\"?\"http://\"+p.host:\"\";if(o!==\"\"&&o===loc.origin&&sw(p.pathname)){var nx=new URL(p);nx.pathname=rp(p.pathname);var dvv=rdv();if(dvv!==null)nx.searchParams.set(R.deviceQuery,dvv);return protocols!==undefined?new OW(nx,protocols):new OW(nx)}return protocols!==undefined?new OW(url,protocols):new OW(url)};w.WebSocket.prototype=OW.prototype;w.WebSocket.CONNECTING=OW.CONNECTING;w.WebSocket.OPEN=OW.OPEN;w.WebSocket.CLOSING=OW.CLOSING;w.WebSocket.CLOSED=OW.CLOSED;var OE=w.EventSource;if(OE!==undefined){w.EventSource=function(url,cfg){var p=new URL(url.toString(),loc.href);if(so(p)&&sf(p.pathname)){var nx=new URL(p);nx.pathname=rp(p.pathname);var dvv=rdv();if(dvv!==null)nx.searchParams.set(R.deviceQuery,dvv);return new OE(nx,cfg)}return new OE(url,cfg)};w.EventSource.prototype=OE.prototype}var restores=[];function patchSrc(C){if(C===undefined)return;var d=Object.getOwnPropertyDescriptor(C.prototype,\"src\");if(d===undefined||d.configurable===false||d.set===undefined)return;var os=d.set;Object.defineProperty(C.prototype,\"src\",{configurable:true,enumerable:d.enumerable!==false,get:d.get,set:function(v){os.call(this,rr(String(v)))}});restores.push(function(){Object.defineProperty(C.prototype,\"src\",d)})}patchSrc(w.HTMLImageElement);patchSrc(w.HTMLScriptElement);patchSrc(w.HTMLIFrameElement);function uf(u,init){var raw=typeof u===\"string\"?u:u.href;if(typeof raw!==\"string\")return of.call(w,u,init||{});var q=new URL(raw,loc.href);if(so(q)&&q.pathname===R.uploadPath)return w.fetch(raw,init||{});return of.call(w,u,init||{})}try{if(w[R.uploadHookGlobal]===undefined)w[R.uploadHookGlobal]={fetch:uf}}catch(e){}seat.restore=function(){w.fetch=of;w.WebSocket=OW;if(OE!==undefined)w.EventSource=OE;for(var i=0;i<restores.length;i++)restores[i]();try{delete w[" + seat + "]}catch(e){w[" + seat + "]=undefined}};w[" + seat + "]=seat" + buildBootWatchdogScript() + "}catch(e){}})();";
}
/** Boot-watchdog latch: one self-reload per session while the boot is broken. */
const BOOT_WATCHDOG_KEY = "dsh-remote-boot-reload";
/** Post-load wait for the app's first conversation surface before the reload. */
const BOOT_WATCHDOG_WAIT_MS = 15e3;
/** Watchdog poll cadence. */
const BOOT_WATCHDOG_POLL_MS = 1e3;
/**
* Build the boot-watchdog script fragment. A remote boot has no recovery
* path of its own: the SPA mounts nothing when a boot-critical request dies
* (a tunnel-edge 429 under burst, a dropped stream, a boot-order race), and
* the phone then shows a permanently blank shell. The watchdog polls for the
* app's conversation surface and reloads once when it never appears; the
* sessionStorage latch keeps a genuinely broken deployment from looping,
* and a successful boot clears the latch so a later failure can recover.
*/
function buildBootWatchdogScript(waitMs = BOOT_WATCHDOG_WAIT_MS, pollMs = BOOT_WATCHDOG_POLL_MS) {
	const key = JSON.stringify(BOOT_WATCHDOG_KEY);
	return ";function wBoot(){try{return !!(w.document&&w.document.querySelector&&(w.document.querySelector(\"[data-conversation-scroll]\")||w.document.querySelector(\"[data-slot=\\\"conversation\\\"]\")))}catch(e){return false}}function wTick(n){try{if(wBoot()){try{w.sessionStorage.removeItem(" + key + ")}catch(e){}return}if(!w.document||w.document.readyState!==\"complete\"){w.setTimeout(function(){wTick(0)}," + pollMs + ");return}if(n<" + waitMs + "){w.setTimeout(function(){wTick(n+" + pollMs + ")}," + pollMs + ");return}var done=false;try{done=w.sessionStorage.getItem(" + key + ")===\"1\"}catch(e){}if(done)return;try{w.sessionStorage.setItem(" + key + ",\"1\")}catch(e){}w.location.reload()}catch(e){}}if(typeof w.setTimeout===\"function\")w.setTimeout(function(){wTick(0)}," + pollMs + ");";
}
/** The script this plugin contributes; built once from the live rules. */
const REMOTE_CHANNEL_BOOT_SCRIPT = buildRemoteChannelBootScript();
//#endregion
//#region src/uuid-polyfill.ts
/**
* Polyfill for crypto.randomUUID for non-secure contexts (LAN HTTP)
* where the browser does not expose crypto.randomUUID.
*
* The script string is injected as an inline <script> in the desktop HTML
* head so the SDK's mintRpcId() sees a working randomUUID even on plain
* http:// origins (#1024).
*/
const UUID_POLYFILL_SCRIPT = [
	"(function(){",
	"var g=typeof globalThis!==\"undefined\"?globalThis:typeof window!==\"undefined\"?window:self;",
	"if(typeof g.crypto===\"undefined\"){g.crypto={};}",
	"if(typeof g.crypto.randomUUID!==\"function\"){",
	"g.crypto.randomUUID=function(){",
	"var a=new Uint8Array(16);",
	"if(g.crypto.getRandomValues){g.crypto.getRandomValues(a);}",
	"else{for(var j=0;j<16;j++){a[j]=Math.random()*256|0;}}",
	"a[6]=(a[6]&0x0f)|0x40;",
	"a[8]=(a[8]&0x3f)|0x80;",
	"var h=\"\",x=\"0123456789abcdef\";",
	"for(var i=0;i<16;i++){h+=x[a[i]>>4]+x[a[i]&0x0f];",
	"if(i===3||i===5||i===7||i===9)h+=\"-\";}",
	"return h;",
	"};",
	"}",
	"})();"
].join("");
//#endregion
//#region src/index.ts
/**
* Mobile remote control for the dsh web GUI — host half. Mounts the pairing
* service (one-time tokens, device sessions, revocation), the /api/wj-pair
* route family (issue/accept/stop/heartbeat/status/events), the api/gate
* listener that enforces pairing on every other /api request from
* non-loopback hosts, and the presence sweep. The browser half (the
* `./client` entry) renders the sidebar entry, the pairing panel, and the
* phone-side pair/accept + deep-link flow.
*/
/** Stable cordis plugin name. */
const name = "wj-dsh-remote";
/** Services required before the pairing surfaces can mount. */
const inject = [
	"webServer",
	"typertGateway",
	"connection"
];
/**
* Settings namespace of the remote-control capability. Under the 0.1.7
* settings model the namespace IS the Host profile entry id, so this is also
* the id the browser half asks `ctx.configForms` for (the family binder
* resolves the same value to the owning entry). Spelled here rather than
* imported: the browser half spells the same value and must not depend on a
* Host package.
*/
const REMOTE_WEB_UI_SETTINGS_NAMESPACE = "wj-dsh-remote";
/**
* Plugin config schema. Under the 0.1.7 settings model this schema IS the
* entry's settings page: the Host derives one form per profile entry from it
* and serves that form only when at least one field is `volatile()`. The marker
* is also what admits a write and what keeps the edit on the live path — the
* Loader commits the new value into the field's reference and announces
* `loader/volatile-update` on this fiber instead of remounting the row, so the
* pairing service, its device sessions, the tunnel and the route registrations
* survive a settings save (see {@link applyImpl}'s sync).
*
* The schema is left to inference rather than annotated with `z<Config>`: a
* volatile field's parsed output is a live reference while its accepted input
* stays the plain value, so the two sides no longer share one shape and the
* annotation would reject the schema the Host must be given.
*
* The deployment-level fields (`trustedHosts`, `devicesFile`, `profile`) are
* deliberately NOT volatile: they belong in the profile patch, so the form
* leaves them to the operator instead of offering a card control that a
* document write could not honor.
*/
const Config = z.object({
	tokenTtlMs: z.number().step(1).min(6e4).default(10 * 6e4).volatile(),
	offlineAfterMs: z.number().step(1).min(5e3).default(25e3).volatile(),
	maxDevices: z.number().step(1).min(1).max(64).default(4).volatile(),
	idleExpireMs: z.number().step(1).min(6e4).default(DEFAULT_IDLE_EXPIRE_MS).volatile(),
	cookieName: z.string().min(1).default("wj_dsh_pair").volatile(),
	requirePairingForLan: z.boolean().default(true).volatile(),
	publicBaseUrl: z.string().volatile(),
	trustedHosts: z.array(z.string()),
	devicesFile: z.string(),
	autoTunnel: z.boolean().default(false).volatile(),
	tunnelToken: z.string().role("secret").volatile(),
	ingressSync: z.boolean().default(false).volatile(),
	cfApiToken: z.string().role("secret").volatile(),
	cfAccountId: z.string().volatile(),
	cfTunnelId: z.string().volatile(),
	relay: z.boolean().default(false).volatile(),
	lanBind: z.boolean().volatile(),
	profile: z.string().pattern(/^[A-Za-z0-9][A-Za-z0-9._-]*$/),
	enabled: z.boolean().default(true).volatile(),
	pairingSource: z.union([...PAIRING_SOURCE_OPTIONS]).default("auto").volatile()
});
/** Presence sweep cadence (a stale device flips to disconnected within two sweeps). */
const SWEEP_INTERVAL_MS = 1e4;
/**
* Re-plan retry while the quick tunnel waits for the webServer port to bind
* (a recompose pass can run this apply ahead of the listener's bind).
*/
const PORT_SETTLE_RETRY_MS = 1e3;
/** Read one resolved config field, following the live reference the schema produces. */
function readConfigField(field, fallback) {
	if (field === void 0) return fallback;
	if (typeof field === "object" && field !== null && typeof field.get === "function") {
		const value = field.get();
		return value === void 0 ? fallback : value;
	}
	return field;
}
/**
* Read one optional resolved config field. A volatile reference is read at
* call time, so an unset field stays `undefined` rather than falling back to a
* schema default (the distinction the LAN toggle and the tunnel plan depend on).
*/
function readOptionalConfigField(field) {
	if (field === void 0) return void 0;
	if (typeof field === "object" && field !== null && typeof field.get === "function") return field.get();
	return field;
}
/**
* The single mapping from resolved plugin config to the pairing service
* config. Both the constructed service and every later apply of this row
* reuse it, so no field can be silently dropped.
*/
function pairingConfigOf(resolved) {
	return {
		tokenTtlMs: resolved.tokenTtlMs,
		offlineAfterMs: resolved.offlineAfterMs,
		maxDevices: resolved.maxDevices,
		idleExpireMs: resolved.idleExpireMs,
		cookieName: resolved.cookieName,
		devicesFile: resolved.devicesFile,
		idPepper: idPepper()
	};
}
/** Default paired-session store: `$DSH_HOME/wj-dsh-remote-devices.json`. */
function defaultDevicesFile(home = dshHome()) {
	return join(home, "wj-dsh-remote-devices.json");
}
/** Per-install pepper for public ids; loaded once per process. */
let cachedIdPepper;
function idPepper() {
	cachedIdPepper ??= loadIdPepper(dshHome());
	return cachedIdPepper;
}
/** Schema defaults, re-read for hand-built test contexts (the loader applies them normally). */
const DEFAULTS = {
	tokenTtlMs: 10 * 6e4,
	offlineAfterMs: 25e3,
	maxDevices: 4,
	idleExpireMs: DEFAULT_IDLE_EXPIRE_MS,
	cookieName: "wj_dsh_pair",
	requirePairingForLan: true,
	publicBaseUrl: void 0,
	trustedHosts: void 0,
	devicesFile: defaultDevicesFile(),
	autoTunnel: false,
	tunnelToken: void 0,
	ingressSync: false,
	cfApiToken: void 0,
	cfAccountId: void 0,
	cfTunnelId: void 0,
	relay: false,
	lanBind: void 0,
	profile: resolveManagedProfile(void 0, void 0, process.env.DSH_PROFILE),
	enabled: true,
	pairingSource: "auto"
};
/**
* The launched profile the Host publishes on its `profileContext` service
* (`{ name, dir, patchPath, … }`). The Desktop client boots the "desktop"
* profile without exporting DSH_PROFILE, so the environment alone resolves
* the wrong profile there and the LAN bind toggle would edit a profile that
* is not running.
* @param ctx - host plugin context.
* @returns the profile name when the Host publishes one; undefined otherwise.
*/
function launchedProfileName(ctx) {
	const fact = ctx.get("profileContext");
	return typeof fact?.name === "string" && fact.name.length > 0 ? fact.name : void 0;
}
/**
* Mount the pairing service, routes, gate listener, and presence sweep.
* @param ctx - host plugin context carrying webServer.
* @param config - resolved plugin config (schema defaults applied by the loader).
*/
const apply = mountOnce("wj-dsh-remote", applyImpl);
/**
* What the running host accepts as a bind, sampled once per boot: the installed
* webserver schema decides the wildcard (see host-bind-capability.ts) and the
* interface list is frozen for the same reason the QR bases are.
*
* The plugin no longer writes a bind anywhere (issue #1917), so the schema
* answer is reported to the settings card and never turned into a profile row;
* the LAN edge listens on a concrete interface literal, which every schema
* line accepts.
* @param configOf - schema factory override (test seam); the installed package's own by default.
* @returns the capability the LAN-edge plan is computed against.
*/
function lanBindCapabilityOf(configOf) {
	return {
		wildcardSupported: wildcardBindSupported(configOf),
		candidates: lanIPv4Addresses()
	};
}
/**
* The LAN URL bases a non-loopback bind is reachable by. A wildcard bind
* answers every interface, so each candidate gets its own base (a multi-homed
* machine can pick the network the phone actually reaches). A concrete literal
* is only reachable at that literal, so it is the only base advertised.
* @param host - the live bind, or the block host on a process whose bind is not settled.
* @param port - the bound port.
* @returns the bases, empty when the bind stays on this machine.
*/
function lanBasesOf(host, port) {
	if (typeof host !== "string" || !isLanReachableBind(host)) return [];
	return (isWildcardLiteral(host) ? lanIPv4Addresses() : [bindUrlHostOf(host)].filter((address) => address !== void 0 && address !== "")).map((address) => ({
		address,
		base: `http://${address}:${String(port)}`
	}));
}
/**
* The LAN-bind status frame the loopback-only `/api/wj-pair/lan-bind` endpoint
* serves, built as one pure value so every field has direct unit coverage.
*
* `bindHost` is the address LAN clients can actually dial - the forwarder's
* listener, or the running bind when the operator pointed `--host` at the
* network - because that is what the card renders as "bind: host:port".
* `localBindHost` keeps the host process's own listener visible beside it.
* @param input - the facts read at request time.
* @param firewallOf - firewall summary reader (injected in tests).
* @returns the frame the settings card reads.
*/
function lanBindFrameOf(input, firewallOf = firewallSummary) {
	const capability = {
		wildcardSupported: input.wildcardSupported,
		candidates: input.candidates
	};
	const plan = forwardPlanOf(input.setting, input.startupHost, capability);
	const reachHost = input.forward.listening ? input.forward.address : input.bindHost;
	return {
		profile: input.profile,
		setting: input.setting ?? null,
		blockHost: input.blockHost ?? null,
		bindHost: reachHost,
		localBindHost: input.bindHost ?? null,
		port: input.port,
		lanUrls: input.port !== void 0 ? lanBasesOf(reachHost, input.port).map((entry) => entry.base) : [],
		firewall: input.port !== void 0 ? firewallOf(input.port, isLanReachableBind(reachHost)) : {
			ok: true,
			managed: false
		},
		platform: process.platform,
		/** The LAN address the forwarder plans to listen on; null when it must stay off. */
		desiredHost: plan.host ?? null,
		/** Whether the running host's schema accepts the wildcard bind (reported only). */
		wildcardSupported: input.wildcardSupported,
		/** The concrete LAN literals this process could listen on. */
		supportedHosts: input.candidates,
		/** The toggle is on but this machine has no LAN IPv4 address to listen on. */
		lanBlocked: plan.reason === "no-address",
		pendingRestart: false,
		/** The block a previous version wrote was removed by this process. */
		legacyBlockRemoved: input.legacyBlockRemoved,
		/** The LAN edge itself: what it listens on, and why not when it is off. */
		forward: {
			listening: input.forward.listening,
			host: input.forward.address ?? null,
			port: input.forward.port ?? null,
			reason: input.forward.listening ? null : input.forwardReason ?? null,
			error: input.forward.error ?? null
		}
	};
}
function applyImpl(ctx, config) {
	const envPublicBase = process.env.DSH_REMOTE_PUBLIC_BASE_URL?.trim() || void 0;
	const resolve = () => ({
		tokenTtlMs: readConfigField(config?.tokenTtlMs, DEFAULTS.tokenTtlMs),
		offlineAfterMs: readConfigField(config?.offlineAfterMs, DEFAULTS.offlineAfterMs),
		maxDevices: readConfigField(config?.maxDevices, DEFAULTS.maxDevices),
		idleExpireMs: readConfigField(config?.idleExpireMs, DEFAULTS.idleExpireMs),
		cookieName: readConfigField(config?.cookieName, DEFAULTS.cookieName),
		requirePairingForLan: readConfigField(config?.requirePairingForLan, DEFAULTS.requirePairingForLan),
		publicBaseUrl: readOptionalConfigField(config?.publicBaseUrl) ?? envPublicBase,
		trustedHosts: readOptionalConfigField(config?.trustedHosts),
		devicesFile: readConfigField(config?.devicesFile, DEFAULTS.devicesFile),
		autoTunnel: readConfigField(config?.autoTunnel, DEFAULTS.autoTunnel),
		tunnelToken: readOptionalConfigField(config?.tunnelToken),
		ingressSync: readConfigField(config?.ingressSync, DEFAULTS.ingressSync),
		cfApiToken: readOptionalConfigField(config?.cfApiToken),
		cfAccountId: readOptionalConfigField(config?.cfAccountId),
		cfTunnelId: readOptionalConfigField(config?.cfTunnelId),
		relay: readConfigField(config?.relay, DEFAULTS.relay),
		lanBind: readOptionalConfigField(config?.lanBind),
		profile: resolveManagedProfile(readOptionalConfigField(config?.profile), launchedProfileName(ctx), process.env.DSH_PROFILE),
		enabled: readConfigField(config?.enabled, DEFAULTS.enabled),
		pairingSource: readConfigField(config?.pairingSource, DEFAULTS.pairingSource)
	});
	const service = new PairingService(pairingConfigOf(resolve()));
	const tunnel = new TunnelManager();
	let relayRegistrar;
	const namedRelayConnector = createNamedRelayConnector();
	/**
	* Whether the lease's own named connector runs. It is the quick tunnel's
	* sibling, so a plan that runs no quick tunnel leaves it off: the claim is
	* made for the bridge grant, not to start a second tunnel.
	*/
	let namedConnectorWanted = false;
	const bridgeRelayConnector = createRelayBridgeRunner({ onState: (state) => {
		if (state.state === "connected") console.log("wj-dsh-remote: relay bridge attached for " + state.instance);
		if (state.state === "failed") console.warn("wj-dsh-remote: relay bridge dial failed (" + state.error + ") — retrying with the same credential");
	} });
	let relayPair;
	/** The claim input the pair last ran for (dedupes settings-sync re-runs). */
	let relayClaimedFor;
	/** The version a claim reports, read once from this package's manifest. */
	let pluginVersion;
	/**
	* The public base the pairing fence trusts. A tunnel reconnect must not
	* strip the host the QR still shows: named and relay hosts never change,
	* and a quick tunnel's host survives a bounded grace window (issue #1547).
	*/
	const publicBase = new PublicBaseKeeper((base) => {
		service.setPublicBaseUrl(base);
	});
	/** The tunnel target the registrar last announced (dedupes sync re-runs). */
	let relayAnnouncedFor;
	/**
	* Drop the registry mapping (the announce half). The lease half is
	* transport-owned — the bridge dials the object directly — so a plan that
	* runs no quick tunnel stops announcing but never drops the lease.
	*/
	const disposeRelayAnnouncer = (unregister = false) => {
		const registrar = relayRegistrar;
		relayRegistrar = void 0;
		relayAnnouncedFor = void 0;
		publicBase.setRelay(void 0);
		if (registrar === void 0) return;
		if (unregister) registrar.unregister().catch(() => void 0);
		registrar.dispose();
	};
	/** Drop the whole relay half: the mapping, the lease and every connector. */
	const disposeRelayHalf = (unregister = false) => {
		disposeRelayAnnouncer(unregister);
		const pair = relayPair;
		relayPair = void 0;
		relayClaimedFor = void 0;
		namedRelayConnector.stop();
		bridgeRelayConnector.stop();
		if (pair === void 0) return;
		if (unregister) pair.release().catch(() => void 0);
		pair.dispose();
	};
	const ensureRelayRegistrar = () => {
		if (resolve().relay === false) return void 0;
		if (relayRegistrar === void 0) try {
			relayRegistrar = new RelayRegistrar(loadRelayIdentity(resolve().profile), (state) => {
				service.setRelayStatus(state.state === "off" ? void 0 : state);
				if (state.state === "running") publicBase.setRelay(state.url);
				else if (state.state === "off") publicBase.setRelay(void 0);
				else if (state.state === "failed") console.warn(`wj-dsh-remote: relay registration failed (${state.error}) — the stable origin may serve its offline page until the retry lands`);
			});
		} catch (error) {
			console.warn(`wj-dsh-remote: relay registry unavailable (${error instanceof Error ? error.message : String(error)}) — the quick URL is the QR base`);
		}
		return relayRegistrar;
	};
	const ensureRelayPair = () => {
		if (resolve().relay === false) return void 0;
		if (relayPair === void 0) try {
			const identity = loadRelayIdentity(resolve().profile);
			pluginVersion ??= readPluginVersion();
			relayPair = new RelayConnectorPair(identity, {
				startNamed: (token, hostname) => {
					if (namedConnectorWanted) namedRelayConnector.start(token, hostname);
				},
				startBridge: (start) => {
					bridgeRelayConnector.start(start);
				},
				onState: (state) => {
					if (state.state === "claimed") console.log(`wj-dsh-remote: relay lease claimed — the ${state.mode} connector serves ${state.hostname}`);
					else if (state.state === "failed") console.warn(`wj-dsh-remote: relay lease claim failed (${state.error}) — the quick connector keeps serving, retrying`);
				}
			});
		} catch (error) {
			console.warn(`wj-dsh-remote: relay lease unavailable (${error instanceof Error ? error.message : String(error)}) — the quick tunnel path is unchanged`);
		}
		return relayPair;
	};
	/**
	* Claim the named lease for one tunnel start. Deduped on the local origin
	* port plus the quick URL, so a settings sync never re-claims while a real
	* restart (a new quick hostname) does — the claim is also what keeps the
	* lease's `last_seen_at` inside the cron GC's TTL.
	*/
	const claimRelayLeaseFor = (port, target) => {
		const key = relayClaimKeyOf(port, target);
		if (key === void 0 || relayClaimedFor === key) return;
		const pair = ensureRelayPair();
		if (pair === void 0 || port === void 0) return;
		relayClaimedFor = key;
		pair.start({
			port,
			pluginVersion
		}).catch(() => void 0);
	};
	const announceRelay = (registrar, target) => {
		if (relayAnnouncedFor === target) return;
		relayAnnouncedFor = target;
		registrar.announce(target);
	};
	let tunnelMode = resolve().autoTunnel ? "quick" : "off";
	/**
	* Retry timer while the quick tunnel waits for the webServer port to bind
	* (undefined when no deferral is pending). Unref'd: never keeps the
	* process alive on its own.
	*/
	let portSettleTimer;
	/** Dedupes the unbound-port warning to one line per unsettled episode. */
	let portSettleWarned = false;
	/** Re-plan once the port settles: the tunnel target and the lease both need it. */
	const schedulePortSettleRetry = () => {
		if (portSettleTimer !== void 0) return;
		portSettleTimer = setTimeout$1(() => {
			portSettleTimer = void 0;
			sync();
		}, PORT_SETTLE_RETRY_MS);
		portSettleTimer.unref();
	};
	tunnel.onPhase((info) => {
		if (tunnelMode === "off") return;
		if (info.phase === "running" && info.url !== void 0) {
			publicBase.markRunning(info.url);
			service.setTunnelStatus({
				state: "running",
				url: info.url
			});
			const registrar = tunnelMode === "quick" ? ensureRelayRegistrar() : void 0;
			if (registrar !== void 0) announceRelay(registrar, info.url);
			if (tunnelMode === "quick") claimRelayLeaseFor(ctx.webServer.port, info.url);
			runPostureProbe();
		} else if (info.phase === "starting") {
			publicBase.markReconnecting();
			service.setTunnelStatus({ state: "starting" });
		} else if (info.phase === "failed") {
			publicBase.markReconnecting();
			service.setTunnelStatus(info.error === void 0 ? { state: "failed" } : {
				state: "failed",
				error: info.error
			});
		}
	});
	ctx.effect(() => () => {
		disposeRelayHalf();
		publicBase.dispose();
		tunnel.dispose();
		if (portSettleTimer !== void 0) clearTimeout(portSettleTimer);
	}, "wj-dsh-remote: auto tunnel");
	let ingressEnabledOnce = false;
	const ingress = new IngressSync({ onFrame: (frame) => {
		if (frame.state !== "off") ingressEnabledOnce = true;
		service.setIngressStatus(ingressEnabledOnce ? frame : void 0);
		if (frame.state === "failed" || frame.state === "conflict") {
			const code = frame.code === void 0 ? "" : ` (${frame.code})`;
			const detail = frame.detail === void 0 ? "" : `: ${frame.detail}`;
			console.warn(`wj-dsh-remote: ingress sync ${frame.state}${code}${detail}`);
		}
	} });
	ctx.effect(() => () => {
		ingress.dispose();
	}, "wj-dsh-remote: ingress sync");
	if (typeof ctx.webServer.host === "string" && ctx.webServer.host !== "" && Number.isFinite(ctx.webServer.port)) service.setLanBases(lanBasesOf(ctx.webServer.host, ctx.webServer.port));
	let disposeRoutes;
	let disposeSweep;
	let lastKnownPort;
	let lastFirewallApplied;
	const capability = lanBindCapabilityOf();
	const lanBindStatus = () => {
		const resolvedNow = resolve();
		let state;
		try {
			state = lanBindState(resolvedNow.profile);
		} catch {
			state = { blockPresent: false };
		}
		const port = Number.isFinite(ctx.webServer.port) ? ctx.webServer.port : lastKnownPort;
		if (Number.isFinite(ctx.webServer.port)) lastKnownPort = ctx.webServer.port;
		return lanBindFrameOf({
			profile: resolvedNow.profile,
			setting: resolvedNow.lanBind,
			blockHost: state.host,
			bindHost: ctx.webServer.host,
			forward: forwarder.snapshot(),
			forwardReason,
			legacyBlockRemoved,
			port,
			wildcardSupported: capability.wildcardSupported,
			candidates: capability.candidates,
			startupHost: ctx.get("webStartup")?.host
		});
	};
	const innerAuth = createInnerAuth(() => {
		if (!Number.isFinite(ctx.webServer.port)) return void 0;
		try {
			return ctx.connection.authenticatedUrl?.(`http://127.0.0.1:${String(ctx.webServer.port)}/`);
		} catch {
			return;
		}
	});
	const APP_SHELL_TTL_MS = 3e4;
	let appShellCache;
	const fetchAppShell = async () => {
		if (!Number.isFinite(ctx.webServer.port)) return void 0;
		if (appShellCache !== void 0 && Date.now() - appShellCache.at < APP_SHELL_TTL_MS) return appShellCache.html;
		const cookie = await innerAuth.ready();
		try {
			const response = await fetch(`http://127.0.0.1:${String(ctx.webServer.port)}/`, withIdentityEncoding({ headers: cookie !== void 0 ? { cookie } : void 0 }));
			if (!response.ok) {
				if (response.status === 401 || response.status === 403) innerAuth.invalidate();
				return;
			}
			const html = await response.text();
			appShellCache = {
				at: Date.now(),
				html
			};
			return html;
		} catch {
			return;
		}
	};
	const routes = [...makeRoutes({
		service,
		requirePairingForLan: () => resolve().requirePairingForLan,
		pairingSource: () => resolve().pairingSource,
		lanBindStatus,
		indexDocument: fetchAppShell,
		trustedHosts: () => {
			const list = [];
			const envHosts = process.env.DSH_REMOTE_TRUSTED_HOSTS;
			if (typeof envHosts === "string" && envHosts.trim() !== "") for (const item of envHosts.split(",")) {
				const trimmed = item.trim();
				if (trimmed !== "") list.push(trimmed);
			}
			const cfgHosts = resolve().trustedHosts;
			if (Array.isArray(cfgHosts)) {
				for (const item of cfgHosts) if (typeof item === "string") {
					const trimmed = item.trim();
					if (trimmed !== "") list.push(trimmed);
				}
			}
			return list;
		}
	}), ...makeRemoteApiRoutes({
		service,
		port: () => ctx.webServer.port,
		auth: innerAuth
	})];
	const upgrades = makeRemoteApiUpgradeRoutes({
		service,
		port: () => ctx.webServer.port,
		auth: innerAuth
	});
	const gate = makeGateListener(service, () => resolve().requirePairingForLan, () => resolve().enabled);
	ctx.effect(() => ctx.on("api/gate", gate), "wj-dsh-remote: api gate");
	let postureKey;
	let postureWasExposed = false;
	const runPostureProbe = () => {
		if (!resolve().enabled) return;
		const port = ctx.webServer.port;
		if (port === void 0) return;
		const targets = postureTargets(service.publicBaseUrl, service.lanAddresses, port);
		if (targets.length === 0) {
			postureKey = void 0;
			service.setPosture(void 0);
			return;
		}
		const key = targets.join("|");
		const claim = claimPostureKey(postureKey, key);
		if (!claim.run) return;
		postureKey = claim.next;
		probePosture({
			port,
			targets
		}).then((snapshot) => {
			service.setPosture(snapshot);
			const exposedHosts = snapshot.hosts.filter((host) => host.exposed).map((host) => host.host);
			const exposed = exposedHosts.length > 0;
			if (exposed && !postureWasExposed) console.error(`wj-dsh-remote: CRITICAL — the /api fence is OPEN for [${exposedHosts.join(", ")}]: unpaired clients reach the full host API. Remove --trusted-host for these hosts (pairing covers them) or bind loopback.`);
			else if (!exposed && postureWasExposed) console.log("wj-dsh-remote: the /api posture probe is clean again (every advertised origin refused with 403).");
			postureWasExposed = exposed;
		}).catch(() => {
			postureKey = releasePostureKey(postureKey, key);
		});
	};
	const initialPostureTimer = setTimeout$1(() => {
		runPostureProbe();
	}, 5e3);
	initialPostureTimer.unref();
	ctx.effect(() => () => {
		clearTimeout(initialPostureTimer);
	}, "wj-dsh-remote: posture probe boot");
	new RemoteWebUiPairing(ctx, (request) => {
		if (!resolve().enabled) return false;
		return isPairedDeviceRequest(service, request);
	});
	const presencePet = startRemotePresencePet({
		onState: (listener) => service.onState(listener),
		pet: () => {
			try {
				return ctx.get("pet");
			} catch {
				return;
			}
		}
	});
	ctx.effect(() => presencePet, "wj-dsh-remote: remote-presence pet visibility");
	if (service.lanAddresses.length > 0) {
		const urls = service.lanAddresses.map((ip) => `http://${ip}:${String(ctx.webServer.port)}`).join(" , ");
		console.log(`wj-dsh-remote: the paired Web GUI is reachable on LAN at ${urls}`);
	}
	const forwarder = new LanForwarder();
	/** Why the forwarder is off as of the last reconcile; the status frame reports it. */
	let forwardReason = "off";
	/** Whether this process removed the block a previous version left behind. */
	let legacyBlockRemoved = false;
	/** The legacy cleanup runs once per process, ahead of every other bind step. */
	let legacyCleanupDone = false;
	/** One operator-facing line per stop reason, so a sync loop cannot flood the log. */
	const warnedForwardReasons = /* @__PURE__ */ new Set();
	let lanExposureWarned = false;
	/** One honest note that LAN exposure rests on pairing, not on the harness fence. */
	const warnLanExposure = () => {
		if (lanExposureWarned) return;
		lanExposureWarned = true;
		console.warn("wj-dsh-remote: LAN-exposed edge — pairing gates the /remote channel; direct /api stays under the harness fence + browser auth (stop() does not revoke an already-redeemed browser credential)");
	};
	/** The address a LAN client dials right now: the forwarder, else the host's own bind. */
	const lanEdgeHost = () => {
		const state = forwarder.snapshot();
		return state.listening ? state.address : ctx.webServer.host;
	};
	/**
	* Point the pairing service at the authority phones actually dial. The QR
	* bases and the phone-facing fences compare the Host header against this
	* list, so following the forwarder is what keeps a paired phone paired.
	*/
	const applyLanBases = () => {
		if (!Number.isFinite(ctx.webServer.port)) return;
		service.setLanBases(lanBasesOf(lanEdgeHost(), ctx.webServer.port));
	};
	/**
	* Remove the managed block a previous version (<= 0.4.8) wrote, once per
	* process and before anything else touches the profile. A surviving block
	* keeps replacing the web server row's config wholesale, so every later start
	* ignores --host/--port and binds a literal an older plugin guessed - the
	* exact failure this issue is about. Nothing is written back.
	* @param profile - the managed profile whose patch file may carry the block.
	*/
	const cleanupLegacyBlock = (profile) => {
		if (legacyCleanupDone) return;
		legacyCleanupDone = true;
		try {
			const result = removeManagedBlock(profile);
			legacyBlockRemoved = result.removed;
			if (result.removed) console.log(`wj-dsh-remote: removed the lan-bind block a previous version wrote into profile ${profile} (${result.host ?? "?"}:${String(result.port ?? "?")}); the web server row is never rewritten again`);
		} catch (error) {
			console.error(`wj-dsh-remote: failed to remove the lan-bind block from profile ${profile}: ${error instanceof Error ? error.message : String(error)}`);
		}
	};
	/**
	* Bring the LAN edge in line with the toggle. Every failure here costs the LAN
	* edge only: the loopback listener is never touched, so an address that
	* disappeared after a network change or a port already taken cannot brick the
	* host - the reason is logged and reported on the status frame.
	* @param value - the effective plugin configuration.
	*/
	const applyForwardEdge = (value) => {
		const startup = ctx.get("webStartup");
		const liveCapability = {
			wildcardSupported: capability.wildcardSupported,
			candidates: lanIPv4Addresses()
		};
		const plan = forwardPlanOf(value.lanBind, startup?.host, liveCapability);
		forwardReason = plan.reason;
		const state = forwarder.snapshot();
		const port = Number.isFinite(ctx.webServer.port) ? ctx.webServer.port : void 0;
		if (plan.host === void 0 || port === void 0) {
			if (state.listening) forwarder.stop().then(applyLanBases);
			else applyLanBases();
			if (plan.reason !== void 0 && !warnedForwardReasons.has(plan.reason)) {
				warnedForwardReasons.add(plan.reason);
				if (plan.reason === "host-bind") {
					console.log(`wj-dsh-remote: the web server itself binds ${startup?.host ?? ""} (from --host), so the LAN forwarder yields that port and this plugin adds no listener`);
					warnLanExposure();
				} else if (plan.reason === "no-address") console.error("wj-dsh-remote: lanBind is on but this machine has no LAN IPv4 address to listen on; LAN access stays off, use a tunnel instead");
			}
			return;
		}
		if (state.listening && state.address === plan.host && state.port === port) return;
		const host = plan.host;
		forwarder.start(host, port).then((next) => {
			if (next.listening) {
				console.log(`wj-dsh-remote: LAN forwarder listening on ${host}:${String(port)} -> ${FORWARD_UPSTREAM_HOST}:${String(next.upstreamPort)}; the web server itself stays on loopback`);
				warnLanExposure();
			} else console.error(`wj-dsh-remote: the LAN forwarder could not listen on ${host}:${String(port)} (${next.error ?? "unknown error"}); loopback access is unaffected and the LAN edge stays off`);
			applyLanBases();
		});
	};
	/**
	* The bind work one sync runs: the legacy block removal, the LAN edge, and the
	* firewall rule. It never writes a profile file except to remove the block an
	* older version left there.
	*
	* The scheduling that reaches it still runs through runDetached (see
	* scheduleLanBindWork): a settings save holds the Host's exclusive HMR
	* transaction in its async context, and a config-file write from inside that
	* context makes the watcher's refresh re-enter it ("HMR transactions cannot be
	* nested", #1751/#1754). The removal is a no-op on every boot after the first,
	* so the ordinary path writes nothing at all.
	* @param value - the effective plugin configuration.
	*/
	const applyLanBindWork = (value) => {
		cleanupLegacyBlock(value.profile);
		applyForwardEdge(value);
		if (value.lanBind === void 0) return;
		const livePort = Number.isFinite(ctx.webServer.port) ? ctx.webServer.port : void 0;
		if (livePort === void 0) {
			console.error("wj-dsh-remote: cannot align the host firewall rule — the web server port is not known yet");
			return;
		}
		const nextFirewall = {
			enabled: value.lanBind === true,
			port: livePort
		};
		if (!firewallActionNeeded(lastFirewallApplied, nextFirewall)) return;
		if (nextFirewall.enabled ? ensureFirewallRule(nextFirewall.port) : removeFirewallRule(nextFirewall.port)) lastFirewallApplied = nextFirewall;
		else console.error("wj-dsh-remote: the host firewall rule could not be updated (admin rights required on managed platforms)");
	};
	ctx.effect(() => () => {
		forwarder.stop();
	}, "wj-dsh-remote: lan forwarder");
	let lanBindWorkPending = false;
	const scheduleLanBindWork = () => {
		if (lanBindWorkPending) return;
		lanBindWorkPending = true;
		runDetached(() => setImmediate(() => {
			lanBindWorkPending = false;
			try {
				applyLanBindWork(resolve());
			} catch (error) {
				console.error(`wj-dsh-remote: the deferred lan-bind assertion failed: ${error instanceof Error ? error.message : String(error)}`);
			}
		}));
	};
	ctx.effect(() => () => {
		lanBindWorkPending = false;
	}, "wj-dsh-remote: lan-bind work");
	const applyTunnelPlan = (value, port) => {
		const plan = tunnelPlanOf(value, port);
		tunnelMode = plan.mode;
		publicBase.setMode(plan.mode);
		const liveTunnelUrl = publicBase.quickUrl();
		namedConnectorWanted = plan.mode === "quick";
		if (plan.mode !== "quick") {
			disposeRelayAnnouncer();
			namedRelayConnector.stop();
			if (value.relay === false) disposeRelayHalf(true);
			if (plan.mode !== "named") publicBase.refresh();
		} else if (value.relay === false) {
			disposeRelayHalf(true);
			publicBase.refresh();
		} else if (liveTunnelUrl !== void 0) {
			const registrar = ensureRelayRegistrar();
			if (registrar !== void 0) announceRelay(registrar, liveTunnelUrl);
		}
		if (plan.mode === "quick") {
			for (const ignored of plan.ignored) console.warn(`wj-dsh-remote: autoTunnel is on — ignoring the configured ${ignored}`);
			const registrar = ensureRelayRegistrar();
			const originHostHeader = registrar === void 0 ? void 0 : new URL(registrar.baseUrl).host;
			tunnel.start(originHostHeader === void 0 ? plan.targetUrl : {
				kind: "quick",
				targetUrl: plan.targetUrl,
				originHostHeader
			});
		} else if (plan.mode === "named") {
			publicBase.markRunning(plan.publicUrl);
			tunnel.start({
				kind: "named",
				token: plan.token,
				publicUrl: plan.publicUrl
			});
		} else {
			tunnel.stop();
			if (value.tunnelToken !== void 0 && value.tunnelToken !== "") console.warn("wj-dsh-remote: tunnelToken is set but publicBaseUrl is missing or not a valid URL — fill the fixed public hostname of the named tunnel (e.g. https://dsh.example.com) to run it");
			if (value.publicBaseUrl !== void 0 && !isHttpUrl(value.publicBaseUrl)) {
				console.warn(`wj-dsh-remote: ignoring malformed publicBaseUrl ${JSON.stringify(value.publicBaseUrl)} (expected https://host[:port])`);
				service.setPublicBaseUrl(void 0);
			} else service.setPublicBaseUrl(value.publicBaseUrl);
		}
	};
	/**
	* Feed the ingress sync the resolved settings. The bound port is the only
	* target fact, so an unbound listener schedules a zero-request wait and the
	* port-settle retry re-plans it. The quick tunnel is never an ingress target:
	* it mints a new hostname per start and owns the public base while it runs,
	* so a deployment on it has no named tunnel to update (the switch reads as
	* off there rather than editing an unrelated tunnel).
	* @param value - the resolved settings.
	* @param port - the bound web server port, undefined before the listener binds.
	*/
	const scheduleIngressSync = (value, port) => {
		ingress.schedule(ingressInputOf(value, port));
	};
	const sync = () => {
		const value = resolve();
		service.config = pairingConfigOf(value);
		scheduleLanBindWork();
		const livePort = livePortOf(ctx.webServer.port);
		const tunnelNeedsPort = livePort === void 0 && value.autoTunnel === true;
		if (tunnelNeedsPort) {
			if (!portSettleWarned) {
				portSettleWarned = true;
				console.warn("wj-dsh-remote: autoTunnel is on but the web server port is not bound yet — the quick tunnel starts once the port settles");
			}
			schedulePortSettleRetry();
		} else {
			portSettleWarned = false;
			applyTunnelPlan(value, livePort);
		}
		scheduleIngressSync(value, livePort);
		if (livePort === void 0 && !tunnelNeedsPort && value.ingressSync === true) schedulePortSettleRetry();
		if (value.enabled && value.relay !== false) if (livePort === void 0) schedulePortSettleRetry();
		else claimRelayLeaseFor(livePort, publicBase.quickUrl());
		const enabled = value.enabled;
		if (!enabled) {
			service.stop();
			tunnel.stop();
			disposeRelayHalf();
			publicBase.reset();
		}
		if (disposeRoutes === void 0 && enabled) disposeRoutes = ctx.effect(() => {
			const disposers = [...routes.map((route) => ctx.webServer.register(route)), ...upgrades.map((route) => ctx.webServer.registerUpgrade(route))];
			return () => {
				for (const dispose of disposers) dispose();
			};
		}, "wj-dsh-remote: pairing routes");
		else if (disposeRoutes !== void 0 && !enabled) {
			disposeRoutes();
			disposeRoutes = void 0;
		}
		if (disposeSweep === void 0 && enabled) disposeSweep = ctx.effect(() => {
			const timer = setInterval(() => {
				service.sweep();
			}, SWEEP_INTERVAL_MS);
			timer.unref();
			return () => {
				clearInterval(timer);
			};
		}, "wj-dsh-remote: presence sweep");
		else if (disposeSweep !== void 0 && !enabled) {
			disposeSweep();
			disposeSweep = void 0;
		}
		runPostureProbe();
	};
	ctx.effect(() => ctx.on("webserver/index-inject", (table) => {
		table.push({
			kind: "script",
			placement: "head",
			text: UUID_POLYFILL_SCRIPT
		});
	}), "wj-dsh-remote: uuid polyfill");
	ctx.effect(() => ctx.on("webserver/index-inject", (table) => {
		const value = resolve();
		if (!value.enabled || !value.requirePairingForLan) return;
		table.push({
			kind: "script",
			placement: "head",
			text: REMOTE_CHANNEL_BOOT_SCRIPT
		});
	}), "wj-dsh-remote: remote channel boot patch");
	ctx.on("loader/volatile-update", () => {
		sync();
	});
	sync();
}
//#endregion
export { Config, REMOTE_WEB_UI_SETTINGS_NAMESPACE, apply, defaultDevicesFile, inject, lanBasesOf, lanBindCapabilityOf, lanBindFrameOf, name, pairingConfigOf };
