import { createRequire } from "node:module";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { setInterval, setTimeout as setTimeout$1 } from "node:timers";
import z from "@deepseek-ai/schemastery";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, networkInterfaces } from "node:os";
import { isAbsolute as isAbsolute$1, join as join$1 } from "node:path/posix";
import { Service } from "@deepseek-ai/cordis";
import { z as z$1 } from "zod";
import http, { createServer, request } from "node:http";
import { connect, isIP } from "node:net";
import { execFile, spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { Tunnel, bin, install } from "cloudflared";
import https, { createServer as createServer$1 } from "node:https";
import { readFile } from "node:fs/promises";
import { AsyncResource } from "node:async_hooks";
//#region \0rolldown/runtime.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJSMin = (cb, mod) => () => (mod || (cb((mod = { exports: {} }).exports, mod), cb = null), mod.exports);
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
var __require = /* #__PURE__ */ (() => createRequire(import.meta.url))();
//#endregion
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
				const { createdAt, lastSeenAt, userAgent, name } = session;
				if (typeof createdAt !== "number" || typeof lastSeenAt !== "number") continue;
				const label = typeof userAgent === "string" ? sanitizeUserAgent(userAgent) : void 0;
				const customName = typeof name === "string" ? sanitizeDeviceName(name) : void 0;
				this.devices.set(deviceId, {
					createdAt,
					lastSeenAt,
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
		if (!this.devices.delete(deviceId)) return false;
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
		const session = this.liveSession(deviceId);
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
		const ids = [...new Set(deviceIds)];
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
	toDeviceSnapshot(id, session, now) {
		return {
			id,
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
		return other !== void 0 && device.id === other.id && device.createdAt === other.createdAt && device.lastSeenAt === other.lastSeenAt && device.online === other.online && device.userAgent === other.userAgent && device.name === other.name;
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
const LOCAL_ONLY_PREFIXES = [
	"/api/wj-pair",
	"/api/update",
	PLUGIN_MANAGER_PATH
];
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
	/**
	* Strict desktop fence: the desktop panel's control endpoints, and every
	* route that mints, stops or streams a credential. A direct desktop request
	* (loopback socket, loopback Host, NO forwarding header) passes; a request a
	* reverse proxy forwarded does not, even though the reachability fence below
	* now accepts the rewritten loopback upstream it presents (issue #1906 stays
	* shut for the control plane while #1919 opens the phone-facing surface).
	*/
	const loopbackFence = (req) => isLoopbackClient(req) && isTrustedApiRequest(req, []);
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
		if (!loopbackFence(req)) {
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
		if (!loopbackFence(req)) {
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
		service.stop();
		writeJson(res, 200, { ok: true });
	};
	const handleRevoke = async (req, res) => {
		if (!requireMethod(req, res, "POST")) return;
		if (!loopbackFence(req)) {
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
		const payload = parsePairPayload(revokePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		if (!service.revoke(payload.deviceId)) {
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
		if (!loopbackFence(req)) {
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
		const payload = parsePairPayload(renamePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		if (!service.rename(payload.deviceId, payload.name)) {
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
		if (!loopbackFence(req)) {
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
		const payload = parsePairPayload(mergePayloadSchema, body);
		if (payload === void 0) {
			writeJson(res, 400, {
				ok: false,
				code: "bad-payload"
			});
			return;
		}
		const merged = service.mergeDuplicates(payload.deviceIds);
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
		const deviceId = readCookie(req.headers.cookie, service.config.cookieName);
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
		if (!lanFence(req)) {
			writeJson(res, 403, {
				ok: false,
				code: "forbidden"
			});
			return;
		}
		const deviceId = readCookie(req.headers.cookie, service.config.cookieName);
		const paired = deviceId !== void 0 && service.hasDevice(deviceId);
		const local = isLoopbackClient(req);
		const snapshot = service.snapshot();
		const { devices: _devices, ...rest } = snapshot;
		const visible = paired || local ? rest : {
			phase: snapshot.phase,
			lanAvailable: snapshot.lanAvailable
		};
		writeJson(res, 200, {
			ok: true,
			paired,
			requirePairingForLan: pairingRequired(),
			...visible
		});
	};
	const handleEvents = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (!loopbackFence(req)) {
			writeJson(res, 403, {
				ok: false,
				code: "forbidden"
			});
			return;
		}
		events.open(req, res);
		events.push(service.snapshot());
	};
	/** LAN-bind facts for the settings card; loopback-only, read per request. */
	const handleLanBind = (req, res) => {
		if (!requireMethod(req, res, "GET")) return;
		if (!loopbackFence(req)) {
			writeJson(res, 403, {
				ok: false,
				code: "forbidden"
			});
			return;
		}
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
function forwardedRequestHeaders(req, port, cookie) {
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
function proxyLoopbackHttp(req, res, port, upstreamPath, auth) {
	Promise.resolve(auth?.ready()).catch(() => void 0).then((cookie) => {
		pipeLoopbackHttp(req, res, port, upstreamPath, auth, typeof cookie === "string" ? cookie : void 0);
	});
}
function pipeLoopbackHttp(req, res, port, upstreamPath, auth, cookie) {
	const headers = forwardedRequestHeaders(req, port, cookie);
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
		if (pairedDeviceIdOf(req, service) === void 0) {
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
		proxyLoopbackHttp(req, res, port, `${inner}${url.search}`, deps.auth);
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
//#region ../../node_modules/.pnpm/negotiator@0.6.4/node_modules/negotiator/lib/charset.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_charset$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredCharsets;
	module.exports.preferredCharsets = preferredCharsets;
	/**
	* Module variables.
	* @private
	*/
	var simpleCharsetRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
	/**
	* Parse the Accept-Charset header.
	* @private
	*/
	function parseAcceptCharset(accept) {
		var accepts = accept.split(",");
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var charset = parseCharset(accepts[i].trim(), i);
			if (charset) accepts[j++] = charset;
		}
		accepts.length = j;
		return accepts;
	}
	/**
	* Parse a charset from the Accept-Charset header.
	* @private
	*/
	function parseCharset(str, i) {
		var match = simpleCharsetRegExp.exec(str);
		if (!match) return null;
		var charset = match[1];
		var q = 1;
		if (match[2]) {
			var params = match[2].split(";");
			for (var j = 0; j < params.length; j++) {
				var p = params[j].trim().split("=");
				if (p[0] === "q") {
					q = parseFloat(p[1]);
					break;
				}
			}
		}
		return {
			charset,
			q,
			i
		};
	}
	/**
	* Get the priority of a charset.
	* @private
	*/
	function getCharsetPriority(charset, accepted, index) {
		var priority = {
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(charset, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the charset.
	* @private
	*/
	function specify(charset, spec, index) {
		var s = 0;
		if (spec.charset.toLowerCase() === charset.toLowerCase()) s |= 1;
		else if (spec.charset !== "*") return null;
		return {
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred charsets from an Accept-Charset header.
	* @public
	*/
	function preferredCharsets(accept, provided) {
		var accepts = parseAcceptCharset(accept === void 0 ? "*" : accept || "");
		if (!provided) return accepts.filter(isQuality).sort(compareSpecs).map(getFullCharset);
		var priorities = provided.map(function getPriority(type, index) {
			return getCharsetPriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(compareSpecs).map(function getCharset(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i || 0;
	}
	/**
	* Get full charset string.
	* @private
	*/
	function getFullCharset(spec) {
		return spec.charset;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@0.6.4/node_modules/negotiator/lib/encoding.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_encoding$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredEncodings;
	module.exports.preferredEncodings = preferredEncodings;
	/**
	* Module variables.
	* @private
	*/
	var simpleEncodingRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
	/**
	* Parse the Accept-Encoding header.
	* @private
	*/
	function parseAcceptEncoding(accept) {
		var accepts = accept.split(",");
		var hasIdentity = false;
		var minQuality = 1;
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var encoding = parseEncoding(accepts[i].trim(), i);
			if (encoding) {
				accepts[j++] = encoding;
				hasIdentity = hasIdentity || specify("identity", encoding);
				minQuality = Math.min(minQuality, encoding.q || 1);
			}
		}
		if (!hasIdentity) accepts[j++] = {
			encoding: "identity",
			q: minQuality,
			i
		};
		accepts.length = j;
		return accepts;
	}
	/**
	* Parse an encoding from the Accept-Encoding header.
	* @private
	*/
	function parseEncoding(str, i) {
		var match = simpleEncodingRegExp.exec(str);
		if (!match) return null;
		var encoding = match[1];
		var q = 1;
		if (match[2]) {
			var params = match[2].split(";");
			for (var j = 0; j < params.length; j++) {
				var p = params[j].trim().split("=");
				if (p[0] === "q") {
					q = parseFloat(p[1]);
					break;
				}
			}
		}
		return {
			encoding,
			q,
			i
		};
	}
	/**
	* Get the priority of an encoding.
	* @private
	*/
	function getEncodingPriority(encoding, accepted, index) {
		var priority = {
			encoding,
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(encoding, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the encoding.
	* @private
	*/
	function specify(encoding, spec, index) {
		var s = 0;
		if (spec.encoding.toLowerCase() === encoding.toLowerCase()) s |= 1;
		else if (spec.encoding !== "*") return null;
		return {
			encoding,
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred encodings from an Accept-Encoding header.
	* @public
	*/
	function preferredEncodings(accept, provided, preferred) {
		var accepts = parseAcceptEncoding(accept || "");
		var comparator = preferred ? function comparator(a, b) {
			if (a.q !== b.q) return b.q - a.q;
			var aPreferred = preferred.indexOf(a.encoding);
			var bPreferred = preferred.indexOf(b.encoding);
			if (aPreferred === -1 && bPreferred === -1) return b.s - a.s || a.o - b.o || a.i - b.i;
			if (aPreferred !== -1 && bPreferred !== -1) return aPreferred - bPreferred;
			return aPreferred === -1 ? 1 : -1;
		} : compareSpecs;
		if (!provided) return accepts.filter(isQuality).sort(comparator).map(getFullEncoding);
		var priorities = provided.map(function getPriority(type, index) {
			return getEncodingPriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(comparator).map(function getEncoding(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i;
	}
	/**
	* Get full encoding string.
	* @private
	*/
	function getFullEncoding(spec) {
		return spec.encoding;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@0.6.4/node_modules/negotiator/lib/language.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_language$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredLanguages;
	module.exports.preferredLanguages = preferredLanguages;
	/**
	* Module variables.
	* @private
	*/
	var simpleLanguageRegExp = /^\s*([^\s\-;]+)(?:-([^\s;]+))?\s*(?:;(.*))?$/;
	/**
	* Parse the Accept-Language header.
	* @private
	*/
	function parseAcceptLanguage(accept) {
		var accepts = accept.split(",");
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var language = parseLanguage(accepts[i].trim(), i);
			if (language) accepts[j++] = language;
		}
		accepts.length = j;
		return accepts;
	}
	/**
	* Parse a language from the Accept-Language header.
	* @private
	*/
	function parseLanguage(str, i) {
		var match = simpleLanguageRegExp.exec(str);
		if (!match) return null;
		var prefix = match[1];
		var suffix = match[2];
		var full = prefix;
		if (suffix) full += "-" + suffix;
		var q = 1;
		if (match[3]) {
			var params = match[3].split(";");
			for (var j = 0; j < params.length; j++) {
				var p = params[j].split("=");
				if (p[0] === "q") q = parseFloat(p[1]);
			}
		}
		return {
			prefix,
			suffix,
			q,
			i,
			full
		};
	}
	/**
	* Get the priority of a language.
	* @private
	*/
	function getLanguagePriority(language, accepted, index) {
		var priority = {
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(language, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the language.
	* @private
	*/
	function specify(language, spec, index) {
		var p = parseLanguage(language);
		if (!p) return null;
		var s = 0;
		if (spec.full.toLowerCase() === p.full.toLowerCase()) s |= 4;
		else if (spec.prefix.toLowerCase() === p.full.toLowerCase()) s |= 2;
		else if (spec.full.toLowerCase() === p.prefix.toLowerCase()) s |= 1;
		else if (spec.full !== "*") return null;
		return {
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred languages from an Accept-Language header.
	* @public
	*/
	function preferredLanguages(accept, provided) {
		var accepts = parseAcceptLanguage(accept === void 0 ? "*" : accept || "");
		if (!provided) return accepts.filter(isQuality).sort(compareSpecs).map(getFullLanguage);
		var priorities = provided.map(function getPriority(type, index) {
			return getLanguagePriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(compareSpecs).map(function getLanguage(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i || 0;
	}
	/**
	* Get full language string.
	* @private
	*/
	function getFullLanguage(spec) {
		return spec.full;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@0.6.4/node_modules/negotiator/lib/mediaType.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_mediaType$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredMediaTypes;
	module.exports.preferredMediaTypes = preferredMediaTypes;
	/**
	* Module variables.
	* @private
	*/
	var simpleMediaTypeRegExp = /^\s*([^\s\/;]+)\/([^;\s]+)\s*(?:;(.*))?$/;
	/**
	* Parse the Accept header.
	* @private
	*/
	function parseAccept(accept) {
		var accepts = splitMediaTypes(accept);
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var mediaType = parseMediaType(accepts[i].trim(), i);
			if (mediaType) accepts[j++] = mediaType;
		}
		accepts.length = j;
		return accepts;
	}
	/**
	* Parse a media type from the Accept header.
	* @private
	*/
	function parseMediaType(str, i) {
		var match = simpleMediaTypeRegExp.exec(str);
		if (!match) return null;
		var params = Object.create(null);
		var q = 1;
		var subtype = match[2];
		var type = match[1];
		if (match[3]) {
			var kvps = splitParameters(match[3]).map(splitKeyValuePair);
			for (var j = 0; j < kvps.length; j++) {
				var pair = kvps[j];
				var key = pair[0].toLowerCase();
				var val = pair[1];
				var value = val && val[0] === "\"" && val[val.length - 1] === "\"" ? val.slice(1, -1) : val;
				if (key === "q") {
					q = parseFloat(value);
					break;
				}
				params[key] = value;
			}
		}
		return {
			type,
			subtype,
			params,
			q,
			i
		};
	}
	/**
	* Get the priority of a media type.
	* @private
	*/
	function getMediaTypePriority(type, accepted, index) {
		var priority = {
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(type, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the media type.
	* @private
	*/
	function specify(type, spec, index) {
		var p = parseMediaType(type);
		var s = 0;
		if (!p) return null;
		if (spec.type.toLowerCase() == p.type.toLowerCase()) s |= 4;
		else if (spec.type != "*") return null;
		if (spec.subtype.toLowerCase() == p.subtype.toLowerCase()) s |= 2;
		else if (spec.subtype != "*") return null;
		var keys = Object.keys(spec.params);
		if (keys.length > 0) if (keys.every(function(k) {
			return spec.params[k] == "*" || (spec.params[k] || "").toLowerCase() == (p.params[k] || "").toLowerCase();
		})) s |= 1;
		else return null;
		return {
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred media types from an Accept header.
	* @public
	*/
	function preferredMediaTypes(accept, provided) {
		var accepts = parseAccept(accept === void 0 ? "*/*" : accept || "");
		if (!provided) return accepts.filter(isQuality).sort(compareSpecs).map(getFullType);
		var priorities = provided.map(function getPriority(type, index) {
			return getMediaTypePriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(compareSpecs).map(function getType(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i || 0;
	}
	/**
	* Get full type string.
	* @private
	*/
	function getFullType(spec) {
		return spec.type + "/" + spec.subtype;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
	/**
	* Count the number of quotes in a string.
	* @private
	*/
	function quoteCount(string) {
		var count = 0;
		var index = 0;
		while ((index = string.indexOf("\"", index)) !== -1) {
			count++;
			index++;
		}
		return count;
	}
	/**
	* Split a key value pair.
	* @private
	*/
	function splitKeyValuePair(str) {
		var index = str.indexOf("=");
		var key;
		var val;
		if (index === -1) key = str;
		else {
			key = str.slice(0, index);
			val = str.slice(index + 1);
		}
		return [key, val];
	}
	/**
	* Split an Accept header into media types.
	* @private
	*/
	function splitMediaTypes(accept) {
		var accepts = accept.split(",");
		for (var i = 1, j = 0; i < accepts.length; i++) if (quoteCount(accepts[j]) % 2 == 0) accepts[++j] = accepts[i];
		else accepts[j] += "," + accepts[i];
		accepts.length = j + 1;
		return accepts;
	}
	/**
	* Split a string of parameters.
	* @private
	*/
	function splitParameters(str) {
		var parameters = str.split(";");
		for (var i = 1, j = 0; i < parameters.length; i++) if (quoteCount(parameters[j]) % 2 == 0) parameters[++j] = parameters[i];
		else parameters[j] += ";" + parameters[i];
		parameters.length = j + 1;
		for (var i = 0; i < parameters.length; i++) parameters[i] = parameters[i].trim();
		return parameters;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@0.6.4/node_modules/negotiator/index.js
/*!
* negotiator
* Copyright(c) 2012 Federico Romero
* Copyright(c) 2012-2014 Isaac Z. Schlueter
* Copyright(c) 2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_negotiator$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var preferredCharsets = require_charset$1();
	var preferredEncodings = require_encoding$1();
	var preferredLanguages = require_language$1();
	var preferredMediaTypes = require_mediaType$1();
	/**
	* Module exports.
	* @public
	*/
	module.exports = Negotiator;
	module.exports.Negotiator = Negotiator;
	/**
	* Create a Negotiator instance from a request.
	* @param {object} request
	* @public
	*/
	function Negotiator(request) {
		if (!(this instanceof Negotiator)) return new Negotiator(request);
		this.request = request;
	}
	Negotiator.prototype.charset = function charset(available) {
		var set = this.charsets(available);
		return set && set[0];
	};
	Negotiator.prototype.charsets = function charsets(available) {
		return preferredCharsets(this.request.headers["accept-charset"], available);
	};
	Negotiator.prototype.encoding = function encoding(available, preferred) {
		var set = this.encodings(available, preferred);
		return set && set[0];
	};
	Negotiator.prototype.encodings = function encodings(available, preferred) {
		return preferredEncodings(this.request.headers["accept-encoding"], available, preferred);
	};
	Negotiator.prototype.language = function language(available) {
		var set = this.languages(available);
		return set && set[0];
	};
	Negotiator.prototype.languages = function languages(available) {
		return preferredLanguages(this.request.headers["accept-language"], available);
	};
	Negotiator.prototype.mediaType = function mediaType(available) {
		var set = this.mediaTypes(available);
		return set && set[0];
	};
	Negotiator.prototype.mediaTypes = function mediaTypes(available) {
		return preferredMediaTypes(this.request.headers.accept, available);
	};
	Negotiator.prototype.preferredCharset = Negotiator.prototype.charset;
	Negotiator.prototype.preferredCharsets = Negotiator.prototype.charsets;
	Negotiator.prototype.preferredEncoding = Negotiator.prototype.encoding;
	Negotiator.prototype.preferredEncodings = Negotiator.prototype.encodings;
	Negotiator.prototype.preferredLanguage = Negotiator.prototype.language;
	Negotiator.prototype.preferredLanguages = Negotiator.prototype.languages;
	Negotiator.prototype.preferredMediaType = Negotiator.prototype.mediaType;
	Negotiator.prototype.preferredMediaTypes = Negotiator.prototype.mediaTypes;
}));
//#endregion
//#region ../../node_modules/.pnpm/safe-buffer@5.2.1/node_modules/safe-buffer/index.js
var require_safe_buffer = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
	var buffer = __require("buffer");
	var Buffer = buffer.Buffer;
	function copyProps(src, dst) {
		for (var key in src) dst[key] = src[key];
	}
	if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) module.exports = buffer;
	else {
		copyProps(buffer, exports);
		exports.Buffer = SafeBuffer;
	}
	function SafeBuffer(arg, encodingOrOffset, length) {
		return Buffer(arg, encodingOrOffset, length);
	}
	SafeBuffer.prototype = Object.create(Buffer.prototype);
	copyProps(Buffer, SafeBuffer);
	SafeBuffer.from = function(arg, encodingOrOffset, length) {
		if (typeof arg === "number") throw new TypeError("Argument must not be a number");
		return Buffer(arg, encodingOrOffset, length);
	};
	SafeBuffer.alloc = function(size, fill, encoding) {
		if (typeof size !== "number") throw new TypeError("Argument must be a number");
		var buf = Buffer(size);
		if (fill !== void 0) if (typeof encoding === "string") buf.fill(fill, encoding);
		else buf.fill(fill);
		else buf.fill(0);
		return buf;
	};
	SafeBuffer.allocUnsafe = function(size) {
		if (typeof size !== "number") throw new TypeError("Argument must be a number");
		return Buffer(size);
	};
	SafeBuffer.allocUnsafeSlow = function(size) {
		if (typeof size !== "number") throw new TypeError("Argument must be a number");
		return buffer.SlowBuffer(size);
	};
}));
//#endregion
//#region ../../node_modules/.pnpm/bytes@3.1.2/node_modules/bytes/index.js
/*!
* bytes
* Copyright(c) 2012-2014 TJ Holowaychuk
* Copyright(c) 2015 Jed Watson
* MIT Licensed
*/
var require_bytes = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	* @public
	*/
	module.exports = bytes;
	module.exports.format = format;
	module.exports.parse = parse;
	/**
	* Module variables.
	* @private
	*/
	var formatThousandsRegExp = /\B(?=(\d{3})+(?!\d))/g;
	var formatDecimalsRegExp = /(?:\.0*|(\.[^0]+)0+)$/;
	var map = {
		b: 1,
		kb: 1024,
		mb: 1 << 20,
		gb: 1 << 30,
		tb: Math.pow(1024, 4),
		pb: Math.pow(1024, 5)
	};
	var parseRegExp = /^((-|\+)?(\d+(?:\.\d+)?)) *(kb|mb|gb|tb|pb)$/i;
	/**
	* Convert the given value in bytes into a string or parse to string to an integer in bytes.
	*
	* @param {string|number} value
	* @param {{
	*  case: [string],
	*  decimalPlaces: [number]
	*  fixedDecimals: [boolean]
	*  thousandsSeparator: [string]
	*  unitSeparator: [string]
	*  }} [options] bytes options.
	*
	* @returns {string|number|null}
	*/
	function bytes(value, options) {
		if (typeof value === "string") return parse(value);
		if (typeof value === "number") return format(value, options);
		return null;
	}
	/**
	* Format the given value in bytes into a string.
	*
	* If the value is negative, it is kept as such. If it is a float,
	* it is rounded.
	*
	* @param {number} value
	* @param {object} [options]
	* @param {number} [options.decimalPlaces=2]
	* @param {number} [options.fixedDecimals=false]
	* @param {string} [options.thousandsSeparator=]
	* @param {string} [options.unit=]
	* @param {string} [options.unitSeparator=]
	*
	* @returns {string|null}
	* @public
	*/
	function format(value, options) {
		if (!Number.isFinite(value)) return null;
		var mag = Math.abs(value);
		var thousandsSeparator = options && options.thousandsSeparator || "";
		var unitSeparator = options && options.unitSeparator || "";
		var decimalPlaces = options && options.decimalPlaces !== void 0 ? options.decimalPlaces : 2;
		var fixedDecimals = Boolean(options && options.fixedDecimals);
		var unit = options && options.unit || "";
		if (!unit || !map[unit.toLowerCase()]) if (mag >= map.pb) unit = "PB";
		else if (mag >= map.tb) unit = "TB";
		else if (mag >= map.gb) unit = "GB";
		else if (mag >= map.mb) unit = "MB";
		else if (mag >= map.kb) unit = "KB";
		else unit = "B";
		var str = (value / map[unit.toLowerCase()]).toFixed(decimalPlaces);
		if (!fixedDecimals) str = str.replace(formatDecimalsRegExp, "$1");
		if (thousandsSeparator) str = str.split(".").map(function(s, i) {
			return i === 0 ? s.replace(formatThousandsRegExp, thousandsSeparator) : s;
		}).join(".");
		return str + unitSeparator + unit;
	}
	/**
	* Parse the string value into an integer in bytes.
	*
	* If no unit is given, it is assumed the value is in bytes.
	*
	* @param {number|string} val
	*
	* @returns {number|null}
	* @public
	*/
	function parse(val) {
		if (typeof val === "number" && !isNaN(val)) return val;
		if (typeof val !== "string") return null;
		var results = parseRegExp.exec(val);
		var floatValue;
		var unit = "b";
		if (!results) {
			floatValue = parseInt(val, 10);
			unit = "b";
		} else {
			floatValue = parseFloat(results[1]);
			unit = results[4].toLowerCase();
		}
		if (isNaN(floatValue)) return null;
		return Math.floor(map[unit] * floatValue);
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/mime-db@1.54.0/node_modules/mime-db/db.json
var require_db = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = {
		"application/1d-interleaved-parityfec": { "source": "iana" },
		"application/3gpdash-qoe-report+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/3gpp-ims+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/3gpphal+json": {
			"source": "iana",
			"compressible": true
		},
		"application/3gpphalforms+json": {
			"source": "iana",
			"compressible": true
		},
		"application/a2l": { "source": "iana" },
		"application/ace+cbor": { "source": "iana" },
		"application/ace+json": {
			"source": "iana",
			"compressible": true
		},
		"application/ace-groupcomm+cbor": { "source": "iana" },
		"application/ace-trl+cbor": { "source": "iana" },
		"application/activemessage": { "source": "iana" },
		"application/activity+json": {
			"source": "iana",
			"compressible": true
		},
		"application/aif+cbor": { "source": "iana" },
		"application/aif+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-cdni+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-cdnifilter+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-costmap+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-costmapfilter+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-directory+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-endpointcost+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-endpointcostparams+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-endpointprop+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-endpointpropparams+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-error+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-networkmap+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-networkmapfilter+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-propmap+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-propmapparams+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-tips+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-tipsparams+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-updatestreamcontrol+json": {
			"source": "iana",
			"compressible": true
		},
		"application/alto-updatestreamparams+json": {
			"source": "iana",
			"compressible": true
		},
		"application/aml": { "source": "iana" },
		"application/andrew-inset": {
			"source": "iana",
			"extensions": ["ez"]
		},
		"application/appinstaller": {
			"compressible": false,
			"extensions": ["appinstaller"]
		},
		"application/applefile": { "source": "iana" },
		"application/applixware": {
			"source": "apache",
			"extensions": ["aw"]
		},
		"application/appx": {
			"compressible": false,
			"extensions": ["appx"]
		},
		"application/appxbundle": {
			"compressible": false,
			"extensions": ["appxbundle"]
		},
		"application/at+jwt": { "source": "iana" },
		"application/atf": { "source": "iana" },
		"application/atfx": { "source": "iana" },
		"application/atom+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["atom"]
		},
		"application/atomcat+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["atomcat"]
		},
		"application/atomdeleted+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["atomdeleted"]
		},
		"application/atomicmail": { "source": "iana" },
		"application/atomsvc+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["atomsvc"]
		},
		"application/atsc-dwd+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["dwd"]
		},
		"application/atsc-dynamic-event-message": { "source": "iana" },
		"application/atsc-held+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["held"]
		},
		"application/atsc-rdt+json": {
			"source": "iana",
			"compressible": true
		},
		"application/atsc-rsat+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rsat"]
		},
		"application/atxml": { "source": "iana" },
		"application/auth-policy+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/automationml-aml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["aml"]
		},
		"application/automationml-amlx+zip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["amlx"]
		},
		"application/bacnet-xdd+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/batch-smtp": { "source": "iana" },
		"application/bdoc": {
			"compressible": false,
			"extensions": ["bdoc"]
		},
		"application/beep+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/bufr": { "source": "iana" },
		"application/c2pa": { "source": "iana" },
		"application/calendar+json": {
			"source": "iana",
			"compressible": true
		},
		"application/calendar+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xcs"]
		},
		"application/call-completion": { "source": "iana" },
		"application/cals-1840": { "source": "iana" },
		"application/captive+json": {
			"source": "iana",
			"compressible": true
		},
		"application/cbor": { "source": "iana" },
		"application/cbor-seq": { "source": "iana" },
		"application/cccex": { "source": "iana" },
		"application/ccmp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/ccxml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ccxml"]
		},
		"application/cda+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/cdfx+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["cdfx"]
		},
		"application/cdmi-capability": {
			"source": "iana",
			"extensions": ["cdmia"]
		},
		"application/cdmi-container": {
			"source": "iana",
			"extensions": ["cdmic"]
		},
		"application/cdmi-domain": {
			"source": "iana",
			"extensions": ["cdmid"]
		},
		"application/cdmi-object": {
			"source": "iana",
			"extensions": ["cdmio"]
		},
		"application/cdmi-queue": {
			"source": "iana",
			"extensions": ["cdmiq"]
		},
		"application/cdni": { "source": "iana" },
		"application/ce+cbor": { "source": "iana" },
		"application/cea": { "source": "iana" },
		"application/cea-2018+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/cellml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/cfw": { "source": "iana" },
		"application/cid-edhoc+cbor-seq": { "source": "iana" },
		"application/city+json": {
			"source": "iana",
			"compressible": true
		},
		"application/city+json-seq": { "source": "iana" },
		"application/clr": { "source": "iana" },
		"application/clue+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/clue_info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/cms": { "source": "iana" },
		"application/cnrp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/coap-eap": { "source": "iana" },
		"application/coap-group+json": {
			"source": "iana",
			"compressible": true
		},
		"application/coap-payload": { "source": "iana" },
		"application/commonground": { "source": "iana" },
		"application/concise-problem-details+cbor": { "source": "iana" },
		"application/conference-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/cose": { "source": "iana" },
		"application/cose-key": { "source": "iana" },
		"application/cose-key-set": { "source": "iana" },
		"application/cose-x509": { "source": "iana" },
		"application/cpl+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["cpl"]
		},
		"application/csrattrs": { "source": "iana" },
		"application/csta+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/cstadata+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/csvm+json": {
			"source": "iana",
			"compressible": true
		},
		"application/cu-seeme": {
			"source": "apache",
			"extensions": ["cu"]
		},
		"application/cwl": {
			"source": "iana",
			"extensions": ["cwl"]
		},
		"application/cwl+json": {
			"source": "iana",
			"compressible": true
		},
		"application/cwl+yaml": { "source": "iana" },
		"application/cwt": { "source": "iana" },
		"application/cybercash": { "source": "iana" },
		"application/dart": { "compressible": true },
		"application/dash+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mpd"]
		},
		"application/dash-patch+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mpp"]
		},
		"application/dashdelta": { "source": "iana" },
		"application/davmount+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["davmount"]
		},
		"application/dca-rft": { "source": "iana" },
		"application/dcd": { "source": "iana" },
		"application/dec-dx": { "source": "iana" },
		"application/dialog-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/dicom": {
			"source": "iana",
			"extensions": ["dcm"]
		},
		"application/dicom+json": {
			"source": "iana",
			"compressible": true
		},
		"application/dicom+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/dii": { "source": "iana" },
		"application/dit": { "source": "iana" },
		"application/dns": { "source": "iana" },
		"application/dns+json": {
			"source": "iana",
			"compressible": true
		},
		"application/dns-message": { "source": "iana" },
		"application/docbook+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["dbk"]
		},
		"application/dots+cbor": { "source": "iana" },
		"application/dpop+jwt": { "source": "iana" },
		"application/dskpp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/dssc+der": {
			"source": "iana",
			"extensions": ["dssc"]
		},
		"application/dssc+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xdssc"]
		},
		"application/dvcs": { "source": "iana" },
		"application/eat+cwt": { "source": "iana" },
		"application/eat+jwt": { "source": "iana" },
		"application/eat-bun+cbor": { "source": "iana" },
		"application/eat-bun+json": {
			"source": "iana",
			"compressible": true
		},
		"application/eat-ucs+cbor": { "source": "iana" },
		"application/eat-ucs+json": {
			"source": "iana",
			"compressible": true
		},
		"application/ecmascript": {
			"source": "apache",
			"compressible": true,
			"extensions": ["ecma"]
		},
		"application/edhoc+cbor-seq": { "source": "iana" },
		"application/edi-consent": { "source": "iana" },
		"application/edi-x12": {
			"source": "iana",
			"compressible": false
		},
		"application/edifact": {
			"source": "iana",
			"compressible": false
		},
		"application/efi": { "source": "iana" },
		"application/elm+json": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/elm+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.cap+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/emergencycalldata.comment+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.control+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.deviceinfo+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.ecall.msd": { "source": "iana" },
		"application/emergencycalldata.legacyesn+json": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.providerinfo+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.serviceinfo+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.subscriberinfo+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emergencycalldata.veds+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/emma+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["emma"]
		},
		"application/emotionml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["emotionml"]
		},
		"application/encaprtp": { "source": "iana" },
		"application/entity-statement+jwt": { "source": "iana" },
		"application/epp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/epub+zip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["epub"]
		},
		"application/eshop": { "source": "iana" },
		"application/exi": {
			"source": "iana",
			"extensions": ["exi"]
		},
		"application/expect-ct-report+json": {
			"source": "iana",
			"compressible": true
		},
		"application/express": {
			"source": "iana",
			"extensions": ["exp"]
		},
		"application/fastinfoset": { "source": "iana" },
		"application/fastsoap": { "source": "iana" },
		"application/fdf": {
			"source": "iana",
			"extensions": ["fdf"]
		},
		"application/fdt+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["fdt"]
		},
		"application/fhir+json": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/fhir+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/fido.trusted-apps+json": { "compressible": true },
		"application/fits": { "source": "iana" },
		"application/flexfec": { "source": "iana" },
		"application/font-sfnt": { "source": "iana" },
		"application/font-tdpfr": {
			"source": "iana",
			"extensions": ["pfr"]
		},
		"application/font-woff": {
			"source": "iana",
			"compressible": false
		},
		"application/framework-attributes+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/geo+json": {
			"source": "iana",
			"compressible": true,
			"extensions": ["geojson"]
		},
		"application/geo+json-seq": { "source": "iana" },
		"application/geopackage+sqlite3": { "source": "iana" },
		"application/geopose+json": {
			"source": "iana",
			"compressible": true
		},
		"application/geoxacml+json": {
			"source": "iana",
			"compressible": true
		},
		"application/geoxacml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/gltf-buffer": { "source": "iana" },
		"application/gml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["gml"]
		},
		"application/gnap-binding-jws": { "source": "iana" },
		"application/gnap-binding-jwsd": { "source": "iana" },
		"application/gnap-binding-rotation-jws": { "source": "iana" },
		"application/gnap-binding-rotation-jwsd": { "source": "iana" },
		"application/gpx+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["gpx"]
		},
		"application/grib": { "source": "iana" },
		"application/gxf": {
			"source": "apache",
			"extensions": ["gxf"]
		},
		"application/gzip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["gz"]
		},
		"application/h224": { "source": "iana" },
		"application/held+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/hjson": { "extensions": ["hjson"] },
		"application/hl7v2+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/http": { "source": "iana" },
		"application/hyperstudio": {
			"source": "iana",
			"extensions": ["stk"]
		},
		"application/ibe-key-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/ibe-pkg-reply+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/ibe-pp-data": { "source": "iana" },
		"application/iges": { "source": "iana" },
		"application/im-iscomposing+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/index": { "source": "iana" },
		"application/index.cmd": { "source": "iana" },
		"application/index.obj": { "source": "iana" },
		"application/index.response": { "source": "iana" },
		"application/index.vnd": { "source": "iana" },
		"application/inkml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ink", "inkml"]
		},
		"application/iotp": { "source": "iana" },
		"application/ipfix": {
			"source": "iana",
			"extensions": ["ipfix"]
		},
		"application/ipp": { "source": "iana" },
		"application/isup": { "source": "iana" },
		"application/its+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["its"]
		},
		"application/java-archive": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"jar",
				"war",
				"ear"
			]
		},
		"application/java-serialized-object": {
			"source": "apache",
			"compressible": false,
			"extensions": ["ser"]
		},
		"application/java-vm": {
			"source": "apache",
			"compressible": false,
			"extensions": ["class"]
		},
		"application/javascript": {
			"source": "apache",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["js"]
		},
		"application/jf2feed+json": {
			"source": "iana",
			"compressible": true
		},
		"application/jose": { "source": "iana" },
		"application/jose+json": {
			"source": "iana",
			"compressible": true
		},
		"application/jrd+json": {
			"source": "iana",
			"compressible": true
		},
		"application/jscalendar+json": {
			"source": "iana",
			"compressible": true
		},
		"application/jscontact+json": {
			"source": "iana",
			"compressible": true
		},
		"application/json": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["json", "map"]
		},
		"application/json-patch+json": {
			"source": "iana",
			"compressible": true
		},
		"application/json-seq": { "source": "iana" },
		"application/json5": { "extensions": ["json5"] },
		"application/jsonml+json": {
			"source": "apache",
			"compressible": true,
			"extensions": ["jsonml"]
		},
		"application/jsonpath": { "source": "iana" },
		"application/jwk+json": {
			"source": "iana",
			"compressible": true
		},
		"application/jwk-set+json": {
			"source": "iana",
			"compressible": true
		},
		"application/jwk-set+jwt": { "source": "iana" },
		"application/jwt": { "source": "iana" },
		"application/kpml-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/kpml-response+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/ld+json": {
			"source": "iana",
			"compressible": true,
			"extensions": ["jsonld"]
		},
		"application/lgr+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["lgr"]
		},
		"application/link-format": { "source": "iana" },
		"application/linkset": { "source": "iana" },
		"application/linkset+json": {
			"source": "iana",
			"compressible": true
		},
		"application/load-control+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/logout+jwt": { "source": "iana" },
		"application/lost+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["lostxml"]
		},
		"application/lostsync+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/lpf+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/lxf": { "source": "iana" },
		"application/mac-binhex40": {
			"source": "iana",
			"extensions": ["hqx"]
		},
		"application/mac-compactpro": {
			"source": "apache",
			"extensions": ["cpt"]
		},
		"application/macwriteii": { "source": "iana" },
		"application/mads+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mads"]
		},
		"application/manifest+json": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["webmanifest"]
		},
		"application/marc": {
			"source": "iana",
			"extensions": ["mrc"]
		},
		"application/marcxml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mrcx"]
		},
		"application/mathematica": {
			"source": "iana",
			"extensions": [
				"ma",
				"nb",
				"mb"
			]
		},
		"application/mathml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mathml"]
		},
		"application/mathml-content+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mathml-presentation+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-associated-procedure-description+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-deregister+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-envelope+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-msk+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-msk-response+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-protection-description+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-reception-report+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-register+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-register-response+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-schedule+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbms-user-service-description+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mbox": {
			"source": "iana",
			"extensions": ["mbox"]
		},
		"application/media-policy-dataset+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mpf"]
		},
		"application/media_control+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mediaservercontrol+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mscml"]
		},
		"application/merge-patch+json": {
			"source": "iana",
			"compressible": true
		},
		"application/metalink+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["metalink"]
		},
		"application/metalink4+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["meta4"]
		},
		"application/mets+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mets"]
		},
		"application/mf4": { "source": "iana" },
		"application/mikey": { "source": "iana" },
		"application/mipc": { "source": "iana" },
		"application/missing-blocks+cbor-seq": { "source": "iana" },
		"application/mmt-aei+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["maei"]
		},
		"application/mmt-usd+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["musd"]
		},
		"application/mods+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mods"]
		},
		"application/moss-keys": { "source": "iana" },
		"application/moss-signature": { "source": "iana" },
		"application/mosskey-data": { "source": "iana" },
		"application/mosskey-request": { "source": "iana" },
		"application/mp21": {
			"source": "iana",
			"extensions": ["m21", "mp21"]
		},
		"application/mp4": {
			"source": "iana",
			"extensions": [
				"mp4",
				"mpg4",
				"mp4s",
				"m4p"
			]
		},
		"application/mpeg4-generic": { "source": "iana" },
		"application/mpeg4-iod": { "source": "iana" },
		"application/mpeg4-iod-xmt": { "source": "iana" },
		"application/mrb-consumer+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/mrb-publish+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/msc-ivr+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/msc-mixer+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/msix": {
			"compressible": false,
			"extensions": ["msix"]
		},
		"application/msixbundle": {
			"compressible": false,
			"extensions": ["msixbundle"]
		},
		"application/msword": {
			"source": "iana",
			"compressible": false,
			"extensions": ["doc", "dot"]
		},
		"application/mud+json": {
			"source": "iana",
			"compressible": true
		},
		"application/multipart-core": { "source": "iana" },
		"application/mxf": {
			"source": "iana",
			"extensions": ["mxf"]
		},
		"application/n-quads": {
			"source": "iana",
			"extensions": ["nq"]
		},
		"application/n-triples": {
			"source": "iana",
			"extensions": ["nt"]
		},
		"application/nasdata": { "source": "iana" },
		"application/news-checkgroups": {
			"source": "iana",
			"charset": "US-ASCII"
		},
		"application/news-groupinfo": {
			"source": "iana",
			"charset": "US-ASCII"
		},
		"application/news-transmission": { "source": "iana" },
		"application/nlsml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/node": {
			"source": "iana",
			"extensions": ["cjs"]
		},
		"application/nss": { "source": "iana" },
		"application/oauth-authz-req+jwt": { "source": "iana" },
		"application/oblivious-dns-message": { "source": "iana" },
		"application/ocsp-request": { "source": "iana" },
		"application/ocsp-response": { "source": "iana" },
		"application/octet-stream": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"bin",
				"dms",
				"lrf",
				"mar",
				"so",
				"dist",
				"distz",
				"pkg",
				"bpk",
				"dump",
				"elc",
				"deploy",
				"exe",
				"dll",
				"deb",
				"dmg",
				"iso",
				"img",
				"msi",
				"msp",
				"msm",
				"buffer"
			]
		},
		"application/oda": {
			"source": "iana",
			"extensions": ["oda"]
		},
		"application/odm+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/odx": { "source": "iana" },
		"application/oebps-package+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["opf"]
		},
		"application/ogg": {
			"source": "iana",
			"compressible": false,
			"extensions": ["ogx"]
		},
		"application/ohttp-keys": { "source": "iana" },
		"application/omdoc+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["omdoc"]
		},
		"application/onenote": {
			"source": "apache",
			"extensions": [
				"onetoc",
				"onetoc2",
				"onetmp",
				"onepkg",
				"one",
				"onea"
			]
		},
		"application/opc-nodeset+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/oscore": { "source": "iana" },
		"application/oxps": {
			"source": "iana",
			"extensions": ["oxps"]
		},
		"application/p21": { "source": "iana" },
		"application/p21+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/p2p-overlay+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["relo"]
		},
		"application/parityfec": { "source": "iana" },
		"application/passport": { "source": "iana" },
		"application/patch-ops-error+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xer"]
		},
		"application/pdf": {
			"source": "iana",
			"compressible": false,
			"extensions": ["pdf"]
		},
		"application/pdx": { "source": "iana" },
		"application/pem-certificate-chain": { "source": "iana" },
		"application/pgp-encrypted": {
			"source": "iana",
			"compressible": false,
			"extensions": ["pgp"]
		},
		"application/pgp-keys": {
			"source": "iana",
			"extensions": ["asc"]
		},
		"application/pgp-signature": {
			"source": "iana",
			"extensions": ["sig", "asc"]
		},
		"application/pics-rules": {
			"source": "apache",
			"extensions": ["prf"]
		},
		"application/pidf+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/pidf-diff+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/pkcs10": {
			"source": "iana",
			"extensions": ["p10"]
		},
		"application/pkcs12": { "source": "iana" },
		"application/pkcs7-mime": {
			"source": "iana",
			"extensions": ["p7m", "p7c"]
		},
		"application/pkcs7-signature": {
			"source": "iana",
			"extensions": ["p7s"]
		},
		"application/pkcs8": {
			"source": "iana",
			"extensions": ["p8"]
		},
		"application/pkcs8-encrypted": { "source": "iana" },
		"application/pkix-attr-cert": {
			"source": "iana",
			"extensions": ["ac"]
		},
		"application/pkix-cert": {
			"source": "iana",
			"extensions": ["cer"]
		},
		"application/pkix-crl": {
			"source": "iana",
			"extensions": ["crl"]
		},
		"application/pkix-pkipath": {
			"source": "iana",
			"extensions": ["pkipath"]
		},
		"application/pkixcmp": {
			"source": "iana",
			"extensions": ["pki"]
		},
		"application/pls+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["pls"]
		},
		"application/poc-settings+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/postscript": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"ai",
				"eps",
				"ps"
			]
		},
		"application/ppsp-tracker+json": {
			"source": "iana",
			"compressible": true
		},
		"application/private-token-issuer-directory": { "source": "iana" },
		"application/private-token-request": { "source": "iana" },
		"application/private-token-response": { "source": "iana" },
		"application/problem+json": {
			"source": "iana",
			"compressible": true
		},
		"application/problem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/provenance+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["provx"]
		},
		"application/provided-claims+jwt": { "source": "iana" },
		"application/prs.alvestrand.titrax-sheet": { "source": "iana" },
		"application/prs.cww": {
			"source": "iana",
			"extensions": ["cww"]
		},
		"application/prs.cyn": {
			"source": "iana",
			"charset": "7-BIT"
		},
		"application/prs.hpub+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/prs.implied-document+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/prs.implied-executable": { "source": "iana" },
		"application/prs.implied-object+json": {
			"source": "iana",
			"compressible": true
		},
		"application/prs.implied-object+json-seq": { "source": "iana" },
		"application/prs.implied-object+yaml": { "source": "iana" },
		"application/prs.implied-structure": { "source": "iana" },
		"application/prs.mayfile": { "source": "iana" },
		"application/prs.nprend": { "source": "iana" },
		"application/prs.plucker": { "source": "iana" },
		"application/prs.rdf-xml-crypt": { "source": "iana" },
		"application/prs.vcfbzip2": { "source": "iana" },
		"application/prs.xsf+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xsf"]
		},
		"application/pskc+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["pskcxml"]
		},
		"application/pvd+json": {
			"source": "iana",
			"compressible": true
		},
		"application/qsig": { "source": "iana" },
		"application/raml+yaml": {
			"compressible": true,
			"extensions": ["raml"]
		},
		"application/raptorfec": { "source": "iana" },
		"application/rdap+json": {
			"source": "iana",
			"compressible": true
		},
		"application/rdf+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rdf", "owl"]
		},
		"application/reginfo+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rif"]
		},
		"application/relax-ng-compact-syntax": {
			"source": "iana",
			"extensions": ["rnc"]
		},
		"application/remote-printing": { "source": "apache" },
		"application/reputon+json": {
			"source": "iana",
			"compressible": true
		},
		"application/resolve-response+jwt": { "source": "iana" },
		"application/resource-lists+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rl"]
		},
		"application/resource-lists-diff+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rld"]
		},
		"application/rfc+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/riscos": { "source": "iana" },
		"application/rlmi+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/rls-services+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rs"]
		},
		"application/route-apd+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rapd"]
		},
		"application/route-s-tsid+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["sls"]
		},
		"application/route-usd+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rusd"]
		},
		"application/rpki-checklist": { "source": "iana" },
		"application/rpki-ghostbusters": {
			"source": "iana",
			"extensions": ["gbr"]
		},
		"application/rpki-manifest": {
			"source": "iana",
			"extensions": ["mft"]
		},
		"application/rpki-publication": { "source": "iana" },
		"application/rpki-roa": {
			"source": "iana",
			"extensions": ["roa"]
		},
		"application/rpki-signed-tal": { "source": "iana" },
		"application/rpki-updown": { "source": "iana" },
		"application/rsd+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["rsd"]
		},
		"application/rss+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["rss"]
		},
		"application/rtf": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rtf"]
		},
		"application/rtploopback": { "source": "iana" },
		"application/rtx": { "source": "iana" },
		"application/samlassertion+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/samlmetadata+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/sarif+json": {
			"source": "iana",
			"compressible": true
		},
		"application/sarif-external-properties+json": {
			"source": "iana",
			"compressible": true
		},
		"application/sbe": { "source": "iana" },
		"application/sbml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["sbml"]
		},
		"application/scaip+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/scim+json": {
			"source": "iana",
			"compressible": true
		},
		"application/scvp-cv-request": {
			"source": "iana",
			"extensions": ["scq"]
		},
		"application/scvp-cv-response": {
			"source": "iana",
			"extensions": ["scs"]
		},
		"application/scvp-vp-request": {
			"source": "iana",
			"extensions": ["spq"]
		},
		"application/scvp-vp-response": {
			"source": "iana",
			"extensions": ["spp"]
		},
		"application/sdp": {
			"source": "iana",
			"extensions": ["sdp"]
		},
		"application/secevent+jwt": { "source": "iana" },
		"application/senml+cbor": { "source": "iana" },
		"application/senml+json": {
			"source": "iana",
			"compressible": true
		},
		"application/senml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["senmlx"]
		},
		"application/senml-etch+cbor": { "source": "iana" },
		"application/senml-etch+json": {
			"source": "iana",
			"compressible": true
		},
		"application/senml-exi": { "source": "iana" },
		"application/sensml+cbor": { "source": "iana" },
		"application/sensml+json": {
			"source": "iana",
			"compressible": true
		},
		"application/sensml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["sensmlx"]
		},
		"application/sensml-exi": { "source": "iana" },
		"application/sep+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/sep-exi": { "source": "iana" },
		"application/session-info": { "source": "iana" },
		"application/set-payment": { "source": "iana" },
		"application/set-payment-initiation": {
			"source": "iana",
			"extensions": ["setpay"]
		},
		"application/set-registration": { "source": "iana" },
		"application/set-registration-initiation": {
			"source": "iana",
			"extensions": ["setreg"]
		},
		"application/sgml": { "source": "iana" },
		"application/sgml-open-catalog": { "source": "iana" },
		"application/shf+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["shf"]
		},
		"application/sieve": {
			"source": "iana",
			"extensions": ["siv", "sieve"]
		},
		"application/simple-filter+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/simple-message-summary": { "source": "iana" },
		"application/simplesymbolcontainer": { "source": "iana" },
		"application/sipc": { "source": "iana" },
		"application/slate": { "source": "iana" },
		"application/smil": { "source": "apache" },
		"application/smil+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["smi", "smil"]
		},
		"application/smpte336m": { "source": "iana" },
		"application/soap+fastinfoset": { "source": "iana" },
		"application/soap+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/sparql-query": {
			"source": "iana",
			"extensions": ["rq"]
		},
		"application/sparql-results+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["srx"]
		},
		"application/spdx+json": {
			"source": "iana",
			"compressible": true
		},
		"application/spirits-event+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/sql": {
			"source": "iana",
			"extensions": ["sql"]
		},
		"application/srgs": {
			"source": "iana",
			"extensions": ["gram"]
		},
		"application/srgs+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["grxml"]
		},
		"application/sru+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["sru"]
		},
		"application/ssdl+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["ssdl"]
		},
		"application/sslkeylogfile": { "source": "iana" },
		"application/ssml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ssml"]
		},
		"application/st2110-41": { "source": "iana" },
		"application/stix+json": {
			"source": "iana",
			"compressible": true
		},
		"application/stratum": { "source": "iana" },
		"application/swid+cbor": { "source": "iana" },
		"application/swid+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["swidtag"]
		},
		"application/tamp-apex-update": { "source": "iana" },
		"application/tamp-apex-update-confirm": { "source": "iana" },
		"application/tamp-community-update": { "source": "iana" },
		"application/tamp-community-update-confirm": { "source": "iana" },
		"application/tamp-error": { "source": "iana" },
		"application/tamp-sequence-adjust": { "source": "iana" },
		"application/tamp-sequence-adjust-confirm": { "source": "iana" },
		"application/tamp-status-query": { "source": "iana" },
		"application/tamp-status-response": { "source": "iana" },
		"application/tamp-update": { "source": "iana" },
		"application/tamp-update-confirm": { "source": "iana" },
		"application/tar": { "compressible": true },
		"application/taxii+json": {
			"source": "iana",
			"compressible": true
		},
		"application/td+json": {
			"source": "iana",
			"compressible": true
		},
		"application/tei+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["tei", "teicorpus"]
		},
		"application/tetra_isi": { "source": "iana" },
		"application/thraud+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["tfi"]
		},
		"application/timestamp-query": { "source": "iana" },
		"application/timestamp-reply": { "source": "iana" },
		"application/timestamped-data": {
			"source": "iana",
			"extensions": ["tsd"]
		},
		"application/tlsrpt+gzip": { "source": "iana" },
		"application/tlsrpt+json": {
			"source": "iana",
			"compressible": true
		},
		"application/tm+json": {
			"source": "iana",
			"compressible": true
		},
		"application/tnauthlist": { "source": "iana" },
		"application/toc+cbor": { "source": "iana" },
		"application/token-introspection+jwt": { "source": "iana" },
		"application/toml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["toml"]
		},
		"application/trickle-ice-sdpfrag": { "source": "iana" },
		"application/trig": {
			"source": "iana",
			"extensions": ["trig"]
		},
		"application/trust-chain+json": {
			"source": "iana",
			"compressible": true
		},
		"application/trust-mark+jwt": { "source": "iana" },
		"application/trust-mark-delegation+jwt": { "source": "iana" },
		"application/ttml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ttml"]
		},
		"application/tve-trigger": { "source": "iana" },
		"application/tzif": { "source": "iana" },
		"application/tzif-leap": { "source": "iana" },
		"application/ubjson": {
			"compressible": false,
			"extensions": ["ubj"]
		},
		"application/uccs+cbor": { "source": "iana" },
		"application/ujcs+json": {
			"source": "iana",
			"compressible": true
		},
		"application/ulpfec": { "source": "iana" },
		"application/urc-grpsheet+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/urc-ressheet+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rsheet"]
		},
		"application/urc-targetdesc+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["td"]
		},
		"application/urc-uisocketdesc+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vc": { "source": "iana" },
		"application/vc+cose": { "source": "iana" },
		"application/vc+jwt": { "source": "iana" },
		"application/vcard+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vcard+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vemmi": { "source": "iana" },
		"application/vividence.scriptfile": { "source": "apache" },
		"application/vnd.1000minds.decision-model+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["1km"]
		},
		"application/vnd.1ob": { "source": "iana" },
		"application/vnd.3gpp-prose+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp-prose-pc3a+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp-prose-pc3ach+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp-prose-pc3ch+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp-prose-pc8+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp-v2x-local-service-information": { "source": "iana" },
		"application/vnd.3gpp.5gnas": { "source": "iana" },
		"application/vnd.3gpp.5gsa2x": { "source": "iana" },
		"application/vnd.3gpp.5gsa2x-local-service-information": { "source": "iana" },
		"application/vnd.3gpp.5gsv2x": { "source": "iana" },
		"application/vnd.3gpp.5gsv2x-local-service-information": { "source": "iana" },
		"application/vnd.3gpp.access-transfer-events+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.bsf+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.crs+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.current-location-discovery+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.gmop+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.gtpc": { "source": "iana" },
		"application/vnd.3gpp.interworking-data": { "source": "iana" },
		"application/vnd.3gpp.lpp": { "source": "iana" },
		"application/vnd.3gpp.mc-signalling-ear": { "source": "iana" },
		"application/vnd.3gpp.mcdata-affiliation-command+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcdata-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcdata-payload": { "source": "iana" },
		"application/vnd.3gpp.mcdata-regroup+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcdata-service-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcdata-signalling": { "source": "iana" },
		"application/vnd.3gpp.mcdata-ue-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcdata-user-profile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-affiliation-command+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-floor-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-location-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-mbms-usage-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-regroup+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-service-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-signed+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-ue-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-ue-init-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcptt-user-profile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-affiliation-command+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-location-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-regroup+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-service-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-transmission-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-ue-config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mcvideo-user-profile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.mid-call+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.ngap": { "source": "iana" },
		"application/vnd.3gpp.pfcp": { "source": "iana" },
		"application/vnd.3gpp.pic-bw-large": {
			"source": "iana",
			"extensions": ["plb"]
		},
		"application/vnd.3gpp.pic-bw-small": {
			"source": "iana",
			"extensions": ["psb"]
		},
		"application/vnd.3gpp.pic-bw-var": {
			"source": "iana",
			"extensions": ["pvb"]
		},
		"application/vnd.3gpp.pinapp-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.s1ap": { "source": "iana" },
		"application/vnd.3gpp.seal-group-doc+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-location-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-mbms-usage-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-network-qos-management-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-ue-config-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-unicast-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.seal-user-profile-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.sms": { "source": "iana" },
		"application/vnd.3gpp.sms+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.srvcc-ext+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.srvcc-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.state-and-event-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.ussd+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp.v2x": { "source": "iana" },
		"application/vnd.3gpp.vae-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp2.bcmcsinfo+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.3gpp2.sms": { "source": "iana" },
		"application/vnd.3gpp2.tcap": {
			"source": "iana",
			"extensions": ["tcap"]
		},
		"application/vnd.3lightssoftware.imagescal": { "source": "iana" },
		"application/vnd.3m.post-it-notes": {
			"source": "iana",
			"extensions": ["pwn"]
		},
		"application/vnd.accpac.simply.aso": {
			"source": "iana",
			"extensions": ["aso"]
		},
		"application/vnd.accpac.simply.imp": {
			"source": "iana",
			"extensions": ["imp"]
		},
		"application/vnd.acm.addressxfer+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.acm.chatbot+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.acucobol": {
			"source": "iana",
			"extensions": ["acu"]
		},
		"application/vnd.acucorp": {
			"source": "iana",
			"extensions": ["atc", "acutc"]
		},
		"application/vnd.adobe.air-application-installer-package+zip": {
			"source": "apache",
			"compressible": false,
			"extensions": ["air"]
		},
		"application/vnd.adobe.flash.movie": { "source": "iana" },
		"application/vnd.adobe.formscentral.fcdt": {
			"source": "iana",
			"extensions": ["fcdt"]
		},
		"application/vnd.adobe.fxp": {
			"source": "iana",
			"extensions": ["fxp", "fxpl"]
		},
		"application/vnd.adobe.partial-upload": { "source": "iana" },
		"application/vnd.adobe.xdp+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xdp"]
		},
		"application/vnd.adobe.xfdf": {
			"source": "apache",
			"extensions": ["xfdf"]
		},
		"application/vnd.aether.imp": { "source": "iana" },
		"application/vnd.afpc.afplinedata": { "source": "iana" },
		"application/vnd.afpc.afplinedata-pagedef": { "source": "iana" },
		"application/vnd.afpc.cmoca-cmresource": { "source": "iana" },
		"application/vnd.afpc.foca-charset": { "source": "iana" },
		"application/vnd.afpc.foca-codedfont": { "source": "iana" },
		"application/vnd.afpc.foca-codepage": { "source": "iana" },
		"application/vnd.afpc.modca": { "source": "iana" },
		"application/vnd.afpc.modca-cmtable": { "source": "iana" },
		"application/vnd.afpc.modca-formdef": { "source": "iana" },
		"application/vnd.afpc.modca-mediummap": { "source": "iana" },
		"application/vnd.afpc.modca-objectcontainer": { "source": "iana" },
		"application/vnd.afpc.modca-overlay": { "source": "iana" },
		"application/vnd.afpc.modca-pagesegment": { "source": "iana" },
		"application/vnd.age": {
			"source": "iana",
			"extensions": ["age"]
		},
		"application/vnd.ah-barcode": { "source": "apache" },
		"application/vnd.ahead.space": {
			"source": "iana",
			"extensions": ["ahead"]
		},
		"application/vnd.airzip.filesecure.azf": {
			"source": "iana",
			"extensions": ["azf"]
		},
		"application/vnd.airzip.filesecure.azs": {
			"source": "iana",
			"extensions": ["azs"]
		},
		"application/vnd.amadeus+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.amazon.ebook": {
			"source": "apache",
			"extensions": ["azw"]
		},
		"application/vnd.amazon.mobi8-ebook": { "source": "iana" },
		"application/vnd.americandynamics.acc": {
			"source": "iana",
			"extensions": ["acc"]
		},
		"application/vnd.amiga.ami": {
			"source": "iana",
			"extensions": ["ami"]
		},
		"application/vnd.amundsen.maze+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.android.ota": { "source": "iana" },
		"application/vnd.android.package-archive": {
			"source": "apache",
			"compressible": false,
			"extensions": ["apk"]
		},
		"application/vnd.anki": { "source": "iana" },
		"application/vnd.anser-web-certificate-issue-initiation": {
			"source": "iana",
			"extensions": ["cii"]
		},
		"application/vnd.anser-web-funds-transfer-initiation": {
			"source": "apache",
			"extensions": ["fti"]
		},
		"application/vnd.antix.game-component": {
			"source": "iana",
			"extensions": ["atx"]
		},
		"application/vnd.apache.arrow.file": { "source": "iana" },
		"application/vnd.apache.arrow.stream": { "source": "iana" },
		"application/vnd.apache.parquet": { "source": "iana" },
		"application/vnd.apache.thrift.binary": { "source": "iana" },
		"application/vnd.apache.thrift.compact": { "source": "iana" },
		"application/vnd.apache.thrift.json": { "source": "iana" },
		"application/vnd.apexlang": { "source": "iana" },
		"application/vnd.api+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.aplextor.warrp+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.apothekende.reservation+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.apple.installer+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["mpkg"]
		},
		"application/vnd.apple.keynote": {
			"source": "iana",
			"extensions": ["key"]
		},
		"application/vnd.apple.mpegurl": {
			"source": "iana",
			"extensions": ["m3u8"]
		},
		"application/vnd.apple.numbers": {
			"source": "iana",
			"extensions": ["numbers"]
		},
		"application/vnd.apple.pages": {
			"source": "iana",
			"extensions": ["pages"]
		},
		"application/vnd.apple.pkpass": {
			"compressible": false,
			"extensions": ["pkpass"]
		},
		"application/vnd.arastra.swi": { "source": "apache" },
		"application/vnd.aristanetworks.swi": {
			"source": "iana",
			"extensions": ["swi"]
		},
		"application/vnd.artisan+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.artsquare": { "source": "iana" },
		"application/vnd.astraea-software.iota": {
			"source": "iana",
			"extensions": ["iota"]
		},
		"application/vnd.audiograph": {
			"source": "iana",
			"extensions": ["aep"]
		},
		"application/vnd.autodesk.fbx": { "extensions": ["fbx"] },
		"application/vnd.autopackage": { "source": "iana" },
		"application/vnd.avalon+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.avistar+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.balsamiq.bmml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["bmml"]
		},
		"application/vnd.balsamiq.bmpr": { "source": "iana" },
		"application/vnd.banana-accounting": { "source": "iana" },
		"application/vnd.bbf.usp.error": { "source": "iana" },
		"application/vnd.bbf.usp.msg": { "source": "iana" },
		"application/vnd.bbf.usp.msg+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.bekitzur-stech+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.belightsoft.lhzd+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.belightsoft.lhzl+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.bint.med-content": { "source": "iana" },
		"application/vnd.biopax.rdf+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.blink-idb-value-wrapper": { "source": "iana" },
		"application/vnd.blueice.multipass": {
			"source": "iana",
			"extensions": ["mpm"]
		},
		"application/vnd.bluetooth.ep.oob": { "source": "iana" },
		"application/vnd.bluetooth.le.oob": { "source": "iana" },
		"application/vnd.bmi": {
			"source": "iana",
			"extensions": ["bmi"]
		},
		"application/vnd.bpf": { "source": "iana" },
		"application/vnd.bpf3": { "source": "iana" },
		"application/vnd.businessobjects": {
			"source": "iana",
			"extensions": ["rep"]
		},
		"application/vnd.byu.uapi+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.bzip3": { "source": "iana" },
		"application/vnd.c3voc.schedule+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.cab-jscript": { "source": "iana" },
		"application/vnd.canon-cpdl": { "source": "iana" },
		"application/vnd.canon-lips": { "source": "iana" },
		"application/vnd.capasystems-pg+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.cendio.thinlinc.clientconf": { "source": "iana" },
		"application/vnd.century-systems.tcp_stream": { "source": "iana" },
		"application/vnd.chemdraw+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["cdxml"]
		},
		"application/vnd.chess-pgn": { "source": "iana" },
		"application/vnd.chipnuts.karaoke-mmd": {
			"source": "iana",
			"extensions": ["mmd"]
		},
		"application/vnd.ciedi": { "source": "iana" },
		"application/vnd.cinderella": {
			"source": "iana",
			"extensions": ["cdy"]
		},
		"application/vnd.cirpack.isdn-ext": { "source": "iana" },
		"application/vnd.citationstyles.style+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["csl"]
		},
		"application/vnd.claymore": {
			"source": "iana",
			"extensions": ["cla"]
		},
		"application/vnd.cloanto.rp9": {
			"source": "iana",
			"extensions": ["rp9"]
		},
		"application/vnd.clonk.c4group": {
			"source": "iana",
			"extensions": [
				"c4g",
				"c4d",
				"c4f",
				"c4p",
				"c4u"
			]
		},
		"application/vnd.cluetrust.cartomobile-config": {
			"source": "iana",
			"extensions": ["c11amc"]
		},
		"application/vnd.cluetrust.cartomobile-config-pkg": {
			"source": "iana",
			"extensions": ["c11amz"]
		},
		"application/vnd.cncf.helm.chart.content.v1.tar+gzip": { "source": "iana" },
		"application/vnd.cncf.helm.chart.provenance.v1.prov": { "source": "iana" },
		"application/vnd.cncf.helm.config.v1+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.coffeescript": { "source": "iana" },
		"application/vnd.collabio.xodocuments.document": { "source": "iana" },
		"application/vnd.collabio.xodocuments.document-template": { "source": "iana" },
		"application/vnd.collabio.xodocuments.presentation": { "source": "iana" },
		"application/vnd.collabio.xodocuments.presentation-template": { "source": "iana" },
		"application/vnd.collabio.xodocuments.spreadsheet": { "source": "iana" },
		"application/vnd.collabio.xodocuments.spreadsheet-template": { "source": "iana" },
		"application/vnd.collection+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.collection.doc+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.collection.next+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.comicbook+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.comicbook-rar": { "source": "iana" },
		"application/vnd.commerce-battelle": { "source": "iana" },
		"application/vnd.commonspace": {
			"source": "iana",
			"extensions": ["csp"]
		},
		"application/vnd.contact.cmsg": {
			"source": "iana",
			"extensions": ["cdbcmsg"]
		},
		"application/vnd.coreos.ignition+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.cosmocaller": {
			"source": "iana",
			"extensions": ["cmc"]
		},
		"application/vnd.crick.clicker": {
			"source": "iana",
			"extensions": ["clkx"]
		},
		"application/vnd.crick.clicker.keyboard": {
			"source": "iana",
			"extensions": ["clkk"]
		},
		"application/vnd.crick.clicker.palette": {
			"source": "iana",
			"extensions": ["clkp"]
		},
		"application/vnd.crick.clicker.template": {
			"source": "iana",
			"extensions": ["clkt"]
		},
		"application/vnd.crick.clicker.wordbank": {
			"source": "iana",
			"extensions": ["clkw"]
		},
		"application/vnd.criticaltools.wbs+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["wbs"]
		},
		"application/vnd.cryptii.pipe+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.crypto-shade-file": { "source": "iana" },
		"application/vnd.cryptomator.encrypted": { "source": "iana" },
		"application/vnd.cryptomator.vault": { "source": "iana" },
		"application/vnd.ctc-posml": {
			"source": "iana",
			"extensions": ["pml"]
		},
		"application/vnd.ctct.ws+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.cups-pdf": { "source": "iana" },
		"application/vnd.cups-postscript": { "source": "iana" },
		"application/vnd.cups-ppd": {
			"source": "iana",
			"extensions": ["ppd"]
		},
		"application/vnd.cups-raster": { "source": "iana" },
		"application/vnd.cups-raw": { "source": "iana" },
		"application/vnd.curl": { "source": "iana" },
		"application/vnd.curl.car": {
			"source": "apache",
			"extensions": ["car"]
		},
		"application/vnd.curl.pcurl": {
			"source": "apache",
			"extensions": ["pcurl"]
		},
		"application/vnd.cyan.dean.root+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.cybank": { "source": "iana" },
		"application/vnd.cyclonedx+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.cyclonedx+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.d2l.coursepackage1p0+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.d3m-dataset": { "source": "iana" },
		"application/vnd.d3m-problem": { "source": "iana" },
		"application/vnd.dart": {
			"source": "iana",
			"compressible": true,
			"extensions": ["dart"]
		},
		"application/vnd.data-vision.rdz": {
			"source": "iana",
			"extensions": ["rdz"]
		},
		"application/vnd.datalog": { "source": "iana" },
		"application/vnd.datapackage+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dataresource+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dbf": {
			"source": "iana",
			"extensions": ["dbf"]
		},
		"application/vnd.dcmp+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["dcmp"]
		},
		"application/vnd.debian.binary-package": { "source": "iana" },
		"application/vnd.dece.data": {
			"source": "iana",
			"extensions": [
				"uvf",
				"uvvf",
				"uvd",
				"uvvd"
			]
		},
		"application/vnd.dece.ttml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["uvt", "uvvt"]
		},
		"application/vnd.dece.unspecified": {
			"source": "iana",
			"extensions": ["uvx", "uvvx"]
		},
		"application/vnd.dece.zip": {
			"source": "iana",
			"extensions": ["uvz", "uvvz"]
		},
		"application/vnd.denovo.fcselayout-link": {
			"source": "iana",
			"extensions": ["fe_launch"]
		},
		"application/vnd.desmume.movie": { "source": "iana" },
		"application/vnd.dir-bi.plate-dl-nosuffix": { "source": "iana" },
		"application/vnd.dm.delegation+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dna": {
			"source": "iana",
			"extensions": ["dna"]
		},
		"application/vnd.document+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dolby.mlp": {
			"source": "apache",
			"extensions": ["mlp"]
		},
		"application/vnd.dolby.mobile.1": { "source": "iana" },
		"application/vnd.dolby.mobile.2": { "source": "iana" },
		"application/vnd.doremir.scorecloud-binary-document": { "source": "iana" },
		"application/vnd.dpgraph": {
			"source": "iana",
			"extensions": ["dpg"]
		},
		"application/vnd.dreamfactory": {
			"source": "iana",
			"extensions": ["dfac"]
		},
		"application/vnd.drive+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ds-keypoint": {
			"source": "apache",
			"extensions": ["kpxx"]
		},
		"application/vnd.dtg.local": { "source": "iana" },
		"application/vnd.dtg.local.flash": { "source": "iana" },
		"application/vnd.dtg.local.html": { "source": "iana" },
		"application/vnd.dvb.ait": {
			"source": "iana",
			"extensions": ["ait"]
		},
		"application/vnd.dvb.dvbisl+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.dvbj": { "source": "iana" },
		"application/vnd.dvb.esgcontainer": { "source": "iana" },
		"application/vnd.dvb.ipdcdftnotifaccess": { "source": "iana" },
		"application/vnd.dvb.ipdcesgaccess": { "source": "iana" },
		"application/vnd.dvb.ipdcesgaccess2": { "source": "iana" },
		"application/vnd.dvb.ipdcesgpdd": { "source": "iana" },
		"application/vnd.dvb.ipdcroaming": { "source": "iana" },
		"application/vnd.dvb.iptv.alfec-base": { "source": "iana" },
		"application/vnd.dvb.iptv.alfec-enhancement": { "source": "iana" },
		"application/vnd.dvb.notif-aggregate-root+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.notif-container+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.notif-generic+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.notif-ia-msglist+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.notif-ia-registration-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.notif-ia-registration-response+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.notif-init+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.dvb.pfr": { "source": "iana" },
		"application/vnd.dvb.service": {
			"source": "iana",
			"extensions": ["svc"]
		},
		"application/vnd.dxr": { "source": "iana" },
		"application/vnd.dynageo": {
			"source": "iana",
			"extensions": ["geo"]
		},
		"application/vnd.dzr": { "source": "iana" },
		"application/vnd.easykaraoke.cdgdownload": { "source": "iana" },
		"application/vnd.ecdis-update": { "source": "iana" },
		"application/vnd.ecip.rlp": { "source": "iana" },
		"application/vnd.eclipse.ditto+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ecowin.chart": {
			"source": "iana",
			"extensions": ["mag"]
		},
		"application/vnd.ecowin.filerequest": { "source": "iana" },
		"application/vnd.ecowin.fileupdate": { "source": "iana" },
		"application/vnd.ecowin.series": { "source": "iana" },
		"application/vnd.ecowin.seriesrequest": { "source": "iana" },
		"application/vnd.ecowin.seriesupdate": { "source": "iana" },
		"application/vnd.efi.img": { "source": "iana" },
		"application/vnd.efi.iso": { "source": "iana" },
		"application/vnd.eln+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.emclient.accessrequest+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.enliven": {
			"source": "iana",
			"extensions": ["nml"]
		},
		"application/vnd.enphase.envoy": { "source": "iana" },
		"application/vnd.eprints.data+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.epson.esf": {
			"source": "iana",
			"extensions": ["esf"]
		},
		"application/vnd.epson.msf": {
			"source": "iana",
			"extensions": ["msf"]
		},
		"application/vnd.epson.quickanime": {
			"source": "iana",
			"extensions": ["qam"]
		},
		"application/vnd.epson.salt": {
			"source": "iana",
			"extensions": ["slt"]
		},
		"application/vnd.epson.ssf": {
			"source": "iana",
			"extensions": ["ssf"]
		},
		"application/vnd.ericsson.quickcall": { "source": "iana" },
		"application/vnd.erofs": { "source": "iana" },
		"application/vnd.espass-espass+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.eszigno3+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["es3", "et3"]
		},
		"application/vnd.etsi.aoc+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.asic-e+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.etsi.asic-s+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.etsi.cug+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvcommand+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvdiscovery+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvprofile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvsad-bc+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvsad-cod+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvsad-npvr+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvservice+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvsync+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.iptvueprofile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.mcid+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.mheg5": { "source": "iana" },
		"application/vnd.etsi.overload-control-policy-dataset+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.pstn+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.sci+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.simservs+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.timestamp-token": { "source": "iana" },
		"application/vnd.etsi.tsl+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.etsi.tsl.der": { "source": "iana" },
		"application/vnd.eu.kasparian.car+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.eudora.data": { "source": "iana" },
		"application/vnd.evolv.ecig.profile": { "source": "iana" },
		"application/vnd.evolv.ecig.settings": { "source": "iana" },
		"application/vnd.evolv.ecig.theme": { "source": "iana" },
		"application/vnd.exstream-empower+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.exstream-package": { "source": "iana" },
		"application/vnd.ezpix-album": {
			"source": "iana",
			"extensions": ["ez2"]
		},
		"application/vnd.ezpix-package": {
			"source": "iana",
			"extensions": ["ez3"]
		},
		"application/vnd.f-secure.mobile": { "source": "iana" },
		"application/vnd.familysearch.gedcom+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.fastcopy-disk-image": { "source": "iana" },
		"application/vnd.fdf": {
			"source": "apache",
			"extensions": ["fdf"]
		},
		"application/vnd.fdsn.mseed": {
			"source": "iana",
			"extensions": ["mseed"]
		},
		"application/vnd.fdsn.seed": {
			"source": "iana",
			"extensions": ["seed", "dataless"]
		},
		"application/vnd.fdsn.stationxml+xml": {
			"source": "iana",
			"charset": "XML-BASED",
			"compressible": true
		},
		"application/vnd.ffsns": { "source": "iana" },
		"application/vnd.ficlab.flb+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.filmit.zfc": { "source": "iana" },
		"application/vnd.fints": { "source": "iana" },
		"application/vnd.firemonkeys.cloudcell": { "source": "iana" },
		"application/vnd.flographit": {
			"source": "iana",
			"extensions": ["gph"]
		},
		"application/vnd.fluxtime.clip": {
			"source": "iana",
			"extensions": ["ftc"]
		},
		"application/vnd.font-fontforge-sfd": { "source": "iana" },
		"application/vnd.framemaker": {
			"source": "iana",
			"extensions": [
				"fm",
				"frame",
				"maker",
				"book"
			]
		},
		"application/vnd.freelog.comic": { "source": "iana" },
		"application/vnd.frogans.fnc": {
			"source": "apache",
			"extensions": ["fnc"]
		},
		"application/vnd.frogans.ltf": {
			"source": "apache",
			"extensions": ["ltf"]
		},
		"application/vnd.fsc.weblaunch": {
			"source": "iana",
			"extensions": ["fsc"]
		},
		"application/vnd.fujifilm.fb.docuworks": { "source": "iana" },
		"application/vnd.fujifilm.fb.docuworks.binder": { "source": "iana" },
		"application/vnd.fujifilm.fb.docuworks.container": { "source": "iana" },
		"application/vnd.fujifilm.fb.jfi+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.fujitsu.oasys": {
			"source": "iana",
			"extensions": ["oas"]
		},
		"application/vnd.fujitsu.oasys2": {
			"source": "iana",
			"extensions": ["oa2"]
		},
		"application/vnd.fujitsu.oasys3": {
			"source": "iana",
			"extensions": ["oa3"]
		},
		"application/vnd.fujitsu.oasysgp": {
			"source": "iana",
			"extensions": ["fg5"]
		},
		"application/vnd.fujitsu.oasysprs": {
			"source": "iana",
			"extensions": ["bh2"]
		},
		"application/vnd.fujixerox.art-ex": { "source": "iana" },
		"application/vnd.fujixerox.art4": { "source": "iana" },
		"application/vnd.fujixerox.ddd": {
			"source": "iana",
			"extensions": ["ddd"]
		},
		"application/vnd.fujixerox.docuworks": {
			"source": "iana",
			"extensions": ["xdw"]
		},
		"application/vnd.fujixerox.docuworks.binder": {
			"source": "iana",
			"extensions": ["xbd"]
		},
		"application/vnd.fujixerox.docuworks.container": { "source": "iana" },
		"application/vnd.fujixerox.hbpl": { "source": "iana" },
		"application/vnd.fut-misnet": { "source": "iana" },
		"application/vnd.futoin+cbor": { "source": "iana" },
		"application/vnd.futoin+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.fuzzysheet": {
			"source": "iana",
			"extensions": ["fzs"]
		},
		"application/vnd.ga4gh.passport+jwt": { "source": "iana" },
		"application/vnd.genomatix.tuxedo": {
			"source": "iana",
			"extensions": ["txd"]
		},
		"application/vnd.genozip": { "source": "iana" },
		"application/vnd.gentics.grd+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.gentoo.catmetadata+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.gentoo.ebuild": { "source": "iana" },
		"application/vnd.gentoo.eclass": { "source": "iana" },
		"application/vnd.gentoo.gpkg": { "source": "iana" },
		"application/vnd.gentoo.manifest": { "source": "iana" },
		"application/vnd.gentoo.pkgmetadata+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.gentoo.xpak": { "source": "iana" },
		"application/vnd.geo+json": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.geocube+xml": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.geogebra.file": {
			"source": "iana",
			"extensions": ["ggb"]
		},
		"application/vnd.geogebra.pinboard": { "source": "iana" },
		"application/vnd.geogebra.slides": {
			"source": "iana",
			"extensions": ["ggs"]
		},
		"application/vnd.geogebra.tool": {
			"source": "iana",
			"extensions": ["ggt"]
		},
		"application/vnd.geometry-explorer": {
			"source": "iana",
			"extensions": ["gex", "gre"]
		},
		"application/vnd.geonext": {
			"source": "iana",
			"extensions": ["gxt"]
		},
		"application/vnd.geoplan": {
			"source": "iana",
			"extensions": ["g2w"]
		},
		"application/vnd.geospace": {
			"source": "iana",
			"extensions": ["g3w"]
		},
		"application/vnd.gerber": { "source": "iana" },
		"application/vnd.globalplatform.card-content-mgt": { "source": "iana" },
		"application/vnd.globalplatform.card-content-mgt-response": { "source": "iana" },
		"application/vnd.gmx": {
			"source": "iana",
			"extensions": ["gmx"]
		},
		"application/vnd.gnu.taler.exchange+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.gnu.taler.merchant+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.google-apps.audio": {},
		"application/vnd.google-apps.document": {
			"compressible": false,
			"extensions": ["gdoc"]
		},
		"application/vnd.google-apps.drawing": {
			"compressible": false,
			"extensions": ["gdraw"]
		},
		"application/vnd.google-apps.drive-sdk": { "compressible": false },
		"application/vnd.google-apps.file": {},
		"application/vnd.google-apps.folder": { "compressible": false },
		"application/vnd.google-apps.form": {
			"compressible": false,
			"extensions": ["gform"]
		},
		"application/vnd.google-apps.fusiontable": {},
		"application/vnd.google-apps.jam": {
			"compressible": false,
			"extensions": ["gjam"]
		},
		"application/vnd.google-apps.mail-layout": {},
		"application/vnd.google-apps.map": {
			"compressible": false,
			"extensions": ["gmap"]
		},
		"application/vnd.google-apps.photo": {},
		"application/vnd.google-apps.presentation": {
			"compressible": false,
			"extensions": ["gslides"]
		},
		"application/vnd.google-apps.script": {
			"compressible": false,
			"extensions": ["gscript"]
		},
		"application/vnd.google-apps.shortcut": {},
		"application/vnd.google-apps.site": {
			"compressible": false,
			"extensions": ["gsite"]
		},
		"application/vnd.google-apps.spreadsheet": {
			"compressible": false,
			"extensions": ["gsheet"]
		},
		"application/vnd.google-apps.unknown": {},
		"application/vnd.google-apps.video": {},
		"application/vnd.google-earth.kml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["kml"]
		},
		"application/vnd.google-earth.kmz": {
			"source": "iana",
			"compressible": false,
			"extensions": ["kmz"]
		},
		"application/vnd.gov.sk.e-form+xml": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.gov.sk.e-form+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.gov.sk.xmldatacontainer+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xdcf"]
		},
		"application/vnd.gpxsee.map+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.grafeq": {
			"source": "iana",
			"extensions": ["gqf", "gqs"]
		},
		"application/vnd.gridmp": { "source": "iana" },
		"application/vnd.groove-account": {
			"source": "iana",
			"extensions": ["gac"]
		},
		"application/vnd.groove-help": {
			"source": "iana",
			"extensions": ["ghf"]
		},
		"application/vnd.groove-identity-message": {
			"source": "iana",
			"extensions": ["gim"]
		},
		"application/vnd.groove-injector": {
			"source": "iana",
			"extensions": ["grv"]
		},
		"application/vnd.groove-tool-message": {
			"source": "iana",
			"extensions": ["gtm"]
		},
		"application/vnd.groove-tool-template": {
			"source": "iana",
			"extensions": ["tpl"]
		},
		"application/vnd.groove-vcard": {
			"source": "iana",
			"extensions": ["vcg"]
		},
		"application/vnd.hal+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.hal+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["hal"]
		},
		"application/vnd.handheld-entertainment+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["zmm"]
		},
		"application/vnd.hbci": {
			"source": "iana",
			"extensions": ["hbci"]
		},
		"application/vnd.hc+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.hcl-bireports": { "source": "iana" },
		"application/vnd.hdt": { "source": "iana" },
		"application/vnd.heroku+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.hhe.lesson-player": {
			"source": "iana",
			"extensions": ["les"]
		},
		"application/vnd.hp-hpgl": {
			"source": "iana",
			"extensions": ["hpgl"]
		},
		"application/vnd.hp-hpid": {
			"source": "iana",
			"extensions": ["hpid"]
		},
		"application/vnd.hp-hps": {
			"source": "iana",
			"extensions": ["hps"]
		},
		"application/vnd.hp-jlyt": {
			"source": "iana",
			"extensions": ["jlt"]
		},
		"application/vnd.hp-pcl": {
			"source": "iana",
			"extensions": ["pcl"]
		},
		"application/vnd.hp-pclxl": {
			"source": "iana",
			"extensions": ["pclxl"]
		},
		"application/vnd.hsl": { "source": "iana" },
		"application/vnd.httphone": { "source": "iana" },
		"application/vnd.hydrostatix.sof-data": {
			"source": "iana",
			"extensions": ["sfd-hdstx"]
		},
		"application/vnd.hyper+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.hyper-item+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.hyperdrive+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.hzn-3d-crossword": { "source": "iana" },
		"application/vnd.ibm.afplinedata": { "source": "apache" },
		"application/vnd.ibm.electronic-media": { "source": "iana" },
		"application/vnd.ibm.minipay": {
			"source": "iana",
			"extensions": ["mpy"]
		},
		"application/vnd.ibm.modcap": {
			"source": "apache",
			"extensions": [
				"afp",
				"listafp",
				"list3820"
			]
		},
		"application/vnd.ibm.rights-management": {
			"source": "iana",
			"extensions": ["irm"]
		},
		"application/vnd.ibm.secure-container": {
			"source": "iana",
			"extensions": ["sc"]
		},
		"application/vnd.iccprofile": {
			"source": "iana",
			"extensions": ["icc", "icm"]
		},
		"application/vnd.ieee.1905": { "source": "iana" },
		"application/vnd.igloader": {
			"source": "iana",
			"extensions": ["igl"]
		},
		"application/vnd.imagemeter.folder+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.imagemeter.image+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.immervision-ivp": {
			"source": "iana",
			"extensions": ["ivp"]
		},
		"application/vnd.immervision-ivu": {
			"source": "iana",
			"extensions": ["ivu"]
		},
		"application/vnd.ims.imsccv1p1": { "source": "iana" },
		"application/vnd.ims.imsccv1p2": { "source": "iana" },
		"application/vnd.ims.imsccv1p3": { "source": "iana" },
		"application/vnd.ims.lis.v2.result+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ims.lti.v2.toolconsumerprofile+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ims.lti.v2.toolproxy+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ims.lti.v2.toolproxy.id+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ims.lti.v2.toolsettings+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ims.lti.v2.toolsettings.simple+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.informedcontrol.rms+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.informix-visionary": { "source": "apache" },
		"application/vnd.infotech.project": { "source": "iana" },
		"application/vnd.infotech.project+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.innopath.wamp.notification": { "source": "iana" },
		"application/vnd.insors.igm": {
			"source": "iana",
			"extensions": ["igm"]
		},
		"application/vnd.intercon.formnet": {
			"source": "iana",
			"extensions": ["xpw", "xpx"]
		},
		"application/vnd.intergeo": {
			"source": "iana",
			"extensions": ["i2g"]
		},
		"application/vnd.intertrust.digibox": { "source": "iana" },
		"application/vnd.intertrust.nncp": { "source": "iana" },
		"application/vnd.intu.qbo": {
			"source": "iana",
			"extensions": ["qbo"]
		},
		"application/vnd.intu.qfx": {
			"source": "iana",
			"extensions": ["qfx"]
		},
		"application/vnd.ipfs.ipns-record": { "source": "iana" },
		"application/vnd.ipld.car": { "source": "iana" },
		"application/vnd.ipld.dag-cbor": { "source": "iana" },
		"application/vnd.ipld.dag-json": { "source": "iana" },
		"application/vnd.ipld.raw": { "source": "iana" },
		"application/vnd.iptc.g2.catalogitem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.iptc.g2.conceptitem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.iptc.g2.knowledgeitem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.iptc.g2.newsitem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.iptc.g2.newsmessage+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.iptc.g2.packageitem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.iptc.g2.planningitem+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ipunplugged.rcprofile": {
			"source": "iana",
			"extensions": ["rcprofile"]
		},
		"application/vnd.irepository.package+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["irp"]
		},
		"application/vnd.is-xpr": {
			"source": "iana",
			"extensions": ["xpr"]
		},
		"application/vnd.isac.fcs": {
			"source": "iana",
			"extensions": ["fcs"]
		},
		"application/vnd.iso11783-10+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.jam": {
			"source": "iana",
			"extensions": ["jam"]
		},
		"application/vnd.japannet-directory-service": { "source": "iana" },
		"application/vnd.japannet-jpnstore-wakeup": { "source": "iana" },
		"application/vnd.japannet-payment-wakeup": { "source": "iana" },
		"application/vnd.japannet-registration": { "source": "iana" },
		"application/vnd.japannet-registration-wakeup": { "source": "iana" },
		"application/vnd.japannet-setstore-wakeup": { "source": "iana" },
		"application/vnd.japannet-verification": { "source": "iana" },
		"application/vnd.japannet-verification-wakeup": { "source": "iana" },
		"application/vnd.jcp.javame.midlet-rms": {
			"source": "iana",
			"extensions": ["rms"]
		},
		"application/vnd.jisp": {
			"source": "iana",
			"extensions": ["jisp"]
		},
		"application/vnd.joost.joda-archive": {
			"source": "iana",
			"extensions": ["joda"]
		},
		"application/vnd.jsk.isdn-ngn": { "source": "iana" },
		"application/vnd.kahootz": {
			"source": "iana",
			"extensions": ["ktz", "ktr"]
		},
		"application/vnd.kde.karbon": {
			"source": "iana",
			"extensions": ["karbon"]
		},
		"application/vnd.kde.kchart": {
			"source": "iana",
			"extensions": ["chrt"]
		},
		"application/vnd.kde.kformula": {
			"source": "iana",
			"extensions": ["kfo"]
		},
		"application/vnd.kde.kivio": {
			"source": "iana",
			"extensions": ["flw"]
		},
		"application/vnd.kde.kontour": {
			"source": "iana",
			"extensions": ["kon"]
		},
		"application/vnd.kde.kpresenter": {
			"source": "iana",
			"extensions": ["kpr", "kpt"]
		},
		"application/vnd.kde.kspread": {
			"source": "iana",
			"extensions": ["ksp"]
		},
		"application/vnd.kde.kword": {
			"source": "iana",
			"extensions": ["kwd", "kwt"]
		},
		"application/vnd.kdl": { "source": "iana" },
		"application/vnd.kenameaapp": {
			"source": "iana",
			"extensions": ["htke"]
		},
		"application/vnd.keyman.kmp+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.keyman.kmx": { "source": "iana" },
		"application/vnd.kidspiration": {
			"source": "iana",
			"extensions": ["kia"]
		},
		"application/vnd.kinar": {
			"source": "iana",
			"extensions": ["kne", "knp"]
		},
		"application/vnd.koan": {
			"source": "iana",
			"extensions": [
				"skp",
				"skd",
				"skt",
				"skm"
			]
		},
		"application/vnd.kodak-descriptor": {
			"source": "iana",
			"extensions": ["sse"]
		},
		"application/vnd.las": { "source": "iana" },
		"application/vnd.las.las+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.las.las+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["lasxml"]
		},
		"application/vnd.laszip": { "source": "iana" },
		"application/vnd.ldev.productlicensing": { "source": "iana" },
		"application/vnd.leap+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.liberty-request+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.llamagraphics.life-balance.desktop": {
			"source": "iana",
			"extensions": ["lbd"]
		},
		"application/vnd.llamagraphics.life-balance.exchange+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["lbe"]
		},
		"application/vnd.logipipe.circuit+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.loom": { "source": "iana" },
		"application/vnd.lotus-1-2-3": {
			"source": "iana",
			"extensions": ["123"]
		},
		"application/vnd.lotus-approach": {
			"source": "iana",
			"extensions": ["apr"]
		},
		"application/vnd.lotus-freelance": {
			"source": "iana",
			"extensions": ["pre"]
		},
		"application/vnd.lotus-notes": {
			"source": "iana",
			"extensions": ["nsf"]
		},
		"application/vnd.lotus-organizer": {
			"source": "iana",
			"extensions": ["org"]
		},
		"application/vnd.lotus-screencam": {
			"source": "iana",
			"extensions": ["scm"]
		},
		"application/vnd.lotus-wordpro": {
			"source": "iana",
			"extensions": ["lwp"]
		},
		"application/vnd.macports.portpkg": {
			"source": "iana",
			"extensions": ["portpkg"]
		},
		"application/vnd.mapbox-vector-tile": {
			"source": "iana",
			"extensions": ["mvt"]
		},
		"application/vnd.marlin.drm.actiontoken+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.marlin.drm.conftoken+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.marlin.drm.license+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.marlin.drm.mdcf": { "source": "iana" },
		"application/vnd.mason+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.maxar.archive.3tz+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.maxmind.maxmind-db": { "source": "iana" },
		"application/vnd.mcd": {
			"source": "iana",
			"extensions": ["mcd"]
		},
		"application/vnd.mdl": { "source": "iana" },
		"application/vnd.mdl-mbsdf": { "source": "iana" },
		"application/vnd.medcalcdata": {
			"source": "iana",
			"extensions": ["mc1"]
		},
		"application/vnd.mediastation.cdkey": {
			"source": "iana",
			"extensions": ["cdkey"]
		},
		"application/vnd.medicalholodeck.recordxr": { "source": "iana" },
		"application/vnd.meridian-slingshot": { "source": "iana" },
		"application/vnd.mermaid": { "source": "iana" },
		"application/vnd.mfer": {
			"source": "iana",
			"extensions": ["mwf"]
		},
		"application/vnd.mfmp": {
			"source": "iana",
			"extensions": ["mfm"]
		},
		"application/vnd.micro+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.micrografx.flo": {
			"source": "iana",
			"extensions": ["flo"]
		},
		"application/vnd.micrografx.igx": {
			"source": "iana",
			"extensions": ["igx"]
		},
		"application/vnd.microsoft.portable-executable": { "source": "iana" },
		"application/vnd.microsoft.windows.thumbnail-cache": { "source": "iana" },
		"application/vnd.miele+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.mif": {
			"source": "iana",
			"extensions": ["mif"]
		},
		"application/vnd.minisoft-hp3000-save": { "source": "iana" },
		"application/vnd.mitsubishi.misty-guard.trustweb": { "source": "iana" },
		"application/vnd.mobius.daf": {
			"source": "iana",
			"extensions": ["daf"]
		},
		"application/vnd.mobius.dis": {
			"source": "iana",
			"extensions": ["dis"]
		},
		"application/vnd.mobius.mbk": {
			"source": "iana",
			"extensions": ["mbk"]
		},
		"application/vnd.mobius.mqy": {
			"source": "iana",
			"extensions": ["mqy"]
		},
		"application/vnd.mobius.msl": {
			"source": "iana",
			"extensions": ["msl"]
		},
		"application/vnd.mobius.plc": {
			"source": "iana",
			"extensions": ["plc"]
		},
		"application/vnd.mobius.txf": {
			"source": "iana",
			"extensions": ["txf"]
		},
		"application/vnd.modl": { "source": "iana" },
		"application/vnd.mophun.application": {
			"source": "iana",
			"extensions": ["mpn"]
		},
		"application/vnd.mophun.certificate": {
			"source": "iana",
			"extensions": ["mpc"]
		},
		"application/vnd.motorola.flexsuite": { "source": "iana" },
		"application/vnd.motorola.flexsuite.adsi": { "source": "iana" },
		"application/vnd.motorola.flexsuite.fis": { "source": "iana" },
		"application/vnd.motorola.flexsuite.gotap": { "source": "iana" },
		"application/vnd.motorola.flexsuite.kmr": { "source": "iana" },
		"application/vnd.motorola.flexsuite.ttc": { "source": "iana" },
		"application/vnd.motorola.flexsuite.wem": { "source": "iana" },
		"application/vnd.motorola.iprm": { "source": "iana" },
		"application/vnd.mozilla.xul+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xul"]
		},
		"application/vnd.ms-3mfdocument": { "source": "iana" },
		"application/vnd.ms-artgalry": {
			"source": "iana",
			"extensions": ["cil"]
		},
		"application/vnd.ms-asf": { "source": "iana" },
		"application/vnd.ms-cab-compressed": {
			"source": "iana",
			"extensions": ["cab"]
		},
		"application/vnd.ms-color.iccprofile": { "source": "apache" },
		"application/vnd.ms-excel": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"xls",
				"xlm",
				"xla",
				"xlc",
				"xlt",
				"xlw"
			]
		},
		"application/vnd.ms-excel.addin.macroenabled.12": {
			"source": "iana",
			"extensions": ["xlam"]
		},
		"application/vnd.ms-excel.sheet.binary.macroenabled.12": {
			"source": "iana",
			"extensions": ["xlsb"]
		},
		"application/vnd.ms-excel.sheet.macroenabled.12": {
			"source": "iana",
			"extensions": ["xlsm"]
		},
		"application/vnd.ms-excel.template.macroenabled.12": {
			"source": "iana",
			"extensions": ["xltm"]
		},
		"application/vnd.ms-fontobject": {
			"source": "iana",
			"compressible": true,
			"extensions": ["eot"]
		},
		"application/vnd.ms-htmlhelp": {
			"source": "iana",
			"extensions": ["chm"]
		},
		"application/vnd.ms-ims": {
			"source": "iana",
			"extensions": ["ims"]
		},
		"application/vnd.ms-lrm": {
			"source": "iana",
			"extensions": ["lrm"]
		},
		"application/vnd.ms-office.activex+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ms-officetheme": {
			"source": "iana",
			"extensions": ["thmx"]
		},
		"application/vnd.ms-opentype": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.ms-outlook": {
			"compressible": false,
			"extensions": ["msg"]
		},
		"application/vnd.ms-package.obfuscated-opentype": { "source": "apache" },
		"application/vnd.ms-pki.seccat": {
			"source": "apache",
			"extensions": ["cat"]
		},
		"application/vnd.ms-pki.stl": {
			"source": "apache",
			"extensions": ["stl"]
		},
		"application/vnd.ms-playready.initiator+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ms-powerpoint": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"ppt",
				"pps",
				"pot"
			]
		},
		"application/vnd.ms-powerpoint.addin.macroenabled.12": {
			"source": "iana",
			"extensions": ["ppam"]
		},
		"application/vnd.ms-powerpoint.presentation.macroenabled.12": {
			"source": "iana",
			"extensions": ["pptm"]
		},
		"application/vnd.ms-powerpoint.slide.macroenabled.12": {
			"source": "iana",
			"extensions": ["sldm"]
		},
		"application/vnd.ms-powerpoint.slideshow.macroenabled.12": {
			"source": "iana",
			"extensions": ["ppsm"]
		},
		"application/vnd.ms-powerpoint.template.macroenabled.12": {
			"source": "iana",
			"extensions": ["potm"]
		},
		"application/vnd.ms-printdevicecapabilities+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ms-printing.printticket+xml": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.ms-printschematicket+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.ms-project": {
			"source": "iana",
			"extensions": ["mpp", "mpt"]
		},
		"application/vnd.ms-tnef": { "source": "iana" },
		"application/vnd.ms-visio.viewer": { "extensions": ["vdx"] },
		"application/vnd.ms-windows.devicepairing": { "source": "iana" },
		"application/vnd.ms-windows.nwprinting.oob": { "source": "iana" },
		"application/vnd.ms-windows.printerpairing": { "source": "iana" },
		"application/vnd.ms-windows.wsd.oob": { "source": "iana" },
		"application/vnd.ms-wmdrm.lic-chlg-req": { "source": "iana" },
		"application/vnd.ms-wmdrm.lic-resp": { "source": "iana" },
		"application/vnd.ms-wmdrm.meter-chlg-req": { "source": "iana" },
		"application/vnd.ms-wmdrm.meter-resp": { "source": "iana" },
		"application/vnd.ms-word.document.macroenabled.12": {
			"source": "iana",
			"extensions": ["docm"]
		},
		"application/vnd.ms-word.template.macroenabled.12": {
			"source": "iana",
			"extensions": ["dotm"]
		},
		"application/vnd.ms-works": {
			"source": "iana",
			"extensions": [
				"wps",
				"wks",
				"wcm",
				"wdb"
			]
		},
		"application/vnd.ms-wpl": {
			"source": "iana",
			"extensions": ["wpl"]
		},
		"application/vnd.ms-xpsdocument": {
			"source": "iana",
			"compressible": false,
			"extensions": ["xps"]
		},
		"application/vnd.msa-disk-image": { "source": "iana" },
		"application/vnd.mseq": {
			"source": "iana",
			"extensions": ["mseq"]
		},
		"application/vnd.msgpack": { "source": "iana" },
		"application/vnd.msign": { "source": "iana" },
		"application/vnd.multiad.creator": { "source": "iana" },
		"application/vnd.multiad.creator.cif": { "source": "iana" },
		"application/vnd.music-niff": { "source": "iana" },
		"application/vnd.musician": {
			"source": "iana",
			"extensions": ["mus"]
		},
		"application/vnd.muvee.style": {
			"source": "iana",
			"extensions": ["msty"]
		},
		"application/vnd.mynfc": {
			"source": "iana",
			"extensions": ["taglet"]
		},
		"application/vnd.nacamar.ybrid+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nato.bindingdataobject+cbor": { "source": "iana" },
		"application/vnd.nato.bindingdataobject+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nato.bindingdataobject+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["bdo"]
		},
		"application/vnd.nato.openxmlformats-package.iepd+zip": {
			"source": "iana",
			"compressible": false
		},
		"application/vnd.ncd.control": { "source": "iana" },
		"application/vnd.ncd.reference": { "source": "iana" },
		"application/vnd.nearst.inv+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nebumind.line": { "source": "iana" },
		"application/vnd.nervana": { "source": "iana" },
		"application/vnd.netfpx": { "source": "iana" },
		"application/vnd.neurolanguage.nlu": {
			"source": "iana",
			"extensions": ["nlu"]
		},
		"application/vnd.nimn": { "source": "iana" },
		"application/vnd.nintendo.nitro.rom": { "source": "iana" },
		"application/vnd.nintendo.snes.rom": { "source": "iana" },
		"application/vnd.nitf": {
			"source": "iana",
			"extensions": ["ntf", "nitf"]
		},
		"application/vnd.noblenet-directory": {
			"source": "iana",
			"extensions": ["nnd"]
		},
		"application/vnd.noblenet-sealer": {
			"source": "iana",
			"extensions": ["nns"]
		},
		"application/vnd.noblenet-web": {
			"source": "iana",
			"extensions": ["nnw"]
		},
		"application/vnd.nokia.catalogs": { "source": "iana" },
		"application/vnd.nokia.conml+wbxml": { "source": "iana" },
		"application/vnd.nokia.conml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nokia.iptv.config+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nokia.isds-radio-presets": { "source": "iana" },
		"application/vnd.nokia.landmark+wbxml": { "source": "iana" },
		"application/vnd.nokia.landmark+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nokia.landmarkcollection+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nokia.n-gage.ac+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ac"]
		},
		"application/vnd.nokia.n-gage.data": {
			"source": "iana",
			"extensions": ["ngdat"]
		},
		"application/vnd.nokia.n-gage.symbian.install": {
			"source": "apache",
			"extensions": ["n-gage"]
		},
		"application/vnd.nokia.ncd": { "source": "iana" },
		"application/vnd.nokia.pcd+wbxml": { "source": "iana" },
		"application/vnd.nokia.pcd+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.nokia.radio-preset": {
			"source": "iana",
			"extensions": ["rpst"]
		},
		"application/vnd.nokia.radio-presets": {
			"source": "iana",
			"extensions": ["rpss"]
		},
		"application/vnd.novadigm.edm": {
			"source": "iana",
			"extensions": ["edm"]
		},
		"application/vnd.novadigm.edx": {
			"source": "iana",
			"extensions": ["edx"]
		},
		"application/vnd.novadigm.ext": {
			"source": "iana",
			"extensions": ["ext"]
		},
		"application/vnd.ntt-local.content-share": { "source": "iana" },
		"application/vnd.ntt-local.file-transfer": { "source": "iana" },
		"application/vnd.ntt-local.ogw_remote-access": { "source": "iana" },
		"application/vnd.ntt-local.sip-ta_remote": { "source": "iana" },
		"application/vnd.ntt-local.sip-ta_tcp_stream": { "source": "iana" },
		"application/vnd.oai.workflows": { "source": "iana" },
		"application/vnd.oai.workflows+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oai.workflows+yaml": { "source": "iana" },
		"application/vnd.oasis.opendocument.base": { "source": "iana" },
		"application/vnd.oasis.opendocument.chart": {
			"source": "iana",
			"extensions": ["odc"]
		},
		"application/vnd.oasis.opendocument.chart-template": {
			"source": "iana",
			"extensions": ["otc"]
		},
		"application/vnd.oasis.opendocument.database": {
			"source": "apache",
			"extensions": ["odb"]
		},
		"application/vnd.oasis.opendocument.formula": {
			"source": "iana",
			"extensions": ["odf"]
		},
		"application/vnd.oasis.opendocument.formula-template": {
			"source": "iana",
			"extensions": ["odft"]
		},
		"application/vnd.oasis.opendocument.graphics": {
			"source": "iana",
			"compressible": false,
			"extensions": ["odg"]
		},
		"application/vnd.oasis.opendocument.graphics-template": {
			"source": "iana",
			"extensions": ["otg"]
		},
		"application/vnd.oasis.opendocument.image": {
			"source": "iana",
			"extensions": ["odi"]
		},
		"application/vnd.oasis.opendocument.image-template": {
			"source": "iana",
			"extensions": ["oti"]
		},
		"application/vnd.oasis.opendocument.presentation": {
			"source": "iana",
			"compressible": false,
			"extensions": ["odp"]
		},
		"application/vnd.oasis.opendocument.presentation-template": {
			"source": "iana",
			"extensions": ["otp"]
		},
		"application/vnd.oasis.opendocument.spreadsheet": {
			"source": "iana",
			"compressible": false,
			"extensions": ["ods"]
		},
		"application/vnd.oasis.opendocument.spreadsheet-template": {
			"source": "iana",
			"extensions": ["ots"]
		},
		"application/vnd.oasis.opendocument.text": {
			"source": "iana",
			"compressible": false,
			"extensions": ["odt"]
		},
		"application/vnd.oasis.opendocument.text-master": {
			"source": "iana",
			"extensions": ["odm"]
		},
		"application/vnd.oasis.opendocument.text-master-template": { "source": "iana" },
		"application/vnd.oasis.opendocument.text-template": {
			"source": "iana",
			"extensions": ["ott"]
		},
		"application/vnd.oasis.opendocument.text-web": {
			"source": "iana",
			"extensions": ["oth"]
		},
		"application/vnd.obn": { "source": "iana" },
		"application/vnd.ocf+cbor": { "source": "iana" },
		"application/vnd.oci.image.manifest.v1+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oftn.l10n+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.contentaccessdownload+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.contentaccessstreaming+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.cspg-hexbinary": { "source": "iana" },
		"application/vnd.oipf.dae.svg+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.dae.xhtml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.mippvcontrolmessage+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.pae.gem": { "source": "iana" },
		"application/vnd.oipf.spdiscovery+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.spdlist+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.ueprofile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oipf.userprofile+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.olpc-sugar": {
			"source": "iana",
			"extensions": ["xo"]
		},
		"application/vnd.oma-scws-config": { "source": "iana" },
		"application/vnd.oma-scws-http-request": { "source": "iana" },
		"application/vnd.oma-scws-http-response": { "source": "iana" },
		"application/vnd.oma.bcast.associated-procedure-parameter+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.bcast.drm-trigger+xml": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.oma.bcast.imd+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.bcast.ltkm": { "source": "iana" },
		"application/vnd.oma.bcast.notification+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.bcast.provisioningtrigger": { "source": "iana" },
		"application/vnd.oma.bcast.sgboot": { "source": "iana" },
		"application/vnd.oma.bcast.sgdd+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.bcast.sgdu": { "source": "iana" },
		"application/vnd.oma.bcast.simple-symbol-container": { "source": "iana" },
		"application/vnd.oma.bcast.smartcard-trigger+xml": {
			"source": "apache",
			"compressible": true
		},
		"application/vnd.oma.bcast.sprov+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.bcast.stkm": { "source": "iana" },
		"application/vnd.oma.cab-address-book+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.cab-feature-handler+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.cab-pcc+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.cab-subs-invite+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.cab-user-prefs+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.dcd": { "source": "iana" },
		"application/vnd.oma.dcdc": { "source": "iana" },
		"application/vnd.oma.dd2+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["dd2"]
		},
		"application/vnd.oma.drm.risd+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.group-usage-list+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.lwm2m+cbor": { "source": "iana" },
		"application/vnd.oma.lwm2m+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.lwm2m+tlv": { "source": "iana" },
		"application/vnd.oma.pal+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.poc.detailed-progress-report+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.poc.final-report+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.poc.groups+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.poc.invocation-descriptor+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.poc.optimized-progress-report+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.push": { "source": "iana" },
		"application/vnd.oma.scidm.messages+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oma.xcap-directory+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.omads-email+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/vnd.omads-file+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/vnd.omads-folder+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/vnd.omaloc-supl-init": { "source": "iana" },
		"application/vnd.onepager": { "source": "iana" },
		"application/vnd.onepagertamp": { "source": "iana" },
		"application/vnd.onepagertamx": { "source": "iana" },
		"application/vnd.onepagertat": { "source": "iana" },
		"application/vnd.onepagertatp": { "source": "iana" },
		"application/vnd.onepagertatx": { "source": "iana" },
		"application/vnd.onvif.metadata": { "source": "iana" },
		"application/vnd.openblox.game+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["obgx"]
		},
		"application/vnd.openblox.game-binary": { "source": "iana" },
		"application/vnd.openeye.oeb": { "source": "iana" },
		"application/vnd.openofficeorg.extension": {
			"source": "apache",
			"extensions": ["oxt"]
		},
		"application/vnd.openstreetmap.data+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["osm"]
		},
		"application/vnd.opentimestamps.ots": { "source": "iana" },
		"application/vnd.openvpi.dspx+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.custom-properties+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.customxmlproperties+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawing+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawingml.chart+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.extended-properties+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.comments+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": {
			"source": "iana",
			"compressible": false,
			"extensions": ["pptx"]
		},
		"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.presprops+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slide": {
			"source": "iana",
			"extensions": ["sldx"]
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slide+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slideshow": {
			"source": "iana",
			"extensions": ["ppsx"]
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.tags+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.template": {
			"source": "iana",
			"extensions": ["potx"]
		},
		"application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
			"source": "iana",
			"compressible": false,
			"extensions": ["xlsx"]
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.template": {
			"source": "iana",
			"extensions": ["xltx"]
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.theme+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.themeoverride+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.vmldrawing": { "source": "iana" },
		"application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
			"source": "iana",
			"compressible": false,
			"extensions": ["docx"]
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.template": {
			"source": "iana",
			"extensions": ["dotx"]
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-package.core-properties+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.openxmlformats-package.relationships+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oracle.resource+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.orange.indata": { "source": "iana" },
		"application/vnd.osa.netdeploy": { "source": "iana" },
		"application/vnd.osgeo.mapguide.package": {
			"source": "iana",
			"extensions": ["mgp"]
		},
		"application/vnd.osgi.bundle": { "source": "iana" },
		"application/vnd.osgi.dp": {
			"source": "iana",
			"extensions": ["dp"]
		},
		"application/vnd.osgi.subsystem": {
			"source": "iana",
			"extensions": ["esa"]
		},
		"application/vnd.otps.ct-kip+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.oxli.countgraph": { "source": "iana" },
		"application/vnd.pagerduty+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.palm": {
			"source": "iana",
			"extensions": [
				"pdb",
				"pqa",
				"oprc"
			]
		},
		"application/vnd.panoply": { "source": "iana" },
		"application/vnd.paos.xml": { "source": "iana" },
		"application/vnd.patentdive": { "source": "iana" },
		"application/vnd.patientecommsdoc": { "source": "iana" },
		"application/vnd.pawaafile": {
			"source": "iana",
			"extensions": ["paw"]
		},
		"application/vnd.pcos": { "source": "iana" },
		"application/vnd.pg.format": {
			"source": "iana",
			"extensions": ["str"]
		},
		"application/vnd.pg.osasli": {
			"source": "iana",
			"extensions": ["ei6"]
		},
		"application/vnd.piaccess.application-licence": { "source": "iana" },
		"application/vnd.picsel": {
			"source": "iana",
			"extensions": ["efif"]
		},
		"application/vnd.pmi.widget": {
			"source": "iana",
			"extensions": ["wg"]
		},
		"application/vnd.poc.group-advertisement+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.pocketlearn": {
			"source": "iana",
			"extensions": ["plf"]
		},
		"application/vnd.powerbuilder6": {
			"source": "iana",
			"extensions": ["pbd"]
		},
		"application/vnd.powerbuilder6-s": { "source": "iana" },
		"application/vnd.powerbuilder7": { "source": "iana" },
		"application/vnd.powerbuilder7-s": { "source": "iana" },
		"application/vnd.powerbuilder75": { "source": "iana" },
		"application/vnd.powerbuilder75-s": { "source": "iana" },
		"application/vnd.preminet": { "source": "iana" },
		"application/vnd.previewsystems.box": {
			"source": "iana",
			"extensions": ["box"]
		},
		"application/vnd.procrate.brushset": { "extensions": ["brushset"] },
		"application/vnd.procreate.brush": { "extensions": ["brush"] },
		"application/vnd.procreate.dream": { "extensions": ["drm"] },
		"application/vnd.proteus.magazine": {
			"source": "iana",
			"extensions": ["mgz"]
		},
		"application/vnd.psfs": { "source": "iana" },
		"application/vnd.pt.mundusmundi": { "source": "iana" },
		"application/vnd.publishare-delta-tree": {
			"source": "iana",
			"extensions": ["qps"]
		},
		"application/vnd.pvi.ptid1": {
			"source": "iana",
			"extensions": ["ptid"]
		},
		"application/vnd.pwg-multiplexed": { "source": "iana" },
		"application/vnd.pwg-xhtml-print+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xhtm"]
		},
		"application/vnd.qualcomm.brew-app-res": { "source": "iana" },
		"application/vnd.quarantainenet": { "source": "iana" },
		"application/vnd.quark.quarkxpress": {
			"source": "iana",
			"extensions": [
				"qxd",
				"qxt",
				"qwd",
				"qwt",
				"qxl",
				"qxb"
			]
		},
		"application/vnd.quobject-quoxdocument": { "source": "iana" },
		"application/vnd.radisys.moml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-audit+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-audit-conf+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-audit-conn+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-audit-dialog+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-audit-stream+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-conf+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog-base+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog-fax-detect+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog-group+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog-speech+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.radisys.msml-dialog-transform+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.rainstor.data": { "source": "iana" },
		"application/vnd.rapid": { "source": "iana" },
		"application/vnd.rar": {
			"source": "iana",
			"extensions": ["rar"]
		},
		"application/vnd.realvnc.bed": {
			"source": "iana",
			"extensions": ["bed"]
		},
		"application/vnd.recordare.musicxml": {
			"source": "iana",
			"extensions": ["mxl"]
		},
		"application/vnd.recordare.musicxml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["musicxml"]
		},
		"application/vnd.relpipe": { "source": "iana" },
		"application/vnd.renlearn.rlprint": { "source": "iana" },
		"application/vnd.resilient.logic": { "source": "iana" },
		"application/vnd.restful+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.rig.cryptonote": {
			"source": "iana",
			"extensions": ["cryptonote"]
		},
		"application/vnd.rim.cod": {
			"source": "apache",
			"extensions": ["cod"]
		},
		"application/vnd.rn-realmedia": {
			"source": "apache",
			"extensions": ["rm"]
		},
		"application/vnd.rn-realmedia-vbr": {
			"source": "apache",
			"extensions": ["rmvb"]
		},
		"application/vnd.route66.link66+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["link66"]
		},
		"application/vnd.rs-274x": { "source": "iana" },
		"application/vnd.ruckus.download": { "source": "iana" },
		"application/vnd.s3sms": { "source": "iana" },
		"application/vnd.sailingtracker.track": {
			"source": "iana",
			"extensions": ["st"]
		},
		"application/vnd.sar": { "source": "iana" },
		"application/vnd.sbm.cid": { "source": "iana" },
		"application/vnd.sbm.mid2": { "source": "iana" },
		"application/vnd.scribus": { "source": "iana" },
		"application/vnd.sealed.3df": { "source": "iana" },
		"application/vnd.sealed.csf": { "source": "iana" },
		"application/vnd.sealed.doc": { "source": "iana" },
		"application/vnd.sealed.eml": { "source": "iana" },
		"application/vnd.sealed.mht": { "source": "iana" },
		"application/vnd.sealed.net": { "source": "iana" },
		"application/vnd.sealed.ppt": { "source": "iana" },
		"application/vnd.sealed.tiff": { "source": "iana" },
		"application/vnd.sealed.xls": { "source": "iana" },
		"application/vnd.sealedmedia.softseal.html": { "source": "iana" },
		"application/vnd.sealedmedia.softseal.pdf": { "source": "iana" },
		"application/vnd.seemail": {
			"source": "iana",
			"extensions": ["see"]
		},
		"application/vnd.seis+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.sema": {
			"source": "iana",
			"extensions": ["sema"]
		},
		"application/vnd.semd": {
			"source": "iana",
			"extensions": ["semd"]
		},
		"application/vnd.semf": {
			"source": "iana",
			"extensions": ["semf"]
		},
		"application/vnd.shade-save-file": { "source": "iana" },
		"application/vnd.shana.informed.formdata": {
			"source": "iana",
			"extensions": ["ifm"]
		},
		"application/vnd.shana.informed.formtemplate": {
			"source": "iana",
			"extensions": ["itp"]
		},
		"application/vnd.shana.informed.interchange": {
			"source": "iana",
			"extensions": ["iif"]
		},
		"application/vnd.shana.informed.package": {
			"source": "iana",
			"extensions": ["ipk"]
		},
		"application/vnd.shootproof+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.shopkick+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.shp": { "source": "iana" },
		"application/vnd.shx": { "source": "iana" },
		"application/vnd.sigrok.session": { "source": "iana" },
		"application/vnd.simtech-mindmapper": {
			"source": "iana",
			"extensions": ["twd", "twds"]
		},
		"application/vnd.siren+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.sketchometry": { "source": "iana" },
		"application/vnd.smaf": {
			"source": "iana",
			"extensions": ["mmf"]
		},
		"application/vnd.smart.notebook": { "source": "iana" },
		"application/vnd.smart.teacher": {
			"source": "iana",
			"extensions": ["teacher"]
		},
		"application/vnd.smintio.portals.archive": { "source": "iana" },
		"application/vnd.snesdev-page-table": { "source": "iana" },
		"application/vnd.software602.filler.form+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["fo"]
		},
		"application/vnd.software602.filler.form-xml-zip": { "source": "iana" },
		"application/vnd.solent.sdkm+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["sdkm", "sdkd"]
		},
		"application/vnd.spotfire.dxp": {
			"source": "iana",
			"extensions": ["dxp"]
		},
		"application/vnd.spotfire.sfs": {
			"source": "iana",
			"extensions": ["sfs"]
		},
		"application/vnd.sqlite3": { "source": "iana" },
		"application/vnd.sss-cod": { "source": "iana" },
		"application/vnd.sss-dtf": { "source": "iana" },
		"application/vnd.sss-ntf": { "source": "iana" },
		"application/vnd.stardivision.calc": {
			"source": "apache",
			"extensions": ["sdc"]
		},
		"application/vnd.stardivision.draw": {
			"source": "apache",
			"extensions": ["sda"]
		},
		"application/vnd.stardivision.impress": {
			"source": "apache",
			"extensions": ["sdd"]
		},
		"application/vnd.stardivision.math": {
			"source": "apache",
			"extensions": ["smf"]
		},
		"application/vnd.stardivision.writer": {
			"source": "apache",
			"extensions": ["sdw", "vor"]
		},
		"application/vnd.stardivision.writer-global": {
			"source": "apache",
			"extensions": ["sgl"]
		},
		"application/vnd.stepmania.package": {
			"source": "iana",
			"extensions": ["smzip"]
		},
		"application/vnd.stepmania.stepchart": {
			"source": "iana",
			"extensions": ["sm"]
		},
		"application/vnd.street-stream": { "source": "iana" },
		"application/vnd.sun.wadl+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["wadl"]
		},
		"application/vnd.sun.xml.calc": {
			"source": "apache",
			"extensions": ["sxc"]
		},
		"application/vnd.sun.xml.calc.template": {
			"source": "apache",
			"extensions": ["stc"]
		},
		"application/vnd.sun.xml.draw": {
			"source": "apache",
			"extensions": ["sxd"]
		},
		"application/vnd.sun.xml.draw.template": {
			"source": "apache",
			"extensions": ["std"]
		},
		"application/vnd.sun.xml.impress": {
			"source": "apache",
			"extensions": ["sxi"]
		},
		"application/vnd.sun.xml.impress.template": {
			"source": "apache",
			"extensions": ["sti"]
		},
		"application/vnd.sun.xml.math": {
			"source": "apache",
			"extensions": ["sxm"]
		},
		"application/vnd.sun.xml.writer": {
			"source": "apache",
			"extensions": ["sxw"]
		},
		"application/vnd.sun.xml.writer.global": {
			"source": "apache",
			"extensions": ["sxg"]
		},
		"application/vnd.sun.xml.writer.template": {
			"source": "apache",
			"extensions": ["stw"]
		},
		"application/vnd.sus-calendar": {
			"source": "iana",
			"extensions": ["sus", "susp"]
		},
		"application/vnd.svd": {
			"source": "iana",
			"extensions": ["svd"]
		},
		"application/vnd.swiftview-ics": { "source": "iana" },
		"application/vnd.sybyl.mol2": { "source": "iana" },
		"application/vnd.sycle+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.syft+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.symbian.install": {
			"source": "apache",
			"extensions": ["sis", "sisx"]
		},
		"application/vnd.syncml+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["xsm"]
		},
		"application/vnd.syncml.dm+wbxml": {
			"source": "iana",
			"charset": "UTF-8",
			"extensions": ["bdm"]
		},
		"application/vnd.syncml.dm+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["xdm"]
		},
		"application/vnd.syncml.dm.notification": { "source": "iana" },
		"application/vnd.syncml.dmddf+wbxml": { "source": "iana" },
		"application/vnd.syncml.dmddf+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["ddf"]
		},
		"application/vnd.syncml.dmtnds+wbxml": { "source": "iana" },
		"application/vnd.syncml.dmtnds+xml": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true
		},
		"application/vnd.syncml.ds.notification": { "source": "iana" },
		"application/vnd.tableschema+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.tao.intent-module-archive": {
			"source": "iana",
			"extensions": ["tao"]
		},
		"application/vnd.tcpdump.pcap": {
			"source": "iana",
			"extensions": [
				"pcap",
				"cap",
				"dmp"
			]
		},
		"application/vnd.think-cell.ppttc+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.tmd.mediaflex.api+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.tml": { "source": "iana" },
		"application/vnd.tmobile-livetv": {
			"source": "iana",
			"extensions": ["tmo"]
		},
		"application/vnd.tri.onesource": { "source": "iana" },
		"application/vnd.trid.tpt": {
			"source": "iana",
			"extensions": ["tpt"]
		},
		"application/vnd.triscape.mxs": {
			"source": "iana",
			"extensions": ["mxs"]
		},
		"application/vnd.trueapp": {
			"source": "iana",
			"extensions": ["tra"]
		},
		"application/vnd.truedoc": { "source": "iana" },
		"application/vnd.ubisoft.webplayer": { "source": "iana" },
		"application/vnd.ufdl": {
			"source": "iana",
			"extensions": ["ufd", "ufdl"]
		},
		"application/vnd.uic.osdm+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.uiq.theme": {
			"source": "iana",
			"extensions": ["utz"]
		},
		"application/vnd.umajin": {
			"source": "iana",
			"extensions": ["umj"]
		},
		"application/vnd.unity": {
			"source": "iana",
			"extensions": ["unityweb"]
		},
		"application/vnd.uoml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["uoml", "uo"]
		},
		"application/vnd.uplanet.alert": { "source": "iana" },
		"application/vnd.uplanet.alert-wbxml": { "source": "iana" },
		"application/vnd.uplanet.bearer-choice": { "source": "iana" },
		"application/vnd.uplanet.bearer-choice-wbxml": { "source": "iana" },
		"application/vnd.uplanet.cacheop": { "source": "iana" },
		"application/vnd.uplanet.cacheop-wbxml": { "source": "iana" },
		"application/vnd.uplanet.channel": { "source": "iana" },
		"application/vnd.uplanet.channel-wbxml": { "source": "iana" },
		"application/vnd.uplanet.list": { "source": "iana" },
		"application/vnd.uplanet.list-wbxml": { "source": "iana" },
		"application/vnd.uplanet.listcmd": { "source": "iana" },
		"application/vnd.uplanet.listcmd-wbxml": { "source": "iana" },
		"application/vnd.uplanet.signal": { "source": "iana" },
		"application/vnd.uri-map": { "source": "iana" },
		"application/vnd.valve.source.material": { "source": "iana" },
		"application/vnd.vcx": {
			"source": "iana",
			"extensions": ["vcx"]
		},
		"application/vnd.vd-study": { "source": "iana" },
		"application/vnd.vectorworks": { "source": "iana" },
		"application/vnd.vel+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.veraison.tsm-report+cbor": { "source": "iana" },
		"application/vnd.veraison.tsm-report+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.verimatrix.vcas": { "source": "iana" },
		"application/vnd.veritone.aion+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.veryant.thin": { "source": "iana" },
		"application/vnd.ves.encrypted": { "source": "iana" },
		"application/vnd.vidsoft.vidconference": { "source": "iana" },
		"application/vnd.visio": {
			"source": "iana",
			"extensions": [
				"vsd",
				"vst",
				"vss",
				"vsw",
				"vsdx",
				"vtx"
			]
		},
		"application/vnd.visionary": {
			"source": "iana",
			"extensions": ["vis"]
		},
		"application/vnd.vividence.scriptfile": { "source": "iana" },
		"application/vnd.vocalshaper.vsp4": { "source": "iana" },
		"application/vnd.vsf": {
			"source": "iana",
			"extensions": ["vsf"]
		},
		"application/vnd.wap.sic": { "source": "iana" },
		"application/vnd.wap.slc": { "source": "iana" },
		"application/vnd.wap.wbxml": {
			"source": "iana",
			"charset": "UTF-8",
			"extensions": ["wbxml"]
		},
		"application/vnd.wap.wmlc": {
			"source": "iana",
			"extensions": ["wmlc"]
		},
		"application/vnd.wap.wmlscriptc": {
			"source": "iana",
			"extensions": ["wmlsc"]
		},
		"application/vnd.wasmflow.wafl": { "source": "iana" },
		"application/vnd.webturbo": {
			"source": "iana",
			"extensions": ["wtb"]
		},
		"application/vnd.wfa.dpp": { "source": "iana" },
		"application/vnd.wfa.p2p": { "source": "iana" },
		"application/vnd.wfa.wsc": { "source": "iana" },
		"application/vnd.windows.devicepairing": { "source": "iana" },
		"application/vnd.wmc": { "source": "iana" },
		"application/vnd.wmf.bootstrap": { "source": "iana" },
		"application/vnd.wolfram.mathematica": { "source": "iana" },
		"application/vnd.wolfram.mathematica.package": { "source": "iana" },
		"application/vnd.wolfram.player": {
			"source": "iana",
			"extensions": ["nbp"]
		},
		"application/vnd.wordlift": { "source": "iana" },
		"application/vnd.wordperfect": {
			"source": "iana",
			"extensions": ["wpd"]
		},
		"application/vnd.wqd": {
			"source": "iana",
			"extensions": ["wqd"]
		},
		"application/vnd.wrq-hp3000-labelled": { "source": "iana" },
		"application/vnd.wt.stf": {
			"source": "iana",
			"extensions": ["stf"]
		},
		"application/vnd.wv.csp+wbxml": { "source": "iana" },
		"application/vnd.wv.csp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.wv.ssp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.xacml+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.xara": {
			"source": "iana",
			"extensions": ["xar"]
		},
		"application/vnd.xarin.cpj": { "source": "iana" },
		"application/vnd.xecrets-encrypted": { "source": "iana" },
		"application/vnd.xfdl": {
			"source": "iana",
			"extensions": ["xfdl"]
		},
		"application/vnd.xfdl.webform": { "source": "iana" },
		"application/vnd.xmi+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/vnd.xmpie.cpkg": { "source": "iana" },
		"application/vnd.xmpie.dpkg": { "source": "iana" },
		"application/vnd.xmpie.plan": { "source": "iana" },
		"application/vnd.xmpie.ppkg": { "source": "iana" },
		"application/vnd.xmpie.xlim": { "source": "iana" },
		"application/vnd.yamaha.hv-dic": {
			"source": "iana",
			"extensions": ["hvd"]
		},
		"application/vnd.yamaha.hv-script": {
			"source": "iana",
			"extensions": ["hvs"]
		},
		"application/vnd.yamaha.hv-voice": {
			"source": "iana",
			"extensions": ["hvp"]
		},
		"application/vnd.yamaha.openscoreformat": {
			"source": "iana",
			"extensions": ["osf"]
		},
		"application/vnd.yamaha.openscoreformat.osfpvg+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["osfpvg"]
		},
		"application/vnd.yamaha.remote-setup": { "source": "iana" },
		"application/vnd.yamaha.smaf-audio": {
			"source": "iana",
			"extensions": ["saf"]
		},
		"application/vnd.yamaha.smaf-phrase": {
			"source": "iana",
			"extensions": ["spf"]
		},
		"application/vnd.yamaha.through-ngn": { "source": "iana" },
		"application/vnd.yamaha.tunnel-udpencap": { "source": "iana" },
		"application/vnd.yaoweme": { "source": "iana" },
		"application/vnd.yellowriver-custom-menu": {
			"source": "iana",
			"extensions": ["cmp"]
		},
		"application/vnd.zul": {
			"source": "iana",
			"extensions": ["zir", "zirz"]
		},
		"application/vnd.zzazz.deck+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["zaz"]
		},
		"application/voicexml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["vxml"]
		},
		"application/voucher-cms+json": {
			"source": "iana",
			"compressible": true
		},
		"application/voucher-jws+json": {
			"source": "iana",
			"compressible": true
		},
		"application/vp": { "source": "iana" },
		"application/vp+cose": { "source": "iana" },
		"application/vp+jwt": { "source": "iana" },
		"application/vq-rtcpxr": { "source": "iana" },
		"application/wasm": {
			"source": "iana",
			"compressible": true,
			"extensions": ["wasm"]
		},
		"application/watcherinfo+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["wif"]
		},
		"application/webpush-options+json": {
			"source": "iana",
			"compressible": true
		},
		"application/whoispp-query": { "source": "iana" },
		"application/whoispp-response": { "source": "iana" },
		"application/widget": {
			"source": "iana",
			"extensions": ["wgt"]
		},
		"application/winhlp": {
			"source": "apache",
			"extensions": ["hlp"]
		},
		"application/wita": { "source": "iana" },
		"application/wordperfect5.1": { "source": "iana" },
		"application/wsdl+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["wsdl"]
		},
		"application/wspolicy+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["wspolicy"]
		},
		"application/x-7z-compressed": {
			"source": "apache",
			"compressible": false,
			"extensions": ["7z"]
		},
		"application/x-abiword": {
			"source": "apache",
			"extensions": ["abw"]
		},
		"application/x-ace-compressed": {
			"source": "apache",
			"extensions": ["ace"]
		},
		"application/x-amf": { "source": "apache" },
		"application/x-apple-diskimage": {
			"source": "apache",
			"extensions": ["dmg"]
		},
		"application/x-arj": {
			"compressible": false,
			"extensions": ["arj"]
		},
		"application/x-authorware-bin": {
			"source": "apache",
			"extensions": [
				"aab",
				"x32",
				"u32",
				"vox"
			]
		},
		"application/x-authorware-map": {
			"source": "apache",
			"extensions": ["aam"]
		},
		"application/x-authorware-seg": {
			"source": "apache",
			"extensions": ["aas"]
		},
		"application/x-bcpio": {
			"source": "apache",
			"extensions": ["bcpio"]
		},
		"application/x-bdoc": {
			"compressible": false,
			"extensions": ["bdoc"]
		},
		"application/x-bittorrent": {
			"source": "apache",
			"extensions": ["torrent"]
		},
		"application/x-blender": { "extensions": ["blend"] },
		"application/x-blorb": {
			"source": "apache",
			"extensions": ["blb", "blorb"]
		},
		"application/x-bzip": {
			"source": "apache",
			"compressible": false,
			"extensions": ["bz"]
		},
		"application/x-bzip2": {
			"source": "apache",
			"compressible": false,
			"extensions": ["bz2", "boz"]
		},
		"application/x-cbr": {
			"source": "apache",
			"extensions": [
				"cbr",
				"cba",
				"cbt",
				"cbz",
				"cb7"
			]
		},
		"application/x-cdlink": {
			"source": "apache",
			"extensions": ["vcd"]
		},
		"application/x-cfs-compressed": {
			"source": "apache",
			"extensions": ["cfs"]
		},
		"application/x-chat": {
			"source": "apache",
			"extensions": ["chat"]
		},
		"application/x-chess-pgn": {
			"source": "apache",
			"extensions": ["pgn"]
		},
		"application/x-chrome-extension": { "extensions": ["crx"] },
		"application/x-cocoa": {
			"source": "nginx",
			"extensions": ["cco"]
		},
		"application/x-compress": { "source": "apache" },
		"application/x-compressed": { "extensions": ["rar"] },
		"application/x-conference": {
			"source": "apache",
			"extensions": ["nsc"]
		},
		"application/x-cpio": {
			"source": "apache",
			"extensions": ["cpio"]
		},
		"application/x-csh": {
			"source": "apache",
			"extensions": ["csh"]
		},
		"application/x-deb": { "compressible": false },
		"application/x-debian-package": {
			"source": "apache",
			"extensions": ["deb", "udeb"]
		},
		"application/x-dgc-compressed": {
			"source": "apache",
			"extensions": ["dgc"]
		},
		"application/x-director": {
			"source": "apache",
			"extensions": [
				"dir",
				"dcr",
				"dxr",
				"cst",
				"cct",
				"cxt",
				"w3d",
				"fgd",
				"swa"
			]
		},
		"application/x-doom": {
			"source": "apache",
			"extensions": ["wad"]
		},
		"application/x-dtbncx+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["ncx"]
		},
		"application/x-dtbook+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["dtb"]
		},
		"application/x-dtbresource+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["res"]
		},
		"application/x-dvi": {
			"source": "apache",
			"compressible": false,
			"extensions": ["dvi"]
		},
		"application/x-envoy": {
			"source": "apache",
			"extensions": ["evy"]
		},
		"application/x-eva": {
			"source": "apache",
			"extensions": ["eva"]
		},
		"application/x-font-bdf": {
			"source": "apache",
			"extensions": ["bdf"]
		},
		"application/x-font-dos": { "source": "apache" },
		"application/x-font-framemaker": { "source": "apache" },
		"application/x-font-ghostscript": {
			"source": "apache",
			"extensions": ["gsf"]
		},
		"application/x-font-libgrx": { "source": "apache" },
		"application/x-font-linux-psf": {
			"source": "apache",
			"extensions": ["psf"]
		},
		"application/x-font-pcf": {
			"source": "apache",
			"extensions": ["pcf"]
		},
		"application/x-font-snf": {
			"source": "apache",
			"extensions": ["snf"]
		},
		"application/x-font-speedo": { "source": "apache" },
		"application/x-font-sunos-news": { "source": "apache" },
		"application/x-font-type1": {
			"source": "apache",
			"extensions": [
				"pfa",
				"pfb",
				"pfm",
				"afm"
			]
		},
		"application/x-font-vfont": { "source": "apache" },
		"application/x-freearc": {
			"source": "apache",
			"extensions": ["arc"]
		},
		"application/x-futuresplash": {
			"source": "apache",
			"extensions": ["spl"]
		},
		"application/x-gca-compressed": {
			"source": "apache",
			"extensions": ["gca"]
		},
		"application/x-glulx": {
			"source": "apache",
			"extensions": ["ulx"]
		},
		"application/x-gnumeric": {
			"source": "apache",
			"extensions": ["gnumeric"]
		},
		"application/x-gramps-xml": {
			"source": "apache",
			"extensions": ["gramps"]
		},
		"application/x-gtar": {
			"source": "apache",
			"extensions": ["gtar"]
		},
		"application/x-gzip": { "source": "apache" },
		"application/x-hdf": {
			"source": "apache",
			"extensions": ["hdf"]
		},
		"application/x-httpd-php": {
			"compressible": true,
			"extensions": ["php"]
		},
		"application/x-install-instructions": {
			"source": "apache",
			"extensions": ["install"]
		},
		"application/x-ipynb+json": {
			"compressible": true,
			"extensions": ["ipynb"]
		},
		"application/x-iso9660-image": {
			"source": "apache",
			"extensions": ["iso"]
		},
		"application/x-iwork-keynote-sffkey": { "extensions": ["key"] },
		"application/x-iwork-numbers-sffnumbers": { "extensions": ["numbers"] },
		"application/x-iwork-pages-sffpages": { "extensions": ["pages"] },
		"application/x-java-archive-diff": {
			"source": "nginx",
			"extensions": ["jardiff"]
		},
		"application/x-java-jnlp-file": {
			"source": "apache",
			"compressible": false,
			"extensions": ["jnlp"]
		},
		"application/x-javascript": { "compressible": true },
		"application/x-keepass2": { "extensions": ["kdbx"] },
		"application/x-latex": {
			"source": "apache",
			"compressible": false,
			"extensions": ["latex"]
		},
		"application/x-lua-bytecode": { "extensions": ["luac"] },
		"application/x-lzh-compressed": {
			"source": "apache",
			"extensions": ["lzh", "lha"]
		},
		"application/x-makeself": {
			"source": "nginx",
			"extensions": ["run"]
		},
		"application/x-mie": {
			"source": "apache",
			"extensions": ["mie"]
		},
		"application/x-mobipocket-ebook": {
			"source": "apache",
			"extensions": ["prc", "mobi"]
		},
		"application/x-mpegurl": { "compressible": false },
		"application/x-ms-application": {
			"source": "apache",
			"extensions": ["application"]
		},
		"application/x-ms-shortcut": {
			"source": "apache",
			"extensions": ["lnk"]
		},
		"application/x-ms-wmd": {
			"source": "apache",
			"extensions": ["wmd"]
		},
		"application/x-ms-wmz": {
			"source": "apache",
			"extensions": ["wmz"]
		},
		"application/x-ms-xbap": {
			"source": "apache",
			"extensions": ["xbap"]
		},
		"application/x-msaccess": {
			"source": "apache",
			"extensions": ["mdb"]
		},
		"application/x-msbinder": {
			"source": "apache",
			"extensions": ["obd"]
		},
		"application/x-mscardfile": {
			"source": "apache",
			"extensions": ["crd"]
		},
		"application/x-msclip": {
			"source": "apache",
			"extensions": ["clp"]
		},
		"application/x-msdos-program": { "extensions": ["exe"] },
		"application/x-msdownload": {
			"source": "apache",
			"extensions": [
				"exe",
				"dll",
				"com",
				"bat",
				"msi"
			]
		},
		"application/x-msmediaview": {
			"source": "apache",
			"extensions": [
				"mvb",
				"m13",
				"m14"
			]
		},
		"application/x-msmetafile": {
			"source": "apache",
			"extensions": [
				"wmf",
				"wmz",
				"emf",
				"emz"
			]
		},
		"application/x-msmoney": {
			"source": "apache",
			"extensions": ["mny"]
		},
		"application/x-mspublisher": {
			"source": "apache",
			"extensions": ["pub"]
		},
		"application/x-msschedule": {
			"source": "apache",
			"extensions": ["scd"]
		},
		"application/x-msterminal": {
			"source": "apache",
			"extensions": ["trm"]
		},
		"application/x-mswrite": {
			"source": "apache",
			"extensions": ["wri"]
		},
		"application/x-netcdf": {
			"source": "apache",
			"extensions": ["nc", "cdf"]
		},
		"application/x-ns-proxy-autoconfig": {
			"compressible": true,
			"extensions": ["pac"]
		},
		"application/x-nzb": {
			"source": "apache",
			"extensions": ["nzb"]
		},
		"application/x-perl": {
			"source": "nginx",
			"extensions": ["pl", "pm"]
		},
		"application/x-pilot": {
			"source": "nginx",
			"extensions": ["prc", "pdb"]
		},
		"application/x-pkcs12": {
			"source": "apache",
			"compressible": false,
			"extensions": ["p12", "pfx"]
		},
		"application/x-pkcs7-certificates": {
			"source": "apache",
			"extensions": ["p7b", "spc"]
		},
		"application/x-pkcs7-certreqresp": {
			"source": "apache",
			"extensions": ["p7r"]
		},
		"application/x-pki-message": { "source": "iana" },
		"application/x-rar-compressed": {
			"source": "apache",
			"compressible": false,
			"extensions": ["rar"]
		},
		"application/x-redhat-package-manager": {
			"source": "nginx",
			"extensions": ["rpm"]
		},
		"application/x-research-info-systems": {
			"source": "apache",
			"extensions": ["ris"]
		},
		"application/x-sea": {
			"source": "nginx",
			"extensions": ["sea"]
		},
		"application/x-sh": {
			"source": "apache",
			"compressible": true,
			"extensions": ["sh"]
		},
		"application/x-shar": {
			"source": "apache",
			"extensions": ["shar"]
		},
		"application/x-shockwave-flash": {
			"source": "apache",
			"compressible": false,
			"extensions": ["swf"]
		},
		"application/x-silverlight-app": {
			"source": "apache",
			"extensions": ["xap"]
		},
		"application/x-sql": {
			"source": "apache",
			"extensions": ["sql"]
		},
		"application/x-stuffit": {
			"source": "apache",
			"compressible": false,
			"extensions": ["sit"]
		},
		"application/x-stuffitx": {
			"source": "apache",
			"extensions": ["sitx"]
		},
		"application/x-subrip": {
			"source": "apache",
			"extensions": ["srt"]
		},
		"application/x-sv4cpio": {
			"source": "apache",
			"extensions": ["sv4cpio"]
		},
		"application/x-sv4crc": {
			"source": "apache",
			"extensions": ["sv4crc"]
		},
		"application/x-t3vm-image": {
			"source": "apache",
			"extensions": ["t3"]
		},
		"application/x-tads": {
			"source": "apache",
			"extensions": ["gam"]
		},
		"application/x-tar": {
			"source": "apache",
			"compressible": true,
			"extensions": ["tar"]
		},
		"application/x-tcl": {
			"source": "apache",
			"extensions": ["tcl", "tk"]
		},
		"application/x-tex": {
			"source": "apache",
			"extensions": ["tex"]
		},
		"application/x-tex-tfm": {
			"source": "apache",
			"extensions": ["tfm"]
		},
		"application/x-texinfo": {
			"source": "apache",
			"extensions": ["texinfo", "texi"]
		},
		"application/x-tgif": {
			"source": "apache",
			"extensions": ["obj"]
		},
		"application/x-ustar": {
			"source": "apache",
			"extensions": ["ustar"]
		},
		"application/x-virtualbox-hdd": {
			"compressible": true,
			"extensions": ["hdd"]
		},
		"application/x-virtualbox-ova": {
			"compressible": true,
			"extensions": ["ova"]
		},
		"application/x-virtualbox-ovf": {
			"compressible": true,
			"extensions": ["ovf"]
		},
		"application/x-virtualbox-vbox": {
			"compressible": true,
			"extensions": ["vbox"]
		},
		"application/x-virtualbox-vbox-extpack": {
			"compressible": false,
			"extensions": ["vbox-extpack"]
		},
		"application/x-virtualbox-vdi": {
			"compressible": true,
			"extensions": ["vdi"]
		},
		"application/x-virtualbox-vhd": {
			"compressible": true,
			"extensions": ["vhd"]
		},
		"application/x-virtualbox-vmdk": {
			"compressible": true,
			"extensions": ["vmdk"]
		},
		"application/x-wais-source": {
			"source": "apache",
			"extensions": ["src"]
		},
		"application/x-web-app-manifest+json": {
			"compressible": true,
			"extensions": ["webapp"]
		},
		"application/x-www-form-urlencoded": {
			"source": "iana",
			"compressible": true
		},
		"application/x-x509-ca-cert": {
			"source": "iana",
			"extensions": [
				"der",
				"crt",
				"pem"
			]
		},
		"application/x-x509-ca-ra-cert": { "source": "iana" },
		"application/x-x509-next-ca-cert": { "source": "iana" },
		"application/x-xfig": {
			"source": "apache",
			"extensions": ["fig"]
		},
		"application/x-xliff+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["xlf"]
		},
		"application/x-xpinstall": {
			"source": "apache",
			"compressible": false,
			"extensions": ["xpi"]
		},
		"application/x-xz": {
			"source": "apache",
			"extensions": ["xz"]
		},
		"application/x-zip-compressed": { "extensions": ["zip"] },
		"application/x-zmachine": {
			"source": "apache",
			"extensions": [
				"z1",
				"z2",
				"z3",
				"z4",
				"z5",
				"z6",
				"z7",
				"z8"
			]
		},
		"application/x400-bp": { "source": "iana" },
		"application/xacml+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/xaml+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["xaml"]
		},
		"application/xcap-att+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xav"]
		},
		"application/xcap-caps+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xca"]
		},
		"application/xcap-diff+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xdf"]
		},
		"application/xcap-el+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xel"]
		},
		"application/xcap-error+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/xcap-ns+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xns"]
		},
		"application/xcon-conference-info+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/xcon-conference-info-diff+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/xenc+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xenc"]
		},
		"application/xfdf": {
			"source": "iana",
			"extensions": ["xfdf"]
		},
		"application/xhtml+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xhtml", "xht"]
		},
		"application/xhtml-voice+xml": {
			"source": "apache",
			"compressible": true
		},
		"application/xliff+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xlf"]
		},
		"application/xml": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"xml",
				"xsl",
				"xsd",
				"rng"
			]
		},
		"application/xml-dtd": {
			"source": "iana",
			"compressible": true,
			"extensions": ["dtd"]
		},
		"application/xml-external-parsed-entity": { "source": "iana" },
		"application/xml-patch+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/xmpp+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/xop+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xop"]
		},
		"application/xproc+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["xpl"]
		},
		"application/xslt+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xsl", "xslt"]
		},
		"application/xspf+xml": {
			"source": "apache",
			"compressible": true,
			"extensions": ["xspf"]
		},
		"application/xv+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"mxml",
				"xhvml",
				"xvml",
				"xvm"
			]
		},
		"application/yaml": { "source": "iana" },
		"application/yang": {
			"source": "iana",
			"extensions": ["yang"]
		},
		"application/yang-data+cbor": { "source": "iana" },
		"application/yang-data+json": {
			"source": "iana",
			"compressible": true
		},
		"application/yang-data+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/yang-patch+json": {
			"source": "iana",
			"compressible": true
		},
		"application/yang-patch+xml": {
			"source": "iana",
			"compressible": true
		},
		"application/yang-sid+json": {
			"source": "iana",
			"compressible": true
		},
		"application/yin+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["yin"]
		},
		"application/zip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["zip"]
		},
		"application/zip+dotlottie": { "extensions": ["lottie"] },
		"application/zlib": { "source": "iana" },
		"application/zstd": { "source": "iana" },
		"audio/1d-interleaved-parityfec": { "source": "iana" },
		"audio/32kadpcm": { "source": "iana" },
		"audio/3gpp": {
			"source": "iana",
			"compressible": false,
			"extensions": ["3gpp"]
		},
		"audio/3gpp2": { "source": "iana" },
		"audio/aac": {
			"source": "iana",
			"extensions": ["adts", "aac"]
		},
		"audio/ac3": { "source": "iana" },
		"audio/adpcm": {
			"source": "apache",
			"extensions": ["adp"]
		},
		"audio/amr": {
			"source": "iana",
			"extensions": ["amr"]
		},
		"audio/amr-wb": { "source": "iana" },
		"audio/amr-wb+": { "source": "iana" },
		"audio/aptx": { "source": "iana" },
		"audio/asc": { "source": "iana" },
		"audio/atrac-advanced-lossless": { "source": "iana" },
		"audio/atrac-x": { "source": "iana" },
		"audio/atrac3": { "source": "iana" },
		"audio/basic": {
			"source": "iana",
			"compressible": false,
			"extensions": ["au", "snd"]
		},
		"audio/bv16": { "source": "iana" },
		"audio/bv32": { "source": "iana" },
		"audio/clearmode": { "source": "iana" },
		"audio/cn": { "source": "iana" },
		"audio/dat12": { "source": "iana" },
		"audio/dls": { "source": "iana" },
		"audio/dsr-es201108": { "source": "iana" },
		"audio/dsr-es202050": { "source": "iana" },
		"audio/dsr-es202211": { "source": "iana" },
		"audio/dsr-es202212": { "source": "iana" },
		"audio/dv": { "source": "iana" },
		"audio/dvi4": { "source": "iana" },
		"audio/eac3": { "source": "iana" },
		"audio/encaprtp": { "source": "iana" },
		"audio/evrc": { "source": "iana" },
		"audio/evrc-qcp": { "source": "iana" },
		"audio/evrc0": { "source": "iana" },
		"audio/evrc1": { "source": "iana" },
		"audio/evrcb": { "source": "iana" },
		"audio/evrcb0": { "source": "iana" },
		"audio/evrcb1": { "source": "iana" },
		"audio/evrcnw": { "source": "iana" },
		"audio/evrcnw0": { "source": "iana" },
		"audio/evrcnw1": { "source": "iana" },
		"audio/evrcwb": { "source": "iana" },
		"audio/evrcwb0": { "source": "iana" },
		"audio/evrcwb1": { "source": "iana" },
		"audio/evs": { "source": "iana" },
		"audio/flac": { "source": "iana" },
		"audio/flexfec": { "source": "iana" },
		"audio/fwdred": { "source": "iana" },
		"audio/g711-0": { "source": "iana" },
		"audio/g719": { "source": "iana" },
		"audio/g722": { "source": "iana" },
		"audio/g7221": { "source": "iana" },
		"audio/g723": { "source": "iana" },
		"audio/g726-16": { "source": "iana" },
		"audio/g726-24": { "source": "iana" },
		"audio/g726-32": { "source": "iana" },
		"audio/g726-40": { "source": "iana" },
		"audio/g728": { "source": "iana" },
		"audio/g729": { "source": "iana" },
		"audio/g7291": { "source": "iana" },
		"audio/g729d": { "source": "iana" },
		"audio/g729e": { "source": "iana" },
		"audio/gsm": { "source": "iana" },
		"audio/gsm-efr": { "source": "iana" },
		"audio/gsm-hr-08": { "source": "iana" },
		"audio/ilbc": { "source": "iana" },
		"audio/ip-mr_v2.5": { "source": "iana" },
		"audio/isac": { "source": "apache" },
		"audio/l16": { "source": "iana" },
		"audio/l20": { "source": "iana" },
		"audio/l24": {
			"source": "iana",
			"compressible": false
		},
		"audio/l8": { "source": "iana" },
		"audio/lpc": { "source": "iana" },
		"audio/matroska": { "source": "iana" },
		"audio/melp": { "source": "iana" },
		"audio/melp1200": { "source": "iana" },
		"audio/melp2400": { "source": "iana" },
		"audio/melp600": { "source": "iana" },
		"audio/mhas": { "source": "iana" },
		"audio/midi": {
			"source": "apache",
			"extensions": [
				"mid",
				"midi",
				"kar",
				"rmi"
			]
		},
		"audio/midi-clip": { "source": "iana" },
		"audio/mobile-xmf": {
			"source": "iana",
			"extensions": ["mxmf"]
		},
		"audio/mp3": {
			"compressible": false,
			"extensions": ["mp3"]
		},
		"audio/mp4": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"m4a",
				"mp4a",
				"m4b"
			]
		},
		"audio/mp4a-latm": { "source": "iana" },
		"audio/mpa": { "source": "iana" },
		"audio/mpa-robust": { "source": "iana" },
		"audio/mpeg": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"mpga",
				"mp2",
				"mp2a",
				"mp3",
				"m2a",
				"m3a"
			]
		},
		"audio/mpeg4-generic": { "source": "iana" },
		"audio/musepack": { "source": "apache" },
		"audio/ogg": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"oga",
				"ogg",
				"spx",
				"opus"
			]
		},
		"audio/opus": { "source": "iana" },
		"audio/parityfec": { "source": "iana" },
		"audio/pcma": { "source": "iana" },
		"audio/pcma-wb": { "source": "iana" },
		"audio/pcmu": { "source": "iana" },
		"audio/pcmu-wb": { "source": "iana" },
		"audio/prs.sid": { "source": "iana" },
		"audio/qcelp": { "source": "iana" },
		"audio/raptorfec": { "source": "iana" },
		"audio/red": { "source": "iana" },
		"audio/rtp-enc-aescm128": { "source": "iana" },
		"audio/rtp-midi": { "source": "iana" },
		"audio/rtploopback": { "source": "iana" },
		"audio/rtx": { "source": "iana" },
		"audio/s3m": {
			"source": "apache",
			"extensions": ["s3m"]
		},
		"audio/scip": { "source": "iana" },
		"audio/silk": {
			"source": "apache",
			"extensions": ["sil"]
		},
		"audio/smv": { "source": "iana" },
		"audio/smv-qcp": { "source": "iana" },
		"audio/smv0": { "source": "iana" },
		"audio/sofa": { "source": "iana" },
		"audio/sp-midi": { "source": "iana" },
		"audio/speex": { "source": "iana" },
		"audio/t140c": { "source": "iana" },
		"audio/t38": { "source": "iana" },
		"audio/telephone-event": { "source": "iana" },
		"audio/tetra_acelp": { "source": "iana" },
		"audio/tetra_acelp_bb": { "source": "iana" },
		"audio/tone": { "source": "iana" },
		"audio/tsvcis": { "source": "iana" },
		"audio/uemclip": { "source": "iana" },
		"audio/ulpfec": { "source": "iana" },
		"audio/usac": { "source": "iana" },
		"audio/vdvi": { "source": "iana" },
		"audio/vmr-wb": { "source": "iana" },
		"audio/vnd.3gpp.iufp": { "source": "iana" },
		"audio/vnd.4sb": { "source": "iana" },
		"audio/vnd.audiokoz": { "source": "iana" },
		"audio/vnd.celp": { "source": "iana" },
		"audio/vnd.cisco.nse": { "source": "iana" },
		"audio/vnd.cmles.radio-events": { "source": "iana" },
		"audio/vnd.cns.anp1": { "source": "iana" },
		"audio/vnd.cns.inf1": { "source": "iana" },
		"audio/vnd.dece.audio": {
			"source": "iana",
			"extensions": ["uva", "uvva"]
		},
		"audio/vnd.digital-winds": {
			"source": "iana",
			"extensions": ["eol"]
		},
		"audio/vnd.dlna.adts": { "source": "iana" },
		"audio/vnd.dolby.heaac.1": { "source": "iana" },
		"audio/vnd.dolby.heaac.2": { "source": "iana" },
		"audio/vnd.dolby.mlp": { "source": "iana" },
		"audio/vnd.dolby.mps": { "source": "iana" },
		"audio/vnd.dolby.pl2": { "source": "iana" },
		"audio/vnd.dolby.pl2x": { "source": "iana" },
		"audio/vnd.dolby.pl2z": { "source": "iana" },
		"audio/vnd.dolby.pulse.1": { "source": "iana" },
		"audio/vnd.dra": {
			"source": "iana",
			"extensions": ["dra"]
		},
		"audio/vnd.dts": {
			"source": "iana",
			"extensions": ["dts"]
		},
		"audio/vnd.dts.hd": {
			"source": "iana",
			"extensions": ["dtshd"]
		},
		"audio/vnd.dts.uhd": { "source": "iana" },
		"audio/vnd.dvb.file": { "source": "iana" },
		"audio/vnd.everad.plj": { "source": "iana" },
		"audio/vnd.hns.audio": { "source": "iana" },
		"audio/vnd.lucent.voice": {
			"source": "iana",
			"extensions": ["lvp"]
		},
		"audio/vnd.ms-playready.media.pya": {
			"source": "iana",
			"extensions": ["pya"]
		},
		"audio/vnd.nokia.mobile-xmf": { "source": "iana" },
		"audio/vnd.nortel.vbk": { "source": "iana" },
		"audio/vnd.nuera.ecelp4800": {
			"source": "iana",
			"extensions": ["ecelp4800"]
		},
		"audio/vnd.nuera.ecelp7470": {
			"source": "iana",
			"extensions": ["ecelp7470"]
		},
		"audio/vnd.nuera.ecelp9600": {
			"source": "iana",
			"extensions": ["ecelp9600"]
		},
		"audio/vnd.octel.sbc": { "source": "iana" },
		"audio/vnd.presonus.multitrack": { "source": "iana" },
		"audio/vnd.qcelp": { "source": "apache" },
		"audio/vnd.rhetorex.32kadpcm": { "source": "iana" },
		"audio/vnd.rip": {
			"source": "iana",
			"extensions": ["rip"]
		},
		"audio/vnd.rn-realaudio": { "compressible": false },
		"audio/vnd.sealedmedia.softseal.mpeg": { "source": "iana" },
		"audio/vnd.vmx.cvsd": { "source": "iana" },
		"audio/vnd.wave": { "compressible": false },
		"audio/vorbis": {
			"source": "iana",
			"compressible": false
		},
		"audio/vorbis-config": { "source": "iana" },
		"audio/wav": {
			"compressible": false,
			"extensions": ["wav"]
		},
		"audio/wave": {
			"compressible": false,
			"extensions": ["wav"]
		},
		"audio/webm": {
			"source": "apache",
			"compressible": false,
			"extensions": ["weba"]
		},
		"audio/x-aac": {
			"source": "apache",
			"compressible": false,
			"extensions": ["aac"]
		},
		"audio/x-aiff": {
			"source": "apache",
			"extensions": [
				"aif",
				"aiff",
				"aifc"
			]
		},
		"audio/x-caf": {
			"source": "apache",
			"compressible": false,
			"extensions": ["caf"]
		},
		"audio/x-flac": {
			"source": "apache",
			"extensions": ["flac"]
		},
		"audio/x-m4a": {
			"source": "nginx",
			"extensions": ["m4a"]
		},
		"audio/x-matroska": {
			"source": "apache",
			"extensions": ["mka"]
		},
		"audio/x-mpegurl": {
			"source": "apache",
			"extensions": ["m3u"]
		},
		"audio/x-ms-wax": {
			"source": "apache",
			"extensions": ["wax"]
		},
		"audio/x-ms-wma": {
			"source": "apache",
			"extensions": ["wma"]
		},
		"audio/x-pn-realaudio": {
			"source": "apache",
			"extensions": ["ram", "ra"]
		},
		"audio/x-pn-realaudio-plugin": {
			"source": "apache",
			"extensions": ["rmp"]
		},
		"audio/x-realaudio": {
			"source": "nginx",
			"extensions": ["ra"]
		},
		"audio/x-tta": { "source": "apache" },
		"audio/x-wav": {
			"source": "apache",
			"extensions": ["wav"]
		},
		"audio/xm": {
			"source": "apache",
			"extensions": ["xm"]
		},
		"chemical/x-cdx": {
			"source": "apache",
			"extensions": ["cdx"]
		},
		"chemical/x-cif": {
			"source": "apache",
			"extensions": ["cif"]
		},
		"chemical/x-cmdf": {
			"source": "apache",
			"extensions": ["cmdf"]
		},
		"chemical/x-cml": {
			"source": "apache",
			"extensions": ["cml"]
		},
		"chemical/x-csml": {
			"source": "apache",
			"extensions": ["csml"]
		},
		"chemical/x-pdb": { "source": "apache" },
		"chemical/x-xyz": {
			"source": "apache",
			"extensions": ["xyz"]
		},
		"font/collection": {
			"source": "iana",
			"extensions": ["ttc"]
		},
		"font/otf": {
			"source": "iana",
			"compressible": true,
			"extensions": ["otf"]
		},
		"font/sfnt": { "source": "iana" },
		"font/ttf": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ttf"]
		},
		"font/woff": {
			"source": "iana",
			"extensions": ["woff"]
		},
		"font/woff2": {
			"source": "iana",
			"extensions": ["woff2"]
		},
		"image/aces": {
			"source": "iana",
			"extensions": ["exr"]
		},
		"image/apng": {
			"source": "iana",
			"compressible": false,
			"extensions": ["apng"]
		},
		"image/avci": {
			"source": "iana",
			"extensions": ["avci"]
		},
		"image/avcs": {
			"source": "iana",
			"extensions": ["avcs"]
		},
		"image/avif": {
			"source": "iana",
			"compressible": false,
			"extensions": ["avif"]
		},
		"image/bmp": {
			"source": "iana",
			"compressible": true,
			"extensions": ["bmp", "dib"]
		},
		"image/cgm": {
			"source": "iana",
			"extensions": ["cgm"]
		},
		"image/dicom-rle": {
			"source": "iana",
			"extensions": ["drle"]
		},
		"image/dpx": {
			"source": "iana",
			"extensions": ["dpx"]
		},
		"image/emf": {
			"source": "iana",
			"extensions": ["emf"]
		},
		"image/fits": {
			"source": "iana",
			"extensions": ["fits"]
		},
		"image/g3fax": {
			"source": "iana",
			"extensions": ["g3"]
		},
		"image/gif": {
			"source": "iana",
			"compressible": false,
			"extensions": ["gif"]
		},
		"image/heic": {
			"source": "iana",
			"extensions": ["heic"]
		},
		"image/heic-sequence": {
			"source": "iana",
			"extensions": ["heics"]
		},
		"image/heif": {
			"source": "iana",
			"extensions": ["heif"]
		},
		"image/heif-sequence": {
			"source": "iana",
			"extensions": ["heifs"]
		},
		"image/hej2k": {
			"source": "iana",
			"extensions": ["hej2"]
		},
		"image/ief": {
			"source": "iana",
			"extensions": ["ief"]
		},
		"image/j2c": { "source": "iana" },
		"image/jaii": {
			"source": "iana",
			"extensions": ["jaii"]
		},
		"image/jais": {
			"source": "iana",
			"extensions": ["jais"]
		},
		"image/jls": {
			"source": "iana",
			"extensions": ["jls"]
		},
		"image/jp2": {
			"source": "iana",
			"compressible": false,
			"extensions": ["jp2", "jpg2"]
		},
		"image/jpeg": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"jpg",
				"jpeg",
				"jpe"
			]
		},
		"image/jph": {
			"source": "iana",
			"extensions": ["jph"]
		},
		"image/jphc": {
			"source": "iana",
			"extensions": ["jhc"]
		},
		"image/jpm": {
			"source": "iana",
			"compressible": false,
			"extensions": ["jpm", "jpgm"]
		},
		"image/jpx": {
			"source": "iana",
			"compressible": false,
			"extensions": ["jpx", "jpf"]
		},
		"image/jxl": {
			"source": "iana",
			"extensions": ["jxl"]
		},
		"image/jxr": {
			"source": "iana",
			"extensions": ["jxr"]
		},
		"image/jxra": {
			"source": "iana",
			"extensions": ["jxra"]
		},
		"image/jxrs": {
			"source": "iana",
			"extensions": ["jxrs"]
		},
		"image/jxs": {
			"source": "iana",
			"extensions": ["jxs"]
		},
		"image/jxsc": {
			"source": "iana",
			"extensions": ["jxsc"]
		},
		"image/jxsi": {
			"source": "iana",
			"extensions": ["jxsi"]
		},
		"image/jxss": {
			"source": "iana",
			"extensions": ["jxss"]
		},
		"image/ktx": {
			"source": "iana",
			"extensions": ["ktx"]
		},
		"image/ktx2": {
			"source": "iana",
			"extensions": ["ktx2"]
		},
		"image/naplps": { "source": "iana" },
		"image/pjpeg": {
			"compressible": false,
			"extensions": ["jfif"]
		},
		"image/png": {
			"source": "iana",
			"compressible": false,
			"extensions": ["png"]
		},
		"image/prs.btif": {
			"source": "iana",
			"extensions": ["btif", "btf"]
		},
		"image/prs.pti": {
			"source": "iana",
			"extensions": ["pti"]
		},
		"image/pwg-raster": { "source": "iana" },
		"image/sgi": {
			"source": "apache",
			"extensions": ["sgi"]
		},
		"image/svg+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["svg", "svgz"]
		},
		"image/t38": {
			"source": "iana",
			"extensions": ["t38"]
		},
		"image/tiff": {
			"source": "iana",
			"compressible": false,
			"extensions": ["tif", "tiff"]
		},
		"image/tiff-fx": {
			"source": "iana",
			"extensions": ["tfx"]
		},
		"image/vnd.adobe.photoshop": {
			"source": "iana",
			"compressible": true,
			"extensions": ["psd"]
		},
		"image/vnd.airzip.accelerator.azv": {
			"source": "iana",
			"extensions": ["azv"]
		},
		"image/vnd.clip": { "source": "iana" },
		"image/vnd.cns.inf2": { "source": "iana" },
		"image/vnd.dece.graphic": {
			"source": "iana",
			"extensions": [
				"uvi",
				"uvvi",
				"uvg",
				"uvvg"
			]
		},
		"image/vnd.djvu": {
			"source": "iana",
			"extensions": ["djvu", "djv"]
		},
		"image/vnd.dvb.subtitle": {
			"source": "iana",
			"extensions": ["sub"]
		},
		"image/vnd.dwg": {
			"source": "iana",
			"extensions": ["dwg"]
		},
		"image/vnd.dxf": {
			"source": "iana",
			"extensions": ["dxf"]
		},
		"image/vnd.fastbidsheet": {
			"source": "iana",
			"extensions": ["fbs"]
		},
		"image/vnd.fpx": {
			"source": "iana",
			"extensions": ["fpx"]
		},
		"image/vnd.fst": {
			"source": "iana",
			"extensions": ["fst"]
		},
		"image/vnd.fujixerox.edmics-mmr": {
			"source": "iana",
			"extensions": ["mmr"]
		},
		"image/vnd.fujixerox.edmics-rlc": {
			"source": "iana",
			"extensions": ["rlc"]
		},
		"image/vnd.globalgraphics.pgb": { "source": "iana" },
		"image/vnd.microsoft.icon": {
			"source": "iana",
			"compressible": true,
			"extensions": ["ico"]
		},
		"image/vnd.mix": { "source": "iana" },
		"image/vnd.mozilla.apng": { "source": "iana" },
		"image/vnd.ms-dds": {
			"compressible": true,
			"extensions": ["dds"]
		},
		"image/vnd.ms-modi": {
			"source": "iana",
			"extensions": ["mdi"]
		},
		"image/vnd.ms-photo": {
			"source": "apache",
			"extensions": ["wdp"]
		},
		"image/vnd.net-fpx": {
			"source": "iana",
			"extensions": ["npx"]
		},
		"image/vnd.pco.b16": {
			"source": "iana",
			"extensions": ["b16"]
		},
		"image/vnd.radiance": { "source": "iana" },
		"image/vnd.sealed.png": { "source": "iana" },
		"image/vnd.sealedmedia.softseal.gif": { "source": "iana" },
		"image/vnd.sealedmedia.softseal.jpg": { "source": "iana" },
		"image/vnd.svf": { "source": "iana" },
		"image/vnd.tencent.tap": {
			"source": "iana",
			"extensions": ["tap"]
		},
		"image/vnd.valve.source.texture": {
			"source": "iana",
			"extensions": ["vtf"]
		},
		"image/vnd.wap.wbmp": {
			"source": "iana",
			"extensions": ["wbmp"]
		},
		"image/vnd.xiff": {
			"source": "iana",
			"extensions": ["xif"]
		},
		"image/vnd.zbrush.pcx": {
			"source": "iana",
			"extensions": ["pcx"]
		},
		"image/webp": {
			"source": "iana",
			"extensions": ["webp"]
		},
		"image/wmf": {
			"source": "iana",
			"extensions": ["wmf"]
		},
		"image/x-3ds": {
			"source": "apache",
			"extensions": ["3ds"]
		},
		"image/x-adobe-dng": { "extensions": ["dng"] },
		"image/x-cmu-raster": {
			"source": "apache",
			"extensions": ["ras"]
		},
		"image/x-cmx": {
			"source": "apache",
			"extensions": ["cmx"]
		},
		"image/x-emf": { "source": "iana" },
		"image/x-freehand": {
			"source": "apache",
			"extensions": [
				"fh",
				"fhc",
				"fh4",
				"fh5",
				"fh7"
			]
		},
		"image/x-icon": {
			"source": "apache",
			"compressible": true,
			"extensions": ["ico"]
		},
		"image/x-jng": {
			"source": "nginx",
			"extensions": ["jng"]
		},
		"image/x-mrsid-image": {
			"source": "apache",
			"extensions": ["sid"]
		},
		"image/x-ms-bmp": {
			"source": "nginx",
			"compressible": true,
			"extensions": ["bmp"]
		},
		"image/x-pcx": {
			"source": "apache",
			"extensions": ["pcx"]
		},
		"image/x-pict": {
			"source": "apache",
			"extensions": ["pic", "pct"]
		},
		"image/x-portable-anymap": {
			"source": "apache",
			"extensions": ["pnm"]
		},
		"image/x-portable-bitmap": {
			"source": "apache",
			"extensions": ["pbm"]
		},
		"image/x-portable-graymap": {
			"source": "apache",
			"extensions": ["pgm"]
		},
		"image/x-portable-pixmap": {
			"source": "apache",
			"extensions": ["ppm"]
		},
		"image/x-rgb": {
			"source": "apache",
			"extensions": ["rgb"]
		},
		"image/x-tga": {
			"source": "apache",
			"extensions": ["tga"]
		},
		"image/x-wmf": { "source": "iana" },
		"image/x-xbitmap": {
			"source": "apache",
			"extensions": ["xbm"]
		},
		"image/x-xcf": { "compressible": false },
		"image/x-xpixmap": {
			"source": "apache",
			"extensions": ["xpm"]
		},
		"image/x-xwindowdump": {
			"source": "apache",
			"extensions": ["xwd"]
		},
		"message/bhttp": { "source": "iana" },
		"message/cpim": { "source": "iana" },
		"message/delivery-status": { "source": "iana" },
		"message/disposition-notification": {
			"source": "iana",
			"extensions": ["disposition-notification"]
		},
		"message/external-body": { "source": "iana" },
		"message/feedback-report": { "source": "iana" },
		"message/global": {
			"source": "iana",
			"extensions": ["u8msg"]
		},
		"message/global-delivery-status": {
			"source": "iana",
			"extensions": ["u8dsn"]
		},
		"message/global-disposition-notification": {
			"source": "iana",
			"extensions": ["u8mdn"]
		},
		"message/global-headers": {
			"source": "iana",
			"extensions": ["u8hdr"]
		},
		"message/http": {
			"source": "iana",
			"compressible": false
		},
		"message/imdn+xml": {
			"source": "iana",
			"compressible": true
		},
		"message/mls": { "source": "iana" },
		"message/news": { "source": "apache" },
		"message/ohttp-req": { "source": "iana" },
		"message/ohttp-res": { "source": "iana" },
		"message/partial": {
			"source": "iana",
			"compressible": false
		},
		"message/rfc822": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"eml",
				"mime",
				"mht",
				"mhtml"
			]
		},
		"message/s-http": { "source": "apache" },
		"message/sip": { "source": "iana" },
		"message/sipfrag": { "source": "iana" },
		"message/tracking-status": { "source": "iana" },
		"message/vnd.si.simp": { "source": "apache" },
		"message/vnd.wfa.wsc": {
			"source": "iana",
			"extensions": ["wsc"]
		},
		"model/3mf": {
			"source": "iana",
			"extensions": ["3mf"]
		},
		"model/e57": { "source": "iana" },
		"model/gltf+json": {
			"source": "iana",
			"compressible": true,
			"extensions": ["gltf"]
		},
		"model/gltf-binary": {
			"source": "iana",
			"compressible": true,
			"extensions": ["glb"]
		},
		"model/iges": {
			"source": "iana",
			"compressible": false,
			"extensions": ["igs", "iges"]
		},
		"model/jt": {
			"source": "iana",
			"extensions": ["jt"]
		},
		"model/mesh": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"msh",
				"mesh",
				"silo"
			]
		},
		"model/mtl": {
			"source": "iana",
			"extensions": ["mtl"]
		},
		"model/obj": {
			"source": "iana",
			"extensions": ["obj"]
		},
		"model/prc": {
			"source": "iana",
			"extensions": ["prc"]
		},
		"model/step": {
			"source": "iana",
			"extensions": [
				"step",
				"stp",
				"stpnc",
				"p21",
				"210"
			]
		},
		"model/step+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["stpx"]
		},
		"model/step+zip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["stpz"]
		},
		"model/step-xml+zip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["stpxz"]
		},
		"model/stl": {
			"source": "iana",
			"extensions": ["stl"]
		},
		"model/u3d": {
			"source": "iana",
			"extensions": ["u3d"]
		},
		"model/vnd.bary": {
			"source": "iana",
			"extensions": ["bary"]
		},
		"model/vnd.cld": {
			"source": "iana",
			"extensions": ["cld"]
		},
		"model/vnd.collada+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["dae"]
		},
		"model/vnd.dwf": {
			"source": "iana",
			"extensions": ["dwf"]
		},
		"model/vnd.flatland.3dml": { "source": "iana" },
		"model/vnd.gdl": {
			"source": "iana",
			"extensions": ["gdl"]
		},
		"model/vnd.gs-gdl": { "source": "apache" },
		"model/vnd.gs.gdl": { "source": "iana" },
		"model/vnd.gtw": {
			"source": "iana",
			"extensions": ["gtw"]
		},
		"model/vnd.moml+xml": {
			"source": "iana",
			"compressible": true
		},
		"model/vnd.mts": {
			"source": "iana",
			"extensions": ["mts"]
		},
		"model/vnd.opengex": {
			"source": "iana",
			"extensions": ["ogex"]
		},
		"model/vnd.parasolid.transmit.binary": {
			"source": "iana",
			"extensions": ["x_b"]
		},
		"model/vnd.parasolid.transmit.text": {
			"source": "iana",
			"extensions": ["x_t"]
		},
		"model/vnd.pytha.pyox": {
			"source": "iana",
			"extensions": ["pyo", "pyox"]
		},
		"model/vnd.rosette.annotated-data-model": { "source": "iana" },
		"model/vnd.sap.vds": {
			"source": "iana",
			"extensions": ["vds"]
		},
		"model/vnd.usda": {
			"source": "iana",
			"extensions": ["usda"]
		},
		"model/vnd.usdz+zip": {
			"source": "iana",
			"compressible": false,
			"extensions": ["usdz"]
		},
		"model/vnd.valve.source.compiled-map": {
			"source": "iana",
			"extensions": ["bsp"]
		},
		"model/vnd.vtu": {
			"source": "iana",
			"extensions": ["vtu"]
		},
		"model/vrml": {
			"source": "iana",
			"compressible": false,
			"extensions": ["wrl", "vrml"]
		},
		"model/x3d+binary": {
			"source": "apache",
			"compressible": false,
			"extensions": ["x3db", "x3dbz"]
		},
		"model/x3d+fastinfoset": {
			"source": "iana",
			"extensions": ["x3db"]
		},
		"model/x3d+vrml": {
			"source": "apache",
			"compressible": false,
			"extensions": ["x3dv", "x3dvz"]
		},
		"model/x3d+xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["x3d", "x3dz"]
		},
		"model/x3d-vrml": {
			"source": "iana",
			"extensions": ["x3dv"]
		},
		"multipart/alternative": {
			"source": "iana",
			"compressible": false
		},
		"multipart/appledouble": { "source": "iana" },
		"multipart/byteranges": { "source": "iana" },
		"multipart/digest": { "source": "iana" },
		"multipart/encrypted": {
			"source": "iana",
			"compressible": false
		},
		"multipart/form-data": {
			"source": "iana",
			"compressible": false
		},
		"multipart/header-set": { "source": "iana" },
		"multipart/mixed": { "source": "iana" },
		"multipart/multilingual": { "source": "iana" },
		"multipart/parallel": { "source": "iana" },
		"multipart/related": {
			"source": "iana",
			"compressible": false
		},
		"multipart/report": { "source": "iana" },
		"multipart/signed": {
			"source": "iana",
			"compressible": false
		},
		"multipart/vnd.bint.med-plus": { "source": "iana" },
		"multipart/voice-message": { "source": "iana" },
		"multipart/x-mixed-replace": { "source": "iana" },
		"text/1d-interleaved-parityfec": { "source": "iana" },
		"text/cache-manifest": {
			"source": "iana",
			"compressible": true,
			"extensions": ["appcache", "manifest"]
		},
		"text/calendar": {
			"source": "iana",
			"extensions": ["ics", "ifb"]
		},
		"text/calender": { "compressible": true },
		"text/cmd": { "compressible": true },
		"text/coffeescript": { "extensions": ["coffee", "litcoffee"] },
		"text/cql": { "source": "iana" },
		"text/cql-expression": { "source": "iana" },
		"text/cql-identifier": { "source": "iana" },
		"text/css": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["css"]
		},
		"text/csv": {
			"source": "iana",
			"compressible": true,
			"extensions": ["csv"]
		},
		"text/csv-schema": { "source": "iana" },
		"text/directory": { "source": "iana" },
		"text/dns": { "source": "iana" },
		"text/ecmascript": { "source": "apache" },
		"text/encaprtp": { "source": "iana" },
		"text/enriched": { "source": "iana" },
		"text/fhirpath": { "source": "iana" },
		"text/flexfec": { "source": "iana" },
		"text/fwdred": { "source": "iana" },
		"text/gff3": { "source": "iana" },
		"text/grammar-ref-list": { "source": "iana" },
		"text/hl7v2": { "source": "iana" },
		"text/html": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"html",
				"htm",
				"shtml"
			]
		},
		"text/jade": { "extensions": ["jade"] },
		"text/javascript": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["js", "mjs"]
		},
		"text/jcr-cnd": { "source": "iana" },
		"text/jsx": {
			"compressible": true,
			"extensions": ["jsx"]
		},
		"text/less": {
			"compressible": true,
			"extensions": ["less"]
		},
		"text/markdown": {
			"source": "iana",
			"compressible": true,
			"extensions": ["md", "markdown"]
		},
		"text/mathml": {
			"source": "nginx",
			"extensions": ["mml"]
		},
		"text/mdx": {
			"compressible": true,
			"extensions": ["mdx"]
		},
		"text/mizar": { "source": "iana" },
		"text/n3": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["n3"]
		},
		"text/parameters": {
			"source": "iana",
			"charset": "UTF-8"
		},
		"text/parityfec": { "source": "iana" },
		"text/plain": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"txt",
				"text",
				"conf",
				"def",
				"list",
				"log",
				"in",
				"ini"
			]
		},
		"text/provenance-notation": {
			"source": "iana",
			"charset": "UTF-8"
		},
		"text/prs.fallenstein.rst": { "source": "iana" },
		"text/prs.lines.tag": {
			"source": "iana",
			"extensions": ["dsc"]
		},
		"text/prs.prop.logic": { "source": "iana" },
		"text/prs.texi": { "source": "iana" },
		"text/raptorfec": { "source": "iana" },
		"text/red": { "source": "iana" },
		"text/rfc822-headers": { "source": "iana" },
		"text/richtext": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rtx"]
		},
		"text/rtf": {
			"source": "iana",
			"compressible": true,
			"extensions": ["rtf"]
		},
		"text/rtp-enc-aescm128": { "source": "iana" },
		"text/rtploopback": { "source": "iana" },
		"text/rtx": { "source": "iana" },
		"text/sgml": {
			"source": "iana",
			"extensions": ["sgml", "sgm"]
		},
		"text/shaclc": { "source": "iana" },
		"text/shex": {
			"source": "iana",
			"extensions": ["shex"]
		},
		"text/slim": { "extensions": ["slim", "slm"] },
		"text/spdx": {
			"source": "iana",
			"extensions": ["spdx"]
		},
		"text/strings": { "source": "iana" },
		"text/stylus": { "extensions": ["stylus", "styl"] },
		"text/t140": { "source": "iana" },
		"text/tab-separated-values": {
			"source": "iana",
			"compressible": true,
			"extensions": ["tsv"]
		},
		"text/troff": {
			"source": "iana",
			"extensions": [
				"t",
				"tr",
				"roff",
				"man",
				"me",
				"ms"
			]
		},
		"text/turtle": {
			"source": "iana",
			"charset": "UTF-8",
			"extensions": ["ttl"]
		},
		"text/ulpfec": { "source": "iana" },
		"text/uri-list": {
			"source": "iana",
			"compressible": true,
			"extensions": [
				"uri",
				"uris",
				"urls"
			]
		},
		"text/vcard": {
			"source": "iana",
			"compressible": true,
			"extensions": ["vcard"]
		},
		"text/vnd.a": { "source": "iana" },
		"text/vnd.abc": { "source": "iana" },
		"text/vnd.ascii-art": { "source": "iana" },
		"text/vnd.curl": {
			"source": "iana",
			"extensions": ["curl"]
		},
		"text/vnd.curl.dcurl": {
			"source": "apache",
			"extensions": ["dcurl"]
		},
		"text/vnd.curl.mcurl": {
			"source": "apache",
			"extensions": ["mcurl"]
		},
		"text/vnd.curl.scurl": {
			"source": "apache",
			"extensions": ["scurl"]
		},
		"text/vnd.debian.copyright": {
			"source": "iana",
			"charset": "UTF-8"
		},
		"text/vnd.dmclientscript": { "source": "iana" },
		"text/vnd.dvb.subtitle": {
			"source": "iana",
			"extensions": ["sub"]
		},
		"text/vnd.esmertec.theme-descriptor": {
			"source": "iana",
			"charset": "UTF-8"
		},
		"text/vnd.exchangeable": { "source": "iana" },
		"text/vnd.familysearch.gedcom": {
			"source": "iana",
			"extensions": ["ged"]
		},
		"text/vnd.ficlab.flt": { "source": "iana" },
		"text/vnd.fly": {
			"source": "iana",
			"extensions": ["fly"]
		},
		"text/vnd.fmi.flexstor": {
			"source": "iana",
			"extensions": ["flx"]
		},
		"text/vnd.gml": { "source": "iana" },
		"text/vnd.graphviz": {
			"source": "iana",
			"extensions": ["gv"]
		},
		"text/vnd.hans": { "source": "iana" },
		"text/vnd.hgl": { "source": "iana" },
		"text/vnd.in3d.3dml": {
			"source": "iana",
			"extensions": ["3dml"]
		},
		"text/vnd.in3d.spot": {
			"source": "iana",
			"extensions": ["spot"]
		},
		"text/vnd.iptc.newsml": { "source": "iana" },
		"text/vnd.iptc.nitf": { "source": "iana" },
		"text/vnd.latex-z": { "source": "iana" },
		"text/vnd.motorola.reflex": { "source": "iana" },
		"text/vnd.ms-mediapackage": { "source": "iana" },
		"text/vnd.net2phone.commcenter.command": { "source": "iana" },
		"text/vnd.radisys.msml-basic-layout": { "source": "iana" },
		"text/vnd.senx.warpscript": { "source": "iana" },
		"text/vnd.si.uricatalogue": { "source": "apache" },
		"text/vnd.sosi": { "source": "iana" },
		"text/vnd.sun.j2me.app-descriptor": {
			"source": "iana",
			"charset": "UTF-8",
			"extensions": ["jad"]
		},
		"text/vnd.trolltech.linguist": {
			"source": "iana",
			"charset": "UTF-8"
		},
		"text/vnd.vcf": { "source": "iana" },
		"text/vnd.wap.si": { "source": "iana" },
		"text/vnd.wap.sl": { "source": "iana" },
		"text/vnd.wap.wml": {
			"source": "iana",
			"extensions": ["wml"]
		},
		"text/vnd.wap.wmlscript": {
			"source": "iana",
			"extensions": ["wmls"]
		},
		"text/vnd.zoo.kcl": { "source": "iana" },
		"text/vtt": {
			"source": "iana",
			"charset": "UTF-8",
			"compressible": true,
			"extensions": ["vtt"]
		},
		"text/wgsl": {
			"source": "iana",
			"extensions": ["wgsl"]
		},
		"text/x-asm": {
			"source": "apache",
			"extensions": ["s", "asm"]
		},
		"text/x-c": {
			"source": "apache",
			"extensions": [
				"c",
				"cc",
				"cxx",
				"cpp",
				"h",
				"hh",
				"dic"
			]
		},
		"text/x-component": {
			"source": "nginx",
			"extensions": ["htc"]
		},
		"text/x-fortran": {
			"source": "apache",
			"extensions": [
				"f",
				"for",
				"f77",
				"f90"
			]
		},
		"text/x-gwt-rpc": { "compressible": true },
		"text/x-handlebars-template": { "extensions": ["hbs"] },
		"text/x-java-source": {
			"source": "apache",
			"extensions": ["java"]
		},
		"text/x-jquery-tmpl": { "compressible": true },
		"text/x-lua": { "extensions": ["lua"] },
		"text/x-markdown": {
			"compressible": true,
			"extensions": ["mkd"]
		},
		"text/x-nfo": {
			"source": "apache",
			"extensions": ["nfo"]
		},
		"text/x-opml": {
			"source": "apache",
			"extensions": ["opml"]
		},
		"text/x-org": {
			"compressible": true,
			"extensions": ["org"]
		},
		"text/x-pascal": {
			"source": "apache",
			"extensions": ["p", "pas"]
		},
		"text/x-processing": {
			"compressible": true,
			"extensions": ["pde"]
		},
		"text/x-sass": { "extensions": ["sass"] },
		"text/x-scss": { "extensions": ["scss"] },
		"text/x-setext": {
			"source": "apache",
			"extensions": ["etx"]
		},
		"text/x-sfv": {
			"source": "apache",
			"extensions": ["sfv"]
		},
		"text/x-suse-ymp": {
			"compressible": true,
			"extensions": ["ymp"]
		},
		"text/x-uuencode": {
			"source": "apache",
			"extensions": ["uu"]
		},
		"text/x-vcalendar": {
			"source": "apache",
			"extensions": ["vcs"]
		},
		"text/x-vcard": {
			"source": "apache",
			"extensions": ["vcf"]
		},
		"text/xml": {
			"source": "iana",
			"compressible": true,
			"extensions": ["xml"]
		},
		"text/xml-external-parsed-entity": { "source": "iana" },
		"text/yaml": {
			"compressible": true,
			"extensions": ["yaml", "yml"]
		},
		"video/1d-interleaved-parityfec": { "source": "iana" },
		"video/3gpp": {
			"source": "iana",
			"extensions": ["3gp", "3gpp"]
		},
		"video/3gpp-tt": { "source": "iana" },
		"video/3gpp2": {
			"source": "iana",
			"extensions": ["3g2"]
		},
		"video/av1": { "source": "iana" },
		"video/bmpeg": { "source": "iana" },
		"video/bt656": { "source": "iana" },
		"video/celb": { "source": "iana" },
		"video/dv": { "source": "iana" },
		"video/encaprtp": { "source": "iana" },
		"video/evc": { "source": "iana" },
		"video/ffv1": { "source": "iana" },
		"video/flexfec": { "source": "iana" },
		"video/h261": {
			"source": "iana",
			"extensions": ["h261"]
		},
		"video/h263": {
			"source": "iana",
			"extensions": ["h263"]
		},
		"video/h263-1998": { "source": "iana" },
		"video/h263-2000": { "source": "iana" },
		"video/h264": {
			"source": "iana",
			"extensions": ["h264"]
		},
		"video/h264-rcdo": { "source": "iana" },
		"video/h264-svc": { "source": "iana" },
		"video/h265": { "source": "iana" },
		"video/h266": { "source": "iana" },
		"video/iso.segment": {
			"source": "iana",
			"extensions": ["m4s"]
		},
		"video/jpeg": {
			"source": "iana",
			"extensions": ["jpgv"]
		},
		"video/jpeg2000": { "source": "iana" },
		"video/jpm": {
			"source": "apache",
			"extensions": ["jpm", "jpgm"]
		},
		"video/jxsv": { "source": "iana" },
		"video/lottie+json": {
			"source": "iana",
			"compressible": true
		},
		"video/matroska": { "source": "iana" },
		"video/matroska-3d": { "source": "iana" },
		"video/mj2": {
			"source": "iana",
			"extensions": ["mj2", "mjp2"]
		},
		"video/mp1s": { "source": "iana" },
		"video/mp2p": { "source": "iana" },
		"video/mp2t": {
			"source": "iana",
			"extensions": [
				"ts",
				"m2t",
				"m2ts",
				"mts"
			]
		},
		"video/mp4": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"mp4",
				"mp4v",
				"mpg4"
			]
		},
		"video/mp4v-es": { "source": "iana" },
		"video/mpeg": {
			"source": "iana",
			"compressible": false,
			"extensions": [
				"mpeg",
				"mpg",
				"mpe",
				"m1v",
				"m2v"
			]
		},
		"video/mpeg4-generic": { "source": "iana" },
		"video/mpv": { "source": "iana" },
		"video/nv": { "source": "iana" },
		"video/ogg": {
			"source": "iana",
			"compressible": false,
			"extensions": ["ogv"]
		},
		"video/parityfec": { "source": "iana" },
		"video/pointer": { "source": "iana" },
		"video/quicktime": {
			"source": "iana",
			"compressible": false,
			"extensions": ["qt", "mov"]
		},
		"video/raptorfec": { "source": "iana" },
		"video/raw": { "source": "iana" },
		"video/rtp-enc-aescm128": { "source": "iana" },
		"video/rtploopback": { "source": "iana" },
		"video/rtx": { "source": "iana" },
		"video/scip": { "source": "iana" },
		"video/smpte291": { "source": "iana" },
		"video/smpte292m": { "source": "iana" },
		"video/ulpfec": { "source": "iana" },
		"video/vc1": { "source": "iana" },
		"video/vc2": { "source": "iana" },
		"video/vnd.cctv": { "source": "iana" },
		"video/vnd.dece.hd": {
			"source": "iana",
			"extensions": ["uvh", "uvvh"]
		},
		"video/vnd.dece.mobile": {
			"source": "iana",
			"extensions": ["uvm", "uvvm"]
		},
		"video/vnd.dece.mp4": { "source": "iana" },
		"video/vnd.dece.pd": {
			"source": "iana",
			"extensions": ["uvp", "uvvp"]
		},
		"video/vnd.dece.sd": {
			"source": "iana",
			"extensions": ["uvs", "uvvs"]
		},
		"video/vnd.dece.video": {
			"source": "iana",
			"extensions": ["uvv", "uvvv"]
		},
		"video/vnd.directv.mpeg": { "source": "iana" },
		"video/vnd.directv.mpeg-tts": { "source": "iana" },
		"video/vnd.dlna.mpeg-tts": { "source": "iana" },
		"video/vnd.dvb.file": {
			"source": "iana",
			"extensions": ["dvb"]
		},
		"video/vnd.fvt": {
			"source": "iana",
			"extensions": ["fvt"]
		},
		"video/vnd.hns.video": { "source": "iana" },
		"video/vnd.iptvforum.1dparityfec-1010": { "source": "iana" },
		"video/vnd.iptvforum.1dparityfec-2005": { "source": "iana" },
		"video/vnd.iptvforum.2dparityfec-1010": { "source": "iana" },
		"video/vnd.iptvforum.2dparityfec-2005": { "source": "iana" },
		"video/vnd.iptvforum.ttsavc": { "source": "iana" },
		"video/vnd.iptvforum.ttsmpeg2": { "source": "iana" },
		"video/vnd.motorola.video": { "source": "iana" },
		"video/vnd.motorola.videop": { "source": "iana" },
		"video/vnd.mpegurl": {
			"source": "iana",
			"extensions": ["mxu", "m4u"]
		},
		"video/vnd.ms-playready.media.pyv": {
			"source": "iana",
			"extensions": ["pyv"]
		},
		"video/vnd.nokia.interleaved-multimedia": { "source": "iana" },
		"video/vnd.nokia.mp4vr": { "source": "iana" },
		"video/vnd.nokia.videovoip": { "source": "iana" },
		"video/vnd.objectvideo": { "source": "iana" },
		"video/vnd.planar": { "source": "iana" },
		"video/vnd.radgamettools.bink": { "source": "iana" },
		"video/vnd.radgamettools.smacker": { "source": "apache" },
		"video/vnd.sealed.mpeg1": { "source": "iana" },
		"video/vnd.sealed.mpeg4": { "source": "iana" },
		"video/vnd.sealed.swf": { "source": "iana" },
		"video/vnd.sealedmedia.softseal.mov": { "source": "iana" },
		"video/vnd.uvvu.mp4": {
			"source": "iana",
			"extensions": ["uvu", "uvvu"]
		},
		"video/vnd.vivo": {
			"source": "iana",
			"extensions": ["viv"]
		},
		"video/vnd.youtube.yt": { "source": "iana" },
		"video/vp8": { "source": "iana" },
		"video/vp9": { "source": "iana" },
		"video/webm": {
			"source": "apache",
			"compressible": false,
			"extensions": ["webm"]
		},
		"video/x-f4v": {
			"source": "apache",
			"extensions": ["f4v"]
		},
		"video/x-fli": {
			"source": "apache",
			"extensions": ["fli"]
		},
		"video/x-flv": {
			"source": "apache",
			"compressible": false,
			"extensions": ["flv"]
		},
		"video/x-m4v": {
			"source": "apache",
			"extensions": ["m4v"]
		},
		"video/x-matroska": {
			"source": "apache",
			"compressible": false,
			"extensions": [
				"mkv",
				"mk3d",
				"mks"
			]
		},
		"video/x-mng": {
			"source": "apache",
			"extensions": ["mng"]
		},
		"video/x-ms-asf": {
			"source": "apache",
			"extensions": ["asf", "asx"]
		},
		"video/x-ms-vob": {
			"source": "apache",
			"extensions": ["vob"]
		},
		"video/x-ms-wm": {
			"source": "apache",
			"extensions": ["wm"]
		},
		"video/x-ms-wmv": {
			"source": "apache",
			"compressible": false,
			"extensions": ["wmv"]
		},
		"video/x-ms-wmx": {
			"source": "apache",
			"extensions": ["wmx"]
		},
		"video/x-ms-wvx": {
			"source": "apache",
			"extensions": ["wvx"]
		},
		"video/x-msvideo": {
			"source": "apache",
			"extensions": ["avi"]
		},
		"video/x-sgi-movie": {
			"source": "apache",
			"extensions": ["movie"]
		},
		"video/x-smv": {
			"source": "apache",
			"extensions": ["smv"]
		},
		"x-conference/x-cooltalk": {
			"source": "apache",
			"extensions": ["ice"]
		},
		"x-shader/x-fragment": { "compressible": true },
		"x-shader/x-vertex": { "compressible": true }
	};
}));
//#endregion
//#region ../../node_modules/.pnpm/mime-db@1.54.0/node_modules/mime-db/index.js
var require_mime_db = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/*!
	* mime-db
	* Copyright(c) 2014 Jonathan Ong
	* Copyright(c) 2015-2022 Douglas Christopher Wilson
	* MIT Licensed
	*/
	/**
	* Module exports.
	*/
	module.exports = require_db();
}));
//#endregion
//#region ../../node_modules/.pnpm/compressible@2.0.18/node_modules/compressible/index.js
/*!
* compressible
* Copyright(c) 2013 Jonathan Ong
* Copyright(c) 2014 Jeremiah Senkpiel
* Copyright(c) 2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_compressible = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module dependencies.
	* @private
	*/
	var db = require_mime_db();
	/**
	* Module variables.
	* @private
	*/
	var COMPRESSIBLE_TYPE_REGEXP = /^text\/|\+(?:json|text|xml)$/i;
	var EXTRACT_TYPE_REGEXP = /^\s*([^;\s]*)(?:;|\s|$)/;
	/**
	* Module exports.
	* @public
	*/
	module.exports = compressible;
	/**
	* Checks if a type is compressible.
	*
	* @param {string} type
	* @return {Boolean} compressible
	* @public
	*/
	function compressible(type) {
		if (!type || typeof type !== "string") return false;
		var match = EXTRACT_TYPE_REGEXP.exec(type);
		var mime = match && match[1].toLowerCase();
		var data = db[mime];
		if (data && data.compressible !== void 0) return data.compressible;
		return COMPRESSIBLE_TYPE_REGEXP.test(mime) || void 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/ms@2.0.0/node_modules/ms/index.js
var require_ms = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Helpers.
	*/
	var s = 1e3;
	var m = s * 60;
	var h = m * 60;
	var d = h * 24;
	var y = d * 365.25;
	/**
	* Parse or format the given `val`.
	*
	* Options:
	*
	*  - `long` verbose formatting [false]
	*
	* @param {String|Number} val
	* @param {Object} [options]
	* @throws {Error} throw an error if val is not a non-empty string or a number
	* @return {String|Number}
	* @api public
	*/
	module.exports = function(val, options) {
		options = options || {};
		var type = typeof val;
		if (type === "string" && val.length > 0) return parse(val);
		else if (type === "number" && isNaN(val) === false) return options.long ? fmtLong(val) : fmtShort(val);
		throw new Error("val is not a non-empty string or a valid number. val=" + JSON.stringify(val));
	};
	/**
	* Parse the given `str` and return milliseconds.
	*
	* @param {String} str
	* @return {Number}
	* @api private
	*/
	function parse(str) {
		str = String(str);
		if (str.length > 100) return;
		var match = /^((?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|years?|yrs?|y)?$/i.exec(str);
		if (!match) return;
		var n = parseFloat(match[1]);
		switch ((match[2] || "ms").toLowerCase()) {
			case "years":
			case "year":
			case "yrs":
			case "yr":
			case "y": return n * y;
			case "days":
			case "day":
			case "d": return n * d;
			case "hours":
			case "hour":
			case "hrs":
			case "hr":
			case "h": return n * h;
			case "minutes":
			case "minute":
			case "mins":
			case "min":
			case "m": return n * m;
			case "seconds":
			case "second":
			case "secs":
			case "sec":
			case "s": return n * s;
			case "milliseconds":
			case "millisecond":
			case "msecs":
			case "msec":
			case "ms": return n;
			default: return;
		}
	}
	/**
	* Short format for `ms`.
	*
	* @param {Number} ms
	* @return {String}
	* @api private
	*/
	function fmtShort(ms) {
		if (ms >= d) return Math.round(ms / d) + "d";
		if (ms >= h) return Math.round(ms / h) + "h";
		if (ms >= m) return Math.round(ms / m) + "m";
		if (ms >= s) return Math.round(ms / s) + "s";
		return ms + "ms";
	}
	/**
	* Long format for `ms`.
	*
	* @param {Number} ms
	* @return {String}
	* @api private
	*/
	function fmtLong(ms) {
		return plural(ms, d, "day") || plural(ms, h, "hour") || plural(ms, m, "minute") || plural(ms, s, "second") || ms + " ms";
	}
	/**
	* Pluralization helper.
	*/
	function plural(ms, n, name) {
		if (ms < n) return;
		if (ms < n * 1.5) return Math.floor(ms / n) + " " + name;
		return Math.ceil(ms / n) + " " + name + "s";
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/debug@2.6.9_supports-color@7.2.0/node_modules/debug/src/debug.js
var require_debug = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* This is the common logic for both the Node.js and web browser
	* implementations of `debug()`.
	*
	* Expose `debug()` as the module.
	*/
	exports = module.exports = createDebug.debug = createDebug["default"] = createDebug;
	exports.coerce = coerce;
	exports.disable = disable;
	exports.enable = enable;
	exports.enabled = enabled;
	exports.humanize = require_ms();
	/**
	* The currently active debug mode names, and names to skip.
	*/
	exports.names = [];
	exports.skips = [];
	/**
	* Map of special "%n" handling functions, for the debug "format" argument.
	*
	* Valid key names are a single, lower or upper-case letter, i.e. "n" and "N".
	*/
	exports.formatters = {};
	/**
	* Previous log timestamp.
	*/
	var prevTime;
	/**
	* Select a color.
	* @param {String} namespace
	* @return {Number}
	* @api private
	*/
	function selectColor(namespace) {
		var hash = 0, i;
		for (i in namespace) {
			hash = (hash << 5) - hash + namespace.charCodeAt(i);
			hash |= 0;
		}
		return exports.colors[Math.abs(hash) % exports.colors.length];
	}
	/**
	* Create a debugger with the given `namespace`.
	*
	* @param {String} namespace
	* @return {Function}
	* @api public
	*/
	function createDebug(namespace) {
		function debug() {
			if (!debug.enabled) return;
			var self = debug;
			var curr = +/* @__PURE__ */ new Date();
			self.diff = curr - (prevTime || curr);
			self.prev = prevTime;
			self.curr = curr;
			prevTime = curr;
			var args = new Array(arguments.length);
			for (var i = 0; i < args.length; i++) args[i] = arguments[i];
			args[0] = exports.coerce(args[0]);
			if ("string" !== typeof args[0]) args.unshift("%O");
			var index = 0;
			args[0] = args[0].replace(/%([a-zA-Z%])/g, function(match, format) {
				if (match === "%%") return match;
				index++;
				var formatter = exports.formatters[format];
				if ("function" === typeof formatter) {
					var val = args[index];
					match = formatter.call(self, val);
					args.splice(index, 1);
					index--;
				}
				return match;
			});
			exports.formatArgs.call(self, args);
			(debug.log || exports.log || console.log.bind(console)).apply(self, args);
		}
		debug.namespace = namespace;
		debug.enabled = exports.enabled(namespace);
		debug.useColors = exports.useColors();
		debug.color = selectColor(namespace);
		if ("function" === typeof exports.init) exports.init(debug);
		return debug;
	}
	/**
	* Enables a debug mode by namespaces. This can include modes
	* separated by a colon and wildcards.
	*
	* @param {String} namespaces
	* @api public
	*/
	function enable(namespaces) {
		exports.save(namespaces);
		exports.names = [];
		exports.skips = [];
		var split = (typeof namespaces === "string" ? namespaces : "").split(/[\s,]+/);
		var len = split.length;
		for (var i = 0; i < len; i++) {
			if (!split[i]) continue;
			namespaces = split[i].replace(/\*/g, ".*?");
			if (namespaces[0] === "-") exports.skips.push(new RegExp("^" + namespaces.substr(1) + "$"));
			else exports.names.push(new RegExp("^" + namespaces + "$"));
		}
	}
	/**
	* Disable debug output.
	*
	* @api public
	*/
	function disable() {
		exports.enable("");
	}
	/**
	* Returns true if the given mode name is enabled, false otherwise.
	*
	* @param {String} name
	* @return {Boolean}
	* @api public
	*/
	function enabled(name) {
		var i, len;
		for (i = 0, len = exports.skips.length; i < len; i++) if (exports.skips[i].test(name)) return false;
		for (i = 0, len = exports.names.length; i < len; i++) if (exports.names[i].test(name)) return true;
		return false;
	}
	/**
	* Coerce `val`.
	*
	* @param {Mixed} val
	* @return {Mixed}
	* @api private
	*/
	function coerce(val) {
		if (val instanceof Error) return val.stack || val.message;
		return val;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/debug@2.6.9_supports-color@7.2.0/node_modules/debug/src/browser.js
var require_browser = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* This is the web browser implementation of `debug()`.
	*
	* Expose `debug()` as the module.
	*/
	exports = module.exports = require_debug();
	exports.log = log;
	exports.formatArgs = formatArgs;
	exports.save = save;
	exports.load = load;
	exports.useColors = useColors;
	exports.storage = "undefined" != typeof chrome && "undefined" != typeof chrome.storage ? chrome.storage.local : localstorage();
	/**
	* Colors.
	*/
	exports.colors = [
		"lightseagreen",
		"forestgreen",
		"goldenrod",
		"dodgerblue",
		"darkorchid",
		"crimson"
	];
	/**
	* Currently only WebKit-based Web Inspectors, Firefox >= v31,
	* and the Firebug extension (any Firefox version) are known
	* to support "%c" CSS customizations.
	*
	* TODO: add a `localStorage` variable to explicitly enable/disable colors
	*/
	function useColors() {
		if (typeof window !== "undefined" && window.process && window.process.type === "renderer") return true;
		return typeof document !== "undefined" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || typeof window !== "undefined" && window.console && (window.console.firebug || window.console.exception && window.console.table) || typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/) && parseInt(RegExp.$1, 10) >= 31 || typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
	}
	/**
	* Map %j to `JSON.stringify()`, since no Web Inspectors do that by default.
	*/
	exports.formatters.j = function(v) {
		try {
			return JSON.stringify(v);
		} catch (err) {
			return "[UnexpectedJSONParseError]: " + err.message;
		}
	};
	/**
	* Colorize log arguments if enabled.
	*
	* @api public
	*/
	function formatArgs(args) {
		var useColors = this.useColors;
		args[0] = (useColors ? "%c" : "") + this.namespace + (useColors ? " %c" : " ") + args[0] + (useColors ? "%c " : " ") + "+" + exports.humanize(this.diff);
		if (!useColors) return;
		var c = "color: " + this.color;
		args.splice(1, 0, c, "color: inherit");
		var index = 0;
		var lastC = 0;
		args[0].replace(/%[a-zA-Z%]/g, function(match) {
			if ("%%" === match) return;
			index++;
			if ("%c" === match) lastC = index;
		});
		args.splice(lastC, 0, c);
	}
	/**
	* Invokes `console.log()` when available.
	* No-op when `console.log` is not a "function".
	*
	* @api public
	*/
	function log() {
		return "object" === typeof console && console.log && Function.prototype.apply.call(console.log, console, arguments);
	}
	/**
	* Save `namespaces`.
	*
	* @param {String} namespaces
	* @api private
	*/
	function save(namespaces) {
		try {
			if (null == namespaces) exports.storage.removeItem("debug");
			else exports.storage.debug = namespaces;
		} catch (e) {}
	}
	/**
	* Load `namespaces`.
	*
	* @return {String} returns the previously persisted debug modes
	* @api private
	*/
	function load() {
		var r;
		try {
			r = exports.storage.debug;
		} catch (e) {}
		if (!r && typeof process !== "undefined" && "env" in process) r = process.env.DEBUG;
		return r;
	}
	/**
	* Enable namespaces listed in `localStorage.debug` initially.
	*/
	exports.enable(load());
	/**
	* Localstorage attempts to return the localstorage.
	*
	* This is necessary because safari throws
	* when a user disables cookies/localstorage
	* and you attempt to access it.
	*
	* @return {LocalStorage}
	* @api private
	*/
	function localstorage() {
		try {
			return window.localStorage;
		} catch (e) {}
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/debug@2.6.9_supports-color@7.2.0/node_modules/debug/src/node.js
var require_node = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module dependencies.
	*/
	var tty = __require("tty");
	var util = __require("util");
	/**
	* This is the Node.js implementation of `debug()`.
	*
	* Expose `debug()` as the module.
	*/
	exports = module.exports = require_debug();
	exports.init = init;
	exports.log = log;
	exports.formatArgs = formatArgs;
	exports.save = save;
	exports.load = load;
	exports.useColors = useColors;
	/**
	* Colors.
	*/
	exports.colors = [
		6,
		2,
		3,
		4,
		5,
		1
	];
	/**
	* Build up the default `inspectOpts` object from the environment variables.
	*
	*   $ DEBUG_COLORS=no DEBUG_DEPTH=10 DEBUG_SHOW_HIDDEN=enabled node script.js
	*/
	exports.inspectOpts = Object.keys(process.env).filter(function(key) {
		return /^debug_/i.test(key);
	}).reduce(function(obj, key) {
		var prop = key.substring(6).toLowerCase().replace(/_([a-z])/g, function(_, k) {
			return k.toUpperCase();
		});
		var val = process.env[key];
		if (/^(yes|on|true|enabled)$/i.test(val)) val = true;
		else if (/^(no|off|false|disabled)$/i.test(val)) val = false;
		else if (val === "null") val = null;
		else val = Number(val);
		obj[prop] = val;
		return obj;
	}, {});
	/**
	* The file descriptor to write the `debug()` calls to.
	* Set the `DEBUG_FD` env variable to override with another value. i.e.:
	*
	*   $ DEBUG_FD=3 node script.js 3>debug.log
	*/
	var fd = parseInt(process.env.DEBUG_FD, 10) || 2;
	if (1 !== fd && 2 !== fd) util.deprecate(function() {}, "except for stderr(2) and stdout(1), any other usage of DEBUG_FD is deprecated. Override debug.log if you want to use a different log function (https://git.io/debug_fd)")();
	var stream = 1 === fd ? process.stdout : 2 === fd ? process.stderr : createWritableStdioStream(fd);
	/**
	* Is stdout a TTY? Colored output is enabled when `true`.
	*/
	function useColors() {
		return "colors" in exports.inspectOpts ? Boolean(exports.inspectOpts.colors) : tty.isatty(fd);
	}
	/**
	* Map %o to `util.inspect()`, all on a single line.
	*/
	exports.formatters.o = function(v) {
		this.inspectOpts.colors = this.useColors;
		return util.inspect(v, this.inspectOpts).split("\n").map(function(str) {
			return str.trim();
		}).join(" ");
	};
	/**
	* Map %o to `util.inspect()`, allowing multiple lines if needed.
	*/
	exports.formatters.O = function(v) {
		this.inspectOpts.colors = this.useColors;
		return util.inspect(v, this.inspectOpts);
	};
	/**
	* Adds ANSI color escape codes if enabled.
	*
	* @api public
	*/
	function formatArgs(args) {
		var name = this.namespace;
		if (this.useColors) {
			var c = this.color;
			var prefix = "  \x1B[3" + c + ";1m" + name + " \x1B[0m";
			args[0] = prefix + args[0].split("\n").join("\n" + prefix);
			args.push("\x1B[3" + c + "m+" + exports.humanize(this.diff) + "\x1B[0m");
		} else args[0] = (/* @__PURE__ */ new Date()).toUTCString() + " " + name + " " + args[0];
	}
	/**
	* Invokes `util.format()` with the specified arguments and writes to `stream`.
	*/
	function log() {
		return stream.write(util.format.apply(util, arguments) + "\n");
	}
	/**
	* Save `namespaces`.
	*
	* @param {String} namespaces
	* @api private
	*/
	function save(namespaces) {
		if (null == namespaces) delete process.env.DEBUG;
		else process.env.DEBUG = namespaces;
	}
	/**
	* Load `namespaces`.
	*
	* @return {String} returns the previously persisted debug modes
	* @api private
	*/
	function load() {
		return process.env.DEBUG;
	}
	/**
	* Copied from `node/src/node.js`.
	*
	* XXX: It's lame that node doesn't expose this API out-of-the-box. It also
	* relies on the undocumented `tty_wrap.guessHandleType()` which is also lame.
	*/
	function createWritableStdioStream(fd) {
		var stream;
		switch (process.binding("tty_wrap").guessHandleType(fd)) {
			case "TTY":
				stream = new tty.WriteStream(fd);
				stream._type = "tty";
				if (stream._handle && stream._handle.unref) stream._handle.unref();
				break;
			case "FILE":
				stream = new (__require("fs")).SyncWriteStream(fd, { autoClose: false });
				stream._type = "fs";
				break;
			case "PIPE":
			case "TCP":
				stream = new (__require("net")).Socket({
					fd,
					readable: false,
					writable: true
				});
				stream.readable = false;
				stream.read = null;
				stream._type = "pipe";
				if (stream._handle && stream._handle.unref) stream._handle.unref();
				break;
			default: throw new Error("Implement me. Unknown stream file type!");
		}
		stream.fd = fd;
		stream._isStdio = true;
		return stream;
	}
	/**
	* Init logic for `debug` instances.
	*
	* Create a new `inspectOpts` object in case `useColors` is set
	* differently for a particular `debug` instance.
	*/
	function init(debug) {
		debug.inspectOpts = {};
		var keys = Object.keys(exports.inspectOpts);
		for (var i = 0; i < keys.length; i++) debug.inspectOpts[keys[i]] = exports.inspectOpts[keys[i]];
	}
	/**
	* Enable namespaces listed in `process.env.DEBUG` initially.
	*/
	exports.enable(load());
}));
//#endregion
//#region ../../node_modules/.pnpm/debug@2.6.9_supports-color@7.2.0/node_modules/debug/src/index.js
var require_src = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Detect Electron renderer process, which is node, but we should
	* treat as a browser.
	*/
	if (typeof process !== "undefined" && process.type === "renderer") module.exports = require_browser();
	else module.exports = require_node();
}));
//#endregion
//#region ../../node_modules/.pnpm/destroy@1.2.0/node_modules/destroy/index.js
/*!
* destroy
* Copyright(c) 2014 Jonathan Ong
* Copyright(c) 2015-2022 Douglas Christopher Wilson
* MIT Licensed
*/
var require_destroy = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module dependencies.
	* @private
	*/
	var EventEmitter$1 = __require("events").EventEmitter;
	var ReadStream = __require("fs").ReadStream;
	var Stream = __require("stream");
	var Zlib = __require("zlib");
	/**
	* Module exports.
	* @public
	*/
	module.exports = destroy;
	/**
	* Destroy the given stream, and optionally suppress any future `error` events.
	*
	* @param {object} stream
	* @param {boolean} suppress
	* @public
	*/
	function destroy(stream, suppress) {
		if (isFsReadStream(stream)) destroyReadStream(stream);
		else if (isZlibStream(stream)) destroyZlibStream(stream);
		else if (hasDestroy(stream)) stream.destroy();
		if (isEventEmitter(stream) && suppress) {
			stream.removeAllListeners("error");
			stream.addListener("error", noop);
		}
		return stream;
	}
	/**
	* Destroy a ReadStream.
	*
	* @param {object} stream
	* @private
	*/
	function destroyReadStream(stream) {
		stream.destroy();
		if (typeof stream.close === "function") stream.on("open", onOpenClose);
	}
	/**
	* Close a Zlib stream.
	*
	* Zlib streams below Node.js 4.5.5 have a buggy implementation
	* of .close() when zlib encountered an error.
	*
	* @param {object} stream
	* @private
	*/
	function closeZlibStream(stream) {
		if (stream._hadError === true) {
			var prop = stream._binding === null ? "_binding" : "_handle";
			stream[prop] = { close: function() {
				this[prop] = null;
			} };
		}
		stream.close();
	}
	/**
	* Destroy a Zlib stream.
	*
	* Zlib streams don't have a destroy function in Node.js 6. On top of that
	* simply calling destroy on a zlib stream in Node.js 8+ will result in a
	* memory leak. So until that is fixed, we need to call both close AND destroy.
	*
	* PR to fix memory leak: https://github.com/nodejs/node/pull/23734
	*
	* In Node.js 6+8, it's important that destroy is called before close as the
	* stream would otherwise emit the error 'zlib binding closed'.
	*
	* @param {object} stream
	* @private
	*/
	function destroyZlibStream(stream) {
		if (typeof stream.destroy === "function")
 // istanbul ignore if: node.js 0.8
		if (stream._binding) {
			stream.destroy();
			if (stream._processing) {
				stream._needDrain = true;
				stream.once("drain", onDrainClearBinding);
			} else stream._binding.clear();
		} else if (stream._destroy && stream._destroy !== Stream.Transform.prototype._destroy) stream.destroy();
		else if (stream._destroy && typeof stream.close === "function") {
			stream.destroyed = true;
			stream.close();
		} else
 // istanbul ignore next
		stream.destroy();
		else if (typeof stream.close === "function") closeZlibStream(stream);
	}
	/**
	* Determine if stream has destroy.
	* @private
	*/
	function hasDestroy(stream) {
		return stream instanceof Stream && typeof stream.destroy === "function";
	}
	/**
	* Determine if val is EventEmitter.
	* @private
	*/
	function isEventEmitter(val) {
		return val instanceof EventEmitter$1;
	}
	/**
	* Determine if stream is fs.ReadStream stream.
	* @private
	*/
	function isFsReadStream(stream) {
		return stream instanceof ReadStream;
	}
	/**
	* Determine if stream is Zlib stream.
	* @private
	*/
	function isZlibStream(stream) {
		return stream instanceof Zlib.Gzip || stream instanceof Zlib.Gunzip || stream instanceof Zlib.Deflate || stream instanceof Zlib.DeflateRaw || stream instanceof Zlib.Inflate || stream instanceof Zlib.InflateRaw || stream instanceof Zlib.Unzip;
	}
	/**
	* No-op function.
	* @private
	*/
	function noop() {}
	/**
	* On drain handler to clear binding.
	* @private
	*/
	// istanbul ignore next: node.js 0.8
	function onDrainClearBinding() {
		this._binding.clear();
	}
	/**
	* On open handler to close stream.
	* @private
	*/
	function onOpenClose() {
		if (typeof this.fd === "number") this.close();
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/on-headers@1.1.0/node_modules/on-headers/index.js
/*!
* on-headers
* Copyright(c) 2014 Douglas Christopher Wilson
* MIT Licensed
*/
var require_on_headers = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	* @public
	*/
	module.exports = onHeaders;
	var set1dArray = typeof __require("http").ServerResponse.prototype.appendHeader === "function" ? set1dArrayWithAppend : set1dArrayWithSet;
	/**
	* Create a replacement writeHead method.
	*
	* @param {function} prevWriteHead
	* @param {function} listener
	* @private
	*/
	function createWriteHead(prevWriteHead, listener) {
		var fired = false;
		return function writeHead(statusCode) {
			var args = setWriteHeadHeaders.apply(this, arguments);
			if (!fired) {
				fired = true;
				listener.call(this);
				if (typeof args[0] === "number" && this.statusCode !== args[0]) {
					args[0] = this.statusCode;
					args.length = 1;
				}
			}
			return prevWriteHead.apply(this, args);
		};
	}
	/**
	* Execute a listener when a response is about to write headers.
	*
	* @param {object} res
	* @return {function} listener
	* @public
	*/
	function onHeaders(res, listener) {
		if (!res) throw new TypeError("argument res is required");
		if (typeof listener !== "function") throw new TypeError("argument listener must be a function");
		res.writeHead = createWriteHead(res.writeHead, listener);
	}
	/**
	* Set headers contained in array on the response object.
	*
	* @param {object} res
	* @param {array} headers
	* @private
	*/
	function setHeadersFromArray(res, headers) {
		if (headers.length && Array.isArray(headers[0])) set2dArray(res, headers);
		else {
			if (headers.length % 2 !== 0) throw new TypeError("headers array is malformed");
			set1dArray(res, headers);
		}
	}
	/**
	* Set headers contained in object on the response object.
	*
	* @param {object} res
	* @param {object} headers
	* @private
	*/
	function setHeadersFromObject(res, headers) {
		var keys = Object.keys(headers);
		for (var i = 0; i < keys.length; i++) {
			var k = keys[i];
			if (k) res.setHeader(k, headers[k]);
		}
	}
	/**
	* Set headers and other properties on the response object.
	*
	* @param {number} statusCode
	* @private
	*/
	function setWriteHeadHeaders(statusCode) {
		var length = arguments.length;
		var headerIndex = length > 1 && typeof arguments[1] === "string" ? 2 : 1;
		var headers = length >= headerIndex + 1 ? arguments[headerIndex] : void 0;
		this.statusCode = statusCode;
		if (Array.isArray(headers)) setHeadersFromArray(this, headers);
		else if (headers) setHeadersFromObject(this, headers);
		var args = new Array(Math.min(length, headerIndex));
		for (var i = 0; i < args.length; i++) args[i] = arguments[i];
		return args;
	}
	function set2dArray(res, headers) {
		var key;
		for (var i = 0; i < headers.length; i++) {
			key = headers[i][0];
			if (key) res.setHeader(key, headers[i][1]);
		}
	}
	function set1dArrayWithAppend(res, headers) {
		for (var i = 0; i < headers.length; i += 2) res.removeHeader(headers[i]);
		var key;
		for (var j = 0; j < headers.length; j += 2) {
			key = headers[j];
			if (key) res.appendHeader(key, headers[j + 1]);
		}
	}
	function set1dArrayWithSet(res, headers) {
		var key;
		for (var i = 0; i < headers.length; i += 2) {
			key = headers[i];
			if (key) res.setHeader(key, headers[i + 1]);
		}
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/vary@1.1.2/node_modules/vary/index.js
/*!
* vary
* Copyright(c) 2014-2017 Douglas Christopher Wilson
* MIT Licensed
*/
var require_vary = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module exports.
	*/
	module.exports = vary;
	module.exports.append = append;
	/**
	* RegExp to match field-name in RFC 7230 sec 3.2
	*
	* field-name    = token
	* token         = 1*tchar
	* tchar         = "!" / "#" / "$" / "%" / "&" / "'" / "*"
	*               / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
	*               / DIGIT / ALPHA
	*               ; any VCHAR, except delimiters
	*/
	var FIELD_NAME_REGEXP = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
	/**
	* Append a field to a vary header.
	*
	* @param {String} header
	* @param {String|Array} field
	* @return {String}
	* @public
	*/
	function append(header, field) {
		if (typeof header !== "string") throw new TypeError("header argument is required");
		if (!field) throw new TypeError("field argument is required");
		var fields = !Array.isArray(field) ? parse(String(field)) : field;
		for (var j = 0; j < fields.length; j++) if (!FIELD_NAME_REGEXP.test(fields[j])) throw new TypeError("field argument contains an invalid header name");
		if (header === "*") return header;
		var val = header;
		var vals = parse(header.toLowerCase());
		if (fields.indexOf("*") !== -1 || vals.indexOf("*") !== -1) return "*";
		for (var i = 0; i < fields.length; i++) {
			var fld = fields[i].toLowerCase();
			if (vals.indexOf(fld) === -1) {
				vals.push(fld);
				val = val ? val + ", " + fields[i] : fields[i];
			}
		}
		return val;
	}
	/**
	* Parse a vary header into an array.
	*
	* @param {String} header
	* @return {Array}
	* @private
	*/
	function parse(header) {
		var end = 0;
		var list = [];
		var start = 0;
		for (var i = 0, len = header.length; i < len; i++) switch (header.charCodeAt(i)) {
			case 32:
				if (start === end) start = end = i + 1;
				break;
			case 44:
				list.push(header.substring(start, end));
				start = end = i + 1;
				break;
			default:
				end = i + 1;
				break;
		}
		list.push(header.substring(start, end));
		return list;
	}
	/**
	* Mark that a request is varied on a header field.
	*
	* @param {Object} res
	* @param {String|Array} field
	* @public
	*/
	function vary(res, field) {
		if (!res || !res.getHeader || !res.setHeader) throw new TypeError("res argument is required");
		var val = res.getHeader("Vary") || "";
		if (val = append(Array.isArray(val) ? val.join(", ") : String(val), field)) res.setHeader("Vary", val);
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/compression@1.8.2_supports-color@7.2.0/node_modules/compression/index.js
/*!
* compression
* Copyright(c) 2010 Sencha Inc.
* Copyright(c) 2011 TJ Holowaychuk
* Copyright(c) 2014 Jonathan Ong
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_compression = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	/**
	* Module dependencies.
	* @private
	*/
	var Negotiator = require_negotiator$1();
	var Buffer = require_safe_buffer().Buffer;
	var bytes = require_bytes();
	var compressible = require_compressible();
	var debug = require_src()("compression");
	var destroy = require_destroy();
	var onHeaders = require_on_headers();
	var vary = require_vary();
	var zlib = __require("zlib");
	/**
	* Module exports.
	*/
	module.exports = compression;
	module.exports.filter = shouldCompress;
	/**
	* @const
	* whether current node version has brotli support
	*/
	var hasBrotliSupport = "createBrotliCompress" in zlib;
	/**
	* Module variables.
	* @private
	*/
	var cacheControlNoTransformRegExp = /(?:^|,)\s*?no-transform\s*?(?:,|$)/i;
	var SUPPORTED_ENCODING = hasBrotliSupport ? [
		"br",
		"gzip",
		"deflate",
		"identity"
	] : [
		"gzip",
		"deflate",
		"identity"
	];
	var PREFERRED_ENCODING = hasBrotliSupport ? ["br", "gzip"] : ["gzip"];
	var encodingSupported = [
		"gzip",
		"deflate",
		"identity",
		"br"
	];
	/**
	* Compress response data with gzip / deflate.
	*
	* @param {Object} [options]
	* @return {Function} middleware
	* @public
	*/
	function compression(options) {
		var opts = options || {};
		var optsBrotli = {};
		if (hasBrotliSupport) {
			Object.assign(optsBrotli, opts.brotli);
			var brotliParams = {};
			brotliParams[zlib.constants.BROTLI_PARAM_QUALITY] = 4;
			optsBrotli.params = Object.assign(brotliParams, optsBrotli.params);
		}
		var filter = opts.filter || shouldCompress;
		var threshold = bytes.parse(opts.threshold);
		var enforceEncoding = opts.enforceEncoding || "identity";
		if (threshold == null) threshold = 1024;
		return function compression(req, res, next) {
			var ended = false;
			var length;
			var listeners = [];
			var stream;
			var closed = false;
			var _end = res.end;
			var _on = res.on;
			var _write = res.write;
			res.flush = function flush() {
				if (stream) stream.flush();
			};
			res.write = function write(chunk, encoding) {
				if (ended) return false;
				if (!headersSent(res)) this.writeHead(this.statusCode);
				return stream ? stream.write(toBuffer(chunk, encoding)) : _write.call(this, chunk, encoding);
			};
			res.end = function end(chunk, encoding) {
				if (ended) return false;
				if (!headersSent(res)) {
					if (!this.getHeader("Content-Length")) length = chunkLength(chunk, encoding);
					this.writeHead(this.statusCode);
				}
				if (!stream) return _end.call(this, chunk, encoding);
				ended = true;
				return chunk ? stream.end(toBuffer(chunk, encoding)) : stream.end();
			};
			res.on = function on(type, listener) {
				if (!listeners || type !== "drain") return _on.call(this, type, listener);
				if (stream) return stream.on(type, listener);
				listeners.push([type, listener]);
				return this;
			};
			function nocompress(msg) {
				debug("no compression: %s", msg);
				addListeners(res, _on, listeners);
				listeners = null;
			}
			_on.call(res, "close", function onResponseClose() {
				closed = true;
				destroy(stream);
			});
			onHeaders(res, function onResponseHeaders() {
				if (!filter(req, res)) {
					nocompress("filtered");
					return;
				}
				if (!shouldTransform(req, res)) {
					nocompress("no transform");
					return;
				}
				vary(res, "Accept-Encoding");
				if (Number(res.getHeader("Content-Length")) < threshold || length < threshold) {
					nocompress("size below threshold");
					return;
				}
				if ((res.getHeader("Content-Encoding") || "identity") !== "identity") {
					nocompress("already encoded");
					return;
				}
				if (req.method === "HEAD") {
					nocompress("HEAD request");
					return;
				}
				var method = new Negotiator(req).encoding(SUPPORTED_ENCODING, PREFERRED_ENCODING);
				if (!req.headers["accept-encoding"] && encodingSupported.indexOf(enforceEncoding) !== -1) method = enforceEncoding;
				if (!method || method === "identity") {
					nocompress("not acceptable");
					return;
				}
				debug("%s compression", method);
				stream = method === "gzip" ? zlib.createGzip(opts) : method === "br" ? zlib.createBrotliCompress(optsBrotli) : zlib.createDeflate(opts);
				if (closed) {
					destroy(stream);
					stream = null;
					return;
				}
				addListeners(stream, stream.on, listeners);
				res.setHeader("Content-Encoding", method);
				res.removeHeader("Content-Length");
				stream.on("data", function onStreamData(chunk) {
					if (_write.call(res, chunk) === false) stream.pause();
				});
				stream.on("end", function onStreamEnd() {
					_end.call(res);
				});
				_on.call(res, "drain", function onResponseDrain() {
					stream.resume();
				});
			});
			next();
		};
	}
	/**
	* Add bufferred listeners to stream
	* @private
	*/
	function addListeners(stream, on, listeners) {
		for (var i = 0; i < listeners.length; i++) on.apply(stream, listeners[i]);
	}
	/**
	* Get the length of a given chunk
	*/
	function chunkLength(chunk, encoding) {
		if (!chunk) return 0;
		return Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk, encoding);
	}
	/**
	* Default filter function.
	* @private
	*/
	function shouldCompress(req, res) {
		var type = res.getHeader("Content-Type");
		if (type === void 0 || !compressible(type)) {
			debug("%s not compressible", type);
			return false;
		}
		return true;
	}
	/**
	* Determine if the entity should be transformed.
	* @private
	*/
	function shouldTransform(req, res) {
		var cacheControl = res.getHeader("Cache-Control");
		return !cacheControl || !cacheControlNoTransformRegExp.test(cacheControl);
	}
	/**
	* Coerce arguments to Buffer
	* @private
	*/
	function toBuffer(chunk, encoding) {
		return Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
	}
	/**
	* Determine if the response headers have been sent.
	*
	* @param {object} res
	* @returns {boolean}
	* @private
	*/
	function headersSent(res) {
		return typeof res.headersSent !== "boolean" ? Boolean(res._header) : res.headersSent;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/ipaddr.js@2.5.0/node_modules/ipaddr.js/lib/ipaddr.js
var require_ipaddr = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	(function(root) {
		"use strict";
		const ipv4Part = "(0?\\d+|0x[a-f0-9]+)";
		const ipv4Regexes = {
			fourOctet: new RegExp(`^${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}$`, "i"),
			threeOctet: new RegExp(`^${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}$`, "i"),
			twoOctet: new RegExp(`^${ipv4Part}\\.${ipv4Part}$`, "i"),
			longValue: new RegExp(`^${ipv4Part}$`, "i")
		};
		const octalRegex = new RegExp(`^0[0-7]+$`, "i");
		const hexRegex = new RegExp(`^0x[a-f0-9]+$`, "i");
		const zoneIndex = "%[0-9a-z]{1,}";
		const ipv6Part = "(?:[0-9a-f]+::?)+";
		const ipv6Regexes = {
			zoneIndex: new RegExp(zoneIndex, "i"),
			"native": new RegExp(`^(::)?(${ipv6Part})?([0-9a-f]+)?(::)?(${zoneIndex})?$`, "i"),
			deprecatedTransitional: new RegExp(`^(?:::)(${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}(${zoneIndex})?)$`, "i"),
			transitional: new RegExp(`^((?:${ipv6Part})|(?:::)(?:${ipv6Part})?)${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}(${zoneIndex})?$`, "i")
		};
		function expandIPv6(string, parts) {
			if (string.indexOf("::") !== string.lastIndexOf("::")) return null;
			let colonCount = 0;
			let lastColon = -1;
			let zoneId = (string.match(ipv6Regexes.zoneIndex) || [])[0];
			let replacement, replacementCount;
			if (zoneId) {
				zoneId = zoneId.substring(1);
				string = string.replace(/%.+$/, "");
			}
			while ((lastColon = string.indexOf(":", lastColon + 1)) >= 0) colonCount++;
			if (string.substr(0, 2) === "::") colonCount--;
			if (string.substr(-2, 2) === "::") colonCount--;
			if (colonCount >= parts) return null;
			replacementCount = parts - colonCount;
			replacement = ":";
			while (replacementCount--) replacement += "0:";
			string = string.replace("::", replacement);
			if (string[0] === ":") string = string.slice(1);
			if (string[string.length - 1] === ":") string = string.slice(0, -1);
			parts = (function() {
				const ref = string.split(":");
				const results = [];
				for (let i = 0; i < ref.length; i++) results.push(ref[i].length > 4 ? NaN : parseInt(ref[i], 16));
				return results;
			})();
			return {
				parts,
				zoneId
			};
		}
		function matchCIDR(first, second, partSize, cidrBits) {
			if (first.length !== second.length) throw new Error("ipaddr: cannot match CIDR for objects with different lengths");
			let part = 0;
			let shift;
			while (cidrBits > 0) {
				shift = partSize - cidrBits;
				if (shift < 0) shift = 0;
				if (first[part] >> shift !== second[part] >> shift) return false;
				cidrBits -= partSize;
				part += 1;
			}
			return true;
		}
		function parseIntAuto(string) {
			if (hexRegex.test(string)) return parseInt(string, 16);
			if (string[0] === "0" && !isNaN(parseInt(string[1], 10))) {
				if (octalRegex.test(string)) return parseInt(string, 8);
				throw new Error(`ipaddr: cannot parse ${string} as octal`);
			}
			return parseInt(string, 10);
		}
		function padPart(part, length) {
			while (part.length < length) part = `0${part}`;
			return part;
		}
		const ipaddr = {};
		ipaddr.IPv4 = (function() {
			function IPv4(octets) {
				if (octets.length !== 4) throw new Error("ipaddr: ipv4 octet count should be 4");
				let i, octet;
				for (i = 0; i < octets.length; i++) {
					octet = octets[i];
					if (!(0 <= octet && octet <= 255)) throw new Error("ipaddr: ipv4 octet should fit in 8 bits");
				}
				this.octets = octets;
			}
			IPv4.prototype.SpecialRanges = {
				unspecified: [[new IPv4([
					0,
					0,
					0,
					0
				]), 8]],
				broadcast: [[new IPv4([
					255,
					255,
					255,
					255
				]), 32]],
				multicast: [[new IPv4([
					224,
					0,
					0,
					0
				]), 4]],
				linkLocal: [[new IPv4([
					169,
					254,
					0,
					0
				]), 16]],
				loopback: [[new IPv4([
					127,
					0,
					0,
					0
				]), 8]],
				carrierGradeNat: [[new IPv4([
					100,
					64,
					0,
					0
				]), 10]],
				"private": [
					[new IPv4([
						10,
						0,
						0,
						0
					]), 8],
					[new IPv4([
						172,
						16,
						0,
						0
					]), 12],
					[new IPv4([
						192,
						168,
						0,
						0
					]), 16]
				],
				reserved: [
					[new IPv4([
						192,
						0,
						0,
						0
					]), 24],
					[new IPv4([
						192,
						0,
						2,
						0
					]), 24],
					[new IPv4([
						192,
						88,
						99,
						0
					]), 24],
					[new IPv4([
						198,
						18,
						0,
						0
					]), 15],
					[new IPv4([
						198,
						51,
						100,
						0
					]), 24],
					[new IPv4([
						203,
						0,
						113,
						0
					]), 24],
					[new IPv4([
						240,
						0,
						0,
						0
					]), 4]
				],
				as112: [[new IPv4([
					192,
					175,
					48,
					0
				]), 24], [new IPv4([
					192,
					31,
					196,
					0
				]), 24]],
				amt: [[new IPv4([
					192,
					52,
					193,
					0
				]), 24]]
			};
			IPv4.prototype.kind = function() {
				return "ipv4";
			};
			IPv4.prototype.match = function(other, cidrRange) {
				let ref;
				if (cidrRange === void 0) {
					ref = other;
					other = ref[0];
					cidrRange = ref[1];
				}
				if (other.kind() !== "ipv4") throw new Error("ipaddr: cannot match ipv4 address with non-ipv4 one");
				return matchCIDR(this.octets, other.octets, 8, cidrRange);
			};
			IPv4.prototype.prefixLengthFromSubnetMask = function() {
				let cidr = 0;
				let stop = false;
				const zerotable = {
					0: 8,
					128: 7,
					192: 6,
					224: 5,
					240: 4,
					248: 3,
					252: 2,
					254: 1,
					255: 0
				};
				let i, octet, zeros;
				for (i = 3; i >= 0; i -= 1) {
					octet = this.octets[i];
					if (octet in zerotable) {
						zeros = zerotable[octet];
						if (stop && zeros !== 0) return null;
						if (zeros !== 8) stop = true;
						cidr += zeros;
					} else return null;
				}
				return 32 - cidr;
			};
			IPv4.prototype.range = function() {
				return ipaddr.subnetMatch(this, this.SpecialRanges);
			};
			IPv4.prototype.toByteArray = function() {
				return this.octets.slice(0);
			};
			IPv4.prototype.toIPv4MappedAddress = function() {
				return ipaddr.IPv6.parse(`::ffff:${this.toString()}`);
			};
			IPv4.prototype.toNormalizedString = function() {
				return this.toString();
			};
			IPv4.prototype.toString = function() {
				return this.octets.join(".");
			};
			return IPv4;
		})();
		ipaddr.IPv4.broadcastAddressFromCIDR = function(string) {
			try {
				const cidr = this.parseCIDR(string);
				const ipInterfaceOctets = cidr[0].toByteArray();
				const subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
				const octets = [];
				let i = 0;
				while (i < 4) {
					octets.push(parseInt(ipInterfaceOctets[i], 10) | parseInt(subnetMaskOctets[i], 10) ^ 255);
					i++;
				}
				return new this(octets);
			} catch (e) {
				throw new Error("ipaddr: the address does not have IPv4 CIDR format", { cause: e });
			}
		};
		ipaddr.IPv4.isIPv4 = function(string) {
			return this.parser(string) !== null;
		};
		ipaddr.IPv4.isValid = function(string) {
			try {
				new this(this.parser(string));
				return true;
			} catch {
				return false;
			}
		};
		ipaddr.IPv4.isValidCIDR = function(string) {
			try {
				this.parseCIDR(string);
				return true;
			} catch {
				return false;
			}
		};
		ipaddr.IPv4.isValidFourPartDecimal = function(string) {
			if (ipaddr.IPv4.isValid(string) && string.match(/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){3}$/)) return true;
			else return false;
		};
		ipaddr.IPv4.isValidCIDRFourPartDecimal = function(string) {
			const match = string.match(/^(.+)\/(\d+)$/);
			if (!ipaddr.IPv4.isValidCIDR(string) || !match) return false;
			return ipaddr.IPv4.isValidFourPartDecimal(match[1]);
		};
		ipaddr.IPv4.networkAddressFromCIDR = function(string) {
			let cidr, i, ipInterfaceOctets, octets, subnetMaskOctets;
			try {
				cidr = this.parseCIDR(string);
				ipInterfaceOctets = cidr[0].toByteArray();
				subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
				octets = [];
				i = 0;
				while (i < 4) {
					octets.push(parseInt(ipInterfaceOctets[i], 10) & parseInt(subnetMaskOctets[i], 10));
					i++;
				}
				return new this(octets);
			} catch (e) {
				throw new Error("ipaddr: the address does not have IPv4 CIDR format", { cause: e });
			}
		};
		ipaddr.IPv4.parse = function(string) {
			const parts = this.parser(string);
			if (parts === null) throw new Error("ipaddr: string is not formatted like an IPv4 Address");
			return new this(parts);
		};
		ipaddr.IPv4.parseCIDR = function(string) {
			let match;
			if (match = string.match(/^(.+)\/(\d+)$/)) {
				const maskLength = parseInt(match[2]);
				if (maskLength >= 0 && maskLength <= 32) {
					const parsed = [this.parse(match[1]), maskLength];
					Object.defineProperty(parsed, "toString", { value: function() {
						return this.join("/");
					} });
					return parsed;
				}
			}
			throw new Error("ipaddr: string is not formatted like an IPv4 CIDR range");
		};
		ipaddr.IPv4.parser = function(string) {
			let match, part, value;
			if (match = string.match(ipv4Regexes.fourOctet)) return (function() {
				const ref = match.slice(1, 6);
				const results = [];
				for (let i = 0; i < ref.length; i++) {
					part = ref[i];
					results.push(parseIntAuto(part));
				}
				return results;
			})();
			else if (match = string.match(ipv4Regexes.longValue)) {
				value = parseIntAuto(match[1]);
				if (value > 4294967295 || value < 0) throw new Error("ipaddr: address outside defined range");
				return (function() {
					const results = [];
					let shift;
					for (shift = 0; shift <= 24; shift += 8) results.push(value >> shift & 255);
					return results;
				})().reverse();
			} else if (match = string.match(ipv4Regexes.twoOctet)) return (function() {
				const ref = match.slice(1, 4);
				const results = [];
				value = parseIntAuto(ref[1]);
				if (value > 16777215 || value < 0) throw new Error("ipaddr: address outside defined range");
				results.push(parseIntAuto(ref[0]));
				results.push(value >> 16 & 255);
				results.push(value >> 8 & 255);
				results.push(value & 255);
				return results;
			})();
			else if (match = string.match(ipv4Regexes.threeOctet)) return (function() {
				const ref = match.slice(1, 5);
				const results = [];
				value = parseIntAuto(ref[2]);
				if (value > 65535 || value < 0) throw new Error("ipaddr: address outside defined range");
				results.push(parseIntAuto(ref[0]));
				results.push(parseIntAuto(ref[1]));
				results.push(value >> 8 & 255);
				results.push(value & 255);
				return results;
			})();
			else return null;
		};
		ipaddr.IPv4.subnetMaskFromPrefixLength = function(prefix) {
			prefix = parseInt(prefix);
			if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error("ipaddr: invalid IPv4 prefix length");
			const octets = [
				0,
				0,
				0,
				0
			];
			let j = 0;
			const filledOctetCount = Math.floor(prefix / 8);
			while (j < filledOctetCount) {
				octets[j] = 255;
				j++;
			}
			if (filledOctetCount < 4) octets[filledOctetCount] = Math.pow(2, prefix % 8) - 1 << 8 - prefix % 8;
			return new this(octets);
		};
		ipaddr.IPv6 = (function() {
			function IPv6(parts, zoneId) {
				let i, part;
				if (parts.length === 16) {
					this.parts = [];
					for (i = 0; i <= 14; i += 2) this.parts.push(parts[i] << 8 | parts[i + 1]);
				} else if (parts.length === 8) this.parts = parts;
				else throw new Error("ipaddr: ipv6 part count should be 8 or 16");
				for (i = 0; i < this.parts.length; i++) {
					part = this.parts[i];
					if (!(0 <= part && part <= 65535)) throw new Error("ipaddr: ipv6 part should fit in 16 bits");
				}
				if (zoneId) this.zoneId = zoneId;
			}
			IPv6.prototype.SpecialRanges = {
				unspecified: [new IPv6([
					0,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 128],
				linkLocal: [new IPv6([
					65152,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 10],
				multicast: [new IPv6([
					65280,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 8],
				loopback: [new IPv6([
					0,
					0,
					0,
					0,
					0,
					0,
					0,
					1
				]), 128],
				uniqueLocal: [new IPv6([
					64512,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 7],
				ipv4Mapped: [new IPv6([
					0,
					0,
					0,
					0,
					0,
					65535,
					0,
					0
				]), 96],
				deprecatedSiteLocal: [new IPv6([
					65216,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 10],
				discard: [new IPv6([
					256,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 64],
				rfc6145: [new IPv6([
					0,
					0,
					0,
					0,
					65535,
					0,
					0,
					0
				]), 96],
				rfc6052: [[new IPv6([
					100,
					65435,
					0,
					0,
					0,
					0,
					0,
					0
				]), 96], [new IPv6([
					100,
					65435,
					1,
					0,
					0,
					0,
					0,
					0
				]), 48]],
				"6to4": [new IPv6([
					8194,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 16],
				teredo: [new IPv6([
					8193,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 32],
				benchmarking: [new IPv6([
					8193,
					2,
					0,
					0,
					0,
					0,
					0,
					0
				]), 48],
				amt: [new IPv6([
					8193,
					3,
					0,
					0,
					0,
					0,
					0,
					0
				]), 32],
				as112v6: [[new IPv6([
					8193,
					4,
					274,
					0,
					0,
					0,
					0,
					0
				]), 48], [new IPv6([
					9760,
					79,
					32768,
					0,
					0,
					0,
					0,
					0
				]), 48]],
				deprecatedOrchid: [new IPv6([
					8193,
					16,
					0,
					0,
					0,
					0,
					0,
					0
				]), 28],
				orchid2: [new IPv6([
					8193,
					32,
					0,
					0,
					0,
					0,
					0,
					0
				]), 28],
				droneRemoteIdProtocolEntityTags: [new IPv6([
					8193,
					48,
					0,
					0,
					0,
					0,
					0,
					0
				]), 28],
				segmentRouting: [new IPv6([
					24320,
					0,
					0,
					0,
					0,
					0,
					0,
					0
				]), 16],
				reserved: [
					[new IPv6([
						8193,
						0,
						0,
						0,
						0,
						0,
						0,
						0
					]), 23],
					[new IPv6([
						8193,
						3512,
						0,
						0,
						0,
						0,
						0,
						0
					]), 32],
					[new IPv6([
						16383,
						0,
						0,
						0,
						0,
						0,
						0,
						0
					]), 20]
				]
			};
			IPv6.prototype.isIPv4MappedAddress = function() {
				return this.range() === "ipv4Mapped";
			};
			IPv6.prototype.kind = function() {
				return "ipv6";
			};
			IPv6.prototype.match = function(other, cidrRange) {
				let ref;
				if (cidrRange === void 0) {
					ref = other;
					other = ref[0];
					cidrRange = ref[1];
				}
				if (other.kind() !== "ipv6") throw new Error("ipaddr: cannot match ipv6 address with non-ipv6 one");
				return matchCIDR(this.parts, other.parts, 16, cidrRange);
			};
			IPv6.prototype.prefixLengthFromSubnetMask = function() {
				let cidr = 0;
				let stop = false;
				const zerotable = {
					0: 16,
					32768: 15,
					49152: 14,
					57344: 13,
					61440: 12,
					63488: 11,
					64512: 10,
					65024: 9,
					65280: 8,
					65408: 7,
					65472: 6,
					65504: 5,
					65520: 4,
					65528: 3,
					65532: 2,
					65534: 1,
					65535: 0
				};
				let part, zeros;
				for (let i = 7; i >= 0; i -= 1) {
					part = this.parts[i];
					if (part in zerotable) {
						zeros = zerotable[part];
						if (stop && zeros !== 0) return null;
						if (zeros !== 16) stop = true;
						cidr += zeros;
					} else return null;
				}
				return 128 - cidr;
			};
			IPv6.prototype.range = function() {
				return ipaddr.subnetMatch(this, this.SpecialRanges);
			};
			IPv6.prototype.toByteArray = function() {
				let part;
				const bytes = [];
				const ref = this.parts;
				for (let i = 0; i < ref.length; i++) {
					part = ref[i];
					bytes.push(part >> 8);
					bytes.push(part & 255);
				}
				return bytes;
			};
			IPv6.prototype.toFixedLengthString = function() {
				const addr = (function() {
					const results = [];
					for (let i = 0; i < this.parts.length; i++) results.push(padPart(this.parts[i].toString(16), 4));
					return results;
				}).call(this).join(":");
				let suffix = "";
				if (this.zoneId) suffix = `%${this.zoneId}`;
				return addr + suffix;
			};
			IPv6.prototype.toIPv4Address = function() {
				if (!this.isIPv4MappedAddress()) throw new Error("ipaddr: trying to convert a generic ipv6 address to ipv4");
				const ref = this.parts.slice(-2);
				const high = ref[0];
				const low = ref[1];
				return new ipaddr.IPv4([
					high >> 8,
					high & 255,
					low >> 8,
					low & 255
				]);
			};
			IPv6.prototype.toNormalizedString = function() {
				const addr = (function() {
					const results = [];
					for (let i = 0; i < this.parts.length; i++) results.push(this.parts[i].toString(16));
					return results;
				}).call(this).join(":");
				let suffix = "";
				if (this.zoneId) suffix = `%${this.zoneId}`;
				return addr + suffix;
			};
			IPv6.prototype.toRFC5952String = function() {
				const regex = /((^|:)(0(:|$)){2,})/g;
				let suffix = "";
				if (this.zoneId) suffix = `%${this.zoneId}`;
				const normalized = this.toNormalizedString();
				const string = normalized.slice(0, normalized.length - suffix.length);
				let bestMatchIndex = 0;
				let bestMatchLength = -1;
				let bestMatchGroups = -1;
				let match;
				while (match = regex.exec(string)) {
					const groups = (match[0].match(/0/g) || []).length;
					if (groups > bestMatchGroups) {
						bestMatchGroups = groups;
						bestMatchIndex = match.index;
						bestMatchLength = match[0].length;
					}
				}
				if (bestMatchLength < 0) return string + suffix;
				return `${string.substring(0, bestMatchIndex)}::${string.substring(bestMatchIndex + bestMatchLength)}${suffix}`;
			};
			IPv6.prototype.toString = function() {
				return this.toRFC5952String();
			};
			return IPv6;
		})();
		ipaddr.IPv6.broadcastAddressFromCIDR = function(string) {
			try {
				const cidr = this.parseCIDR(string);
				const ipInterfaceOctets = cidr[0].toByteArray();
				const subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
				const octets = [];
				let i = 0;
				while (i < 16) {
					octets.push(parseInt(ipInterfaceOctets[i], 10) | parseInt(subnetMaskOctets[i], 10) ^ 255);
					i++;
				}
				return new this(octets);
			} catch (e) {
				throw new Error("ipaddr: the address does not have IPv6 CIDR format", { cause: e });
			}
		};
		ipaddr.IPv6.isIPv6 = function(string) {
			return this.parser(string) !== null;
		};
		ipaddr.IPv6.isValid = function(string) {
			if (typeof string === "string" && string.indexOf(":") === -1) return false;
			try {
				const addr = this.parser(string);
				new this(addr.parts, addr.zoneId);
				return true;
			} catch {
				return false;
			}
		};
		ipaddr.IPv6.isValidCIDR = function(string) {
			if (typeof string === "string" && string.indexOf(":") === -1) return false;
			try {
				this.parseCIDR(string);
				return true;
			} catch {
				return false;
			}
		};
		ipaddr.IPv6.networkAddressFromCIDR = function(string) {
			let cidr, i, ipInterfaceOctets, octets, subnetMaskOctets;
			try {
				cidr = this.parseCIDR(string);
				ipInterfaceOctets = cidr[0].toByteArray();
				subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
				octets = [];
				i = 0;
				while (i < 16) {
					octets.push(parseInt(ipInterfaceOctets[i], 10) & parseInt(subnetMaskOctets[i], 10));
					i++;
				}
				return new this(octets);
			} catch (e) {
				throw new Error("ipaddr: the address does not have IPv6 CIDR format", { cause: e });
			}
		};
		ipaddr.IPv6.parse = function(string) {
			const addr = this.parser(string);
			if (addr === null) throw new Error("ipaddr: string is not formatted like an IPv6 Address");
			return new this(addr.parts, addr.zoneId);
		};
		ipaddr.IPv6.parseCIDR = function(string) {
			let maskLength, match, parsed;
			if (match = string.match(/^(.+)\/(\d+)$/)) {
				maskLength = parseInt(match[2]);
				if (maskLength >= 0 && maskLength <= 128) {
					parsed = [this.parse(match[1]), maskLength];
					Object.defineProperty(parsed, "toString", { value: function() {
						return this.join("/");
					} });
					return parsed;
				}
			}
			throw new Error("ipaddr: string is not formatted like an IPv6 CIDR range");
		};
		ipaddr.IPv6.parser = function(string) {
			let addr, i, match, octet, octets, zoneId;
			if (match = string.match(ipv6Regexes.deprecatedTransitional)) return this.parser(`::ffff:${match[1]}`);
			if (ipv6Regexes.native.test(string)) return expandIPv6(string, 8);
			if (match = string.match(ipv6Regexes.transitional)) {
				zoneId = match[6] || "";
				addr = match[1];
				if (!match[1].endsWith("::")) addr = addr.slice(0, -1);
				addr = expandIPv6(addr + zoneId, 6);
				if (addr && addr.parts) {
					octets = [
						parseInt(match[2]),
						parseInt(match[3]),
						parseInt(match[4]),
						parseInt(match[5])
					];
					for (i = 0; i < octets.length; i++) {
						octet = octets[i];
						if (!(0 <= octet && octet <= 255)) return null;
					}
					addr.parts.push(octets[0] << 8 | octets[1]);
					addr.parts.push(octets[2] << 8 | octets[3]);
					return {
						parts: addr.parts,
						zoneId: addr.zoneId
					};
				}
			}
			return null;
		};
		ipaddr.IPv6.subnetMaskFromPrefixLength = function(prefix) {
			prefix = parseInt(prefix);
			if (Number.isNaN(prefix) || prefix < 0 || prefix > 128) throw new Error("ipaddr: invalid IPv6 prefix length");
			const octets = [
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0
			];
			let j = 0;
			const filledOctetCount = Math.floor(prefix / 8);
			while (j < filledOctetCount) {
				octets[j] = 255;
				j++;
			}
			if (filledOctetCount < 16) octets[filledOctetCount] = Math.pow(2, prefix % 8) - 1 << 8 - prefix % 8;
			return new this(octets);
		};
		ipaddr.fromByteArray = function(bytes) {
			const length = bytes.length;
			if (length === 4) return new ipaddr.IPv4(bytes);
			else if (length === 16) return new ipaddr.IPv6(bytes);
			else throw new Error("ipaddr: the binary input is neither an IPv6 nor IPv4 address");
		};
		ipaddr.isValid = function(string) {
			return ipaddr.IPv6.isValid(string) || ipaddr.IPv4.isValid(string);
		};
		ipaddr.isValidCIDR = function(string) {
			return ipaddr.IPv6.isValidCIDR(string) || ipaddr.IPv4.isValidCIDR(string);
		};
		ipaddr.parse = function(string) {
			if (ipaddr.IPv6.isValid(string)) return ipaddr.IPv6.parse(string);
			else if (ipaddr.IPv4.isValid(string)) return ipaddr.IPv4.parse(string);
			else throw new Error("ipaddr: the address has neither IPv6 nor IPv4 format");
		};
		ipaddr.parseCIDR = function(string) {
			try {
				return ipaddr.IPv6.parseCIDR(string);
			} catch {
				try {
					return ipaddr.IPv4.parseCIDR(string);
				} catch (e) {
					throw new Error("ipaddr: the address has neither IPv6 nor IPv4 CIDR format", { cause: e });
				}
			}
		};
		ipaddr.process = function(string) {
			const addr = this.parse(string);
			if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) return addr.toIPv4Address();
			else return addr;
		};
		ipaddr.subnetMatch = function(address, rangeList, defaultName) {
			let i, rangeName, rangeSubnets, subnet;
			if (defaultName === void 0 || defaultName === null) defaultName = "unicast";
			for (rangeName in rangeList) if (Object.prototype.hasOwnProperty.call(rangeList, rangeName)) {
				rangeSubnets = rangeList[rangeName];
				if (rangeSubnets[0] && !(rangeSubnets[0] instanceof Array)) rangeSubnets = [rangeSubnets];
				for (i = 0; i < rangeSubnets.length; i++) {
					subnet = rangeSubnets[i];
					if (address.kind() === subnet[0].kind() && address.match.apply(address, subnet)) return rangeName;
				}
			}
			return defaultName;
		};
		if (typeof module !== "undefined" && module.exports) module.exports = ipaddr;
		else root.ipaddr = ipaddr;
	})(exports);
}));
//#endregion
//#region ../../node_modules/.pnpm/content-type@2.1.0/node_modules/content-type/dist/index.js
var require_dist = /* @__PURE__ */ __commonJSMin(((exports) => {
	/*!
	* content-type
	* Copyright(c) 2015 Douglas Christopher Wilson
	* MIT Licensed
	*/
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.format = format;
	exports.parse = parse;
	const TEXT_REGEXP = /^[\u0009\u0020-\u007e\u0080-\u00ff]*$/;
	const TOKEN_REGEXP = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
	/**
	* RegExp to match chars that must be quoted-pair in RFC 9110 sec 5.6.4
	*/
	const QUOTE_REGEXP = /[\\"]/g;
	/**
	* RegExp to match type in RFC 9110 sec 8.3.1
	*
	* media-type = type "/" subtype
	* type       = token
	* subtype    = token
	*/
	const TYPE_REGEXP = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
	/**
	* Null object perf optimization. Faster than `Object.create(null)` and `{ __proto__: null }`.
	*/
	const NullObject = /* @__PURE__ */ (() => {
		const C = function() {};
		C.prototype = Object.create(null);
		return C;
	})();
	/**
	* Format an object into a `Content-Type` header.
	*/
	function format(obj) {
		const { type, parameters } = obj;
		if (!type || !TYPE_REGEXP.test(type)) throw new TypeError(`Invalid type: ${type}`);
		let result = type;
		if (parameters) for (const param of Object.keys(parameters)) {
			if (!TOKEN_REGEXP.test(param)) throw new TypeError(`Invalid parameter name: ${param}`);
			result += `; ${param}=${qstring(parameters[param])}`;
		}
		return result;
	}
	/**
	* Parse a `Content-Type` header.
	*/
	function parse(header, options) {
		const stopChar = options?.comma === true ? COMMA : 65536;
		const len = header.length;
		let index = skipOWS(header, options?.start ?? 0, len);
		const valueStart = index;
		index = skipValue(header, index, len, stopChar);
		const valueEnd = trailingOWS(header, valueStart, index);
		const type = header.slice(valueStart, valueEnd).toLowerCase();
		if (options?.parameters === false) return {
			type,
			index,
			parameters: new NullObject()
		};
		return parseParameters(header, type, index, len, stopChar);
	}
	const SP = 32;
	const HTAB = 9;
	const SEMI = 59;
	const EQ = 61;
	const DQUOTE = 34;
	const BSLASH = 92;
	const COMMA = 44;
	/**
	* Parses the parameters of a `Content-Type` header starting at the given index.
	*/
	function parseParameters(header, type, index, len, stopChar) {
		const parameters = new NullObject();
		parameter: while (index < len) {
			if (header.charCodeAt(index) === stopChar) break;
			index = skipOWS(header, index + 1, len);
			const keyStart = index;
			while (index < len) {
				const code = header.charCodeAt(index);
				if (code === stopChar) break parameter;
				if (code === SEMI) continue parameter;
				if (code === EQ) {
					const keyEnd = trailingOWS(header, keyStart, index);
					const key = header.slice(keyStart, keyEnd).toLowerCase();
					index = skipOWS(header, index + 1, len);
					if (index < len && header.charCodeAt(index) === DQUOTE) {
						index++;
						let value = "";
						while (index < len) {
							const code = header.charCodeAt(index++);
							if (code === DQUOTE) {
								index = skipValue(header, index, len, stopChar);
								if (parameters[key] === void 0) parameters[key] = value;
								break;
							}
							if (code === BSLASH && index < len) {
								value += header[index++];
								continue;
							}
							value += String.fromCharCode(code);
						}
						continue parameter;
					}
					const valueStart = index;
					index = skipValue(header, index, len, stopChar);
					if (parameters[key] === void 0) {
						const valueEnd = trailingOWS(header, valueStart, index);
						parameters[key] = header.slice(valueStart, valueEnd);
					}
					continue parameter;
				}
				index++;
			}
		}
		return {
			type,
			index,
			parameters
		};
	}
	/**
	* Skip over characters until a semicolon or other exit character.
	*/
	function skipValue(str, index, len, stopChar) {
		while (index < len) {
			const code = str.charCodeAt(index);
			if (code === SEMI || code === stopChar) break;
			index++;
		}
		return index;
	}
	/**
	* Skip optional whitespace (OWS) in an HTTP header value.
	*
	* OWS is defined in RFC 9110 sec 5.6.3 as SP (" ") or HTAB ("\t").
	*/
	function skipOWS(header, index, len) {
		while (index < len) {
			const char = header.charCodeAt(index);
			if (char !== SP && char !== HTAB) break;
			index++;
		}
		return index;
	}
	/**
	* Trim optional whitespace (OWS) from the end of a substring.
	*
	* OWS is defined in RFC 9110 sec 5.6.3 as SP (" ") or HTAB ("\t").
	*/
	function trailingOWS(header, start, end) {
		while (end > start) {
			const char = header.charCodeAt(end - 1);
			if (char !== SP && char !== HTAB) break;
			end--;
		}
		return end;
	}
	/**
	* Serialize a parameter value.
	*/
	function qstring(str) {
		if (TOKEN_REGEXP.test(str)) return str;
		if (TEXT_REGEXP.test(str)) return `"${str.replace(QUOTE_REGEXP, "\\$&")}"`;
		throw new TypeError(`Invalid parameter value: ${str}`);
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@1.1.0/node_modules/negotiator/lib/accept.js
/*!
* negotiator
* Copyright(c) 2026 Blake Embrey
* MIT Licensed
*/
var require_accept = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var contentType = require_dist();
	/**
	* Module exports.
	* @private
	*/
	module.exports = parseAccept;
	/**
	* Parse an Accept-style header.
	* @private
	*/
	function parseAccept(header) {
		var values = [];
		var index = 0;
		while (index < header.length) {
			var start = skipOptionalWhitespace(header, index);
			var parsed = contentType.parse(header, {
				comma: true,
				start
			});
			parsed.type = header.slice(start, start + parsed.type.length);
			values.push(parsed);
			index = parsed.index + 1;
		}
		return values;
	}
	/**
	* Skip optional whitespace.
	* @private
	*/
	function skipOptionalWhitespace(header, index) {
		var cursor = index;
		while (header.charCodeAt(cursor) === 32 || header.charCodeAt(cursor) === 9) cursor++;
		return cursor;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@1.1.0/node_modules/negotiator/lib/charset.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_charset = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var parseAccept = require_accept();
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredCharsets;
	module.exports.preferredCharsets = preferredCharsets;
	/**
	* Module variables.
	* @private
	*/
	function parseAcceptCharset(accept) {
		var accepts = parseAccept(accept);
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var charset = formatCharset(accepts[i], i);
			if (charset) accepts[j++] = charset;
		}
		accepts.length = j;
		return accepts;
	}
	/**
	* Format a parsed charset for negotiation.
	* @private
	*/
	function formatCharset(parsed, i) {
		if (!parsed.type) return null;
		return {
			charset: parsed.type,
			q: parsed.parameters.q ? parseFloat(parsed.parameters.q) : 1,
			i
		};
	}
	/**
	* Get the priority of a charset.
	* @private
	*/
	function getCharsetPriority(charset, accepted, index) {
		var priority = {
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(charset, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the charset.
	* @private
	*/
	function specify(charset, spec, index) {
		var s = 0;
		if (spec.charset.toLowerCase() === charset.toLowerCase()) s |= 1;
		else if (spec.charset !== "*") return null;
		return {
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred charsets from an Accept-Charset header.
	* @public
	*/
	function preferredCharsets(accept, provided) {
		var accepts = parseAcceptCharset(accept === void 0 ? "*" : accept || "");
		if (!provided) return accepts.filter(isQuality).sort(compareSpecs).map(getFullCharset);
		var priorities = provided.map(function getPriority(type, index) {
			return getCharsetPriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(compareSpecs).map(function getCharset(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i || 0;
	}
	/**
	* Get full charset string.
	* @private
	*/
	function getFullCharset(spec) {
		return spec.charset;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@1.1.0/node_modules/negotiator/lib/encoding.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_encoding = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var parseAccept = require_accept();
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredEncodings;
	module.exports.preferredEncodings = preferredEncodings;
	/**
	* Module variables.
	* @private
	*/
	function parseAcceptEncoding(accept) {
		var accepts = parseAccept(accept);
		var hasIdentity = false;
		var minQuality = 1;
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var encoding = formatEncoding(accepts[i], i);
			if (encoding) {
				accepts[j++] = encoding;
				hasIdentity = hasIdentity || specify("identity", encoding);
				minQuality = Math.min(minQuality, encoding.q || 1);
			}
		}
		if (!hasIdentity) accepts[j++] = {
			encoding: "identity",
			q: minQuality,
			i
		};
		accepts.length = j;
		return accepts;
	}
	/**
	* Format a parsed encoding for negotiation.
	* @private
	*/
	function formatEncoding(parsed, i) {
		if (!parsed.type) return null;
		return {
			encoding: parsed.type,
			q: parsed.parameters.q ? parseFloat(parsed.parameters.q) : 1,
			i
		};
	}
	/**
	* Get the priority of an encoding.
	* @private
	*/
	function getEncodingPriority(encoding, accepted, index) {
		var priority = {
			encoding,
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(encoding, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the encoding.
	* @private
	*/
	function specify(encoding, spec, index) {
		var s = 0;
		if (spec.encoding.toLowerCase() === encoding.toLowerCase()) s |= 1;
		else if (spec.encoding !== "*") return null;
		return {
			encoding,
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred encodings from an Accept-Encoding header.
	* @public
	*/
	function preferredEncodings(accept, provided, preferred) {
		var accepts = parseAcceptEncoding(accept || "");
		var comparator = preferred ? function comparator(a, b) {
			if (a.q !== b.q) return b.q - a.q;
			var aPreferred = preferred.indexOf(a.encoding);
			var bPreferred = preferred.indexOf(b.encoding);
			if (aPreferred === -1 && bPreferred === -1) return b.s - a.s || a.o - b.o || a.i - b.i;
			if (aPreferred !== -1 && bPreferred !== -1) return aPreferred - bPreferred;
			return aPreferred === -1 ? 1 : -1;
		} : compareSpecs;
		if (!provided) return accepts.filter(isQuality).sort(comparator).map(getFullEncoding);
		var priorities = provided.map(function getPriority(type, index) {
			return getEncodingPriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(comparator).map(function getEncoding(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i;
	}
	/**
	* Get full encoding string.
	* @private
	*/
	function getFullEncoding(spec) {
		return spec.encoding;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@1.1.0/node_modules/negotiator/lib/language.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_language = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var contentType = require_dist();
	var parseAccept = require_accept();
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredLanguages;
	module.exports.preferredLanguages = preferredLanguages;
	/**
	* Module variables.
	* @private
	*/
	function parseAcceptLanguage(accept) {
		var accepts = parseAccept(accept);
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var language = formatLanguage(accepts[i], i);
			if (language) accepts[j++] = language;
		}
		accepts.length = j;
		return accepts;
	}
	/**
	* Format a parsed language for negotiation.
	* @private
	*/
	function formatLanguage(parsed, i) {
		if (!parsed.type) return null;
		var hyphen = parsed.type.indexOf("-");
		return {
			prefix: hyphen === -1 ? parsed.type : parsed.type.slice(0, hyphen),
			suffix: hyphen === -1 ? void 0 : parsed.type.slice(hyphen + 1),
			q: parsed.parameters.q ? parseFloat(parsed.parameters.q) : 1,
			i,
			full: parsed.type
		};
	}
	/**
	* Get the priority of a language.
	* @private
	*/
	function getLanguagePriority(language, accepted, index) {
		var priority = {
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(language, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the language.
	* @private
	*/
	function specify(language, spec, index) {
		var p = formatLanguage(contentType.parse(language), 0);
		if (!p) return null;
		var s = 0;
		if (spec.full.toLowerCase() === p.full.toLowerCase()) s |= 4;
		else if (spec.prefix.toLowerCase() === p.full.toLowerCase()) s |= 2;
		else if (spec.full.toLowerCase() === p.prefix.toLowerCase()) s |= 1;
		else if (spec.full !== "*") return null;
		return {
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred languages from an Accept-Language header.
	* @public
	*/
	function preferredLanguages(accept, provided) {
		var accepts = parseAcceptLanguage(accept === void 0 ? "*" : accept || "");
		if (!provided) return accepts.filter(isQuality).sort(compareSpecs).map(getFullLanguage);
		var priorities = provided.map(function getPriority(type, index) {
			return getLanguagePriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(compareSpecs).map(function getLanguage(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i || 0;
	}
	/**
	* Get full language string.
	* @private
	*/
	function getFullLanguage(spec) {
		return spec.full;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@1.1.0/node_modules/negotiator/lib/mediaType.js
/**
* negotiator
* Copyright(c) 2012 Isaac Z. Schlueter
* Copyright(c) 2014 Federico Romero
* Copyright(c) 2014-2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_mediaType = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var contentType = require_dist();
	var parseAcceptHeader = require_accept();
	/**
	* Module exports.
	* @public
	*/
	module.exports = preferredMediaTypes;
	module.exports.preferredMediaTypes = preferredMediaTypes;
	/**
	* Module variables.
	* @private
	*/
	function parseAccept(accept) {
		var accepts = parseAcceptHeader(accept);
		for (var i = 0, j = 0; i < accepts.length; i++) {
			var mediaType = formatMediaType(accepts[i], i);
			if (mediaType) accepts[j++] = mediaType;
		}
		accepts.length = j;
		return accepts;
	}
	/**
	* Format a parsed content type for negotiation.
	* @private
	*/
	function formatMediaType(parsed, i) {
		var slash = parsed.type.indexOf("/");
		if (slash === -1) return null;
		var q = parsed.parameters.q ? parseFloat(parsed.parameters.q) : 1;
		delete parsed.parameters.q;
		return {
			type: parsed.type.slice(0, slash),
			subtype: parsed.type.slice(slash + 1),
			params: parsed.parameters,
			q,
			i
		};
	}
	/**
	* Get the priority of a media type.
	* @private
	*/
	function getMediaTypePriority(type, accepted, index) {
		var priority = {
			o: -1,
			q: 0,
			s: 0
		};
		for (var i = 0; i < accepted.length; i++) {
			var spec = specify(type, accepted[i], index);
			if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) priority = spec;
		}
		return priority;
	}
	/**
	* Get the specificity of the media type.
	* @private
	*/
	function specify(type, spec, index) {
		var p = formatMediaType(contentType.parse(type), 0);
		var s = 0;
		if (!p) return null;
		if (spec.type.toLowerCase() == p.type.toLowerCase()) s |= 4;
		else if (spec.type != "*") return null;
		if (spec.subtype.toLowerCase() == p.subtype.toLowerCase()) s |= 2;
		else if (spec.subtype != "*") return null;
		var keys = Object.keys(spec.params);
		if (keys.length > 0) if (keys.every(function(k) {
			return spec.params[k] == "*" || (spec.params[k] || "").toLowerCase() == (p.params[k] || "").toLowerCase();
		})) s |= 1;
		else return null;
		return {
			i: index,
			o: spec.i,
			q: spec.q,
			s
		};
	}
	/**
	* Get the preferred media types from an Accept header.
	* @public
	*/
	function preferredMediaTypes(accept, provided) {
		var accepts = parseAccept(accept === void 0 ? "*/*" : accept || "");
		if (!provided) return accepts.filter(isQuality).sort(compareSpecs).map(getFullType);
		var priorities = provided.map(function getPriority(type, index) {
			return getMediaTypePriority(type, accepts, index);
		});
		return priorities.filter(isQuality).sort(compareSpecs).map(function getType(priority) {
			return provided[priorities.indexOf(priority)];
		});
	}
	/**
	* Compare two specs.
	* @private
	*/
	function compareSpecs(a, b) {
		return b.q - a.q || b.s - a.s || a.o - b.o || a.i - b.i || 0;
	}
	/**
	* Get full type string.
	* @private
	*/
	function getFullType(spec) {
		return spec.type + "/" + spec.subtype;
	}
	/**
	* Check if a spec has any quality.
	* @private
	*/
	function isQuality(spec) {
		return spec.q > 0;
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/negotiator@1.1.0/node_modules/negotiator/index.js
/*!
* negotiator
* Copyright(c) 2012 Federico Romero
* Copyright(c) 2012-2014 Isaac Z. Schlueter
* Copyright(c) 2015 Douglas Christopher Wilson
* MIT Licensed
*/
var require_negotiator = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	var preferredCharsets = require_charset();
	var preferredEncodings = require_encoding();
	var preferredLanguages = require_language();
	var preferredMediaTypes = require_mediaType();
	/**
	* Module exports.
	* @public
	*/
	module.exports = Negotiator;
	module.exports.Negotiator = Negotiator;
	/**
	* Create a Negotiator instance from a request.
	* @param {object} request
	* @public
	*/
	function Negotiator(request) {
		if (!(this instanceof Negotiator)) return new Negotiator(request);
		this.request = request;
	}
	Negotiator.prototype.charset = function charset(available) {
		var set = this.charsets(available);
		return set && set[0];
	};
	Negotiator.prototype.charsets = function charsets(available) {
		return preferredCharsets(this.request.headers["accept-charset"], available);
	};
	Negotiator.prototype.encoding = function encoding(available, opts) {
		var set = this.encodings(available, opts);
		return set && set[0];
	};
	Negotiator.prototype.encodings = function encodings(available, options) {
		var opts = options || {};
		return preferredEncodings(this.request.headers["accept-encoding"], available, opts.preferred);
	};
	Negotiator.prototype.language = function language(available) {
		var set = this.languages(available);
		return set && set[0];
	};
	Negotiator.prototype.languages = function languages(available) {
		return preferredLanguages(this.request.headers["accept-language"], available);
	};
	Negotiator.prototype.mediaType = function mediaType(available) {
		var set = this.mediaTypes(available);
		return set && set[0];
	};
	Negotiator.prototype.mediaTypes = function mediaTypes(available) {
		return preferredMediaTypes(this.request.headers.accept, available);
	};
	Negotiator.prototype.preferredCharset = Negotiator.prototype.charset;
	Negotiator.prototype.preferredCharsets = Negotiator.prototype.charsets;
	Negotiator.prototype.preferredEncoding = Negotiator.prototype.encoding;
	Negotiator.prototype.preferredEncodings = Negotiator.prototype.encodings;
	Negotiator.prototype.preferredLanguage = Negotiator.prototype.language;
	Negotiator.prototype.preferredLanguages = Negotiator.prototype.languages;
	Negotiator.prototype.preferredMediaType = Negotiator.prototype.mediaType;
	Negotiator.prototype.preferredMediaTypes = Negotiator.prototype.mediaTypes;
}));
//#endregion
//#region ../../node_modules/.pnpm/@deepseek-ai+dsh-host-webserver@0.2.1-rc.3_@deepseek-ai+cordis@4.0.5_supports-color@7.2.0/node_modules/@deepseek-ai/dsh-host-webserver/lib/index.js
var lib_exports = /* @__PURE__ */ __exportAll({
	WebServer: () => WebServer,
	bindUrlHost: () => bindUrlHost,
	default: () => WebServer,
	isLoopbackHost: () => isLoopbackHost,
	isWildcardHost: () => isWildcardHost,
	normalizeBindAddress: () => normalizeBindAddress,
	renderIndexInjections: () => renderIndexInjections
});
var import_compression = /* @__PURE__ */ __toESM(require_compression(), 1);
var import_ipaddr = /* @__PURE__ */ __toESM(require_ipaddr(), 1);
var import_negotiator = /* @__PURE__ */ __toESM(require_negotiator(), 1);
/**
* Structured index injections: the typed rows plugins contribute to the boot
* HTML instead of raw `tapIndex` string transforms. Rows are pure
* JSON-serializable data because one table feeds two renderers: the served
* form renders rows into the index.html text ({@link renderIndexInjections}),
* and a static worker deployment ships the same rows over its boot payload
* for a page-side interpreter. Anything not expressible as a row stays on
* `tapIndex`, which runs after row rendering.
*/
/** Escape a row value before placing it in a quoted HTML attribute. */
function escapeHtmlAttribute(value) {
	return value.replaceAll("&", "&amp;").replaceAll("\"", "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}
function assertNever(row) {
	throw new Error(`webserver: unknown index injection row ${JSON.stringify(row)}`);
}
/** Render one row to markup with its placement. */
function renderRow(row) {
	switch (row.kind) {
		case "global": return {
			placement: "head",
			markup: `<script>globalThis[${JSON.stringify(row.name).replaceAll("<", "\\u003c")}] = ${row.value === void 0 ? "undefined" : JSON.stringify(row.value).replaceAll("<", "\\u003c")}<\/script>`
		};
		case "script": return {
			placement: row.placement,
			markup: `<script>${row.text}<\/script>`
		};
		case "script-src": return {
			placement: row.placement,
			markup: `<script src="${escapeHtmlAttribute(row.src)}"><\/script>`
		};
		case "script-preload": return {
			placement: "head",
			markup: `<link rel="preload" as="script" href="${escapeHtmlAttribute(row.src)}">`
		};
		case "style": return {
			placement: "head",
			markup: `<style>${row.text}</style>`
		};
		case "html": return {
			placement: row.placement,
			markup: row.html
		};
		default: return assertNever(row);
	}
}
/** Insert `markup` into `html` at `at`. */
function splice(html, at, markup) {
	return `${html.slice(0, at)}${markup}${html.slice(at)}`;
}
/**
* Tail script settling the boot-readiness deferred (`__DSH_BOOT_READY__`):
* the client entry awaits its `.promise` before reading any injected state.
* Whichever side runs first creates the deferred (`??=`), so a bootstrap that
* applies the table asynchronously installs it ahead of the entry module and
* settles it after the last row; the served form below creates and resolves
* it in one statement, because every row is already in the document text.
*/
const READY_MARKUP = "<script>(globalThis.__DSH_BOOT_READY__ ??= Promise.withResolvers()).resolve()<\/script>";
/**
* Render rows into an index.html body: head rows immediately after the
* opening head tag, body rows immediately after the opening body tag, each
* group in table order, and the boot-readiness tail after the last body row.
* @param html - the raw index.html body.
* @param rows - the collected injection table.
* @returns the html with every row rendered.
*/
function renderIndexInjections(html, rows) {
	let head = "";
	let body = "";
	for (const row of rows) {
		const rendered = renderRow(row);
		if (rendered.placement === "head") head += rendered.markup;
		else body += rendered.markup;
	}
	body += READY_MARKUP;
	let out = html;
	if (head !== "") {
		const open = /<head(?:\s[^>]*)?>/i.exec(out);
		out = open === null ? `${head}${out}` : splice(out, open.index + open[0].length, head);
	}
	if (body !== "") {
		const open = /<body(?:\s[^>]*)?>/i.exec(out);
		out = open === null ? `${out}${body}` : splice(out, open.index + open[0].length, body);
	}
	return out;
}
/**
* @deepseek-ai/dsh-host-webserver — node:http route registration — node:https
* when `tls` names a certificate and key — with optional gzip, index injection,
* and one fallback seat. It knows no harness concepts and serves no files; the
* composing application owns dist serving. Electron uses file:// plus IPC
* instead, and this package never prints the URL.
* Route handlers retain direct response ownership.
*/
const DEFAULT_COMPRESSION = "none";
const DEFAULT_COMPRESSION_LEVEL = 1;
const DEFAULT_COMPRESSION_THRESHOLD_BYTES = 1024;
/** Dotted-quad tail of the IPv6 mixed notation: `::0.0.0.1`, `1:2:3:4:5:6:127.0.0.1`. */
const IPV4_TAIL = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
/**
* Rewrite a dotted-quad tail as the two hex groups holding the same bytes.
* ipaddr.js 2.5.0 reads an all-zero prefix plus a quad (`::0.0.0.1`) as the
* IPv4-mapped form `::ffff:0:1`, while `getaddrinfo` — and so `listen` — reads
* that tail as the low 32 bits of the address itself, which makes `::0.0.0.1`
* the loopback literal `::1`. Parsing the rewritten text keeps the parsed value
* equal to the value the socket binds.
*/
function withHexTail(host) {
	const tail = IPV4_TAIL.exec(host);
	if (tail === null) return host;
	const [, head = "", a = "", b = "", c = "", d = ""] = tail;
	return `${head}${(Number(a) << 8 | Number(b)).toString(16)}:${(Number(c) << 8 | Number(d)).toString(16)}`;
}
/**
* Parse a concrete IP literal, normalizing IPv4-mapped IPv6 to IPv4.
* `node:net` decides what a value must look like for `listen` to accept it, and
* a trailing `%zone` (a local interface selector, never address text) comes off
* before parsing; the value handed to `listen` keeps its zone.
*/
function parseIpLiteral(host) {
	if (isIP(host) === 0) return void 0;
	const zoneAt = host.indexOf("%");
	const parsed = import_ipaddr.default.parse(withHexTail(zoneAt === -1 ? host : host.slice(0, zoneAt)));
	return parsed instanceof import_ipaddr.default.IPv6 && parsed.isIPv4MappedAddress() ? parsed.toIPv4Address() : parsed;
}
/** Rejection for a bind address that is no concrete IP literal. */
function notLiteralError(value) {
	return /* @__PURE__ */ new Error(`webserver: host ${JSON.stringify(value)} is not a concrete IPv4 or IPv6 address literal`);
}
/** ipaddr's IPv4 unspecified range covers all of 0/8; only the all-zero address binds every interface. */
function isWildcardAddress(parsed) {
	return (parsed instanceof import_ipaddr.default.IPv4 ? parsed.octets : parsed.parts).every((part) => part === 0);
}
/**
* Whether a bind address requests every interface at once.
* @param host - bind address from configuration.
* @returns true for IPv4 any, IPv6 any, and an IPv4-mapped form of IPv4 any.
*/
function isWildcardHost(host) {
	const parsed = parseIpLiteral(host);
	return parsed !== void 0 && isWildcardAddress(parsed);
}
/**
* Whether a bind address names the local loopback authority.
* @param host - bind address from configuration.
* @returns true for any address in 127/8, `::1`, and their IPv4-mapped forms.
*/
function isLoopbackHost(host) {
	const parsed = parseIpLiteral(host);
	return parsed !== void 0 && parsed.range() === "loopback";
}
/**
* Canonical text of the address a bind literal names: IPv4 and IPv4-mapped
* literals read as dotted quad, every other literal as its compressed IPv6
* value. The text names the address `listen` binds, so `::0.0.0.1` reads as
* `::1`. A `%zone` selects an interface and never appears in the text.
* @param host - concrete IPv4 or IPv6 literal, with or without a zone.
* @returns the address text, ready to be a URL host.
* @throws when `host` is no concrete IPv4 or IPv6 address literal.
*/
function normalizeBindAddress(host) {
	const parsed = parseIpLiteral(host);
	if (parsed === void 0) throw notLiteralError(host);
	return parsed.toString();
}
/**
* The URL host form of a bind address. Loopback addresses use their canonical
* text, so browsers treat them as local, trustworthy origins: a mapped literal
* such as `::ffff:127.0.0.1` reads as `127.0.0.1`, and `::0.0.0.1` reads as
* `::1`. A redundant loopback zone is dropped; other addresses keep their text,
* and IPv6 text is bracketed.
* @param host - concrete IPv4 or IPv6 bind literal.
* @returns the URL host, or `undefined` when a non-loopback interface zone id makes the address inexpressible in a URL.
*/
function bindUrlHost(host) {
	const zoneAt = host.indexOf("%");
	const bare = zoneAt === -1 ? host : host.slice(0, zoneAt);
	if (!isLoopbackHost(bare) && zoneAt !== -1) return void 0;
	const text = isLoopbackHost(bare) ? normalizeBindAddress(bare) : host;
	return isIP(text) === 6 ? `[${text}]` : text;
}
function createGzipMiddleware(config) {
	const middleware = (0, import_compression.default)({
		level: config.compressionLevel,
		threshold: config.compressionThresholdBytes,
		filter(request, response) {
			if (response.getHeader("content-range") !== void 0) return false;
			const contentType = response.getHeader("content-type");
			if (typeof contentType === "string" && contentType.toLowerCase().startsWith("text/event-stream")) return false;
			if (typeof contentType === "string" && /^multipart\/form-data(?:;|$)/i.test(contentType)) return true;
			return import_compression.default.filter(request, response);
		}
	});
	return (req, res, next) => {
		if (res.socket === void 0) {
			next();
			return;
		}
		const encoding = new import_negotiator.default(req).encoding(["gzip", "identity"]);
		const gzipRequest = Object.create(req);
		Object.defineProperty(gzipRequest, "headers", { value: {
			...req.headers,
			"accept-encoding": encoding === "gzip" ? "gzip" : "identity"
		} });
		middleware(gzipRequest, res, next);
	};
}
/**
* Read one TLS material file for activation. The error names the config field
* and the resolved path; empty content is rejected here because node:tls
* silently accepts it, which would bind a listener that can never complete a
* handshake.
* @param field - the config field being read, for the diagnostic.
* @param path - absolute path to read.
* @returns the file's text.
*/
async function readTlsFile(field, path) {
	let content;
	try {
		content = await readFile(path, "utf8");
	} catch (error) {
		throw new Error(`webserver: cannot read tls.${field} ${path}: ${error instanceof Error ? error.message : String(error)}`);
	}
	if (content.trim().length === 0) throw new Error(`webserver: tls.${field} ${path} is empty`);
	return content;
}
/**
* The browser HTTP carrier service. Activation loads any configured TLS
* material, then listens immediately; a material or listen failure rejects
* initialization, and the boot process reports the failed fiber. Route
* registration order does not affect requests because configured named routes
* must be distinct, and the fallback handler answers anything not yet claimed
* during startup with 404 until its owner registers.
*/
var WebServer = class extends Service {
	config;
	static Config = z.object({
		host: z.transform(z.string(), (value) => {
			const parsed = parseIpLiteral(value);
			if (parsed === void 0) throw notLiteralError(value);
			if (isWildcardAddress(parsed)) throw new Error(`webserver: host ${JSON.stringify(value)} is an unspecified (wildcard) address, which is not supported: binding every interface would expose remote code execution to the network; bind one concrete IPv4 or IPv6 address of a local interface instead`);
			return value;
		}).required(),
		port: z.natural().max(65535).required(),
		tls: z.object({
			certFile: z.string().required(),
			keyFile: z.string().required()
		}).default(void 0),
		compression: z.union([z.const("none"), z.const("gzip")]).default(DEFAULT_COMPRESSION),
		compressionLevel: z.number().step(1).min(0).max(9).default(DEFAULT_COMPRESSION_LEVEL),
		compressionThresholdBytes: z.natural().default(DEFAULT_COMPRESSION_THRESHOLD_BYTES)
	});
	exact = /* @__PURE__ */ new Map();
	prefixes = /* @__PURE__ */ new Map();
	upgrades = /* @__PURE__ */ new Map();
	upgradedSockets = /* @__PURE__ */ new Set();
	/**
	* Raw connections of a TLS listener, held until they close. A TLS connection
	* joins closeAllConnections()'s table only once its handshake completes, so a
	* socket still handshaking — or one whose peer never sends a ClientHello —
	* would otherwise keep `close()` waiting on the TLS handshake timeout. Empty
	* for the plain listener, whose connections closeAllConnections() reaches.
	*/
	tlsConnections = /* @__PURE__ */ new Set();
	indexTaps = [];
	fallback;
	server;
	listenedPort;
	gzip;
	tlsConfig;
	constructor(ctx, config) {
		super(ctx, "webServer");
		this.config = config;
		const resolved = config;
		this.tlsConfig = resolved.tls ?? void 0;
		this.gzip = resolved.compression === "gzip" ? createGzipMiddleware(resolved) : void 0;
	}
	/** The listening port (the OS-assigned value when config.port is 0), or `undefined` before `listen` binds. */
	get port() {
		return this.listenedPort;
	}
	/** The configured bind address (one concrete local interface). */
	get host() {
		return this.config.host;
	}
	/**
	* The protocol the listener speaks: `'https:'` when `tls` is configured. The
	* value follows configuration, never a socket or a request header, so a
	* consumer reads it before any request and no proxy can change it.
	*/
	get protocol() {
		return this.tlsConfig === void 0 ? "http:" : "https:";
	}
	/**
	* The root URL local clients use to reach the bound listener: the protocol,
	* the {@link bindUrlHost} form of the bind address, and the listening port.
	* @returns the origin, for example `http://127.0.0.1:3080`.
	* @throws before `listen` binds a port, or when the bind address has no URL form.
	*/
	getOrigin() {
		const host = bindUrlHost(this.config.host);
		if (host === void 0) throw new Error(`webserver: bind address ${JSON.stringify(this.config.host)} carries an interface zone id, which no URL can express`);
		if (this.listenedPort === void 0) throw new Error("webserver: origin read before the listener bound a port");
		return `${this.protocol}//${host}:${String(this.listenedPort)}`;
	}
	/**
	* Register a named route. Duplicate (kind, path) throws — route patterns are
	* a composition-level contract, so a collision is a misconfiguration.
	* @param route - kind, path, and the owning handler.
	* @returns the disposer removing the route.
	*/
	register(route) {
		const table = route.kind === "exact" ? this.exact : this.prefixes;
		if (table.has(route.path)) throw new Error(`webserver: duplicate ${route.kind} route "${route.path}"`);
		table.set(route.path, route);
		return () => {
			table.delete(route.path);
		};
	}
	/**
	* Register an exact-path HTTP upgrade route. Duplicate paths throw because
	* one socket can have only one protocol owner.
	* @param route - pathname and handler owning negotiation plus socket use.
	* @returns the disposer removing the route.
	*/
	registerUpgrade(route) {
		if (this.upgrades.has(route.path)) throw new Error(`webserver: duplicate upgrade route "${route.path}"`);
		this.upgrades.set(route.path, route);
		return () => {
			this.upgrades.delete(route.path);
		};
	}
	/**
	* Claim the fallback seat: the handler answering every request no named
	* route matches (the SPA dist server in the shipped Web composition). One
	* owner only — a second registration throws, because two fallbacks cannot
	* compose.
	* @param handler - owns the full response lifecycle of unmatched requests.
	* @returns the disposer releasing the seat.
	*/
	registerFallback(handler) {
		if (this.fallback !== void 0) throw new Error("webserver: fallback already registered");
		this.fallback = handler;
		return () => {
			this.fallback = void 0;
		};
	}
	/**
	* Register a raw-HTML index transform, the escape hatch for markup no
	* {@link IndexInjection} row expresses: {@link renderIndex} applies taps in
	* registration order after rendering the structured rows.
	* @param transform - pure html-to-html function.
	* @returns the disposer removing the transform.
	*/
	tapIndex(transform) {
		this.indexTaps.push(transform);
		return () => {
			const at = this.indexTaps.indexOf(transform);
			if (at !== -1) this.indexTaps.splice(at, 1);
		};
	}
	/** Listen; resolves once the socket is bound (rejection = FAILED fiber). */
	async [Service.init]() {
		const handle = async (req, res) => {
			/* v8 ignore next -- `?? '/'` arm: node:http always sets url on server
			requests; the field is only optional on the client-side IncomingMessage type */
			const rawPath = new URL(req.url ?? "/", "http://x").pathname;
			const route = this.match(rawPath);
			if (route !== void 0) {
				await route.handler(req, res);
				return;
			}
			const fallback = this.fallback;
			if (fallback === void 0) {
				res.writeHead(404);
				res.end();
				return;
			}
			await fallback(req, res);
		};
		const listener = (req, res) => {
			const next = () => {
				handle(req, res).catch((err) => {
					this.ctx.logger.warn(err instanceof Error ? err : new Error(String(err)));
					if (res.headersSent) {
						res.destroy();
						return;
					}
					res.writeHead(400);
					res.end();
				});
			};
			if (this.gzip === void 0) next();
			else this.gzip(req, res, next);
		};
		const tls = this.tlsConfig;
		await this.ctx.effect(async () => {
			if (tls === void 0) this.server = createServer(listener);
			else {
				const certFile = resolve(tls.certFile);
				const keyFile = resolve(tls.keyFile);
				const [cert, key] = await Promise.all([readTlsFile("certFile", certFile), readTlsFile("keyFile", keyFile)]);
				try {
					this.server = createServer$1({
						cert,
						key
					}, listener);
				} catch (error) {
					throw new Error(`webserver: tls.certFile ${certFile} and tls.keyFile ${keyFile} are not a usable certificate and key pair: ${error instanceof Error ? error.message : String(error)}`);
				}
				this.server.on("connection", (socket) => {
					this.tlsConnections.add(socket);
					socket.once("close", () => {
						this.tlsConnections.delete(socket);
					});
				});
			}
			this.server.on("upgrade", (req, socket, head) => {
				const onError = (error) => {
					this.ctx.logger.warn(error);
					socket.destroy();
				};
				socket.on("error", onError);
				socket.once("close", () => {
					socket.off("error", onError);
					this.upgradedSockets.delete(socket);
				});
				let route;
				try {
					/* v8 ignore next -- node:http always sets url on server requests. */
					route = this.upgrades.get(new URL(req.url ?? "/", "http://x").pathname);
				} catch (error) {
					this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
					socket.destroy();
					return;
				}
				if (route === void 0) {
					socket.destroy();
					return;
				}
				this.upgradedSockets.add(socket);
				try {
					Promise.resolve(route.handler(req, socket, head)).catch((error) => {
						this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
						socket.destroy();
					});
				} catch (error) {
					this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
					socket.destroy();
				}
			});
			await new Promise((resolve, reject) => {
				this.server.once("error", reject);
				this.server.listen(this.config.port, this.config.host, () => {
					this.server.off("error", reject);
					this.server.on("error", (err) => {
						this.ctx.logger.error(err);
					});
					this.listenedPort = this.server.address().port;
					resolve();
				});
			});
			return async () => {
				const serverClosed = new Promise((resolve) => {
					this.server.close(() => {
						resolve();
					});
				});
				this.server.closeAllConnections();
				const socketsClosed = [...this.upgradedSockets, ...this.tlsConnections].map((socket) => new Promise((resolve) => {
					socket.once("close", () => {
						resolve();
					});
					socket.destroy();
				}));
				await Promise.all([serverClosed, ...socketsClosed]);
			};
		}, "webServer.listen");
	}
	/** Longest-prefix-wins over the prefix table after an exact-table miss. */
	match(pathname) {
		const exact = this.exact.get(pathname);
		if (exact !== void 0) return exact;
		let best;
		for (const [prefix, route] of this.prefixes) {
			if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
			if (best === void 0 || prefix.length > best.path.length) best = route;
		}
		return best;
	}
	/**
	* Run an index.html body through the registered taps in registration order
	* — called by the fallback owner on every index response it renders.
	* @param html - the raw index.html body.
	* @returns the transformed body.
	*/
	applyIndexTaps(html) {
		let out = html;
		for (const transform of this.indexTaps) out = transform(out);
		return out;
	}
	/**
	* Gather the structured injection table: one `webserver/index-inject` emit,
	* every subscriber pushes its current rows. Fresh per call, so subscribers
	* read live state (module graph, theme preference) at emit time.
	* @returns rows in subscriber activation order.
	*/
	collectIndexInjections() {
		const table = [];
		this.ctx.emit("webserver/index-inject", table);
		return table;
	}
	/**
	* Render one index.html body: the structured injection table first, then
	* the raw `tapIndex` transforms over the result.
	* @param html - the raw index.html body.
	* @returns the transformed body.
	*/
	renderIndex(html) {
		return this.applyIndexTaps(renderIndexInjections(html, this.collectIndexInjections()));
	}
};
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
	const factory = configOf ?? configSchemaOf(lib_exports);
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
		const fn = lib_exports[name];
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
		const fn = bindUrlHost;
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
	return "(function(){try{var w=window,loc=w.location,h=loc.hostname;var R=" + json + ";if(h==='localhost'||h==='::1'||h==='[::1]'||/^127(\\.\\d{1,3}){3}$/.test(h))return;var pr=loc.protocol;if(typeof pr===\"string\"&&pr!==\"\"&&R.webProtocols.indexOf(pr)===-1)return;try{if(w.__DSH_TRANSPORT__&&w.__DSH_TRANSPORT__.ownsHost===true&&h.indexOf(\".\")===-1&&h.indexOf(\":\")===-1)return}catch(e){}try{if(w[R.hostGrantGlobal]===true){if(w.__DSH_TRANSPORT__===undefined)w.__DSH_TRANSPORT__={};w.__DSH_TRANSPORT__.ownsHost=true}}catch(e){}function rdv(){try{return w.sessionStorage.getItem(R.deviceKey)}catch(e){return null}}function att(init){var dv=rdv();if(dv===null)return init;var h=init&&init.headers;if(typeof Headers!==\"undefined\"&&h instanceof Headers){try{h.set(R.deviceHeader,dv)}catch(e){}return init}if(typeof h===\"object\"&&h!==null){var o={};for(var k in h)o[k]=h[k];o[R.deviceHeader]=dv;return Object.assign({},init,{headers:o})}return init}function sf(p){if(p.indexOf(R.pairPrefix)===0)return false;if(p.indexOf(R.updatePrefix)===0)return false;if(p===R.settingsBridgePrefix||p.indexOf(R.settingsBridgePrefix+\"/\")===0)return false;if(p.indexOf(R.apiPrefix)===0)return true;if(p.indexOf(R.sidebarPrefix)===0||p===\"/sidebar\")return true;if(p.indexOf(R.gitPrefix)===0||p===\"/git\")return true;if(p.indexOf(R.petPrefix)===0||p===\"/pet\")return true;/*wj-adapters:start*/if(/^\\/dsh-market\\/(?:registry|status|installed|updates|updates\\/summary|find-compatible|discovery-compatibility|snapshots|logs|presets|bundle-order|groups|check|changelog|build-env|channel|entry-visibility|github-proxy|api\\/v1\\/capabilities)(?:\\/|$)/.test(p))return true;/*wj-adapters:end*/return false}function sw(p){return R.wsPaths.indexOf(p)!==-1}function rp(p){return R.remotePrefix+p}function so(u){return u.origin===loc.origin}function rr(raw){var u;try{u=new URL(raw,loc.href)}catch(e){return raw}if(u.origin!==loc.origin)return raw;if(!sf(u.pathname))return raw;u.pathname=rp(u.pathname);if(raw.charAt(0)===\"/\"&&raw.charAt(1)!==\"/\")return u.pathname+u.search+u.hash;return u.href}function uc(v){if(typeof v!==\"object\"||v===null)return undefined;var n=v.result;if(typeof n===\"object\"&&n!==null){var e=n.error;if(typeof e===\"object\"&&e!==null&&typeof e.code===\"string\")return e.code}var t=v.error;if(typeof t===\"object\"&&t!==null&&typeof t.code===\"string\")return t.code;return undefined}var seat={onUnpaired:null,onPaired:null,pendingUnpaired:false,restore:function(){}};function denied(res){if(res.status!==403)return false;return res.clone().json().then(function(b){return uc(b)===\"unpaired\"}).catch(function(){return false})}function signal(unpaired){if(unpaired){if(seat.onUnpaired)seat.onUnpaired();else seat.pendingUnpaired=true}else{seat.pendingUnpaired=false;if(seat.onPaired)seat.onPaired()}}var of=w.fetch;w.fetch=function(input,init){var raw=typeof input===\"string\"||input instanceof URL?input.toString():input.url;var url=new URL(raw,loc.href);if(so(url)&&sf(url.pathname)){var next=new URL(url);next.pathname=rp(url.pathname);var target=typeof input===\"string\"||input instanceof URL?next.toString():new Request(next,input);return Promise.resolve(of.call(w,target,att(init))).then(function(res){void Promise.resolve(denied(res)).then(signal);return res})}return of.call(w,input,init)};var OW=w.WebSocket;w.WebSocket=function(url,protocols){var p=new URL(url.toString(),loc.href);var o=p.protocol===\"wss:\"?\"https://\"+p.host:p.protocol===\"ws:\"?\"http://\"+p.host:\"\";if(o!==\"\"&&o===loc.origin&&sw(p.pathname)){var nx=new URL(p);nx.pathname=rp(p.pathname);var dvv=rdv();if(dvv!==null)nx.searchParams.set(R.deviceQuery,dvv);return protocols!==undefined?new OW(nx,protocols):new OW(nx)}return protocols!==undefined?new OW(url,protocols):new OW(url)};w.WebSocket.prototype=OW.prototype;w.WebSocket.CONNECTING=OW.CONNECTING;w.WebSocket.OPEN=OW.OPEN;w.WebSocket.CLOSING=OW.CLOSING;w.WebSocket.CLOSED=OW.CLOSED;var OE=w.EventSource;if(OE!==undefined){w.EventSource=function(url,cfg){var p=new URL(url.toString(),loc.href);if(so(p)&&sf(p.pathname)){var nx=new URL(p);nx.pathname=rp(p.pathname);var dvv=rdv();if(dvv!==null)nx.searchParams.set(R.deviceQuery,dvv);return new OE(nx,cfg)}return new OE(url,cfg)};w.EventSource.prototype=OE.prototype}var restores=[];function patchSrc(C){if(C===undefined)return;var d=Object.getOwnPropertyDescriptor(C.prototype,\"src\");if(d===undefined||d.configurable===false||d.set===undefined)return;var os=d.set;Object.defineProperty(C.prototype,\"src\",{configurable:true,enumerable:d.enumerable!==false,get:d.get,set:function(v){os.call(this,rr(String(v)))}});restores.push(function(){Object.defineProperty(C.prototype,\"src\",d)})}patchSrc(w.HTMLImageElement);patchSrc(w.HTMLScriptElement);patchSrc(w.HTMLIFrameElement);function uf(u,init){var raw=typeof u===\"string\"?u:u.href;if(typeof raw!==\"string\")return of.call(w,u,init||{});var q=new URL(raw,loc.href);if(so(q)&&q.pathname===R.uploadPath)return w.fetch(raw,init||{});return of.call(w,u,init||{})}try{if(w[R.uploadHookGlobal]===undefined)w[R.uploadHookGlobal]={fetch:uf}}catch(e){}seat.restore=function(){w.fetch=of;w.WebSocket=OW;if(OE!==undefined)w.EventSource=OE;for(var i=0;i<restores.length;i++)restores[i]();try{delete w[" + seat + "]}catch(e){w[" + seat + "]=undefined}};w[" + seat + "]=seat" + buildBootWatchdogScript() + "}catch(e){}})();";
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
		devicesFile: resolved.devicesFile
	};
}
/** Default paired-session store: `$DSH_HOME/wj-dsh-remote-devices.json`. */
function defaultDevicesFile(home = dshHome()) {
	return join(home, "wj-dsh-remote-devices.json");
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
