/**
 * Validates and normalises one entry of a domain list: a domain pattern, an
 * IPv4 address, or an IPv4 CIDR. It mirrors `config.ParseEntry` in the helper,
 * which stays the authority: the app uses it to reject an entry early with a
 * readable message, and the helper checks again.
 */

/** The shortest CIDR a list may hold. */
export const MIN_PREFIX_BITS = 8;

export type EntryKind = "domain" | "ip" | "cidr";

/** A valid entry. `value` is canonical: a CIDR is its network address and a /32 is the plain IP. */
export interface ParsedEntry {
  kind: EntryKind;
  value: string;
}

export type ParseResult = { ok: true; entry: ParsedEntry } | { ok: false; message: string };

/** Ranges an entry may never be or overlap: this-network, loopback, link-local, multicast/reserved. */
const RESERVED: readonly { base: number; bits: number; name: string }[] = [
  { base: 0x00000000, bits: 8, name: "this network 0.0.0.0/8" },
  { base: 0x7f000000, bits: 8, name: "loopback 127.0.0.0/8" },
  { base: 0xa9fe0000, bits: 16, name: "link-local 169.254.0.0/16" },
  { base: 0xe0000000, bits: 3, name: "multicast and reserved 224.0.0.0/3" },
];

// Exact names, "*.example.com" and "qa*.example.com": one '*', first label only.
const DOMAIN_PATTERN =
  /^(?:[a-zA-Z0-9-]*\*[a-zA-Z0-9-]*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*)[a-zA-Z]{2,}$/;

const IPV6_MESSAGE = "IPv6 is not supported; use an IPv4 address or CIDR";

/** IPv6 text has at least two colons; one colon is an IPv4 address with a port. */
function looksIPv6(text: string): boolean {
  return text.split(":").length - 1 >= 2;
}

/** Four decimal octets, each 0-255 with no leading zero, as Go's netip reads them. */
function parseIPv4(text: string): number | undefined {
  const parts = text.split(".");
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    value = value * 256 + octet;
  }
  return value;
}

/** A prefix length 0-32 with no sign or leading zero. */
function parseBits(text: string): number | undefined {
  if (!/^(0|[1-9][0-9]?)$/.test(text)) return undefined;
  const bits = Number(text);
  return bits <= 32 ? bits : undefined;
}

function mask(bits: number): number {
  return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
}

function format(address: number): string {
  return [address >>> 24, (address >>> 16) & 0xff, (address >>> 8) & 0xff, address & 0xff].join(".");
}

/** The reserved range the network `address/bits` is or overlaps, if any. */
function overlappedReserved(address: number, bits: number): string | undefined {
  for (const block of RESERVED) {
    const shared = Math.min(bits, block.bits);
    if ((address & mask(shared)) >>> 0 === (block.base & mask(shared)) >>> 0) return block.name;
  }
  return undefined;
}

function fail(message: string): ParseResult {
  return { ok: false, message };
}

/** Classifies `entry`, or returns the reason it is not valid. */
export function parseEntry(entry: string): ParseResult {
  if (entry === "") return fail("Pattern cannot be empty");

  const slash = entry.indexOf("/");
  if (slash >= 0) {
    if (looksIPv6(entry)) return fail(IPV6_MESSAGE);
    const address = parseIPv4(entry.slice(0, slash));
    const bits = parseBits(entry.slice(slash + 1));
    if (address === undefined || bits === undefined) {
      return fail("Not a valid IPv4 CIDR such as 10.20.0.0/16");
    }
    if (bits < MIN_PREFIX_BITS) {
      return fail(`/${bits} is too broad: the shortest CIDR allowed is /${MIN_PREFIX_BITS}`);
    }
    const reserved = overlappedReserved(address, bits);
    if (reserved) return fail(`${entry} is or overlaps ${reserved}, which cannot be routed`);
    const network = (address & mask(bits)) >>> 0;
    if (bits === 32) return { ok: true, entry: { kind: "ip", value: format(network) } };
    return { ok: true, entry: { kind: "cidr", value: `${format(network)}/${bits}` } };
  }

  if (entry.includes(":")) return fail(looksIPv6(entry) ? IPV6_MESSAGE : "Not a valid IPv4 address");

  const address = parseIPv4(entry);
  if (address !== undefined) {
    const reserved = overlappedReserved(address, 32);
    if (reserved) return fail(`${entry} is or overlaps ${reserved}, which cannot be routed`);
    return { ok: true, entry: { kind: "ip", value: format(address) } };
  }
  if (/^[0-9.]+$/.test(entry)) return fail("Not a valid IPv4 address");

  if (DOMAIN_PATTERN.test(entry)) return { ok: true, entry: { kind: "domain", value: entry } };
  return fail("Invalid pattern format");
}

/** The message explaining why `entry` is invalid, or undefined when it is valid. */
export function validateEntry(entry: string): string | undefined {
  const result = parseEntry(entry);
  return result.ok ? undefined : result.message;
}

/**
 * The form an entry is stored in: a valid IP or CIDR in canonical form
 * (10.20.5.1/16 becomes 10.20.0.0/16, x/32 becomes x); anything else as written.
 */
export function canonicalEntry(entry: string): string {
  const result = parseEntry(entry);
  return result.ok && result.entry.kind !== "domain" ? result.entry.value : entry;
}

/** What an entry is, for its icon and label. An invalid entry is a domain or wildcard. */
export function entryDisplayKind(pattern: string): "ip" | "range" | "wildcard" | "domain" {
  const result = parseEntry(pattern);
  if (result.ok && result.entry.kind === "ip") return "ip";
  if (result.ok && result.entry.kind === "cidr") return "range";
  return pattern.includes("*") ? "wildcard" : "domain";
}
