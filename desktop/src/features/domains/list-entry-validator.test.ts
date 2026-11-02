import { describe, expect, it } from "vitest";
import { canonicalEntry, entryDisplayKind, parseEntry, validateEntry } from "./list-entry-validator";

describe("domain patterns", () => {
  it("accepts exact and wildcard patterns", () => {
    for (const pattern of ["example.com", "api.example.com", "*.example.com", "qa*.example.com", "a-b.example.co"]) {
      expect(validateEntry(pattern), pattern).toBeUndefined();
    }
  });

  it("rejects malformed patterns", () => {
    const bad = ["", "*", "*.com", "a.*.example.com", "*.*.example.com", "ex*ample", "-a.example.com", "example.c", "example.com.", "exa mple.com"];
    for (const pattern of bad) expect(validateEntry(pattern), pattern).toBeDefined();
  });
});

describe("IPv4 and CIDR entries", () => {
  it("accepts addresses and ranges", () => {
    const good = ["10.20.30.40", "10.20.0.0/16", "10.20.5.1/16", "10.20.30.40/32", "10.20.30.41/31", "10.0.0.0/8", "192.168.1.77/24", "223.255.255.255", "126.255.255.255/9", "169.253.0.0/16"];
    for (const entry of good) expect(validateEntry(entry), entry).toBeUndefined();
  });

  it("rejects IPv6", () => {
    for (const entry of ["::1", "2001:db8::1", "2001:db8::/32", "::ffff:10.0.0.1"]) {
      expect(validateEntry(entry), entry).toBe("IPv6 is not supported; use an IPv4 address or CIDR");
    }
  });

  it("rejects CIDRs shorter than /8", () => {
    for (const entry of ["10.0.0.0/7", "0.0.0.0/0", "128.0.0.0/1", "224.0.0.0/4"]) {
      expect(validateEntry(entry), entry).toContain("too broad");
    }
  });

  it("rejects reserved ranges", () => {
    const bad = ["0.0.0.0/8", "0.0.0.1", "127.0.0.1", "127.5.0.0/16", "224.0.0.0/8", "239.1.1.1", "255.255.255.255", "240.0.0.0/8", "169.254.1.0/24", "169.254.169.254"];
    for (const entry of bad) expect(validateEntry(entry), entry).toContain("cannot be routed");
  });

  it("rejects malformed IPv4 entries", () => {
    const bad = ["10.20.30.400", "10.20.30", "010.20.30.40", "10.20.30.40/33", "10.20.30.40/", "10.20.30.40/abc", "10.20.30.40/08", "10.20.30.40:80", "10.20.30.40.5", "10..30.40", "-10.20.30.40/16"];
    for (const entry of bad) expect(validateEntry(entry), entry).toBeDefined();
  });

  it("says why an entry is not an address", () => {
    expect(validateEntry("")).toBe("Pattern cannot be empty");
    expect(validateEntry("10.20.30.400")).toBe("Not a valid IPv4 address");
    expect(validateEntry("10.20.30.40:80")).toBe("Not a valid IPv4 address");
    expect(validateEntry("10.20.30.40/33")).toBe("Not a valid IPv4 CIDR such as 10.20.0.0/16");
    expect(validateEntry("ex*ample")).toBe("Invalid pattern format");
    expect(validateEntry("10.0.0.0/7")).toBe("/7 is too broad: the shortest CIDR allowed is /8");
    expect(validateEntry("127.0.0.1")).toBe("127.0.0.1 is or overlaps loopback 127.0.0.0/8, which cannot be routed");
  });
});

describe("normalisation", () => {
  it("canonicalises IPs and CIDRs", () => {
    expect(canonicalEntry("10.20.5.1/16")).toBe("10.20.0.0/16");
    expect(canonicalEntry("10.20.30.40/32")).toBe("10.20.30.40");
    expect(canonicalEntry("10.20.30.41/31")).toBe("10.20.30.40/31");
    expect(canonicalEntry("192.168.1.77/24")).toBe("192.168.1.0/24");
    expect(canonicalEntry("10.20.30.40")).toBe("10.20.30.40");
    expect(canonicalEntry("Example.COM")).toBe("Example.COM");
    expect(canonicalEntry("10.0.0.0/7")).toBe("10.0.0.0/7");
  });

  it("classifies entries", () => {
    const kind = (entry: string) => {
      const result = parseEntry(entry);
      return result.ok ? result.entry.kind : undefined;
    };
    expect(kind("example.com")).toBe("domain");
    expect(kind("*.example.com")).toBe("domain");
    expect(kind("10.20.30.40")).toBe("ip");
    expect(kind("10.20.30.40/32")).toBe("ip");
    expect(kind("10.20.0.0/16")).toBe("cidr");
    expect(kind("10.0.0.0/7")).toBeUndefined();
  });

  it("labels rows by what the entry is", () => {
    expect(entryDisplayKind("10.20.30.40")).toBe("ip");
    expect(entryDisplayKind("10.20.0.0/16")).toBe("range");
    expect(entryDisplayKind("*.example.com")).toBe("wildcard");
    expect(entryDisplayKind("example.com")).toBe("domain");
  });
});
