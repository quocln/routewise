import { describe, expect, it } from "vitest";
import { MAX_CONFIG_BYTES, nameFromFile, readWireGuardConfig } from "./wireguard-config-file";

const FAKE_CONFIG = "[Interface]\nPrivateKey = FAKE-NOT-A-REAL-KEY\n";

describe("readWireGuardConfig", () => {
  it("returns the text of the file", async () => {
    const file = new File([FAKE_CONFIG], "work.conf");
    expect(await readWireGuardConfig(file)).toBe(FAKE_CONFIG);
  });

  it("refuses a file that is too large, naming it but not its content", async () => {
    const file = new File([`${FAKE_CONFIG}${"x".repeat(MAX_CONFIG_BYTES)}`], "big.conf");
    const error = await readWireGuardConfig(file).catch((e: Error) => e);
    expect(error).toEqual(new Error("big.conf is too large to be a WireGuard config."));
  });

  it("refuses a file that is not UTF-8 text", async () => {
    const file = new File([new Uint8Array([0xff, 0xfe, 0xfd])], "bin.conf");
    const error = await readWireGuardConfig(file).catch((e: Error) => e);
    expect(error).toEqual(new Error("bin.conf is not a text file."));
  });
});

describe("nameFromFile", () => {
  it("drops the extension", () => {
    expect(nameFromFile(new File([""], "office.vpn.conf"))).toBe("office.vpn");
    expect(nameFromFile(new File([""], "noext"))).toBe("noext");
  });
});
