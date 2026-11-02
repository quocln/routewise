/** The largest file accepted as a WireGuard config. */
export const MAX_CONFIG_BYTES = 256 * 1024;

/**
 * Reads a WireGuard config file the user picked. Errors name the file, never
 * its content, because the content holds a private key.
 */
export async function readWireGuardConfig(file: File): Promise<string> {
  if (file.size > MAX_CONFIG_BYTES) throw new Error(`${file.name} is too large to be a WireGuard config.`);
  let bytes: ArrayBuffer;
  try {
    bytes = await file.arrayBuffer();
  } catch {
    throw new Error(`Could not read ${file.name}.`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${file.name} is not a text file.`);
  }
}

/** A profile name suggested by a config file name: "work.conf" becomes "work". */
export function nameFromFile(file: File): string {
  return file.name.replace(/\.[^.]*$/, "");
}
