const SHAPE_MESSAGE = "Enter a DSN like https://<key>@<host>/<project id>.";

/**
 * Client-side check of a DSN's shape, so an obvious typo is caught before the
 * round trip. The helper validates it again and its message wins. Empty is
 * valid: it switches reporting off. Returns a message, or undefined when fine.
 * The DSN is a secret: it is never part of the message.
 */
export function dsnValidationMessage(raw: string): string | undefined {
  const dsn = raw.trim();
  if (dsn === "") return undefined;
  let url: URL;
  try {
    url = new URL(dsn);
  } catch {
    return SHAPE_MESSAGE;
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.hostname === "" || url.username === "") {
    return SHAPE_MESSAGE;
  }
  const project = url.pathname.split("/").filter(Boolean).pop() ?? "";
  return project === "" ? "The DSN needs a project id at the end." : undefined;
}
