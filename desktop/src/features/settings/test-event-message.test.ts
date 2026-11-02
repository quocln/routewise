import { describe, expect, it } from "vitest";
import { testEventMessage } from "./error-reporting-section";

describe("testEventMessage", () => {
  it("shows the short event id of a sent event", () => {
    expect(testEventMessage({ outcome: "sent", eventId: "0123456789abcdef" })).toEqual({
      kind: "ok",
      text: "Test event sent (01234567). It should appear in your project shortly.",
    });
  });

  it("explains why nothing was sent", () => {
    expect(testEventMessage({ outcome: "notRunning" }).kind).toBe("error");
    expect(testEventMessage({ outcome: "dropped" }).text).toBe("The SDK did not accept the test event.");
  });
});
