import { describe, expect, it } from "vitest";

import { primaryConnectionAction, primaryConnectionActionDisabled } from "./connectionControls";

describe("primary connection control", () => {
  it("turns a click during startup into cancellation instead of duplicate connect", () => {
    expect(primaryConnectionAction(false, "starting")).toBe("disconnect");
    expect(primaryConnectionActionDisabled(false, "starting")).toBe(false);
  });

  it("remains disabled while stop is already in progress", () => {
    expect(primaryConnectionActionDisabled(false, "stopping")).toBe(true);
  });
});
