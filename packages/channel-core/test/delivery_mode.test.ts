import { afterEach, describe, expect, test } from "vitest";
import { DELIVERY_MODE_ENV, selectDeliveryMode } from "../src/config.js";

const originalDelivery = process.env[DELIVERY_MODE_ENV];

afterEach(() => {
  if (originalDelivery === undefined) {
    delete process.env[DELIVERY_MODE_ENV];
  } else {
    process.env[DELIVERY_MODE_ENV] = originalDelivery;
  }
});

describe("selectDeliveryMode", () => {
  test("an unset AWEB_DELIVERY keeps the native channel", () => {
    expect(selectDeliveryMode({})).toEqual({ mode: "channel" });
  });

  test("channel keeps the native channel", () => {
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "channel" })).toEqual({ mode: "channel" });
  });

  test("session hands delivery to an external wake path", () => {
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "session" })).toEqual({ mode: "session" });
  });

  test("an unknown value warns and still delivers through the native channel", () => {
    const selection = selectDeliveryMode({ [DELIVERY_MODE_ENV]: "external" });
    expect(selection.mode).toBe("channel");
    expect(selection.warning).toContain(DELIVERY_MODE_ENV);
    expect(selection.warning).toContain("external");
    expect(selection.warning).toContain("channel");
    expect(selection.warning).toContain("session");
  });

  test("an unknown value never turns delivery off", () => {
    // The failure this guards is silent deafness: a typo must not leave the
    // agent with neither the channel nor an external wake path.
    for (const value of ["sessions", "sesion", "off", "none", "true", "0"]) {
      expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: value }).mode).toBe("channel");
      expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: value }).warning).toBeTruthy();
    }
  });

  test("an empty or whitespace value reads as unset, without a warning", () => {
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "" })).toEqual({ mode: "channel" });
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "   " })).toEqual({ mode: "channel" });
  });

  test("surrounding whitespace and letter case do not change the decision", () => {
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "  session  " })).toEqual({ mode: "session" });
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "SESSION" })).toEqual({ mode: "session" });
    expect(selectDeliveryMode({ [DELIVERY_MODE_ENV]: "Channel" })).toEqual({ mode: "channel" });
  });

  test("reads the process environment when no environment is passed", () => {
    process.env[DELIVERY_MODE_ENV] = "session";
    expect(selectDeliveryMode()).toEqual({ mode: "session" });
    delete process.env[DELIVERY_MODE_ENV];
    expect(selectDeliveryMode()).toEqual({ mode: "channel" });
  });
});
