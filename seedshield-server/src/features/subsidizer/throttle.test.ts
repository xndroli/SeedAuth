import { describe, it, expect, beforeEach, vi } from "vitest";
import { ThrottlePolicy } from "./throttle.js";

describe("ThrottlePolicy", () => {
  let throttle: ThrottlePolicy;

  beforeEach(() => {
    throttle = new ThrottlePolicy(2, 1000); // 2 requests per 1 second
  });

  it("should allow requests within limit", () => {
    expect(throttle.checkAndIncrement("device1")).toBe(true);
    expect(throttle.checkAndIncrement("device1")).toBe(true);
  });

  it("should block requests exceeding limit", () => {
    throttle.checkAndIncrement("device1");
    throttle.checkAndIncrement("device1");
    expect(throttle.checkAndIncrement("device1")).toBe(false);
  });

  it("should allow requests from different devices", () => {
    throttle.checkAndIncrement("device1");
    throttle.checkAndIncrement("device1");
    expect(throttle.checkAndIncrement("device2")).toBe(true);
  });

  it("should reset after window passes", () => {
    vi.useFakeTimers();
    throttle.checkAndIncrement("device1");
    throttle.checkAndIncrement("device1");
    expect(throttle.checkAndIncrement("device1")).toBe(false);

    vi.advanceTimersByTime(1001);
    expect(throttle.checkAndIncrement("device1")).toBe(true);
    vi.useRealTimers();
  });

  it("should reset manually", () => {
    throttle.checkAndIncrement("device1");
    throttle.checkAndIncrement("device1");
    expect(throttle.checkAndIncrement("device1")).toBe(false);

    throttle.reset("device1");
    expect(throttle.checkAndIncrement("device1")).toBe(true);
  });
});
