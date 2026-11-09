import { describe, expect, it } from "vitest";
import { formatTime } from "../web/format-time";

describe("formatTime", () => {
  it("formats local time as YYYY-MM-DD HH:MM, 24 h, zero padded", () => {
    expect(formatTime(new Date(2026, 10, 9, 22, 3).getTime())).toBe("2026-11-09 22:03");
    expect(formatTime(new Date(2026, 0, 2, 4, 5).getTime())).toBe("2026-01-02 04:05");
    expect(formatTime(new Date(2026, 5, 1, 0, 0).getTime())).toBe("2026-06-01 00:00");
  });
});
