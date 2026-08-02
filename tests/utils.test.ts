import { describe, expect, it } from "vitest";
import { assertNever, createId } from "../src/utils.js";

describe("assertNever", () => {
    it("throws an error describing the unexpected value", () => {
        expect(() => assertNever("surprise" as never)).toThrow("Unexpected value");
    });
});

describe("createId", () => {
    it("builds a profile id from name and version", () => {
        expect(createId("chrome", "140")).toBe("chrome-140");
    });
});
