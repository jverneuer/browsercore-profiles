import { describe, expect, it } from "vitest";
import { assertNever, createId } from "../src/utils.js";
import type { ProfileId } from "../src/types.js";

describe("assertNever", () => {
    it("throws an error describing the unexpected value", () => {
        expect(() => assertNever("surprise" as never)).toThrow("Unexpected value");
    });

    it("includes the JSON-serialized value in the message", () => {
        // Complex values surface as JSON so the exhaustiveness failure is debuggable.
        try {
            assertNever({ weird: true } as never);
            expect.unreachable("expected throw");
        } catch (e) {
            expect((e as Error).message).toContain('"weird":true');
        }
    });
});

describe("createId", () => {
    it("builds a profile id from name and version", () => {
        expect(createId("chrome", "140")).toBe("chrome-140");
    });

    it("produces a value assignable to the branded ProfileId type", () => {
        // The helper exists specifically to brand a plain string as ProfileId;
        // it must round-trip through the type system without a cast at call sites.
        const id: ProfileId = createId("firefox", "135");
        expect(id).toBe("firefox-135");
    });

    it("handles multi-segment versions and unusual names", () => {
        expect(createId("edge", "128.0.2739.70")).toBe("edge-128.0.2739.70");
        expect(createId("my-browser", "1")).toBe("my-browser-1");
    });
});
