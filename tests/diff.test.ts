import { describe, expect, it } from "vitest";
import { getProfile } from "../src/index.js";
import type { BrowserProfile, ProfileId } from "../src/types.js";
import { diffProfiles } from "../src/diff.js";

/**
 * Build a structurally-equal clone of a profile (same values, new references) so
 * the diff exercises value comparison rather than reference equality short-circuit.
 */
function clone(profile: BrowserProfile): BrowserProfile {
    return JSON.parse(JSON.stringify(profile)) as BrowserProfile;
}

describe("diffProfiles", () => {
    it("returns an empty diff for two structurally-identical profiles", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const b = clone(a);

        expect(diffProfiles(a, b)).toEqual([]);
    });

    it("reports exactly one diff when a single tls field (grease) differs", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const b: BrowserProfile = {
            ...a,
            tls: { ...a.tls, grease: false },
        };

        const diffs = diffProfiles(a, b);

        expect(diffs).toHaveLength(1);
        expect(diffs[0]?.path).toBe("tls.grease");
        expect(diffs[0]?.a).toBe(true);
        expect(diffs[0]?.b).toBe(false);
    });

    it("reports a diff when cipher suites are reordered", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const reordered = [...a.tls.cipherSuites].reverse();
        const b: BrowserProfile = {
            ...a,
            tls: { ...a.tls, cipherSuites: reordered },
        };

        const diffs = diffProfiles(a, b);

        // Reordering changes at least the first element.
        expect(diffs.some((d) => d.path === "tls.cipherSuites[0]")).toBe(true);
        expect(diffs.length).toBeGreaterThan(0);
    });

    it("reports a diff at the nested path when http2 settings differ", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const b: BrowserProfile = {
            ...a,
            http2: {
                ...a.http2,
                settings: {
                    ...a.http2.settings,
                    maxConcurrentStreams: 1,
                },
            },
        };

        const diffs = diffProfiles(a, b);

        expect(diffs).toContainEqual({
            path: "http2.settings.maxConcurrentStreams",
            a: 100,
            b: 1,
        });
    });

    it("ignores array order when compareArrayOrder is false", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const reordered = [...a.tls.cipherSuites].reverse();
        const b: BrowserProfile = {
            ...a,
            tls: { ...a.tls, cipherSuites: reordered },
        };

        const diffs = diffProfiles(a, b, { compareArrayOrder: false });

        expect(diffs).toEqual([]);
    });

    it("reports a top-level name/version diff", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const b: BrowserProfile = { ...a, name: "firefox", version: "135.0" };

        const diffs = diffProfiles(a, b);

        expect(diffs).toContainEqual({ path: "name", a: "chrome", b: "firefox" });
        expect(diffs).toContainEqual({ path: "version", a: "140.0.7339.18", b: "135.0" });
    });

    it("reports a single whole-array diff when multisets differ in unordered mode", () => {
        const a = getProfile("chrome-140" as ProfileId);
        // Same membership except one element differs — order-insensitive comparison
        // must still surface the difference as one diff at the array path.
        const b: BrowserProfile = {
            ...a,
            tls: {
                ...a.tls,
                cipherSuites: [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ],
            },
        };
        const c: BrowserProfile = {
            ...a,
            tls: {
                ...a.tls,
                cipherSuites: [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                ],
            },
        };

        const diffs = diffProfiles(b, c, { compareArrayOrder: false });

        expect(diffs).toEqual([
            {
                path: "tls.cipherSuites",
                a: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
                b: [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                ],
            },
        ]);
    });

    it("compares arrays of objects as multisets regardless of property order", () => {
        const a = getProfile("chrome-140" as ProfileId);
        // The structural diff is built to handle nested objects/arrays (DiffNode).
        // Exercise that path: two arrays with the same object members in different
        // order, and object keys in different order, must compare equal unordered.
        const left = {
            ...a,
            tls: { ...a.tls, cipherSuites: [{ k: 1 }, { z: 2, a: 3 }] },
        } as unknown as BrowserProfile;
        const right = {
            ...a,
            tls: { ...a.tls, cipherSuites: [{ a: 3, z: 2 }, { k: 1 }] },
        } as unknown as BrowserProfile;

        expect(diffProfiles(left, right, { compareArrayOrder: false })).toEqual([]);
    });

    it("reports per-index diffs when ordered arrays differ in length", () => {
        const a = getProfile("chrome-140" as ProfileId);
        const shorter: BrowserProfile = {
            ...a,
            tls: { ...a.tls, cipherSuites: a.tls.cipherSuites.slice(0, 3) },
        };
        const longer: BrowserProfile = {
            ...a,
            tls: { ...a.tls, cipherSuites: [...a.tls.cipherSuites, "TLS_AES_128_CCM_SHA256"] },
        };

        const aDiffs = diffProfiles(shorter, longer);
        const bDiffs = diffProfiles(longer, shorter);

        // shorter → longer: extra element in `b` at index === shorter length.
        expect(aDiffs.some((d) => d.path === `tls.cipherSuites[${shorter.tls.cipherSuites.length}]`)).toBe(true);
        // longer → shorter: extra element in `a` at index === shorter length.
        expect(bDiffs.some((d) => d.path === `tls.cipherSuites[${shorter.tls.cipherSuites.length}]`)).toBe(true);
    });

    it("emits a diff when one value is an array and the other is not", () => {
        const a = getProfile("chrome-140" as ProfileId);
        // Same path, but `a` holds an array while `b` holds a scalar — incomparable,
        // so the whole subtree is reported as a single diff.
        const b = {
            ...a,
            tls: { ...a.tls, cipherSuites: "not-an-array" },
        } as unknown as BrowserProfile;

        const diffs = diffProfiles(a, b);

        expect(diffs).toEqual([{ path: "tls.cipherSuites", a: a.tls.cipherSuites, b: "not-an-array" }]);
    });

    it("reports keys present in only one object", () => {
        const a = getProfile("chrome-140" as ProfileId);
        // `a` has a key `b` lacks, and `b` has a key `a` lacks, at the nested level.
        const left = {
            ...a,
            tls: { ...a.tls, extraOnlyInA: "x" },
        } as unknown as BrowserProfile;
        const right = {
            ...a,
            tls: { ...a.tls, extraOnlyInB: "y" },
        } as unknown as BrowserProfile;

        const diffs = diffProfiles(left, right);

        expect(diffs).toContainEqual({ path: "tls.extraOnlyInA", a: "x", b: undefined });
        expect(diffs).toContainEqual({ path: "tls.extraOnlyInB", a: undefined, b: "y" });
    });

    it("compares nested arrays as multisets in unordered mode", () => {
        const a = getProfile("chrome-140" as ProfileId);
        // Array-of-arrays: the inner arrays must be recursively stabilized and
        // compared as multisets, so reordered members compare equal.
        const left = {
            ...a,
            tls: { ...a.tls, cipherSuites: [[1, 2], [3, 4]] },
        } as unknown as BrowserProfile;
        const right = {
            ...a,
            tls: { ...a.tls, cipherSuites: [[3, 4], [1, 2]] },
        } as unknown as BrowserProfile;

        expect(diffProfiles(left, right, { compareArrayOrder: false })).toEqual([]);
    });

    it("reports a single whole-array diff in unordered mode when the arrays differ in length", () => {
        const a = getProfile("chrome-140" as ProfileId);
        // Unordered comparison first checks length equality; arrays of different
        // lengths can never be equal as multisets, so one diff at the array path
        // is emitted (and the per-element loop is skipped).
        const shorter = {
            ...a,
            tls: { ...a.tls, cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] },
        } as BrowserProfile;
        const longer = {
            ...a,
            tls: {
                ...a.tls,
                cipherSuites: [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ],
            },
        } as BrowserProfile;

        const diffs = diffProfiles(shorter, longer, { compareArrayOrder: false });

        expect(diffs).toEqual([
            {
                path: "tls.cipherSuites",
                a: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
                b: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
            },
        ]);
    });
});
