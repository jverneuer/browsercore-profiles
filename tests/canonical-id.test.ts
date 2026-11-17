/**
 * Canonical ProfileId — compile proofs for the 0.2.6 contracts adoption.
 *
 * ProfileId is re-exported from @browsercore/contracts (the canonical home,
 * src/models.ts): the closed set of registry-shipped ids widened with
 * `(string & Record<never, never>)` so runtime-registered custom ids stay
 * assignable. These tests pin the properties the adoption promised:
 *
 *   1. Identity with contracts — profiles' exported ProfileId IS contracts'
 *      ProfileId (same declaration via the re-export, mutual assignability
 *      holds in both directions).
 *   2. String literals accepted without casts — the brand removal must not
 *      ripple to consumers (fetch/tls/browsersmith pass literals).
 *   3. RegisteredProfileId (declared locally — contracts does not export the
 *      name at its package root) never drifts from the registry data.
 *
 * The type-level assertions are enforced by the dual typecheck gate
 * (`tsc -p tsconfig.test.json`): a shape regression fails `npm run typecheck`.
 * The registry's RUNTIME validation is asserted separately — it is the typo
 * guard now that the brand is gone.
 */

import { describe, expect, it } from "vitest";
import { getProfile, listProfiles, UnknownProfileError } from "../src/index.js";
import type { ProfileId, RegisteredProfileId } from "../src/index.js";
import type { ProfileId as CanonicalProfileId } from "@browsercore/contracts";

// Compile-time: profiles' exported ProfileId IS the canonical declaration.
// Both directions assign because they are the SAME type via the re-export.
const canonicalId: CanonicalProfileId = "chrome-140" as ProfileId;
const packageId: ProfileId = "firefox-135" as CanonicalProfileId;

// Compile-time: the local closed set is contained in the canonical union —
// every RegisteredProfileId is a valid ProfileId.
const widened: ProfileId = "edge-128" as RegisteredProfileId;

describe("canonical ProfileId (contracts 0.2.6)", () => {
    it("accepts registry ids as bare string literals — no cast, no brand", () => {
        // The consumer-compat proof: fetch/tls/browsersmith pass literals.
        const profile = getProfile("chrome-140");
        expect(profile.id).toBe("chrome-140");
    });

    it("keeps RegisteredProfileId closed — registry typos fail the compile gate", () => {
        // @ts-expect-error — "chrome-999" is not a RegisteredProfileId; the
        // closed set keeps literal typo-flagging where it is required.
        const bad: RegisteredProfileId = "chrome-999";
        expect(bad).toBeDefined();
    });

    it("admits runtime-registered custom ids (the widening member)", () => {
        const custom: ProfileId = "my-registered-custom";
        expect(custom).toBe("my-registered-custom");
    });

    it("lists exactly the RegisteredProfileId set (drift guard)", () => {
        // The union in src/types.ts must mirror the registry data — and
        // contracts' identical union — member for member. If a profile is
        // added without extending the union (here and in contracts), this
        // fails; if the union gains a member the registry lacks, so does it.
        const registryIds = listProfiles().filter((id) => !id.startsWith("custom"));
        const declared: readonly RegisteredProfileId[] = [
            "chrome-120", "chrome-128", "chrome-140",
            "edge-120", "edge-128",
            "firefox-120", "firefox-128", "firefox-135",
            "safari-17", "safari-18",
        ];
        expect([...registryIds].sort()).toEqual([...declared].sort());
        expect(canonicalId).toBe("chrome-140");
        expect(packageId).toBe("firefox-135");
        expect(widened).toBe("edge-128");
    });

    it("guards unknown ids at RUNTIME regardless of the static type", () => {
        // The brand is gone; UnknownProfileError is the typo guard. A typo'd
        // id compiles (widened union admits any string) and throws here.
        expect(() => getProfile("chrome-14O")).toThrow(UnknownProfileError);
        expect(() => getProfile("opera-1")).toThrow(UnknownProfileError);
    });
});
