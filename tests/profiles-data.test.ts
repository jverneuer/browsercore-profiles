import { describe, expect, it } from "vitest";
import {
    ChromeProfiles,
    EdgeProfiles,
    FirefoxProfiles,
    SafariProfiles,
    getProfile,
    listProfiles,
    registerProfile,
} from "../src/index.js";
import type { BrowserProfile, ProfileId } from "../src/types.js";
import {
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
    VERSION_CODES,
} from "../src/codes.js";

/**
 * Cross-cutting invariants over every shipped profile. These tests catch data
 * drift (a typo'd cipher name, a duplicated extension code, an http2 settings
 * field that disagrees with its top-level twin) regardless of which profile a
 * future edit touches.
 */

const profileMaps = { ChromeProfiles, FirefoxProfiles, SafariProfiles, EdgeProfiles };

/** Every shipped profile, flattened to [mapKey, profile] pairs. */
const allProfiles: BrowserProfile[] = [
    ...Object.values(ChromeProfiles),
    ...Object.values(FirefoxProfiles),
    ...Object.values(SafariProfiles),
    ...Object.values(EdgeProfiles),
];

describe("shipped profiles — identity & registry", () => {
    it("every exported profile is the exact reference returned by getProfile", () => {
        // The registry indexes built-ins at module load; it must hold the same
        // object reference the per-browser maps export, so callers can compare
        // by identity if they choose.
        for (const profile of allProfiles) {
            expect(getProfile(profile.id)).toBe(profile);
        }
    });

    it("profile ids are unique across all families", () => {
        const ids = allProfiles.map((p) => p.id);
        expect(new Set(ids).size).toBe(ids.length);
    });

    it("each profile map keys its profiles by a matching short id", () => {
        // e.g. ChromeProfiles.chrome120 has id "chrome-120".
        expect(ChromeProfiles.chrome120.id).toBe("chrome-120");
        expect(ChromeProfiles.chrome128.id).toBe("chrome-128");
        expect(ChromeProfiles.chrome140.id).toBe("chrome-140");
        expect(FirefoxProfiles.firefox120.id).toBe("firefox-120");
        expect(FirefoxProfiles.firefox128.id).toBe("firefox-128");
        expect(FirefoxProfiles.firefox135.id).toBe("firefox-135");
        expect(SafariProfiles.safari17.id).toBe("safari-17");
        expect(SafariProfiles.safari18.id).toBe("safari-18");
        expect(EdgeProfiles.edge120.id).toBe("edge-120");
        expect(EdgeProfiles.edge128.id).toBe("edge-128");
    });

    it("the profile name matches the family the profile is exported from", () => {
        for (const p of Object.values(ChromeProfiles)) expect(p.name).toBe("chrome");
        for (const p of Object.values(FirefoxProfiles)) expect(p.name).toBe("firefox");
        for (const p of Object.values(SafariProfiles)) expect(p.name).toBe("safari");
        for (const p of Object.values(EdgeProfiles)) expect(p.name).toBe("edge");
    });

    it("id and version are non-empty strings", () => {
        for (const p of allProfiles) {
            expect(p.id.length).toBeGreaterThan(0);
            expect(p.version.length).toBeGreaterThan(0);
        }
    });
});

describe("shipped profiles — TLS invariants", () => {
    it("cipher suite lists have no duplicates", () => {
        // A duplicated cipher would skew JA3 length and is always a data bug.
        for (const p of allProfiles) {
            const suites = p.tls.cipherSuites;
            expect(new Set(suites).size, `${p.id}: cipherSuites must be unique`).toBe(suites.length);
        }
    });

    it("extension order has no duplicate type codes", () => {
        for (const p of allProfiles) {
            const order = p.tls.extensionOrder;
            expect(new Set(order).size, `${p.id}: extensionOrder must be unique`).toBe(order.length);
        }
    });

    it("supported versions are advertised highest-first (TLS 1.3 before 1.2)", () => {
        for (const p of allProfiles) {
            expect(p.tls.supportedVersions[0]).toBe("TLS 1.3");
            expect(p.tls.supportedVersions[1]).toBe("TLS 1.2");
        }
    });

    it("key-share groups have no duplicates", () => {
        for (const p of allProfiles) {
            expect(new Set(p.tls.keyShareGroups).size).toBe(p.tls.keyShareGroups.length);
        }
    });

    it("signature algorithms have no duplicates, except Safari's intentional rsa_pss_rsae_sha384 twin", () => {
        // curl-impersonate's ground-truth Safari signature intentionally duplicates
        // rsa_pss_rsae_sha384 (0x0805) — a real WebKit quirk preserved by patching
        // out BoringSSL's uniqueness check. See boringssl-old-ciphers.patch in
        // curl-impersonate. No other profile duplicates a signature algorithm.
        for (const p of allProfiles) {
            const sigAlgs = p.tls.signatureAlgorithms;
            const uniqueCount = new Set(sigAlgs).size;
            if (p.name === "safari") {
                expect(uniqueCount).toBe(sigAlgs.length - 1);
                const deduped = Array.from(new Set(sigAlgs));
                expect(deduped).toContain("rsa_pss_rsae_sha384");
            } else {
                expect(uniqueCount, `${p.id}: signatureAlgorithms must be unique`).toBe(sigAlgs.length);
            }
        }
    });

    it("every TLS name a profile references resolves in the codes allow-list", () => {
        // A name that fails to resolve would throw ValidationError at projection
        // time; this surfaces the offending name directly per-profile.
        for (const p of allProfiles) {
            for (const c of p.tls.cipherSuites) {
                expect(CIPHER_SUITE_CODES[c], `${p.id}: unknown cipher ${c}`).toBeDefined();
            }
            for (const g of p.tls.keyShareGroups) {
                expect(NAMED_GROUP_CODES[g], `${p.id}: unknown group ${g}`).toBeDefined();
            }
            for (const s of p.tls.signatureAlgorithms) {
                expect(SIGNATURE_SCHEME_CODES[s], `${p.id}: unknown sig scheme ${s}`).toBeDefined();
            }
            for (const v of p.tls.supportedVersions) {
                expect(VERSION_CODES[v], `${p.id}: unknown version ${v}`).toBeDefined();
            }
        }
    });

    it("GREASE-bearing browsers (Chrome, Edge, Safari) lead with the GREASE cipher placeholder", () => {
        // curl-impersonate ground truth: Chrome, Edge, and Safari all insert a
        // GREASE cipher slot at the top of their cipher list. Firefox does not.
        for (const p of Object.values(ChromeProfiles)) {
            expect(p.tls.cipherSuites[0]).toBe(CIPHER_GREASE_PLACEHOLDER);
        }
        for (const p of Object.values(EdgeProfiles)) {
            expect(p.tls.cipherSuites[0]).toBe(CIPHER_GREASE_PLACEHOLDER);
        }
        for (const p of Object.values(SafariProfiles)) {
            expect(p.tls.cipherSuites[0]).toBe(CIPHER_GREASE_PLACEHOLDER);
        }
        for (const p of Object.values(FirefoxProfiles)) {
            expect(p.tls.cipherSuites).not.toContain(CIPHER_GREASE_PLACEHOLDER);
        }
    });
});

describe("shipped profiles — HTTP/2 invariants", () => {
    it("settings fields agree with their top-level twins", () => {
        // http2 exposes both `settings.{initialWindowSize,maxFrameSize,headerTableSize}`
        // and top-level aliases; they must match or downstream tuning logic splits
        // on which value it reads.
        for (const p of allProfiles) {
            expect(p.http2.settings.initialWindowSize, `${p.id}: initialWindowSize`).toBe(p.http2.initialWindowSize);
            expect(p.http2.settings.maxFrameSize, `${p.id}: maxFrameSize`).toBe(p.http2.maxFrameSize);
            expect(p.http2.settings.headerTableSize, `${p.id}: headerTableSize`).toBe(p.http2.headerTableSize);
        }
    });

    it("advertises sane numeric ranges", () => {
        for (const p of allProfiles) {
            expect(p.http2.initialWindowSize).toBeGreaterThan(0);
            expect(p.http2.maxFrameSize).toBeGreaterThanOrEqual(16384); // RFC 9113 minimum
            expect(p.http2.headerTableSize).toBeGreaterThanOrEqual(0);
            expect(p.http2.weight).toBeGreaterThanOrEqual(1);
            expect(p.http2.weight).toBeLessThanOrEqual(256); // 1..256 per RFC 7540
            expect(p.http2.settings.enablePush).toBe(false); // every shipped browser disables push
        }
    });

    it("Chrome and Edge share the same HTTP/2 tuning", () => {
        // Edge is Chromium-based; its window/frame/table sizes mirror Chrome.
        const chrome = ChromeProfiles.chrome140;
        const edge = EdgeProfiles.edge128;
        expect(edge.http2.initialWindowSize).toBe(chrome.http2.initialWindowSize);
        expect(edge.http2.maxFrameSize).toBe(chrome.http2.maxFrameSize);
        expect(edge.http2.headerTableSize).toBe(chrome.http2.headerTableSize);
    });
});

describe("shipped profiles — HTTP/1 invariants", () => {
    it("connection is keep-alive and accept-encoding advertises br", () => {
        for (const p of allProfiles) {
            expect(p.http1.connection).toBe("keep-alive");
            expect(p.http1.acceptEncoding).toContain("br");
        }
    });

    it("header order is non-empty and duplicate-free", () => {
        for (const p of allProfiles) {
            expect(p.http1.headerOrder.length).toBeGreaterThan(0);
            expect(new Set(p.http1.headerOrder).size).toBe(p.http1.headerOrder.length);
        }
    });

    it("every profile advertises a non-empty user-agent matching its family", () => {
        const uaByFamily: Record<string, RegExp> = {
            chrome: /Chrome\//,
            firefox: /Firefox\//,
            safari: /Version\//,
            edge: /Edg\//,
        };
        for (const p of allProfiles) {
            const ua = p.http1.defaultHeaders["user-agent"];
            expect(typeof ua).toBe("string");
            expect(ua.length).toBeGreaterThan(0);
            expect(ua).toMatch(uaByFamily[p.name]);
        }
    });
});

describe("registry — overwrite and ordering", () => {
    it("registerProfile overwrites a built-in id with a new reference", () => {
        // The registry contract: "Overwrites any existing profile with the same id."
        const original = getProfile("chrome-140" as ProfileId);
        const replacement: BrowserProfile = {
            ...original,
            version: "140.0.0.0-fake",
        };

        registerProfile(replacement);
        try {
            expect(getProfile("chrome-140" as ProfileId)).toBe(replacement);
            expect(getProfile("chrome-140" as ProfileId)).not.toBe(original);
            expect(getProfile("chrome-140" as ProfileId).version).toBe("140.0.0.0-fake");
        } finally {
            // Restore the built-in so other test files / tests see the original.
            registerProfile(original);
        }
        expect(getProfile("chrome-140" as ProfileId)).toBe(original);
    });

    it("listProfiles returns a value that no longer mutates the registry when pushed to", () => {
        // Returns a fresh Array each call; mutating it must not affect later lookups.
        const before = listProfiles();
        const len = before.length;
        before.push("injected" as ProfileId);
        const after = listProfiles();
        expect(after.length).toBe(len);
        expect(after).not.toContain("injected");
    });

    it("built-ins are listed in family insertion order (chrome, firefox, safari, edge)", () => {
        const ids = listProfiles();
        const chromeIdx = ids.indexOf("chrome-120" as ProfileId);
        const firefoxIdx = ids.indexOf("firefox-120" as ProfileId);
        const safariIdx = ids.indexOf("safari-17" as ProfileId);
        const edgeIdx = ids.indexOf("edge-120" as ProfileId);

        expect(chromeIdx).toBeGreaterThanOrEqual(0);
        expect(chromeIdx).toBeLessThan(firefoxIdx);
        expect(firefoxIdx).toBeLessThan(safariIdx);
        expect(safariIdx).toBeLessThan(edgeIdx);
    });

    it("profileMaps export exactly the expected families", () => {
        expect(Object.keys(profileMaps).sort()).toEqual([
            "ChromeProfiles",
            "EdgeProfiles",
            "FirefoxProfiles",
            "SafariProfiles",
        ]);
    });
});
