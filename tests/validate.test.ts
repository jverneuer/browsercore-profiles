import { describe, expect, it } from "vitest";
import { getProfile, listProfiles } from "../src/index.js";
import type { ProfileId } from "../src/types.js";
import {
    buildExpectedClientHello,
    validateProfileAgainstCapture,
    ValidationError,
} from "../src/validate.js";
import type { TlsCapture } from "../src/validate.js";

describe("buildExpectedClientHello", () => {
    it("projects chrome-140 cipher suites and extensions to known wire codes", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        // GREASE placeholder → canonical first GREASE code 0x0a0a.
        expect(expected.cipherSuites[0]).toBe(0x0a0a);
        // TLS 1.3 suites per IANA registry.
        expect(expected.cipherSuites[1]).toBe(0x1301); // TLS_AES_128_GCM_SHA256
        expect(expected.cipherSuites[2]).toBe(0x1302); // TLS_AES_256_GCM_SHA384
        expect(expected.cipherSuites[3]).toBe(0x1303); // TLS_CHACHA20_POLY1305_SHA256

        // Extension type codes from the IANA TLS ExtensionType registry.
        expect(expected.extensionTypes).toContain(0); // SNI
        expect(expected.extensionTypes).toContain(43); // supported_versions
        expect(expected.extensionTypes).toContain(51); // key_share
        expect(expected.extensionTypes).toContain(13); // signature_algorithms
        expect(expected.extensionTypes).toContain(16); // ALPN
        expect(expected.extensionTypes).toContain(10); // supported_groups

        // Named groups.
        expect(expected.keyShareGroups).toContain(0x001d); // x25519
        expect(expected.keyShareGroups).toContain(0x0017); // secp256r1

        // Signature schemes (first entry: ecdsa_secp256r1_sha256).
        expect(expected.signatureAlgorithms[0]).toBe(0x0403);

        // Supported versions: TLS 1.3 then TLS 1.2.
        expect(expected.supportedVersions[0]).toBe(0x0304);
        expect(expected.supportedVersions[1]).toBe(0x0303);

        expect(expected.grease).toBe(true);
        expect(expected.sni).toBe("example.com");
    });
});

describe("validateProfileAgainstCapture", () => {
    it("reports ok for a matching fake capture", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        const capture: TlsCapture = {
            cipherSuites: expected.cipherSuites,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(true);
        expect(result.diffs).toEqual([]);
    });

    it("accepts a different GREASE-pattern value in a GREASE cipher slot", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        // Replace the canonical GREASE code with another valid GREASE value.
        const ciphers = [...expected.cipherSuites];
        ciphers[0] = 0x1a1a;

        const capture: TlsCapture = {
            cipherSuites: ciphers,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(true);
        expect(result.diffs).toEqual([]);
    });

    it("reports not ok with diffs for a mismatched capture", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        const capture: TlsCapture = {
            // First real cipher suite flipped to a wrong value.
            cipherSuites: [expected.cipherSuites[0], 0xdead, ...expected.cipherSuites.slice(2)],
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            // GREASE flag also flipped.
            grease: false,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.grease")).toBe(true);
        expect(result.diffs.some((d) => d.path === "tls.cipherSuites[1]")).toBe(true);
    });

    it("reports a diff when a non-cipher numeric array (extensions) mismatches", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        // Flip the first extension type code.
        const extensionTypes = [...expected.extensionTypes];
        extensionTypes[0] = 9999;

        const capture: TlsCapture = {
            cipherSuites: expected.cipherSuites,
            extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.extensionTypes[0]")).toBe(true);
    });

    it("builds an expected ClientHello for every registered profile", () => {
        // The cipher/signature lookup tables must cover every value the shipped
        // profiles use; a missing entry is a latent bug (throws ValidationError).
        for (const id of listProfiles()) {
            const profile = getProfile(id);
            expect(() => buildExpectedClientHello(profile, "example.com")).not.toThrow();
        }
    });

    it("maps Firefox cipher suites and signature schemes to IANA codes", () => {
        const profile = getProfile("firefox-135" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        // Firefox leads with TLS_AES_128_GCM_SHA256 and advertises ed25519 +
        // rsa_pkcs1_sha1 — schemes Chrome does not offer.
        expect(expected.cipherSuites[0]).toBe(0x1301);
        expect(expected.signatureAlgorithms).toContain(0x0807); // ed25519
        expect(expected.signatureAlgorithms).toContain(0x0201); // rsa_pkcs1_sha1
    });

    it("maps Safari cipher suites (SHA-256/SHA-384 CBC) to IANA codes", () => {
        const profile = getProfile("safari-18" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        // Safari's cipher list includes the CBC SHA-256/SHA-384 variants.
        expect(expected.cipherSuites).toContain(0xc024); // ECDSA AES-256-CBC-SHA384
        expect(expected.cipherSuites).toContain(0x003c); // RSA AES-128-CBC-SHA256
        expect(expected.cipherSuites).toContain(0x003d); // RSA AES-256-CBC-SHA256
    });

    it("throws ValidationError when a profile references an unknown cipher suite", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const bad: typeof profile = {
            ...profile,
            tls: { ...profile.tls, cipherSuites: ["NOT_A_REAL_CIPHER"] },
        };

        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(ValidationError);
    });

    it("reports a mismatch when a GREASE cipher slot holds a non-GREASE value", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");

        // Index 0 is a GREASE slot; a non-GREASE value there must be flagged.
        const ciphers = [...expected.cipherSuites];
        ciphers[0] = 0xdead;

        const capture: TlsCapture = {
            cipherSuites: ciphers,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.cipherSuites[0]")).toBe(true);
    });
});

describe("buildExpectedClientHello — projection error paths", () => {
    // The codes tables double as an allow-list: an unknown name in a profile is a
    // bug, and projection surfaces it as a ValidationError naming the field.
    const base = getProfile("chrome-140" as ProfileId);

    it("throws ValidationError naming the cipher suite field on an unknown cipher", () => {
        const bad = { ...base, tls: { ...base.tls, cipherSuites: ["NOPE"] } } as typeof base;
        try {
            buildExpectedClientHello(bad, "example.com");
            expect.unreachable("expected throw");
        } catch (e) {
            expect(e).toBeInstanceOf(ValidationError);
            expect((e as Error).message).toContain("cipher suite");
            expect((e as Error).message).toContain("NOPE");
        }
    });

    it("throws ValidationError on an unknown named group", () => {
        const bad = { ...base, tls: { ...base.tls, keyShareGroups: ["no-group"] } } as typeof base;
        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(ValidationError);
        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(/named group/);
    });

    it("throws ValidationError on an unknown signature scheme", () => {
        const bad = {
            ...base,
            tls: { ...base.tls, signatureAlgorithms: ["no-sig"] },
        } as typeof base;
        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(ValidationError);
        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(/signature scheme/);
    });

    it("throws ValidationError on an unknown TLS version", () => {
        const bad = {
            ...base,
            tls: { ...base.tls, supportedVersions: ["TLS 9.9"] },
        } as typeof base;
        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(ValidationError);
        expect(() => buildExpectedClientHello(bad, "example.com")).toThrow(/TLS version/);
    });

    it("throws on the first bad value only (stops at the offending suite)", () => {
        // mapCipherSuite throws eagerly, so a bad entry surfaces before later ones.
        const bad = {
            ...base,
            tls: {
                ...base.tls,
                cipherSuites: ["TLS_AES_128_GCM_SHA256", "BAD_CIPHER"],
            },
        } as typeof base;
        try {
            buildExpectedClientHello(bad, "example.com");
            expect.unreachable("expected throw");
        } catch (e) {
            expect((e as Error).message).toContain("BAD_CIPHER");
        }
    });
});

describe("ValidationError", () => {
    it("has kind 'ValidationError', a descriptive name, and a ProfileError chain", () => {
        // ValidationError extends ProfileError; confirm its discriminant + name so
        // callers matching on `kind` / `name` keep working.
        const cause = new Error("boom");
        const err = new ValidationError("bad", { cause });
        expect(err.kind).toBe("ValidationError");
        expect(err.name).toBe("ValidationError");
        expect(err.message).toBe("bad");
        expect(err.cause).toBe(cause);
        // Falls back to undefined cause when not provided.
        expect(new ValidationError("bad").cause).toBeUndefined();
    });
});

describe("validateProfileAgainstCapture — remaining mismatch paths", () => {
    it("reports diffs when supportedVersions mismatch", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const capture: TlsCapture = {
            cipherSuites: expected.cipherSuites,
            extensionTypes: expected.extensionTypes,
            supportedVersions: [expected.supportedVersions[1], expected.supportedVersions[0]],
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.supportedVersions[0]")).toBe(true);
        expect(result.diffs.some((d) => d.path === "tls.supportedVersions[1]")).toBe(true);
    });

    it("reports diffs when keyShareGroups mismatch", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const groups = [...expected.keyShareGroups];
        groups[0] = 0x0018; // secp384r1 instead of x25519
        const capture: TlsCapture = {
            cipherSuites: expected.cipherSuites,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: groups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.keyShareGroups[0]")).toBe(true);
    });

    it("reports diffs when signatureAlgorithms mismatch", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const sigs = [...expected.signatureAlgorithms];
        sigs[0] = 0x0201; // rsa_pkcs1_sha1 instead of ecdsa_secp256r1_sha256
        const capture: TlsCapture = {
            cipherSuites: expected.cipherSuites,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: sigs,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.signatureAlgorithms[0]")).toBe(true);
    });

    it("reports a per-index diff when the capture cipher list is shorter than expected", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const capture: TlsCapture = {
            // Drop the trailing two suites — those indices must show as diffs.
            cipherSuites: expected.cipherSuites.slice(0, -2),
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        const last = expected.cipherSuites.length - 1;
        expect(result.diffs.some((d) => d.path === `tls.cipherSuites[${last}]`)).toBe(true);
    });

    it("reports diffs when the capture cipher list is longer than expected", () => {
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const capture: TlsCapture = {
            cipherSuites: [...expected.cipherSuites, 0x1304], // extra TLS_AES_128_CCM_SHA256
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(
            result.diffs.some((d) => d.path === `tls.cipherSuites[${expected.cipherSuites.length}]`),
        ).toBe(true);
    });

    it("accepts a non-GREASE profile (Firefox) against a matching capture", () => {
        // Firefox has grease:false and no GREASE cipher slot — its happy path must
        // not depend on GREASE-aware comparison.
        const profile = getProfile("firefox-135" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const capture: TlsCapture = {
            cipherSuites: expected.cipherSuites,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: false,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(true);
        expect(result.diffs).toEqual([]);
    });

    it("accepts the maximum GREASE value 0xfafa in a GREASE cipher slot", () => {
        // The GREASE range is 0x0a0a..0xfafa in steps of 0x1010; the top end must
        // be accepted just like the canonical 0x0a0a.
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const ciphers = [...expected.cipherSuites];
        ciphers[0] = 0xfafa;
        const capture: TlsCapture = {
            cipherSuites: ciphers,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(true);
    });

    it("rejects 0x0000 at a GREASE cipher slot (not a real GREASE value)", () => {
        // RFC 8701 reserves 0x0a0a..0xfafa in steps of 0x1010; 0x0000 shares the
        // high===low byte shape but is NOT a GREASE value, so it must be flagged.
        const profile = getProfile("chrome-140" as ProfileId);
        const expected = buildExpectedClientHello(profile, "example.com");
        const ciphers = [...expected.cipherSuites];
        ciphers[0] = 0x0000; // GREASE slot carrying 0x0000

        const capture: TlsCapture = {
            cipherSuites: ciphers,
            extensionTypes: expected.extensionTypes,
            supportedVersions: expected.supportedVersions,
            keyShareGroups: expected.keyShareGroups,
            signatureAlgorithms: expected.signatureAlgorithms,
            grease: true,
        };

        const result = validateProfileAgainstCapture(profile, capture);

        expect(result.ok).toBe(false);
        expect(result.diffs.some((d) => d.path === "tls.cipherSuites[0]")).toBe(true);
    });
});
