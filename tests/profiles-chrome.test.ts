/**
 * Chrome profile verification against curl-impersonate ground truth.
 *
 * Every value projected from these profiles is checked against the wire values
 * reported by real curl-impersonate ClientHello captures
 * (testing-worktree/captures/_probe/output/chrome*.json): ja3 / ja4 / peetprint
 * strings and the decoded cipher-suite / extension / group / signature lists.
 *
 * Ground-truth anchors used below:
 *   - chrome-120: ja3 698f6d684588ddc1217dfb4454916129
 *     `771,4866...47-53,43-13-11-18-0-65037-27-23-10-45-17513-16-5-35-51-65281,29-23-24,0`
 *     peetprint `...|0-10-11-13-16-17513-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE`.
 *   - chrome-124 (proxy for chrome-128): groups `GREASE-25497-29-23-24`
 *     (X25519Kyber768), app_settings 17513.
 *   - chrome-131 / chrome-133a / chrome-136 (proxies for chrome-140):
 *     groups `GREASE-4588-29-23-24` (X25519MLKEM768), app_settings 17613.
 */
import { describe, expect, it } from "vitest";
import { ChromeProfiles } from "../src/profiles/chrome.js";
import {
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
} from "../src/codes.js";
import { buildExpectedClientHello } from "../src/validate.js";
import type { BrowserProfile } from "../src/types.js";

const chrome = {
    chrome120: ChromeProfiles.chrome120,
    chrome128: ChromeProfiles.chrome128,
    chrome140: ChromeProfiles.chrome140,
} as const;

/** Map a profile's TLS fields to the wire codes a ClientHello would carry. */
function expectedWire(profile: BrowserProfile) {
    return buildExpectedClientHello(profile, "tls.peet.ws");
}

describe("chrome profiles — cipher suites", () => {
    it("chrome-120 cipher list matches the ja3 capture exactly", () => {
        // ja3 cipher field: 4866...47-53 (GREASE stripped). Wire order from the
        // capture, translated back to suite names.
        const expected = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        ];
        const suites = chrome.chrome120.tls.cipherSuites;
        expect(suites[0]).toBe(CIPHER_GREASE_PLACEHOLDER);
        expect(suites.slice(1)).toEqual(expected);
    });

    it("every cipher suite projects to its correct IANA wire code", () => {
        const wire = expectedWire(chrome.chrome120).cipherSuites;
        // Drop the randomized GREASE slot, then compare the deterministic codes.
        const codes = wire.slice(1);
        const expected = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        expect(codes).toEqual(expected);
    });

    it("cipher list has no duplicates once the GREASE slot is removed", () => {
        for (const p of Object.values(chrome)) {
            const suites = p.tls.cipherSuites.filter((s) => s !== CIPHER_GREASE_PLACEHOLDER);
            expect(new Set(suites).size).toBe(suites.length);
        }
    });
});

describe("chrome profiles — extension order", () => {
    it("uses the canonical pre-permutation order matching the peetprint", () => {
        // The peetprint-normalized order is
        // 0-10-11-13-16-APP_SETTINGS-18-23-27-35-43-45-5-51-65037-65281.
        // pre_shared_key (41) must never appear; ECH (65037) must be present.
        for (const p of Object.values(chrome)) {
            expect(p.tls.extensionOrder).not.toContain(41);
            expect(p.tls.extensionOrder).toContain(65037);
        }
    });

    it("orders extensions identically except for the app_settings slot", () => {
        // Every version shares the same shape; only the application_settings
        // extension code differs (17513 vs 17613).
        const base = [0, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 5, 51, 65037, 65281];
        for (const p of Object.values(chrome)) {
            const order = [...p.tls.extensionOrder];
            // Remove the version-dependent slot before comparing the rest.
            const idx = order.indexOf(17513) >= 0 ? order.indexOf(17513) : order.indexOf(17613);
            expect(idx).toBe(5);
            order.splice(idx, 1);
            expect(order).toEqual(base);
        }
    });

    it("chrome-120 and chrome-128 use application_settings_old (17513)", () => {
        expect(chrome.chrome120.tls.extensionOrder).toContain(17513);
        expect(chrome.chrome128.tls.extensionOrder).toContain(17513);
        expect(chrome.chrome120.tls.extensionOrder).not.toContain(17613);
        expect(chrome.chrome128.tls.extensionOrder).not.toContain(17613);
    });

    it("chrome-140 uses application_settings (17613)", () => {
        expect(chrome.chrome140.tls.extensionOrder).toContain(17613);
        expect(chrome.chrome140.tls.extensionOrder).not.toContain(17513);
    });
});

describe("chrome profiles — signature algorithms", () => {
    it("advertises all 8 schemes from the ja4_r capture", () => {
        // ja4_r sig field: 0403,0804,0401,0503,0805,0501,0806,0601.
        const expected = [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ];
        for (const p of Object.values(chrome)) {
            expect(p.tls.signatureAlgorithms).toEqual(expected);
        }
    });

    it("the two previously-missing schemes project to correct IANA codes", () => {
        expect(SIGNATURE_SCHEME_CODES.rsa_pss_rsae_sha512).toBe(0x0806);
        expect(SIGNATURE_SCHEME_CODES.rsa_pkcs1_sha512).toBe(0x0601);
        const wire = expectedWire(chrome.chrome120).signatureAlgorithms;
        expect(wire.slice(-2)).toEqual([0x0806, 0x0601]);
    });

    it("has no duplicate signature schemes", () => {
        for (const p of Object.values(chrome)) {
            expect(new Set(p.tls.signatureAlgorithms).size).toBe(p.tls.signatureAlgorithms.length);
        }
    });
});

describe("chrome profiles — supported groups", () => {
    it("chrome-120 groups match the ja3 capture (29-23-24)", () => {
        // ja3 groups field excludes GREASE; the capture's supported_groups
        // extension is [GREASE, X25519, P-256, P-384].
        expect(chrome.chrome120.tls.keyShareGroups).toEqual(["x25519", "secp256r1", "secp384r1"]);
    });

    it("chrome-128 adds the X25519Kyber768 hybrid group (chrome-124+)", () => {
        // chrome-124 capture: groups GREASE-25497-29-23-24. chrome-128 sits between
        // 124 and the MLKEM switch at 131, so it carries the draft Kyber group.
        expect(chrome.chrome128.tls.keyShareGroups).toEqual([
            "X25519Kyber768",
            "x25519",
            "secp256r1",
            "secp384r1",
        ]);
    });

    it("chrome-140 adds the X25519MLKEM768 hybrid group (chrome-131+)", () => {
        // chrome-131 capture: groups GREASE-4588-29-23-24.
        expect(chrome.chrome140.tls.keyShareGroups).toEqual([
            "X25519MLKEM768",
            "x25519",
            "secp256r1",
            "secp384r1",
        ]);
    });

    it("the new hybrid groups project to correct IANA codes", () => {
        expect(NAMED_GROUP_CODES.X25519Kyber768).toBe(0x6399);
        expect(NAMED_GROUP_CODES.X25519MLKEM768).toBe(0x11ec);
        expect(expectedWire(chrome.chrome128).keyShareGroups[0]).toBe(0x6399);
        expect(expectedWire(chrome.chrome140).keyShareGroups[0]).toBe(0x11ec);
    });

    it("has no duplicate groups", () => {
        for (const p of Object.values(chrome)) {
            expect(new Set(p.tls.keyShareGroups).size).toBe(p.tls.keyShareGroups.length);
        }
    });
});

describe("chrome profiles — HTTP/2 settings", () => {
    it("advertises MAX_HEADER_LIST_SIZE = 262144 from the SETTINGS frame", () => {
        // Reported SETTINGS: HEADER_TABLE_SIZE=65536; ENABLE_PUSH=0;
        // INITIAL_WINDOW_SIZE=6291456; MAX_HEADER_LIST_SIZE=262144.
        // akamai fingerprint: 1:65536;2:0;4:6291456;6:262144|...
        for (const p of Object.values(chrome)) {
            expect(p.http2.settings.maxHeaderListSize).toBe(262144);
        }
    });

    it("matches Chrome's known SETTINGS frame values", () => {
        for (const p of Object.values(chrome)) {
            expect(p.http2.settings.headerTableSize).toBe(65536);
            expect(p.http2.settings.enablePush).toBe(false);
            expect(p.http2.settings.initialWindowSize).toBe(6291456);
            expect(p.http2.settings.maxFrameSize).toBe(16384);
        }
    });

    it("keeps settings in sync with their top-level twins", () => {
        for (const p of Object.values(chrome)) {
            expect(p.http2.settings.initialWindowSize).toBe(p.http2.initialWindowSize);
            expect(p.http2.settings.maxFrameSize).toBe(p.http2.maxFrameSize);
            expect(p.http2.settings.headerTableSize).toBe(p.http2.headerTableSize);
        }
    });
});

describe("chrome profiles — GREASE and identity", () => {
    it("sets the GREASE cipher placeholder at position 0", () => {
        for (const p of Object.values(chrome)) {
            expect(p.tls.grease).toBe(true);
            expect(p.tls.cipherSuites[0]).toBe(CIPHER_GREASE_PLACEHOLDER);
        }
    });

    it("advertises TLS 1.3 before TLS 1.2", () => {
        for (const p of Object.values(chrome)) {
            expect(p.tls.supportedVersions).toEqual(["TLS 1.3", "TLS 1.2"]);
        }
    });

    it("version and user-agent agree for each profile", () => {
        expect(chrome.chrome120.version).toBe("120.0.6099.71");
        expect(chrome.chrome120.http1.defaultHeaders["user-agent"]).toContain("Chrome/120");
        expect(chrome.chrome128.version).toBe("128.0.6613.137");
        expect(chrome.chrome128.http1.defaultHeaders["user-agent"]).toContain("Chrome/128");
        expect(chrome.chrome140.version).toBe("140.0.7339.18");
        expect(chrome.chrome140.http1.defaultHeaders["user-agent"]).toContain("Chrome/140");
    });
});
