import { describe, expect, it } from "vitest";
import {
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
    VERSION_CODES,
} from "../src/codes.js";

/**
 * The codes tables are an allow-list: every name a profile may reference must map
 * to its canonical IANA 2-byte code, and the GREASE placeholder must be present.
 * These tests pin the exact wire values (so a typo'd code is caught immediately)
 * and exercise entries that no shipped profile currently uses — those would
 * otherwise be dead, unverified data in the allow-list.
 */

describe("CIPHER_GREASE_PLACEHOLDER", () => {
    it("is the canonical Chrome/Edge GREASE marker string", () => {
        expect(CIPHER_GREASE_PLACEHOLDER).toBe("TLS_GREASE_RESERVED_0");
    });

    it("has an entry in CIPHER_SUITE_CODES mapped to the first GREASE code", () => {
        // 0x0a0a is the first value in the GREASE range 0x0a0a..0xfafa (step 0x1010).
        expect(CIPHER_SUITE_CODES[CIPHER_GREASE_PLACEHOLDER]).toBe(0x0a0a);
    });
});

describe("CIPHER_SUITE_CODES", () => {
    it("maps every entry to a 2-byte IANA code", () => {
        for (const code of Object.values(CIPHER_SUITE_CODES)) {
            expect(Number.isInteger(code)).toBe(true);
            expect(code).toBeGreaterThanOrEqual(0x0000);
            expect(code).toBeLessThanOrEqual(0xffff);
        }
    });

    it("maps the TLS 1.3 AEAD suites to their IANA codes", () => {
        expect(CIPHER_SUITE_CODES.TLS_AES_128_GCM_SHA256).toBe(0x1301);
        expect(CIPHER_SUITE_CODES.TLS_AES_256_GCM_SHA384).toBe(0x1302);
        expect(CIPHER_SUITE_CODES.TLS_CHACHA20_POLY1305_SHA256).toBe(0x1303);
        // Not used by any shipped profile — verify the allow-list still carries it.
        expect(CIPHER_SUITE_CODES.TLS_AES_128_CCM_SHA256).toBe(0x1304);
    });

    it("maps the ECDHE ECDSA suites", () => {
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).toBe(0xc02b);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384).toBe(0xc02c);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256).toBe(0xcca9);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA).toBe(0xc009);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA).toBe(0xc00a);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256).toBe(0xc023);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384).toBe(0xc024);
    });

    it("maps the ECDHE RSA suites", () => {
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).toBe(0xc02f);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).toBe(0xc030);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256).toBe(0xcca8);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA).toBe(0xc013);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA).toBe(0xc014);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256).toBe(0xc027);
        expect(CIPHER_SUITE_CODES.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384).toBe(0xc028);
    });

    it("maps the plain RSA suites", () => {
        expect(CIPHER_SUITE_CODES.TLS_RSA_WITH_AES_128_GCM_SHA256).toBe(0x009c);
        expect(CIPHER_SUITE_CODES.TLS_RSA_WITH_AES_256_GCM_SHA384).toBe(0x009d);
        expect(CIPHER_SUITE_CODES.TLS_RSA_WITH_AES_128_CBC_SHA).toBe(0x002f);
        expect(CIPHER_SUITE_CODES.TLS_RSA_WITH_AES_256_CBC_SHA).toBe(0x0035);
        expect(CIPHER_SUITE_CODES.TLS_RSA_WITH_AES_128_CBC_SHA256).toBe(0x003c);
        expect(CIPHER_SUITE_CODES.TLS_RSA_WITH_AES_256_CBC_SHA256).toBe(0x003d);
    });
});

describe("NAMED_GROUP_CODES", () => {
    it("maps the three supported groups", () => {
        expect(NAMED_GROUP_CODES.x25519).toBe(0x001d);
        expect(NAMED_GROUP_CODES.secp256r1).toBe(0x0017);
        expect(NAMED_GROUP_CODES.secp384r1).toBe(0x0018);
    });
});

describe("SIGNATURE_SCHEME_CODES", () => {
    it("maps the ECDSA and RSA-PSS schemes", () => {
        expect(SIGNATURE_SCHEME_CODES.ecdsa_secp256r1_sha256).toBe(0x0403);
        expect(SIGNATURE_SCHEME_CODES.ecdsa_secp384r1_sha384).toBe(0x0503);
        expect(SIGNATURE_SCHEME_CODES.rsa_pss_rsae_sha256).toBe(0x0804);
        expect(SIGNATURE_SCHEME_CODES.rsa_pss_rsae_sha384).toBe(0x0805);
    });

    it("maps the PKCS#1 and Ed25519 schemes", () => {
        expect(SIGNATURE_SCHEME_CODES.rsa_pkcs1_sha256).toBe(0x0401);
        expect(SIGNATURE_SCHEME_CODES.rsa_pkcs1_sha384).toBe(0x0501);
        expect(SIGNATURE_SCHEME_CODES.rsa_pkcs1_sha1).toBe(0x0201);
        expect(SIGNATURE_SCHEME_CODES.ed25519).toBe(0x0807);
    });
});

describe("VERSION_CODES", () => {
    it("maps TLS 1.3 and TLS 1.2 (the versions every profile advertises)", () => {
        expect(VERSION_CODES["TLS 1.3"]).toBe(0x0304);
        expect(VERSION_CODES["TLS 1.2"]).toBe(0x0303);
    });

    it("maps the legacy versions no shipped profile advertises", () => {
        // These are part of the allow-list for completeness; ensure they stay correct.
        expect(VERSION_CODES["TLS 1.1"]).toBe(0x0302);
        expect(VERSION_CODES["TLS 1.0"]).toBe(0x0301);
    });
});
