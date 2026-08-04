/**
 * Byte-accurate verification that the Safari profiles match curl-impersonate's
 * ground-truth TLS signature (Safari 15.5 on macOS 12.4).
 *
 * Ground truth source:
 *   gh api repos/lwthiker/curl-impersonate/contents/tests/signatures/safari.yaml
 *
 * Every expected wire code below is copied verbatim from that signature, so a
 * mismatch means the profile has drifted from the real browser.
 */

import { describe, expect, it } from "vitest";
import { SafariProfiles } from "../src/index.js";
import { buildExpectedClientHello } from "../src/validate.js";
import {
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
    VERSION_CODES,
} from "../src/codes.js";

/** Look up a wire code by name, failing the test with a clear message if unknown. */
function code(map: Readonly<Record<string, number>>, name: string): number {
    const c = map[name];
    if (c === undefined) throw new Error(`No wire code for ${name}`);
    return c;
}

/** Map a Safari profile's cipher suites to their 2-byte IANA wire codes. */
function cipherCodes(profile: typeof SafariProfiles.safari17): number[] {
    return profile.tls.cipherSuites.map((c) => code(CIPHER_SUITE_CODES, c));
}

/** Map a Safari profile's key-share groups to their 2-byte IANA wire codes. */
function groupCodes(profile: typeof SafariProfiles.safari17): number[] {
    return profile.tls.keyShareGroups.map((g) => code(NAMED_GROUP_CODES, g));
}

/** Map a Safari profile's signature algorithms to their 2-byte IANA wire codes. */
function sigCodes(profile: typeof SafariProfiles.safari17): number[] {
    return profile.tls.signatureAlgorithms.map((s) => code(SIGNATURE_SCHEME_CODES, s));
}

/** Map a Safari profile's supported versions to their 2-byte IANA wire codes. */
function versionCodes(profile: typeof SafariProfiles.safari17): number[] {
    return profile.tls.supportedVersions.map((v) => code(VERSION_CODES, v));
}

describe("Safari profiles — curl-impersonate ground truth", () => {
    it("safari17 and safari18 share an identical TLS fingerprint", () => {
        const a = buildExpectedClientHello(SafariProfiles.safari17, "");
        const b = buildExpectedClientHello(SafariProfiles.safari18, "");
        expect(a.cipherSuites).toEqual(b.cipherSuites);
        expect(a.extensionTypes).toEqual(b.extensionTypes);
        expect(a.supportedVersions).toEqual(b.supportedVersions);
        expect(a.keyShareGroups).toEqual(b.keyShareGroups);
        expect(a.signatureAlgorithms).toEqual(b.signatureAlgorithms);
        expect(a.grease).toBe(true);
        expect(b.grease).toBe(true);
    });

    it("cipher suites match the curl-impersonate signature exactly (in wire order)", () => {
        // From safari_15_5_macos12_4.signature.tls_client_hello.ciphersuites,
        // with the leading GREASE slot preserved as TLS_GREASE_RESERVED_0.
        const got = cipherCodes(SafariProfiles.safari17);
        expect(got[0]).toBe(0x0a0a); // GREASE placeholder
        expect(got).toEqual([
            0x0a0a, // GREASE
            0x1301, 0x1302, 0x1303, // TLS_AES_128/256_GCM_SHA256/384, CHACHA20
            0xc02c, 0xc02b, 0xcca9, // ECDHE_ECDSA: AES_256/128_GCM, CHACHA20
            0xc030, 0xc02f, 0xcca8, // ECDHE_RSA: AES_256/128_GCM, CHACHA20
            0xc00a, 0xc009, // ECDHE_ECDSA: AES_256/128_CBC_SHA (SHA, not SHA256)
            0xc014, 0xc013, // ECDHE_RSA: AES_256/128_CBC_SHA
            0x009d, 0x009c, // RSA: AES_256/128_GCM_SHA384/256
            0x0035, 0x002f, // RSA: AES_256/128_CBC_SHA
            0xc008, 0xc012, 0x000a, // 3DES tail (ECDHE_ECDSA, ECDHE_RSA, RSA)
        ]);
    });

    it("extension order matches the curl-impersonate signature exactly (in wire order)", () => {
        // From safari_15_5.signature.tls_client_hello.extensions, GREASE slots
        // excluded (their values are randomized per-connection).
        const got = buildExpectedClientHello(SafariProfiles.safari17, "").extensionTypes;
        expect(got).toEqual([
            0, // server_name
            23, // extended_master_secret
            65281, // renegotiation_info
            10, // supported_groups
            11, // ec_point_formats
            16, // application_layer_protocol_negotiation
            5, // status_request
            13, // signature_algorithms
            18, // signed_certificate_timestamp
            51, // keyshare
            45, // psk_key_exchange_modes
            43, // supported_versions
            27, // compress_certificate
            21, // padding
        ]);
    });

    it("supported groups match the curl-impersonate signature exactly", () => {
        // From safari_15_5.signature.tls_client_hello.extensions.supported_groups,
        // GREASE slot excluded.
        const got = groupCodes(SafariProfiles.safari17);
        expect(got).toEqual([
            0x001d, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
        ]);
    });

    it("supported versions match the curl-impersonate signature exactly", () => {
        // From safari_15_5.signature.tls_client_hello.extensions.supported_versions,
        // GREASE slot excluded.
        const got = versionCodes(SafariProfiles.safari17);
        expect(got).toEqual([
            0x0304, // TLS 1.3
            0x0303, // TLS 1.2
            0x0302, // TLS 1.1
            0x0301, // TLS 1.0
        ]);
    });

    it("signature algorithms match the curl-impersonate signature exactly, including the intentional 0x0805 duplicate", () => {
        // From safari_15_5.signature.tls_client_hello.extensions.signature_algorithms.
        // Note the duplicate 0x0805 (rsa_pss_rsae_sha384) — a real WebKit quirk.
        const got = sigCodes(SafariProfiles.safari17);
        expect(got).toEqual([
            0x0403, // ecdsa_secp256r1_sha256
            0x0804, // rsa_pss_rsae_sha256
            0x0401, // rsa_pkcs1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0203, // ecdsa_sha1
            0x0805, // rsa_pss_rsae_sha384
            0x0805, // rsa_pss_rsae_sha384 (intentional duplicate)
            0x0501, // rsa_pkcs1_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0601, // rsa_pkcs1_sha512
            0x0201, // rsa_pkcs1_sha1
        ]);
    });

    it("does not advertise session_ticket or pre_shared_key extensions", () => {
        // Safari's extension set is distinct from Chrome/Edge — it omits these.
        const ext = buildExpectedClientHello(SafariProfiles.safari17, "").extensionTypes;
        expect(ext).not.toContain(35); // session_ticket
        expect(ext).not.toContain(41); // pre_shared_key
    });

    it("safari17 and safari18 differ only in version and User-Agent", () => {
        const a = SafariProfiles.safari17;
        const b = SafariProfiles.safari18;
        expect(a.version).toBe("17.6");
        expect(b.version).toBe("18.1");
        expect(a.http1.defaultHeaders["user-agent"]).toContain("Version/17.6");
        expect(b.http1.defaultHeaders["user-agent"]).toContain("Version/18.1");
    });
});
