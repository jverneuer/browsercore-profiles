/**
 * Byte-accurate verification that the Edge profiles match curl-impersonate's
 * ground-truth TLS signature (Edge 101 on Windows 10).
 *
 * Ground truth source:
 *   gh api repos/lwthiker/curl-impersonate/contents/tests/signatures/edge.yaml
 *
 * Every expected wire code below is copied verbatim from that signature, so a
 * mismatch means the profile has drifted from the real browser.
 */

import { describe, expect, it } from "vitest";
import { EdgeProfiles } from "../src/index.js";
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

/** Map an Edge profile's cipher suites to their 2-byte IANA wire codes. */
function cipherCodes(profile: typeof EdgeProfiles.edge120): number[] {
    return profile.tls.cipherSuites.map((c) => code(CIPHER_SUITE_CODES, c));
}

/** Map an Edge profile's key-share groups to their 2-byte IANA wire codes. */
function groupCodes(profile: typeof EdgeProfiles.edge120): number[] {
    return profile.tls.keyShareGroups.map((g) => code(NAMED_GROUP_CODES, g));
}

/** Map an Edge profile's signature algorithms to their 2-byte IANA wire codes. */
function sigCodes(profile: typeof EdgeProfiles.edge120): number[] {
    return profile.tls.signatureAlgorithms.map((s) => code(SIGNATURE_SCHEME_CODES, s));
}

/** Map an Edge profile's supported versions to their 2-byte IANA wire codes. */
function versionCodes(profile: typeof EdgeProfiles.edge120): number[] {
    return profile.tls.supportedVersions.map((v) => code(VERSION_CODES, v));
}

describe("Edge profiles — curl-impersonate ground truth", () => {
    it("edge120 and edge128 share an identical TLS fingerprint", () => {
        const a = buildExpectedClientHello(EdgeProfiles.edge120, "");
        const b = buildExpectedClientHello(EdgeProfiles.edge128, "");
        expect(a.cipherSuites).toEqual(b.cipherSuites);
        expect(a.extensionTypes).toEqual(b.extensionTypes);
        expect(a.supportedVersions).toEqual(b.supportedVersions);
        expect(a.keyShareGroups).toEqual(b.keyShareGroups);
        expect(a.signatureAlgorithms).toEqual(b.signatureAlgorithms);
        expect(a.grease).toBe(true);
        expect(b.grease).toBe(true);
    });

    it("cipher suites match the curl-impersonate signature exactly (in wire order)", () => {
        // From edge_101.signature.tls_client_hello.ciphersuites, with the
        // leading GREASE slot preserved as TLS_GREASE_RESERVED_0. Same set and
        // order as Chrome (Chromium-based).
        const got = cipherCodes(EdgeProfiles.edge120);
        expect(got[0]).toBe(0x0a0a); // GREASE placeholder
        expect(got).toEqual([
            0x0a0a, // GREASE
            0x1301, 0x1302, 0x1303, // TLS_AES_128/256_GCM_SHA256/384, CHACHA20
            0xc02b, 0xc02f, // ECDHE_ECDSA/RSA: AES_128_GCM
            0xc02c, 0xc030, // ECDHE_ECDSA/RSA: AES_256_GCM
            0xcca9, 0xcca8, // ECDHE_ECDSA/RSA: CHACHA20
            0xc013, 0xc014, // ECDHE_RSA: AES_128/256_CBC_SHA
            0x009c, 0x009d, // RSA: AES_128/256_GCM_SHA256/384
            0x002f, 0x0035, // RSA: AES_128/256_CBC_SHA
        ]);
    });

    it("extension order matches the curl-impersonate signature exactly (in wire order)", () => {
        // From edge_101.signature.tls_client_hello.extensions, GREASE slots
        // excluded (their values are randomized per-connection).
        const got = buildExpectedClientHello(EdgeProfiles.edge120, "").extensionTypes;
        expect(got).toEqual([
            0, // server_name
            23, // extended_master_secret
            65281, // renegotiation_info
            10, // supported_groups
            11, // ec_point_formats
            35, // session_ticket
            16, // application_layer_protocol_negotiation
            5, // status_request
            13, // signature_algorithms
            18, // signed_certificate_timestamp
            51, // keyshare
            45, // psk_key_exchange_modes
            43, // supported_versions
            27, // compress_certificate
            17513, // application_settings (ALPS)
            21, // padding
        ]);
    });

    it("supported groups match the curl-impersonate signature exactly", () => {
        // From edge_101.signature.tls_client_hello.extensions.supported_groups,
        // GREASE slot excluded.
        const got = groupCodes(EdgeProfiles.edge120);
        expect(got).toEqual([
            0x001d, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
        ]);
    });

    it("supported versions match the curl-impersonate signature exactly", () => {
        // From edge_101.signature.tls_client_hello.extensions.supported_versions,
        // GREASE slot excluded. Edge advertises only TLS 1.3 and 1.2.
        const got = versionCodes(EdgeProfiles.edge120);
        expect(got).toEqual([
            0x0304, // TLS 1.3
            0x0303, // TLS 1.2
        ]);
    });

    it("signature algorithms match the curl-impersonate signature exactly", () => {
        // From edge_101.signature.tls_client_hello.extensions.signature_algorithms.
        const got = sigCodes(EdgeProfiles.edge120);
        expect(got).toEqual([
            0x0403, // ecdsa_secp256r1_sha256
            0x0804, // rsa_pss_rsae_sha256
            0x0401, // rsa_pkcs1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0805, // rsa_pss_rsae_sha384
            0x0501, // rsa_pkcs1_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0601, // rsa_pkcs1_sha512
        ]);
    });

    it("advertises session_ticket and application_settings extensions (Chromium parity)", () => {
        const ext = buildExpectedClientHello(EdgeProfiles.edge120, "").extensionTypes;
        expect(ext).toContain(35); // session_ticket
        expect(ext).toContain(17513); // application_settings (ALPS)
    });

    it("edge120 and edge128 differ only in version, UA, and sec-ch-ua brands", () => {
        const a = EdgeProfiles.edge120;
        const b = EdgeProfiles.edge128;
        expect(a.version).toBe("120.0.2210.91");
        expect(b.version).toBe("128.0.2739.70");
        expect(a.http1.defaultHeaders["user-agent"]).toContain("Edg/120");
        expect(b.http1.defaultHeaders["user-agent"]).toContain("Edg/128");
        expect(a.http1.defaultHeaders["sec-ch-ua"]).toContain('Microsoft Edge";v="120"');
        expect(b.http1.defaultHeaders["sec-ch-ua"]).toContain('Microsoft Edge";v="128"');
    });
});
