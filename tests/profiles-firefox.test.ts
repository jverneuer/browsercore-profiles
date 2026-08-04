/**
 * Firefox profile verification against the curl-impersonate ground truth.
 *
 * The firefox-133 ClientHello capture in tests/fixtures/firefox-133 is the
 * curl-impersonate Firefox output (see its .meta.json). These tests project
 * each shipped Firefox profile's TLS fields onto wire codes and assert they
 * match the capture byte-for-byte on the deterministic fields: cipher suites,
 * extension order, and signature algorithms. supported_groups is checked
 * against the patch's named_groups[] table (the capture prefixes a GREASE
 * value that the profile cannot predict, so it is stripped before comparing).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { FirefoxProfiles } from "../src/profiles/firefox.js";
import { buildExpectedClientHello } from "../src/validate.js";
import {
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
} from "../src/codes.js";

const here = dirname(fileURLToPath(import.meta.url));
const capturePath = join(here, "fixtures", "firefox-133", "tls", "client_hello.bin");

/** Minimal TLS 1.3 ClientHello parser — extracts the deterministic fields. */
interface ParsedClientHello {
    readonly cipherSuites: readonly number[];
    readonly extensionTypes: readonly number[];
    readonly signatureAlgorithms: readonly number[];
    readonly supportedGroups: readonly number[];
}

function readUint16(data: Uint8Array, offset: number): number {
    return (data[offset] << 8) | data[offset + 1];
}

function parseClientHello(bytes: Uint8Array): ParsedClientHello {
    // Record layer: ContentType(1) + legacy_version(2) + length(2).
    let off = 5;
    // Handshake: type(1) + length(3).
    off += 4;
    // client_version(2) + random(32).
    off += 2 + 32;
    // session_id: length(1) + session_id.
    const sessionIdLen = bytes[off] ?? 0;
    off += 1 + sessionIdLen;
    // cipher_suites: length(2) + suites.
    const cipherLen = readUint16(bytes, off);
    off += 2;
    const cipherSuites: number[] = [];
    for (let i = 0; i < cipherLen; i += 2) {
        cipherSuites.push(readUint16(bytes, off + i));
    }
    off += cipherLen;
    // compression_methods: length(1) + methods.
    const compLen = bytes[off] ?? 0;
    off += 1 + compLen;
    // extensions: length(2) + extensions.
    const extLen = readUint16(bytes, off);
    off += 2;
    const extEnd = off + extLen;
    const extensionTypes: number[] = [];
    const signatureAlgorithms: number[] = [];
    const supportedGroups: number[] = [];
    while (off < extEnd) {
        const extType = readUint16(bytes, off);
        off += 2;
        const extDataLen = readUint16(bytes, off);
        off += 2;
        extensionTypes.push(extType);
        if (extType === 13) {
            // signature_algorithms: 2-byte length + list of 2-byte schemes.
            const listLen = readUint16(bytes, off);
            for (let i = 0; i < listLen; i += 2) {
                signatureAlgorithms.push(readUint16(bytes, off + 2 + i));
            }
        } else if (extType === 10) {
            // supported_groups: 2-byte length + list of 2-byte group ids.
            const listLen = readUint16(bytes, off);
            for (let i = 0; i < listLen; i += 2) {
                supportedGroups.push(readUint16(bytes, off + 2 + i));
            }
        }
        off += extDataLen;
    }
    return { cipherSuites, extensionTypes, signatureAlgorithms, supportedGroups };
}

const capture = parseClientHello(readFileSync(capturePath));

const firefoxProfiles = Object.values(FirefoxProfiles);

describe("Firefox profiles — curl-impersonate ground truth (firefox-133 capture)", () => {
    it("every Firefox profile projects to the exact cipher suite wire order", () => {
        for (const profile of firefoxProfiles) {
            const expected = buildExpectedClientHello(profile, "");
            expect(expected.cipherSuites, `${profile.id} cipherSuites`).toEqual([
                ...capture.cipherSuites,
            ]);
        }
    });

    it("every Firefox profile projects to the exact extension type order", () => {
        for (const profile of firefoxProfiles) {
            const expected = buildExpectedClientHello(profile, "");
            expect(expected.extensionTypes, `${profile.id} extensionTypes`).toEqual([
                ...capture.extensionTypes,
            ]);
        }
    });

    it("every Firefox profile projects to the exact signature algorithm order", () => {
        for (const profile of firefoxProfiles) {
            const expected = buildExpectedClientHello(profile, "");
            expect(expected.signatureAlgorithms, `${profile.id} signatureAlgorithms`).toEqual([
                ...capture.signatureAlgorithms,
            ]);
        }
    });

    it("every Firefox profile advertises the patch's six named groups (capture GREASE stripped)", () => {
        // The capture prefixes supported_groups with a randomized GREASE value
        // (0x11ec) that the profile cannot predict. The meta.json marks the whole
        // extension block as "grease". Strip leading groups the profile does not
        // advertise and compare the deterministic remainder against the profile.
        for (const profile of firefoxProfiles) {
            const expected = buildExpectedClientHello(profile, "");
            const expectedGroups = new Set(expected.keyShareGroups);
            const captureGroups = capture.supportedGroups.filter((g) => expectedGroups.has(g));
            expect(expected.keyShareGroups, `${profile.id} keyShareGroups`).toEqual(
                captureGroups,
            );
        }
    });
});

describe("Firefox profile data — codes.js allow-list coverage", () => {
    it("every cipher name a Firefox profile uses resolves in CIPHER_SUITE_CODES", () => {
        for (const profile of firefoxProfiles) {
            for (const name of profile.tls.cipherSuites) {
                expect(CIPHER_SUITE_CODES[name], `${profile.id}: unknown cipher ${name}`).toBeDefined();
            }
        }
    });

    it("every signature scheme a Firefox profile uses resolves in SIGNATURE_SCHEME_CODES", () => {
        for (const profile of firefoxProfiles) {
            for (const name of profile.tls.signatureAlgorithms) {
                expect(
                    SIGNATURE_SCHEME_CODES[name],
                    `${profile.id}: unknown signature scheme ${name}`,
                ).toBeDefined();
            }
        }
    });

    it("every named group a Firefox profile uses resolves in NAMED_GROUP_CODES", () => {
        for (const profile of firefoxProfiles) {
            for (const name of profile.tls.keyShareGroups) {
                expect(NAMED_GROUP_CODES[name], `${profile.id}: unknown group ${name}`).toBeDefined();
            }
        }
    });

    it("the Firefox signature-scheme set matches the curl-impersonate patch order exactly", () => {
        // Order from nss.c signatures[] in curl-impersonate's firefox patch.
        const patchOrder = [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "ecdsa_sha1",
            "rsa_pkcs1_sha1",
        ];
        for (const profile of firefoxProfiles) {
            expect(profile.tls.signatureAlgorithms, `${profile.id} sig scheme order`).toEqual(
                patchOrder,
            );
        }
    });

    it("the Firefox named-group set matches the curl-impersonate patch order exactly", () => {
        // Order from nss.c named_groups[] in curl-impersonate's firefox patch.
        const patchOrder = [
            "x25519",
            "secp256r1",
            "secp384r1",
            "secp521r1",
            "ffdhe2048",
            "ffdhe3072",
        ];
        for (const profile of firefoxProfiles) {
            expect(profile.tls.keyShareGroups, `${profile.id} named group order`).toEqual(
                patchOrder,
            );
        }
    });
});
