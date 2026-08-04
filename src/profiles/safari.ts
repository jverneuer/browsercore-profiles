/**
 * Safari fingerprint definitions.
 *
 * Safari (WebKit) has a distinct TLS fingerprint: it enables GREASE, uses a
 * cipher order that prioritizes ChaCha20 less aggressively than Chrome, and
 * advertises a smaller set of signature algorithms. HTTP/2 settings are
 * conservative. Values mirror curl-impersonate's Safari 15.5 ground-truth
 * signature byte-for-byte (see tests/profiles-safari.test.ts for the wire-code
 * mapping). Safari 17 and 18 share this fingerprint; they differ only in
 * version string and User-Agent.
 */

import type { BrowserProfile, ProfileId } from "../types.js";

/** TLS 1.3 GREASE placeholder cipher (0x?a?a) Safari inserts at the top of the list. */
const GREASE = "TLS_GREASE_RESERVED_0";

/**
 * Safari TLS extension order, in wire order, taken verbatim from the
 * curl-impersonate signature. GREASE extension slots are excluded (their values
 * are randomized per-connection and the profile stores literal wire codes).
 */
const SAFARI_EXTENSION_ORDER: readonly number[] = [
    0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21,
];

const safariTlsBase = {
    extensionOrder: SAFARI_EXTENSION_ORDER,
    supportedVersions: ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"],
    keyShareGroups: ["x25519", "secp256r1", "secp384r1", "secp521r1"],
    /**
     * Safari's signature algorithm list, in wire order. Note the intentional
     * duplicate rsa_pss_rsae_sha384 (0x0805) — this is a real Safari quirk that
     * curl-impersonate preserves (BoringSSL's uniqueness check is patched out
     * for this reason). See boringssl-old-ciphers.patch in curl-impersonate.
     */
    signatureAlgorithms: [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_sha1",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ],
    grease: true,
} as const;

const safariHttp2Base = {
    initialWindowSize: 1048576,
    maxFrameSize: 16384,
    headerTableSize: 65536,
    weight: 256,
} as const;

const safariHttp1Base = {
    connection: "keep-alive",
    acceptEncoding: "gzip, deflate, br",
    headerOrder: [
        "host",
        "accept",
        "accept-encoding",
        "accept-language",
        "user-agent",
        "connection",
    ],
} as const;

/**
 * Safari cipher suites in wire order, matching curl-impersonate's Safari 15.5
 * signature. The legacy tail uses SHA-CBC (not SHA256-CBC) variants followed by
 * a 3DES tail — BoringSSL dropped these, but curl-impersonate restores them.
 */
const SAFARI_CIPHERS: readonly string[] = [
    GREASE,
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
];

export const safari17: BrowserProfile = {
    id: "safari-17" as ProfileId,
    name: "safari",
    version: "17.6",
    tls: {
        ...safariTlsBase,
        cipherSuites: SAFARI_CIPHERS,
    },
    http2: {
        ...safariHttp2Base,
        settings: {
            headerTableSize: 65536,
            enablePush: false,
            maxConcurrentStreams: 100,
            initialWindowSize: 1048576,
            maxFrameSize: 16384,
        },
    },
    http1: {
        ...safariHttp1Base,
        defaultHeaders: {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        },
    },
};

export const safari18: BrowserProfile = {
    id: "safari-18" as ProfileId,
    name: "safari",
    version: "18.1",
    tls: {
        ...safariTlsBase,
        cipherSuites: SAFARI_CIPHERS,
    },
    http2: {
        ...safariHttp2Base,
        settings: {
            headerTableSize: 65536,
            enablePush: false,
            maxConcurrentStreams: 100,
            initialWindowSize: 1048576,
            maxFrameSize: 16384,
        },
    },
    http1: {
        ...safariHttp1Base,
        defaultHeaders: {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        },
    },
};

export const SafariProfiles = {
    safari17,
    safari18,
} as const;
