/**
 * Safari fingerprint definitions.
 *
 * Safari (WebKit) has a distinct TLS fingerprint: it enables GREASE, uses a
 * cipher order that prioritizes ChaCha20 less aggressively than Chrome, and
 * advertises a smaller set of signature algorithms. TLS values mirror
 * curl-impersonate's Safari 15.5 ground-truth signature byte-for-byte (see
 * tests/profiles-safari.test.ts for the wire-code mapping).
 *
 * HTTP/2 values are per published Safari captures that document the SETTINGS
 * wire order (fixed in #55 — the pre-0.2.5 h2 data was never oracle-validated
 * and drew GOAWAY(PROTOCOL_ERROR) from strict nginx edges, because it carried
 * an invented SETTINGS set plus a 0-increment connection WINDOW_UPDATE, which
 * RFC 9113 §6.9 makes a PROTOCOL_ERROR):
 *
 *   - Safari 17.0 on macOS (lexiforest/curl-impersonate
 *     tests/signatures/safari_17.0_macOS.yaml): SETTINGS frame
 *     `2:0; 4:4194304; 3:100` (wire order 2,4,3), then a connection-level
 *     WINDOW_UPDATE of 10485760, then HEADERS with pseudo order
 *     :method,:scheme,:path,:authority and NO `priority` header
 *     (akamai `2:0;4:4194304;3:100|10485760|0|m,s,p,a`). Cross-confirmed by a
 *     real macOS Safari 18.2 capture with the identical akamai hash
 *     (lexiforest/curl_cffi#460) and by bogdanfinn/tls-client's desktop Safari
 *     15.6.1/16.0 profiles (same window/pseudo, ids 4,3).
 *   - Safari 18.0 on macOS (lexiforest/curl-impersonate
 *     tests/signatures/safari_18.0_macOS.yaml): SETTINGS frame
 *     `2:0; 3:100; 4:2097152; 8:1; 9:1` (wire order 2,3,4,8,9), then a
 *     connection-level WINDOW_UPDATE of 10420225, then HEADERS with pseudo
 *     order :method,:scheme,:authority,:path and `priority: u=0, i`
 *     (akamai `2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p`). Safari 18.4+/
 *     26/27 drop id 8 (curl-impersonate safari_18.4_macOS/safari270
 *     signatures; bogdanfinn/tls-client Safari_27_2 desktop capture), keeping
 *     ids [2,3,4,9]. Cross-confirmed by a real iOS Safari 18.3 capture with
 *     the identical akamai hash (lexiforest/curl_cffi#530) and tls-client's
 *     Safari iOS 18.0/18.5 profiles.
 *
 * The WINDOW_UPDATE increments are the exact frame values: Safari 17.x grows
 * the connection window by 10485760 bytes; Safari 18.x by 10420225
 * (10420225 + the 65535 RFC default = 10485760 total = 10 MiB).
 */

import type { BrowserProfile } from "../types.js";

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
    ecPointFormats: [0x00],
    compressCertificateAlgorithms: [0x02],
} as const;

/**
 * HTTP/2 tuning shared by both Safari profiles. Real Safari 17/18 SETTINGS
 * frames carry ONLY ids 2, 3, 4 (+ 8/9 on 18.x) — no HEADER_TABLE_SIZE (1),
 * no MAX_FRAME_SIZE (5), no MAX_HEADER_LIST_SIZE (6), and no h2 GREASE (see
 * the captured frames quoted at the top of this file). The top-level
 * `headerTableSize`/`maxFrameSize` stay at RFC defaults (7541 §4.1 table 4096,
 * 9113 §6.5.2 frame 16384) as engine tuning values; they are NOT serialized.
 */
const safariHttp2Base = {
    maxFrameSize: 16384,
    headerTableSize: 4096,
    weight: 256,
    grease: false,
} as const;

/**
 * Safari 17.x h2 impersonation per the curl-impersonate safari_17.0_macOS
 * capture: SETTINGS ids [2, 4, 3], connection WINDOW_UPDATE 10485760, pseudo
 * headers m,s,p,a (WebKit order — distinct from Chrome's m,a,s,p).
 */
const safari17Http2Impersonation = {
    settingsOrder: [2, 4, 3],
    connectionWindowUpdate: 10485760,
    pseudoHeaderOrder: ["method", "scheme", "path", "authority"],
} as const;

/**
 * Safari 18.x h2 impersonation per the curl-impersonate safari_18.0_macOS
 * capture: SETTINGS ids [2, 3, 4, 8, 9], connection WINDOW_UPDATE 10420225,
 * pseudo headers m,s,a,p (WebKit reshuffled :path and :authority in 18), and
 * the h2-only extensible-priority header on navigations (`priority: u=0, i`,
 * present in the capture's HEADERS alongside the sec-fetch defaults).
 */
const safari18Http2Impersonation = {
    settingsOrder: [2, 3, 4, 8, 9],
    connectionWindowUpdate: 10420225,
    pseudoHeaderOrder: ["method", "scheme", "authority", "path"],
} as const;

/**
 * Safari 17.x SETTINGS payload (wire ids 2, 4, 3): ENABLE_PUSH=0,
 * INITIAL_WINDOW_SIZE=4 MiB, MAX_CONCURRENT_STREAMS=100. No id 1/5/6, no GREASE.
 */
const safari17Http2Settings = {
    enablePush: false,
    maxConcurrentStreams: 100,
    initialWindowSize: 4194304,
} as const;

/**
 * Safari 18.x SETTINGS payload (wire ids 2, 3, 4, 8, 9): ENABLE_PUSH=0,
 * MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=2 MiB,
 * ENABLE_CONNECT_PROTOCOL=1, NO_RFC7540_PRIORITIES=1. Ids 8/9 are RFC 8441/9113
 * settings beyond the RFC 7540 id range — engines map them by numeric id
 * (browsercore-fetch ≥0.2.20 maps only 1-6 today; until then the wire frame
 * carries ids 2,3,4, which matches tls-client's Safari iOS 18 profiles modulo
 * id 9 and is protocol-valid everywhere).
 */
const safari18Http2Settings = {
    enablePush: false,
    maxConcurrentStreams: 100,
    initialWindowSize: 2097152,
    enableConnectProtocol: 1,
    noRfc7540Priorities: 1,
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
    id: "safari-17",
    name: "safari",
    version: "17.6",
    tls: {
        ...safariTlsBase,
        cipherSuites: SAFARI_CIPHERS,
    },
    http2: {
        ...safariHttp2Base,
        ...safari17Http2Impersonation,
        initialWindowSize: safari17Http2Settings.initialWindowSize,
        settings: safari17Http2Settings,
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
    id: "safari-18",
    name: "safari",
    version: "18.1",
    tls: {
        ...safariTlsBase,
        cipherSuites: SAFARI_CIPHERS,
    },
    http2: {
        ...safariHttp2Base,
        ...safari18Http2Impersonation,
        initialWindowSize: safari18Http2Settings.initialWindowSize,
        settings: safari18Http2Settings,
        // Safari 18+ sends the extensible-priority header on h2 navigations
        // (safari_18.0_macOS capture HEADERS: `priority: u=0, i`). Not an h1
        // default. Safari 17.0's capture has no priority header — 17.x omits it.
        http2DefaultHeaders: { "priority": "u=0, i" },
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
