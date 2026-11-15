/**
 * Firefox fingerprint definitions.
 *
 * TLS values mirror curl-impersonate's Firefox build (see
 * lwthiker/curl-impersonate firefox/patches/curl-impersonate.patch — nss.c).
 * Cipher order, extension order, signature algorithms, and named groups are
 * byte-accurate against the firefox-133 ClientHello capture
 * (tests/fixtures/firefox-133) and the patch's signatures[]/named_groups[]
 * tables. HTTP/2 data (SETTINGS values + order, pseudo-header order, h2-only
 * headers) is aligned to the firefox-133 oracle capture in browsercore-testing
 * — see the firefoxHttp2Impersonation / firefoxHttp2Settings comments.
 *
 * Note on cipher names: codes.js maps names to wire codes with a
 * browser-specific remapping (AES_256->0x1302, ChaCha20->0x1303) so that this
 * profile's name order produces Firefox's true wire order
 * (0x1301,0x1303,0x1302,...). Do not reorder these names to match IANA — that
 * would emit Chrome's wire order. Verified against the capture.
 */

import type { BrowserProfile, ProfileId } from "../types.js";

const firefoxTlsBase = {
    extensionOrder: [
        0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 27, 65037,
    ],
    supportedVersions: ["TLS 1.3", "TLS 1.2"],
    keyShareGroups: [
        "x25519",
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "ffdhe2048",
        "ffdhe3072",
    ],
    signatureAlgorithms: [
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
    ],
    grease: false,
} as const;

const firefoxTlsCiphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
] as const;

/**
 * Firefox HTTP/2 tuning shared across versions.
 *
 * `initialWindowSize` follows the real Firefox SETTINGS frame (131072 per the
 * firefox-133 oracle capture in browsercore-testing) — the connection-level
 * window grows via the preface WINDOW_UPDATE, not via SETTINGS.
 * firefox-120 predates the impersonation data and pins the legacy 12MB value
 * from the curl-impersonate patch; see its inline override.
 */
const firefoxHttp2Base = {
    initialWindowSize: 131072,
    maxFrameSize: 16384,
    headerTableSize: 65536,
    weight: 256,
} as const;

/**
 * Impersonation fields shared by firefox-128 and firefox-135 (but not
 * firefox-120, which predates the impersonation data). Firefox differs from
 * Chrome: no HTTP/2 GREASE, a distinct connection WINDOW_UPDATE, and
 * compress_certificate offers brotli + zlib (not just brotli).
 */
const firefoxTlsImpersonation = {
    ecPointFormats: [0x00],
    compressCertificateAlgorithms: [0x02, 0x01],
} as const;

/**
 * HTTP/2 impersonation fields shared by firefox-128 and firefox-135 (but not
 * firefox-120, which predates the impersonation data). Values are aligned to
 * the firefox-133 oracle capture (browsercore-testing/captures/firefox-133/
 * oracle_capture.reference.json): SETTINGS `1:65536;2:0;4:131072;5:16384|
 * 12517377|0|m,p,a,s` and pseudo-header wire order
 * `:method,:path,:authority,:scheme`.
 */
const firefoxHttp2Impersonation = {
    settingsOrder: [1, 2, 4, 5],
    grease: false,
    connectionWindowUpdate: 12517377,
    pseudoHeaderOrder: ["method", "path", "authority", "scheme"],
} as const;

/**
 * Firefox SETTINGS frame payload per the firefox-133 oracle: four entries,
 * ending in MAX_FRAME_SIZE (id 5) — Firefox sends MAX_FRAME_SIZE where Chrome
 * sends MAX_HEADER_LIST_SIZE, and never sends MAX_CONCURRENT_STREAMS.
 */
const firefoxHttp2Settings = {
    headerTableSize: 65536,
    enablePush: false,
    initialWindowSize: 131072,
    maxFrameSize: 16384,
} as const;

const firefoxHttp1Base = {
    connection: "keep-alive",
    acceptEncoding: "gzip, deflate, br",
    headerOrder: [
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
    ],
} as const;

export const firefox120: BrowserProfile = {
    id: "firefox-120" as ProfileId,
    name: "firefox",
    version: "120.0",
    tls: {
        ...firefoxTlsBase,
        cipherSuites: firefoxTlsCiphers,
    },
    http2: {
        ...firefoxHttp2Base,
        // Pre-impersonation legacy data (no oracle capture): keep the
        // curl-impersonate patch's 12MB SETTINGS window.
        initialWindowSize: 12582912,
        settings: {
            headerTableSize: 65536,
            enablePush: false,
            maxConcurrentStreams: 100,
            initialWindowSize: 12582912,
            maxFrameSize: 16384,
        },
    },
    http1: {
        ...firefoxHttp1Base,
        defaultHeaders: {
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "upgrade-insecure-requests": "1",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
        },
    },
};

export const firefox128: BrowserProfile = {
    id: "firefox-128" as ProfileId,
    name: "firefox",
    version: "128.0",
    tls: {
        ...firefoxTlsBase,
        ...firefoxTlsImpersonation,
        cipherSuites: firefoxTlsCiphers,
    },
    http2: {
        ...firefoxHttp2Base,
        ...firefoxHttp2Impersonation,
        settings: firefoxHttp2Settings,
        // h2-only defaults per real Firefox: `te: trailers` has been sent for
        // as long as Firefox has spoken h2. The `priority` header is NOT set
        // here — it first shipped in Firefox 133, after this profile.
        http2DefaultHeaders: { "te": "trailers" },
    },
    http1: {
        ...firefoxHttp1Base,
        defaultHeaders: {
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "upgrade-insecure-requests": "1",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
        },
    },
};

export const firefox135: BrowserProfile = {
    id: "firefox-135" as ProfileId,
    name: "firefox",
    version: "135.0",
    tls: {
        ...firefoxTlsBase,
        ...firefoxTlsImpersonation,
        cipherSuites: firefoxTlsCiphers,
    },
    http2: {
        ...firefoxHttp2Base,
        ...firefoxHttp2Impersonation,
        settings: firefoxHttp2Settings,
        // h2-only defaults per the firefox-133 oracle HEADERS frame
        // (wire order: priority before te).
        http2DefaultHeaders: { "priority": "u=0, i", "te": "trailers" },
    },
    http1: {
        ...firefoxHttp1Base,
        defaultHeaders: {
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "upgrade-insecure-requests": "1",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
        },
    },
};

export const FirefoxProfiles = {
    firefox120,
    firefox128,
    firefox135,
} as const;
