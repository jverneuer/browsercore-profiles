/**
 * Chrome fingerprint definitions.
 *
 * TLS values are byte-accurate against real curl-impersonate ClientHello
 * captures. The authoritative ground truth is the lwthiker/curl-impersonate
 * wire captures (testing-worktree/captures/_probe/output/chrome*.json) together
 * with their reported ja3 / ja4 / peetprint fingerprints. Every value here is
 * verified against those captures:
 *
 *   - chrome-120: ja3 698f6d684588ddc1217dfb4454916129, peetprint
 *     8ad9325e12f531d2983b78860de7b0ec (no post-quantum group).
 *   - chrome-124..130: X25519Kyber768 (0x6399) added to supported_groups.
 *   - chrome-131+: X25519MLKEM768 (0x11ec) replaces Kyber768; the
 *     application_settings extension moves from 17513 to 17613.
 *
 * Chrome permutes its extension order at runtime (tls_permute_extensions), so
 * `extensionOrder` stores the canonical pre-permutation seed that
 * curl-impersonate configures — matching the peetprint's normalized order.
 * GREASE slots are tracked separately via the `grease` flag; the runtime
 * randomizes the actual 0x?a?a values per RFC 8701.
 */

import type { BrowserProfile, ProfileId } from "../types.js";

/** TLS 1.3 GREASE placeholder cipher (0x?a?a) Chrome inserts at the top of the list. */
const GREASE = "TLS_GREASE_RESERVED_0";

/**
 * Canonical (pre-permutation) Chrome extension order.
 *
 * Mirrors the peetprint-normalized order `0-10-11-13-16-APP_SETTINGS-18-23-27-
 * 35-43-45-5-51-65037-65281`. The only version-dependent slot is the
 * application_settings extension: 17513 (application_settings_old) through
 * chrome ~131, then 17613 (application_settings) from chrome ~132 onward.
 */
const chromeExtensionOrder = (appSettings: number): readonly number[] => [
    0, 10, 11, 13, 16, appSettings, 18, 23, 27, 35, 43, 45, 5, 51, 65037, 65281,
];

const chromeTlsBase = {
    supportedVersions: ["TLS 1.3", "TLS 1.2"],
    signatureAlgorithms: [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ],
    grease: true,
} as const;

const chromeHttp2Base = {
    initialWindowSize: 6291456,
    maxFrameSize: 16384,
    headerTableSize: 65536,
    weight: 256,
} as const;

const chromeHttp2Settings = {
    headerTableSize: 65536,
    enablePush: false,
    maxConcurrentStreams: 100,
    initialWindowSize: 6291456,
    maxFrameSize: 16384,
    maxHeaderListSize: 262144,
} as const;

const chromeHttp1Base = {
    connection: "keep-alive",
    acceptEncoding: "gzip, deflate, br",
    headerOrder: [
        "host",
        "connection",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
    ],
} as const;

const chromeCipherSuites: readonly string[] = [
    GREASE,
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

export const chrome120: BrowserProfile = {
    id: "chrome-120" as ProfileId,
    name: "chrome",
    version: "120.0.6099.71",
    tls: {
        ...chromeTlsBase,
        extensionOrder: chromeExtensionOrder(17513),
        keyShareGroups: ["x25519", "secp256r1", "secp384r1"],
        cipherSuites: chromeCipherSuites,
    },
    http2: {
        ...chromeHttp2Base,
        settings: chromeHttp2Settings,
    },
    http1: {
        ...chromeHttp1Base,
        defaultHeaders: {
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "upgrade-insecure-requests": "1",
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-language": "en-US,en;q=0.9",
        },
    },
};

export const chrome128: BrowserProfile = {
    id: "chrome-128" as ProfileId,
    name: "chrome",
    version: "128.0.6613.137",
    tls: {
        ...chromeTlsBase,
        extensionOrder: chromeExtensionOrder(17513),
        keyShareGroups: ["X25519Kyber768", "x25519", "secp256r1", "secp384r1"],
        cipherSuites: chromeCipherSuites,
    },
    http2: {
        ...chromeHttp2Base,
        settings: chromeHttp2Settings,
    },
    http1: {
        ...chromeHttp1Base,
        defaultHeaders: {
            "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "upgrade-insecure-requests": "1",
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-language": "en-US,en;q=0.9",
        },
    },
};

export const chrome140: BrowserProfile = {
    id: "chrome-140" as ProfileId,
    name: "chrome",
    version: "140.0.7339.18",
    tls: {
        ...chromeTlsBase,
        extensionOrder: chromeExtensionOrder(17613),
        keyShareGroups: ["X25519MLKEM768", "x25519", "secp256r1", "secp384r1"],
        cipherSuites: chromeCipherSuites,
    },
    http2: {
        ...chromeHttp2Base,
        settings: chromeHttp2Settings,
    },
    http1: {
        ...chromeHttp1Base,
        defaultHeaders: {
            "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "upgrade-insecure-requests": "1",
            "user-agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-language": "en-US,en;q=0.9",
        },
    },
};

export const ChromeProfiles = {
    chrome120,
    chrome128,
    chrome140,
} as const;
