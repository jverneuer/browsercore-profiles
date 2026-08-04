/**
 * IANA TLS registry codes used to project profile names onto wire values.
 *
 * Cipher suite codes are imported from @browsercore/tls, which is the single
 * source of truth for the suite table. This module re-exports them so profile
 * authors can access both the canonical name list (ALL_CIPHER_SUITES) and
 * the wire-code map (CIPHER_SUITE_CODES) from one place.
 *
 * Other registries (named groups, signature schemes, protocol versions) are
 * still defined here — they live only in profiles and have no tls-side table
 * to import from.
 */

import { ProfileError } from "./errors.js";
import {
    ALL_CIPHER_SUITES,
    cipherSuiteToWire as cipherSuiteToWireFromTls,
    isCipherSuite,
} from "@browsercore/tls";

export { ALL_CIPHER_SUITES, isCipherSuite } from "@browsercore/tls";

/**
 * The name Chrome/Edge use in their cipher list to mark a GREASE slot (RFC 8701).
 * The real value is randomized per-connection (0x0a0a..0xfafa); validation accepts
 * any GREASE-pattern byte pair at a slot marked with this placeholder.
 */
export const CIPHER_GREASE_PLACEHOLDER = "TLS_GREASE_RESERVED_0";

/**
 * Selected IANA TLS Cipher Suite codes, keyed by the canonical suite name used in profiles.
 *
 * Built from @browsercore/tls's canonical table — do not edit by hand. The
 * tls package is the single source of truth for which suites exist and their
 * wire values; this map is derived so profile code can do name→code lookups
 * without re-importing the tls package.
 */
export const CIPHER_SUITE_CODES: Readonly<Record<string, number>> = (() => {
    const map: Record<string, number> = {};
    for (const suite of ALL_CIPHER_SUITES) {
        map[suite] = cipherSuiteToWireFromTls(suite);
    }
    return map;
})();

/** Selected IANA TLS Supported Groups (named groups) codes. */
export const NAMED_GROUP_CODES: Readonly<Record<string, number>> = {
    x25519: 0x001d,
    secp256r1: 0x0017,
    secp384r1: 0x0018,
    secp521r1: 0x0019,
    ffdhe2048: 0x0100,
    ffdhe3072: 0x0101,
    // Chrome 124+ adds the hybrid post-quantum group. The draft Kyber768 code
    // (0x6399) shipped in Chrome 124–130; the final MLKEM768 code (0x11ec) has
    // been used since Chrome 131. Both appear at the front of the group list.
    X25519Kyber768: 0x6399,
    X25519MLKEM768: 0x11ec,
};

/** Selected IANA TLS SignatureScheme codes. */
export const SIGNATURE_SCHEME_CODES: Readonly<Record<string, number>> = {
    ecdsa_secp256r1_sha256: 0x0403,
    ecdsa_secp384r1_sha384: 0x0503,
    ecdsa_secp521r1_sha512: 0x0603,
    ecdsa_sha1: 0x0203,
    rsa_pss_rsae_sha256: 0x0804,
    rsa_pss_rsae_sha384: 0x0805,
    rsa_pss_rsae_sha512: 0x0806,
    rsa_pkcs1_sha256: 0x0401,
    rsa_pkcs1_sha384: 0x0501,
    rsa_pkcs1_sha512: 0x0601,
    rsa_pkcs1_sha1: 0x0201,
    ed25519: 0x0807,
};

/** IANA TLS ProtocolVersion codes for the supported_versions extension. */
export const VERSION_CODES: Readonly<Record<string, number>> = {
    "TLS 1.3": 0x0304,
    "TLS 1.2": 0x0303,
    "TLS 1.1": 0x0302,
    "TLS 1.0": 0x0301,
};

/**
 * Map a cipher-suite name to its 2-byte IANA wire code.
 *
 * Delegates to @browsercore/tls's canonical mapping. Throws a profiles-side
 * {@link ProfileError} (not a tls error) on an unknown name so callers get a
 * domain-appropriate error type.
 */
export function cipherSuiteToWire(name: string): number {
    if (!isCipherSuite(name)) {
        throw new ProfileError("UnknownCipherSuite", `Unknown cipher suite: ${name}`);
    }
    return cipherSuiteToWireFromTls(name);
}
