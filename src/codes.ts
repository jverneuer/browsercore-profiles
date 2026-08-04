/**
 * IANA TLS registry codes used to project profile names onto wire values.
 *
 * These are the canonical 2-byte codes from the IANA TLS parameter registries.
 * Only the codes referenced by the shipped profiles are mapped here — an
 * unknown name is a bug in a profile definition and surfaces as a
 * {@link ValidationError} at projection time, so the tables double as an
 * allow-list that keeps profile data honest.
 *
 * Registries:
 *   - Cipher suites: tls-parameters.xhtml#tls-parameters-4
 *   - Named groups:   tls-parameters.xhtml#tls-parameters-8
 *   - Signature schemes: tls-parameters.xhtml#tls-parameters-16
 */

import { ProfileError } from "./errors.js";

/**
 * The name Chrome/Edge use in their cipher list to mark a GREASE slot (RFC 8701).
 * The real value is randomized per-connection (0x0a0a..0xfafa); validation accepts
 * any GREASE-pattern byte pair at a slot marked with this placeholder.
 */
export const CIPHER_GREASE_PLACEHOLDER = "TLS_GREASE_RESERVED_0";

/** Selected IANA TLS Cipher Suite codes, keyed by the canonical suite name used in profiles. */
export const CIPHER_SUITE_CODES: Readonly<Record<string, number>> = {
    // GREASE: real value is randomized per-connection (0x0a0a..0xfafa). We use the
    // first canonical GREASE code for the expected representation; validation
    // accepts any GREASE-pattern value at a GREASE slot.
    [CIPHER_GREASE_PLACEHOLDER]: 0x0a0a,
    TLS_AES_128_GCM_SHA256: 0x1301,
    TLS_AES_256_GCM_SHA384: 0x1302,
    TLS_CHACHA20_POLY1305_SHA256: 0x1303,
    TLS_AES_128_CCM_SHA256: 0x1304,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xc02b,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xc02f,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xc030,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca8,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: 0xc013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: 0xc014,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: 0xc009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: 0xc00a,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: 0xc023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: 0xc024,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: 0xc027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: 0xc028,
    TLS_RSA_WITH_AES_128_GCM_SHA256: 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384: 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA: 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA: 0x0035,
    TLS_RSA_WITH_AES_128_CBC_SHA256: 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256: 0x003d,
};

/** Selected IANA TLS Supported Groups (named groups) codes. */
export const NAMED_GROUP_CODES: Readonly<Record<string, number>> = {
    x25519: 0x001d,
    secp256r1: 0x0017,
    secp384r1: 0x0018,
};

/** Selected IANA TLS SignatureScheme codes. */
export const SIGNATURE_SCHEME_CODES: Readonly<Record<string, number>> = {
    ecdsa_secp256r1_sha256: 0x0403,
    rsa_pss_rsae_sha256: 0x0804,
    rsa_pkcs1_sha256: 0x0401,
    ecdsa_secp384r1_sha384: 0x0503,
    rsa_pss_rsae_sha384: 0x0805,
    rsa_pkcs1_sha384: 0x0501,
    ed25519: 0x0807,
    rsa_pkcs1_sha1: 0x0201,
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
 * This is the single projection seam from a profile's cipher name to the bytes
 * a ClientHello carries. It throws on an unknown name rather than returning a
 * sentinel: 0x0000 would be ambiguous (it collides with
 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV), and a silent default would hide a bug in
 * a profile definition. An unknown name is therefore always an error here,
 * never a 0x0000 fallback.
 */
export function cipherSuiteToWire(name: string): number {
    const code = CIPHER_SUITE_CODES[name];
    if (code === undefined) {
        throw new ProfileError("UnknownCipherSuite", `Unknown cipher suite: ${name}`);
    }
    return code;
}
