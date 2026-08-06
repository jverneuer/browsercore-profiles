/**
 * IANA TLS registry codes — re-exported from @browsercore/tls.
 *
 * The canonical tables live in `@browsercore/tls/src/iana/` — the single
 * source of truth for TLS protocol wire codes. This module re-exports them
 * for backwards compatibility with existing consumers that import from
 * `@browsercore/profiles`.
 *
 * The `cipherSuiteToWire` projection function below is profile-specific
 * (it wraps the lookup with a {@link ProfileError} and is used by the
 * profile validation tools).
 */

import { ProfileError } from "./errors.js";

// Re-export IANA tables from the canonical source in @browsercore/tls
export {
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
    VERSION_CODES,
} from "@browsercore/tls";

// Re-import for the projection function below
import { CIPHER_SUITE_CODES as _CIPHER_SUITE_CODES } from "@browsercore/tls";

/**
 * Map a cipher-suite name to its 2-byte IANA wire code.
 *
 * This is the single projection seam from a profile's cipher name to the bytes
 * a ClientHello carries. It throws on an unknown name rather than returning a
 * sentinel: 0x0000 would be ambiguous (it collides with
 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV), and a silent default would hide a bug in
 * a profile definition. An unknown name is therefore always an error here,
 * never a 0x0000 fallback.
 *
 * @param name - Canonical cipher-suite name as used in a {@link TlsProfile}
 *   (e.g. `"TLS_AES_128_GCM_SHA256"`).
 * @returns The 2-byte IANA code for the cipher suite.
 * @throws {ProfileError} With kind `"UnknownCipherSuite"` if the name is not
 *   in the IANA cipher suite registry.
 *
 * @example
 * ```ts
 * cipherSuiteToWire("TLS_AES_128_GCM_SHA256"); // 0x1301
 * cipherSuiteToWire("TLS_GREASE_RESERVED_0");  // 0x0a0a (placeholder)
 * ```
 *
 * @since 0.1.0
 */
export function cipherSuiteToWire(name: string): number {
    const code = _CIPHER_SUITE_CODES[name];
    if (code === undefined) {
        throw new ProfileError("UnknownCipherSuite", `Unknown cipher suite: ${name}`);
    }
    return code;
}
