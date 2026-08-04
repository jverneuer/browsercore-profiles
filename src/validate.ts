/**
 * Profile validation against real captures.
 *
 * Real Wireshark / JA4 captures are produced later by the testing package; this
 * module is the reusable utility that consumes them. It projects a profile's TLS
 * fields onto the wire values a ClientHello would carry, then compares those
 * expectations to a captured ClientHello, reporting diffs.
 *
 * A key honesty: GREASE (RFC 8701) values are randomized per-connection, so a
 * profile cannot predict the exact GREASE bytes. We handle this where the data
 * lets us — cipher suites mark GREASE slots with a named placeholder, so a
 * GREASE slot in the profile matches any GREASE-pattern byte pair in the capture.
 * Extension GREASE is not handled here because the profile stores literal wire
 * codes for extensions (not placeholders), so it cannot robustly flag a GREASE
 * extension slot. See the per-field comments below.
 */

import type { BrowserProfile } from "./types.js";
import type { ProfileDiff } from "./diff.js";
import { ProfileError } from "./errors.js";
import {
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
    VERSION_CODES,
} from "./codes.js";

/** A captured ClientHello, as parsed out of a packet capture by the testing package. */
export interface TlsCapture {
    /** Offered cipher suites as IANA 2-byte codes, in wire order. */
    readonly cipherSuites: readonly number[];
    /** Extension type codes present, in wire order. */
    readonly extensionTypes: readonly number[];
    /** Supported versions advertised, as 2-byte codes, highest first. */
    readonly supportedVersions: readonly number[];
    /** Key-share named-group ids offered. */
    readonly keyShareGroups: readonly number[];
    /** Signature algorithm codes offered. */
    readonly signatureAlgorithms: readonly number[];
    /** Whether the ClientHello used GREASE randomization. */
    readonly grease: boolean;
    /** Optional JA3 / JA4 strings, when the capture tool computed them. */
    readonly ja3?: string;
    readonly ja4?: string;
}

/** The wire values a profile's ClientHello is expected to carry. */
export interface ClientHelloExpected {
    /** Cipher suites as IANA 2-byte codes, in wire order. */
    readonly cipherSuites: readonly number[];
    /** Extension type codes, in wire order. */
    readonly extensionTypes: readonly number[];
    /** Supported versions as 2-byte codes, highest first. */
    readonly supportedVersions: readonly number[];
    /** Key-share named-group ids. */
    readonly keyShareGroups: readonly number[];
    /** Signature algorithm codes. */
    readonly signatureAlgorithms: readonly number[];
    /** Whether GREASE randomization is expected. */
    readonly grease: boolean;
    /** SNI hostname the client would send, derived from the connection target. */
    readonly sni: string;
}

/** Validation / projection failure (unknown profile value, bad capture, etc.). */
export class ValidationError extends ProfileError {
    public override readonly kind = "ValidationError" as const;

    /**
     * @param message - Description of what failed to validate or project.
     * @param options - `cause` wraps the underlying error.
     */
    constructor(message: string, options?: { cause?: Error }) {
        super("ValidationError", message, options);
        this.name = "ValidationError";
    }
}

/**
 * Outcome of validating a profile against a captured ClientHello.
 *
 * Produced by {@link validateProfileAgainstCapture}.
 */
export interface ValidationResult {
    /** True when every field matches (respecting GREASE randomization for cipher suites). */
    readonly ok: boolean;
    /** Empty when `ok` is true; otherwise one {@link ProfileDiff} per mismatched field. */
    readonly diffs: ProfileDiff[];
}

function lookupCode(
    map: Readonly<Record<string, number>>,
    name: string,
    field: string,
): number {
    const code = map[name];
    if (code === undefined) {
        throw new ValidationError(`Unknown ${field}: ${name}`);
    }
    return code;
}

/** Map a cipher-suite name to its 2-byte IANA code. */
function mapCipherSuite(name: string): number {
    return lookupCode(CIPHER_SUITE_CODES, name, "cipher suite");
}

/** Map a named-group name to its IANA id. */
function mapNamedGroup(name: string): number {
    return lookupCode(NAMED_GROUP_CODES, name, "named group");
}

/** Map a signature-scheme name to its IANA code. */
function mapSignatureScheme(name: string): number {
    return lookupCode(SIGNATURE_SCHEME_CODES, name, "signature scheme");
}

/** Map a TLS version string to its 2-byte wire code. */
function mapVersion(name: string): number {
    return lookupCode(VERSION_CODES, name, "TLS version");
}

/**
 * Project a profile's TLS fields onto the wire values its ClientHello should
 * carry for a connection to `serverName`.
 *
 * Extension order is taken verbatim from the profile (already stored as wire
 * codes), since extension order is a fingerprint signal. Cipher suites, named
 * groups, signature schemes, and TLS versions are projected through the IANA
 * code tables in {@link codes.ts}.
 *
 * @param profile - The {@link BrowserProfile} to project.
 * @param serverName - The SNI server name the connection targets.
 * @returns The {@link ClientHelloExpected} wire values.
 * @throws {ValidationError} If the profile references an unknown cipher suite,
 *   named group, signature scheme, or TLS version.
 *
 * @example
 * ```ts
 * const expected = buildExpectedClientHello(chrome140, "example.com");
 * // expected.cipherSuites = [0x1301, 0x1302, ...]
 * ```
 *
 * @since 0.1.0
 */
export function buildExpectedClientHello(
    profile: BrowserProfile,
    serverName: string,
): ClientHelloExpected {
    return {
        cipherSuites: profile.tls.cipherSuites.map(mapCipherSuite),
        extensionTypes: Array.from(profile.tls.extensionOrder),
        supportedVersions: profile.tls.supportedVersions.map(mapVersion),
        keyShareGroups: profile.tls.keyShareGroups.map(mapNamedGroup),
        signatureAlgorithms: profile.tls.signatureAlgorithms.map(mapSignatureScheme),
        grease: profile.tls.grease,
        sni: serverName,
    };
}

/**
 * A 2-byte value matches the GREASE pattern 0x?a?a (high byte === low byte).
 * RFC 8701 reserves the range 0x0a0a..0xfafa in steps of 0x1010, so values below
 * 0x0a0a (notably 0x0000) are excluded even though they share the high===low
 * byte shape.
 */
function isGreaseValue(v: number): boolean {
    return v >= 0x0a0a && (v >> 8) === (v & 0xff);
}

/**
 * Element-wise diff of two numeric arrays, reporting one {@link ProfileDiff} per
 * mismatched index (including length differences).
 */
function diffNumberArray(
    path: string,
    expected: readonly number[],
    actual: readonly number[],
    out: ProfileDiff[],
): void {
    const n = Math.max(expected.length, actual.length);
    for (let i = 0; i < n; i++) {
        const e = expected[i];
        const c = actual[i];
        if (e !== c) {
            out.push({ path: `${path}[${i}]`, a: e, b: c });
        }
    }
}

/** Diff cipher suites with GREASE awareness: a GREASE slot matches any GREASE-pattern value. */
function diffCipherSuites(
    profile: BrowserProfile,
    expected: readonly number[],
    capture: readonly number[],
    out: ProfileDiff[],
): void {
    const n = Math.max(expected.length, capture.length);
    for (let i = 0; i < n; i++) {
        const path = `tls.cipherSuites[${i}]`;
        const e = expected[i];
        const c = capture[i];
        const greaseSlot = profile.tls.cipherSuites[i] === CIPHER_GREASE_PLACEHOLDER;
        if (greaseSlot) {
            // Profile reserves a GREASE slot; accept any GREASE-pattern value, but a
            // missing or non-GREASE value is still a mismatch.
            if (c === undefined || !isGreaseValue(c)) {
                out.push({ path, a: e, b: c });
            }
            continue;
        }
        if (e !== c) {
            out.push({ path, a: e, b: c });
        }
    }
}

/**
 * Validate a profile against a captured ClientHello.
 *
 * Projects the profile to expected wire values (via {@link buildExpectedClientHello})
 * and compares them field-by-field against the capture. Returns `ok: true` when
 * every field matches (respecting GREASE randomization for cipher suites), and
 * the list of diffs otherwise.
 *
 * SNI is not compared because captures do not record the destination hostname.
 *
 * @param profile - The {@link BrowserProfile} to validate.
 * @param capture - A {@link TlsCapture} parsed from a packet capture.
 * @returns A {@link ValidationResult} indicating match/mismatch.
 * @throws {ValidationError} If the profile references an unknown cipher suite,
 *   named group, signature scheme, or TLS version.
 *
 * @example
 * ```ts
 * const result = validateProfileAgainstCapture(chrome140, capture);
 * if (!result.ok) {
 *     for (const d of result.diffs) {
 *         console.log(`${d.path}: expected ${d.a}, got ${d.b}`);
 *     }
 * }
 * ```
 *
 * @see buildExpectedClientHello for the projection step.
 * @since 0.1.0
 */
export function validateProfileAgainstCapture(
    profile: BrowserProfile,
    capture: TlsCapture,
): ValidationResult {
    const expected = buildExpectedClientHello(profile, "");
    const diffs: ProfileDiff[] = [];

    diffCipherSuites(profile, expected.cipherSuites, capture.cipherSuites, diffs);
    diffNumberArray("tls.extensionTypes", expected.extensionTypes, capture.extensionTypes, diffs);
    diffNumberArray("tls.supportedVersions", expected.supportedVersions, capture.supportedVersions, diffs);
    diffNumberArray("tls.keyShareGroups", expected.keyShareGroups, capture.keyShareGroups, diffs);
    diffNumberArray(
        "tls.signatureAlgorithms",
        expected.signatureAlgorithms,
        capture.signatureAlgorithms,
        diffs,
    );

    if (expected.grease !== capture.grease) {
        diffs.push({ path: "tls.grease", a: expected.grease, b: capture.grease });
    }

    return { ok: diffs.length === 0, diffs };
}
