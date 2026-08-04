/**
 * @browsercore/profiles — public API surface.
 *
 * Pure data package: browser fingerprint definitions across TLS, HTTP/2, and
 * HTTP/1.1. No protocol implementation lives here — higher layers read these
 * definitions and translate them into bytes / header order / settings frames.
 */

export {
    getProfile,
    listProfiles,
    registerProfile,
} from "./registry.js";

export {
    diffProfiles,
} from "./diff.js";

export type {
    DiffOptions,
    ProfileDiff,
} from "./diff.js";

export {
    buildExpectedClientHello,
    validateProfileAgainstCapture,
    ValidationError,
} from "./validate.js";

export type {
    TlsCapture,
    ClientHelloExpected,
    ValidationResult,
} from "./validate.js";

export {
    cipherSuiteToWire,
    CIPHER_GREASE_PLACEHOLDER,
    CIPHER_SUITE_CODES,
    NAMED_GROUP_CODES,
    SIGNATURE_SCHEME_CODES,
    VERSION_CODES,
} from "./codes.js";

export {
    ChromeProfiles,
    FirefoxProfiles,
    SafariProfiles,
    EdgeProfiles,
} from "./index.internal.js";

export {
    ProfileError,
    UnknownProfileError,
} from "./errors.js";

export type {
    BrowserProfile,
    Http1Profile,
    Http2Profile,
    Http2Settings,
    Http2Priority,
    ProfileId,
    ProfileName,
    TlsProfile,
} from "./types.js";

export { assertNever } from "./utils.js";
