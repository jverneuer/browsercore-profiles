/**
 * Small shared helpers for @browsercore/profiles.
 *
 * Kept dependency-free so every package can copy the pattern without pulling in
 * cross-package imports.
 */

/**
 * Compile-time exhaustiveness check for `switch`/`if-else` over discriminated unions.
 *
 * Call in the `default` branch with the narrowed variable: `default: assertNever(x)`.
 * The argument is typed `never`, so adding a new union member forces every handler
 * to compile-error until it handles the new case. At runtime (if the check is ever
 * bypassed by an untyped value) it throws with the offending value.
 *
 * @param x - A value that must be `never` at compile time.
 * @throws {Error} If reached at runtime with a non-`never` value.
 *
 * @example
 * ```ts
 * switch (state.state) {
 *     case "open": return doOpen();
 *     case "closed": return doClosed();
 *     default: return assertNever(state.state);
 * }
 * ```
 *
 * @since 0.1.0
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

import type { ProfileId } from "./types.js";

/**
 * Build a branded {@link ProfileId} from a browser name + version.
 *
 * The canonical id format is `"${name}-${version}"`, e.g. `"chrome-140"`.
 * The version is the major version only — patch-level differences within a
 * major release do not change the fingerprint.
 *
 * @param name - Browser family name, e.g. `"chrome"`.
 * @param version - Major version string, e.g. `"140"`.
 * @returns A branded {@link ProfileId}.
 *
 * @example
 * ```ts
 * createId("chrome", "140"); // ProfileId<"chrome-140">
 * createId("firefox", "128"); // ProfileId<"firefox-128">
 * ```
 *
 * @since 0.1.0
 */
export function createId(name: string, version: string): ProfileId {
    return `${name}-${version}` as ProfileId;
}
