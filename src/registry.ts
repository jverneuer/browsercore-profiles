/**
 * Profile registry — the single source of truth for known browser fingerprints.
 *
 * Backed by a `Map`, which preserves insertion order, so {@link listProfiles}
 * returns ids in a stable, deterministic sequence (built-ins first, then any
 * runtime-registered profiles). Built-in profiles are indexed once at module
 * evaluation; later {@link registerProfile} calls append or overwrite by id.
 */

import type { BrowserProfile, ProfileId } from "./types.js";
import { UnknownProfileError } from "./errors.js";
import { ChromeProfiles } from "./profiles/chrome.js";
import { FirefoxProfiles } from "./profiles/firefox.js";
import { SafariProfiles } from "./profiles/safari.js";
import { EdgeProfiles } from "./profiles/edge.js";

const registry = new Map<ProfileId, BrowserProfile>();

function index(profile: BrowserProfile): void {
    registry.set(profile.id, profile);
}

// Built-in profiles — indexed at module evaluation.
for (const profile of Object.values(ChromeProfiles)) {
    index(profile);
}
for (const profile of Object.values(FirefoxProfiles)) {
    index(profile);
}
for (const profile of Object.values(SafariProfiles)) {
    index(profile);
}
for (const profile of Object.values(EdgeProfiles)) {
    index(profile);
}

/**
 * Look up a profile by its branded id.
 *
 * Built-in profiles (chrome, firefox, safari, edge) are always available.
 * Custom profiles registered via {@link registerProfile} are returned here too.
 *
 * @param id - The {@link ProfileId} to look up.
 * @returns The matching {@link BrowserProfile}.
 * @throws {UnknownProfileError} If no profile with the given id is registered.
 *
 * @example
 * ```ts
 * const chrome = getProfile("chrome-140" as ProfileId);
 * console.log(chrome.tls.cipherSuites);
 * ```
 *
 * @since 0.1.0
 */
export function getProfile(id: ProfileId): BrowserProfile {
    const profile = registry.get(id);
    if (profile === undefined) {
        throw new UnknownProfileError(id);
    }
    return profile;
}

/**
 * List every registered profile id, in insertion order.
 *
 * Built-in profiles come first (chrome, firefox, safari, edge in that order),
 * followed by any custom profiles registered via {@link registerProfile}.
 * The order is stable because the registry is backed by a `Map`.
 *
 * @returns A readonly array of {@link ProfileId} values.
 *
 * @example
 * ```ts
 * for (const id of listProfiles()) {
 *     console.log(id); // "chrome-140", "firefox-128", ...
 * }
 * ```
 *
 * @since 0.1.0
 */
export function listProfiles(): ReadonlyArray<ProfileId> {
    return Array.from(registry.keys());
}

/**
 * Register a custom profile (e.g. a private build or a future browser version).
 *
 * Adds the profile to the registry, or overwrites any existing profile with the
 * same id. After registration the profile is returned from {@link getProfile}
 * and listed by {@link listProfiles}.
 *
 * @param profile - The {@link BrowserProfile} to register.
 *
 * @example
 * ```ts
 * registerProfile({
 *     id: "chrome-141" as ProfileId,
 *     name: "chrome",
 *     version: "141.0.0.0",
 *     tls: { ... },
 *     http2: { ... },
 *     http1: { ... },
 * });
 * ```
 *
 * @since 0.1.0
 */
export function registerProfile(profile: BrowserProfile): void {
    index(profile);
}
