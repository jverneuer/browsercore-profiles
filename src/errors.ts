/**
 * Typed errors for @browsercore/profiles.
 *
 * Errors are part of the API — callers match on `kind` instead of parsing messages.
 */

/**
 * Base class for all profile lookup / registration failures.
 *
 * Extends `Error` with a `kind` discriminator and an optional `cause`. All
 * profile-package errors extend this class (directly or via {@link ValidationError}),
 * so a single `catch` on `ProfileError` captures every failure mode the package
 * raises, while `instanceof` against a subclass narrows to a specific case.
 *
 * @example
 * ```ts
 * try {
 *     const profile = getProfile("chrome-999" as ProfileId);
 * } catch (e) {
 *     if (e instanceof UnknownProfileError) {
 *         // fall back to a known profile...
 *     }
 *     throw e;
 * }
 * ```
 *
 * @since 0.1.0
 */
export class ProfileError extends Error {
    public readonly kind: string;
    public override readonly cause: Error | undefined;

    /**
     * @param kind - Discriminator string for `instanceof`-free matching.
     * @param message - Human-readable description of the failure.
     * @param options - Standard `Error` options; `cause` preserves the wrapped error.
     */
    constructor(
        kind: string,
        message: string,
        options?: { cause?: Error },
    ) {
        super(message, options);
        this.name = new.target.name;
        this.kind = kind;
        this.cause = options?.cause;
    }
}

/**
 * No profile exists for the requested {@link ProfileId}.
 *
 * Raised by {@link getProfile} when the id is not in the registry. Built-in
 * profiles are always present; this typically indicates a typo or an
 * uninstalled custom profile.
 *
 * @example
 * ```ts
 * try {
 *     getProfile("chrome-000" as ProfileId);
 * } catch (e) {
 *     if (e instanceof UnknownProfileError) {
 *         console.error(`No profile for id: ${e.profileId}`);
 *     }
 * }
 * ```
 *
 * @since 0.1.0
 */
export class UnknownProfileError extends ProfileError {
    public override readonly kind = "UnknownProfileError" as const;
    public readonly profileId: string;

    /**
     * @param profileId - The {@link ProfileId} that was not found.
     */
    constructor(profileId: string) {
        super("UnknownProfileError", `Unknown browser profile: ${profileId}`);
        this.name = "UnknownProfileError";
        this.profileId = profileId;
    }
}
