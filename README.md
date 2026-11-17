# @browsercore/profiles

[![npm version](https://img.shields.io/npm/v/@browsercore/profiles)](https://www.npmjs.com/package/@browsercore/profiles)
[![coverage](https://img.shields.io/endpoint?url=https://jverneuer.github.io/browsercore-profiles/badge.json)](https://jverneuer.github.io/browsercore-profiles/COVERAGE.md)
[![CI](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-profiles/ci.yml?label=ci)](https://github.com/jverneuer/browsercore-profiles/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@browsercore/profiles.svg)](LICENSE)

Browser fingerprint definitions (TLS / HTTP/2 / HTTP/1.1). Pure data — no protocol implementation lives here. Higher layers read these definitions and translate them into bytes, header order, and SETTINGS frames.

## Responsibility

Define WHAT a browser fingerprint looks like: ordered cipher suites, TLS extension order, GREASE behavior, HTTP/2 SETTINGS, and HTTP/1.1 header order. Adding a new Chrome version means adding a new entry here — protocol implementations never change.

## What it does NOT know about

- TLS handshakes or cryptography
- HTTP parsing or serialization
- Sockets or I/O
- Cookies

## Install

```bash
npm install @browsercore/profiles
```

## Quick usage

```ts
import { getProfile, listProfiles, registerProfile } from "@browsercore/profiles";

const chrome = getProfile("chrome-140"); // registry ids are bare literals — no cast
console.log(chrome.tls.cipherSuites); // ordered cipher list
console.log(chrome.http2.settings); // HTTP/2 SETTINGS frame values

const all = listProfiles(); // ["chrome-120", "chrome-128", ...] — insertion order

registerProfile(myCustomProfile); // extensibility hook
```

**Canonical id types (0.2.6).** `ProfileId` is no longer declared in this package — `@browsercore/contracts` 0.2.6 (`src/models.ts`) is its canonical home, and `@browsercore/profiles` re-exports the canonical definition: the closed set of registry-shipped ids widened with `(string & Record<never, never>)`, so known ids keep literal autocomplete and typo-flagging while runtime-registered custom ids (`registerProfile`) stay assignable. `RegisteredProfileId` — the closed registry set — is declared here as a verbatim mirror of contracts' union (contracts declares it but deliberately does not export the name at its package root); `tests/canonical-id.test.ts` pins it to the registry data so it cannot drift. The former package-local brand (`string & { __brand: "ProfileId" }`) is gone: consumers that passed string literals (fetch, tls, browsersmith) compile unchanged — without the `as ProfileId` casts the brand used to demand. Unknown ids are guarded at runtime: `getProfile` throws `UnknownProfileError` for any id not in the registry.

## Public API

| Export | Kind | Purpose |
| --- | --- | --- |
| `getProfile()` | function | Look up a profile by id (throws `UnknownProfileError` if absent) |
| `listProfiles()` | function | List every registered id, in insertion order |
| `registerProfile()` | function | Register or overwrite a custom profile at runtime |
| `diffProfiles()` | function | Field-by-field diff of two profiles, reporting each differing path |
| `DiffOptions` | interface | Diff tuning (e.g. order-sensitive vs. multiset array comparison) |
| `ProfileDiff` | interface | A single difference located by its dotted path |
| `buildExpectedClientHello()` | function | Project a profile's TLS fields onto expected wire codes |
| `validateProfileAgainstCapture()` | function | Validate a profile against a captured ClientHello |
| `ValidationResult` | interface | `{ ok, diffs }` outcome of validation |
| `TlsCapture` | interface | A captured ClientHello parsed out of a packet capture |
| `ClientHelloExpected` | interface | The wire values a profile's ClientHello should carry |
| `BrowserProfile` | interface | Complete fingerprint across TLS + HTTP/2 + HTTP/1.1 |
| `TlsProfile` | interface | Cipher order, extensions, GREASE, signature algorithms |
| `Http2Profile` | interface | SETTINGS, window sizes, priority |
| `Http2Settings` | interface | HTTP/2 numeric settings (RFC 9113 §6.5.1) |
| `Http2Priority` | interface | Stream priority descriptor |
| `Http1Profile` | interface | Default headers, header order, accept-encoding |
| `ProfileId` | type alias | Canonical profile identifier re-exported from `@browsercore/contracts` — registry ids + custom registered ids (`"chrome-140"`) |
| `RegisteredProfileId` | literal union | Closed set of registry-shipped ids (mirrors `@browsercore/contracts` `src/models.ts`) |
| `ProfileName` | literal union | `"chrome" \| "firefox" \| "safari" \| "edge"` |
| `ChromeProfiles` / `FirefoxProfiles` / `SafariProfiles` / `EdgeProfiles` | const maps | Per-browser profile definitions |
| `assertNever()` | function | Exhaustiveness check for switches over unions |
| `ProfileError` | class | Base typed error (matched on `kind`) |
| `UnknownProfileError` | class | Thrown when a profile id is not found |
| `ValidationError` | class | Thrown on an unknown profile value or bad capture |

## Shipped profiles

| Browser | Profiles |
| --- | --- |
| Chrome | `chrome-120`, `chrome-128`, `chrome-140` |
| Firefox | `firefox-120`, `firefox-128`, `firefox-135` |
| Safari | `safari-17`, `safari-18` |
| Edge | `edge-120`, `edge-128` |

## Dependency graph

```
@browsercore/profiles
```

No other `@browsercore/*` runtime packages and no Node built-ins are imported. This is a pure data package. `@browsercore/dev` is a dev-only dependency that supplies shared build / lint / test configuration (see [Shared config](#shared-config)).

## Source layout

```
src/
├─ index.ts            Public API surface — re-exports from the rest of the package
├─ index.internal.ts   Barrel re-exporting the per-browser profile maps
├─ registry.ts         getProfile / listProfiles / registerProfile (Map-backed)
├─ diff.ts             diffProfiles — field-by-field diff of two profiles
├─ validate.ts         buildExpectedClientHello / validateProfileAgainstCapture
├─ codes.ts            IANA TLS registry codes (cipher suites, groups, versions, sig schemes)
├─ errors.ts           ProfileError / UnknownProfileError / ValidationError
├─ types.ts            BrowserProfile + per-layer profile interfaces
├─ utils.ts            assertNever / createId
└─ profiles/           Per-browser profile definitions
   ├─ chrome.ts        chrome-120, chrome-128, chrome-140
   ├─ firefox.ts       firefox-120, firefox-128, firefox-135
   ├─ safari.ts        safari-17, safari-18
   └─ edge.ts          edge-120, edge-128
```

## Development

Requires **Node >= 26**. ESM only (`"type": "module"`).

```sh
npm install      # installs @browsercore/dev (file:../dev) + siblings
npm run build    # tsc -p tsconfig.build.json (emit to dist/)
npm run typecheck
npm run lint     # oxlint --type-aware src/
npm test         # vitest run
```

Run a single test file:

```sh
npx vitest run tests/profiles.test.ts
```

Run tests by name pattern:

```sh
npx vitest run -t "returns a known Chrome profile by id"
```

Generate a coverage report:

```sh
npm test -- --coverage
node ../dev/bin/coverage-md.mjs   # writes COVERAGE.md + coverage/badge.json
```

### Shared config

This package adopts `@browsercore/dev`, the shared config package for the
`@browsercore/*` family. Configuration is centralized — this repo only wires it in:

| Concern | Mechanism |
| --- | --- |
| TypeScript strict flags | `tsconfig.json` extends `@browsercore/dev/tsconfig.base.json` |
| Vitest config | `vitest.config.ts` calls `definePackageConfig({ name: "profiles" })` |
| Oxlint config | `oxlint.config.ts` extends `@browsercore/dev/oxlint` |
| Coverage report | `coverage-md` bin from `@browsercore/dev` |

`@browsercore/dev` is declared as a devDependency via `"@browsercore/dev": "file:../dev"`.


## Contributing

Contributions are welcome — bug reports, reproductions, docs and code alike. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the full guide lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md). First timer? Check the [`good first issue`](https://github.com/jverneuer/browsercore-profiles/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label. Security issues: [SECURITY.md](SECURITY.md), never a public issue.

## License

MIT
