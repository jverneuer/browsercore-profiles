# @browsercore/profiles

[![npm version](https://img.shields.io/npm/v/@browsercore/profiles)](https://www.npmjs.com/package/@browsercore/profiles)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-profiles/main/.github/coverage-badge.json)](https://github.com/jverneuer/browsercore-profiles/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-profiles/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-profiles/actions/workflows/ci.yml)

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
import type { ProfileId } from "@browsercore/profiles";

const chrome = getProfile("chrome-140" as ProfileId);
console.log(chrome.tls.cipherSuites); // ordered cipher list
console.log(chrome.http2.settings); // HTTP/2 SETTINGS frame values

const all = listProfiles(); // ["chrome-120", "chrome-128", ...] — insertion order

registerProfile(myCustomProfile); // extensibility hook
```

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
| `ProfileId` | branded type | Opaque profile identifier (`"chrome-140"`) |
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

## License

MIT
