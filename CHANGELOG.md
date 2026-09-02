Changelog
=========

All notable changes to this fork. The original `dflydev/hawk` had a single
release, `v0.0.0` (2013-10-30); this changelog starts from the state of its
`master` branch at commit `937fe56`.

## 0.1.0 — 2026-09-02 — fork of dflydev/hawk

The Hawk protocol itself is unchanged. A bewit or an `Authorization` header
issued by `dflydev/hawk` verifies here, and one issued here verifies there —
verified in both directions against the original package.

### Security

 * MAC comparison now goes through `hash_equals()` everywhere. `Client::authenticate()`
   compared response MACs and payload hashes with `!==` / `===`, which stops at
   the first differing byte.
 * `ext` is escaped in the normalized string (`\` → `\\`, newline → `\n`), as the
   Hawk specification requires and as the reference implementation does. The
   original left a `// TODO: escape ext` there; without escaping, a newline in
   `ext` moves the field boundaries, so two different requests can share a MAC.
   **This is the only change to the bytes on the wire, and it only affects
   requests that use `ext`.**
 * Nonces come from `random_bytes()`. The default provider used
   `ircmaxell/random-lib`'s `getLowStrengthGenerator()` — an `mt_rand()`-based
   generator that the library itself documents as unsuitable for cryptography.
   A predictable nonce defeats the only replay protection Hawk has.
 * Header attribute values are escaped (`\` and `"`), and values containing CR,
   LF or NUL are refused. The original interpolated values straight between
   quotes, so `UnauthorizedException::getHeader()` — whose `error` attribute is
   the exception message — could emit a header carrying a second header.
 * MAC algorithms are limited to `sha256` and `sha512`. Any other name used to
   reach `hash_hmac()` and raise a `ValueError`.
 * `Credentials` marks the shared key `#[\SensitiveParameter]` and hides it from
   `__debugInfo()`, keeping it out of stack traces and dumps.
 * An unknown credentials id is refused with `UnauthorizedException` instead of
   calling a method on `null`.

### Fixed

 * `Server::authenticateBewit()` decodes base64url correctly. The original called
   `str_replace()` with two empty search strings (the encode/decode pairs were
   reversed wholesale instead of swapped), and decoded in non-strict mode, so any
   byte outside the alphabet was silently dropped. Decoding is now strict.
 * A bewit with the wrong number of fields is refused. The original ran
   `list(...) = explode(...)` without counting, producing "Undefined array key"
   notices and `null`s that flowed into arithmetic and into the MAC comparison.
 * A non-numeric `ts` in an `Authorization` header is refused. `abs($ts - $now)`
   raised a `TypeError` on it — a 500 driven by request content.
 * The bewit regex no longer contains a literal `$` inside a character class
   (`[^&$]`, a typo for an anchor) and is anchored with the `D` modifier, so it
   cannot match before a trailing newline.
 * `HeaderParser` reads `key="value"` pairs with a real pattern instead of
   `explode(', ')`, so a value containing `, ` no longer breaks parsing; quoted
   pairs are unescaped; a value's own quotes survive (`trim($value, '"')` used to
   strip all of them); the scheme match is case-insensitive per RFC 9110 and
   requires a following space, so `Hawkish` is no longer accepted as `Hawk`.
 * `HeaderFactory::createFromHeaderObjectOrString()` always returns a `Header`.
   It used to return `null` when the error callback did not throw.
 * `ServerBuilder::setTimestampSkewSec(0)` and `setLocaltimeOffsetSec(0)` are
   honoured. `?:` turned them back into the defaults, so zero skew could not be
   configured.
 * The client refuses a relative URI instead of emitting a warning and signing an
   empty host, and refuses a credentials id or `ext` containing a backslash —
   the bewit field separator — instead of producing an unparseable bewit.
 * Required header attributes are checked before `Artifacts` is built, rather
   than after reading them.

### Changed

 * Package renamed to `byfareska/hawk`, namespace `Dflydev\Hawk` →
   `Byfareska\Hawk`, autoloading PSR-0 → PSR-4.
 * Requires PHP 8.4+. `declare(strict_types=1)` throughout, native parameter and
   return types, promoted constructor properties, `final readonly` value objects.
   The original created dynamic properties, deprecated since PHP 8.2 and an error
   in PHP 9.
 * No runtime dependencies: `ircmaxell/random-lib` (and with it
   `ircmaxell/security-lib`) is gone.
 * Every exception implements `Byfareska\Hawk\Exception\HawkException`, so
   callers no longer have to catch `\Throwable`.
 * `authenticateBewit()` is declared on `ServerInterface` and `createBewit()` on
   `ClientInterface`; both existed only on the concrete classes.
 * `Header::attribute()` returns attributes as strings; the value used to be an
   `int` when it came from the client and a `string` when it came from the parser.
 * Tests run on PHPUnit 12, with PHPStan at level max and PHP-CS-Fixer in CI.
   Travis CI and Scrutinizer configuration removed.

### Kept deliberately

 * The public API keeps its shape — same class names, same method names, same
   builders — so the fork is a drop-in replacement once the namespace is changed.
 * `Crypto::fixedTimeComparison()` stays public under its original name.
