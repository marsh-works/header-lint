# header-lint

A small command-line linter for HTTP response headers. Point it at the
output of `curl -I` (or any text file with one header per line) and it
reports problems with line numbers, the way a compiler reports errors.

## Why

Checking response headers by eye is tedious and error-prone: is that
`Strict-Transport-Security` value actually enabling HSTS, or did someone
leave `max-age=0` in from a debugging session? Did `Set-Cookie` forget
`Secure`? Full web security scanners exist, but they're heavy and usually
want a live target. Sometimes you just have a text file (a saved response,
a pasted bug report, a fixture in a test suite) and want a fast pass over
it.

## Usage

```sh
curl -sI https://example.com | node src/cli.ts
```

or against a file:

```sh
node src/cli.ts headers.txt
```

Example input (`headers.txt`):

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Type: text/html; charset=utf-8
X-XSS-Protection: 1; mode=block
Set-Cookie: session=abc123; Path=/
Strict-Transport-Security: max-age=0
```

Example output:

```
3: warning duplicate-header  "Content-Type" was already set on line 2; duplicates are undefined behavior for most clients
4: info    deprecated-header  X-XSS-Protection is deprecated; modern browsers ignore it and it can introduce XSS in older ones. Use Content-Security-Policy instead.
5: warning weak-cookie-attributes  Set-Cookie is missing recommended attribute(s): Secure, HttpOnly, SameSite
6: warning hsts-zero-max-age  Strict-Transport-Security max-age=0 disables HSTS for future visits
6: info    missing-recommended-header  no x-content-type-options header found; consider adding one
6: info    missing-recommended-header  no content-security-policy header found; consider adding one
```

The process exits `0` if there are no findings, `1` if the worst finding is
a warning, and `2` if there's an error (such as a line that isn't a valid
header at all) or a bad invocation.

## What it checks right now

- Malformed lines that aren't valid `Name: value` headers
- Headers that were sent more than once when they shouldn't repeat
- Deprecated or discouraged headers (`X-XSS-Protection`, `Public-Key-Pins`, `X-Powered-By`)
- Empty header values
- `X-Content-Type-Options` set to anything other than `nosniff`
- `Strict-Transport-Security` missing `max-age` or set to `max-age=0`
- `Set-Cookie` missing `Secure`, `HttpOnly`, or `SameSite`
- Missing recommended security headers overall

## Requirements

Node.js 23.6+ (for native TypeScript execution — no build step, no
dependencies). Run `node src/cli.ts` directly.

## License

MIT, see [LICENSE](LICENSE).
