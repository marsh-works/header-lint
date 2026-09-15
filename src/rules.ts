import { parseHeaders, type HeaderLine } from './parser.ts';

export type Severity = 'error' | 'warning' | 'info';

export interface Finding {
  line: number;
  severity: Severity;
  rule: string;
  message: string;
}

// Headers that must not appear more than once (RFC 7230 section 3.2.2).
// Set-Cookie is deliberately excluded: repeating it is normal.
const NO_REPEAT = new Set([
  'content-type',
  'content-length',
  'location',
  'host',
  'last-modified',
  'etag',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
]);

// Headers that are deprecated or actively discouraged in current guidance.
const DEPRECATED: Record<string, string> = {
  'x-xss-protection':
    'X-XSS-Protection is deprecated; modern browsers ignore it and it can introduce XSS in older ones. Use Content-Security-Policy instead.',
  'public-key-pins': 'Public-Key-Pins (HPKP) was removed from all major browsers. Remove it.',
  'x-powered-by': 'X-Powered-By reveals server implementation details to attackers for no benefit.',
};

// Security headers a response should generally set. Reported once, at the
// end of the document, since the finding isn't tied to one line.
const RECOMMENDED = [
  'strict-transport-security',
  'x-content-type-options',
  'content-security-policy',
];

export function lint(input: string): Finding[] {
  const { headers, malformed } = parseHeaders(input);
  const findings: Finding[] = [];

  for (const m of malformed) {
    findings.push({
      line: m.line,
      severity: 'error',
      rule: 'malformed-header-line',
      message: `line does not look like a valid "Name: value" header: ${JSON.stringify(m.text)}`,
    });
  }

  checkDuplicates(headers, findings);
  checkDeprecated(headers, findings);
  checkEmptyValues(headers, findings);
  checkContentTypeOptions(headers, findings);
  checkHsts(headers, findings);
  checkSetCookie(headers, findings);
  checkMissingRecommended(headers, findings);

  return findings.sort((a, b) => a.line - b.line);
}

function checkDuplicates(headers: HeaderLine[], findings: Finding[]): void {
  const seen = new Map<string, number>();
  for (const h of headers) {
    const key = h.name.toLowerCase();
    if (!NO_REPEAT.has(key)) continue;
    const firstLine = seen.get(key);
    if (firstLine !== undefined) {
      findings.push({
        line: h.line,
        severity: 'warning',
        rule: 'duplicate-header',
        message: `"${h.name}" was already set on line ${firstLine}; duplicates are undefined behavior for most clients`,
      });
    } else {
      seen.set(key, h.line);
    }
  }
}

function checkDeprecated(headers: HeaderLine[], findings: Finding[]): void {
  for (const h of headers) {
    const message = DEPRECATED[h.name.toLowerCase()];
    if (message) {
      findings.push({ line: h.line, severity: 'info', rule: 'deprecated-header', message });
    }
  }
}

function checkEmptyValues(headers: HeaderLine[], findings: Finding[]): void {
  for (const h of headers) {
    if (h.value === '') {
      findings.push({
        line: h.line,
        severity: 'warning',
        rule: 'empty-value',
        message: `"${h.name}" has an empty value`,
      });
    }
  }
}

function checkContentTypeOptions(headers: HeaderLine[], findings: Finding[]): void {
  for (const h of headers) {
    if (h.name.toLowerCase() !== 'x-content-type-options') continue;
    if (h.value.toLowerCase() !== 'nosniff') {
      findings.push({
        line: h.line,
        severity: 'warning',
        rule: 'invalid-x-content-type-options',
        message: `X-Content-Type-Options should be exactly "nosniff", got "${h.value}"`,
      });
    }
  }
}

function checkHsts(headers: HeaderLine[], findings: Finding[]): void {
  for (const h of headers) {
    if (h.name.toLowerCase() !== 'strict-transport-security') continue;
    const match = /max-age=(\d+)/i.exec(h.value);
    if (!match) {
      findings.push({
        line: h.line,
        severity: 'warning',
        rule: 'hsts-missing-max-age',
        message: 'Strict-Transport-Security is missing a max-age directive',
      });
    } else if (Number(match[1]) === 0) {
      findings.push({
        line: h.line,
        severity: 'warning',
        rule: 'hsts-zero-max-age',
        message: 'Strict-Transport-Security max-age=0 disables HSTS for future visits',
      });
    }
  }
}

function checkSetCookie(headers: HeaderLine[], findings: Finding[]): void {
  for (const h of headers) {
    if (h.name.toLowerCase() !== 'set-cookie') continue;
    const lower = h.value.toLowerCase();
    const missing: string[] = [];
    if (!lower.includes('secure')) missing.push('Secure');
    if (!lower.includes('httponly')) missing.push('HttpOnly');
    if (!lower.includes('samesite')) missing.push('SameSite');
    if (missing.length > 0) {
      findings.push({
        line: h.line,
        severity: 'warning',
        rule: 'weak-cookie-attributes',
        message: `Set-Cookie is missing recommended attribute(s): ${missing.join(', ')}`,
      });
    }
  }
}

function checkMissingRecommended(headers: HeaderLine[], findings: Finding[]): void {
  const present = new Set(headers.map((h) => h.name.toLowerCase()));
  const lastLine = headers.length > 0 ? headers[headers.length - 1]!.line : 1;
  for (const name of RECOMMENDED) {
    if (!present.has(name)) {
      findings.push({
        line: lastLine,
        severity: 'info',
        rule: 'missing-recommended-header',
        message: `no ${name} header found; consider adding one`,
      });
    }
  }
}
