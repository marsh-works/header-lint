// Parses a raw block of HTTP response headers into structured lines,
// keeping the original 1-indexed line number for every header so
// findings can point back at the source text.

export interface HeaderLine {
  name: string;
  value: string;
  line: number;
}

export interface MalformedLine {
  line: number;
  text: string;
}

export interface ParseResult {
  headers: HeaderLine[];
  malformed: MalformedLine[];
}

// RFC 7230 token characters, i.e. what a header field-name is allowed to use.
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const STATUS_OR_REQUEST_LINE =
  /^(HTTP\/\d(\.\d)?\s+\d{3}\b|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b/;

export function parseHeaders(input: string): ParseResult {
  const lines = input.split(/\r\n|\n/);
  const headers: HeaderLine[] = [];
  const malformed: MalformedLine[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? '';
    const lineNo = i + 1;

    if (raw.trim() === '') continue;

    // Tolerate a leading status line ("HTTP/1.1 200 OK") or request line
    // ("GET / HTTP/1.1") since that's what curl -I and similar tools print.
    if (i === 0 && STATUS_OR_REQUEST_LINE.test(raw)) continue;

    const idx = raw.indexOf(':');
    if (idx <= 0) {
      malformed.push({ line: lineNo, text: raw });
      continue;
    }

    const name = raw.slice(0, idx).trim();
    const value = raw.slice(idx + 1).trim();
    const rawName = raw.slice(0, idx);

    // A space between the field-name and the colon is a smuggling risk
    // (RFC 7230 section 3.2.4) and must be rejected, not just trimmed.
    if (rawName !== name || !TOKEN_RE.test(name)) {
      malformed.push({ line: lineNo, text: raw });
      continue;
    }

    headers.push({ name, value, line: lineNo });
  }

  return { headers, malformed };
}
