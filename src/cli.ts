import { readFileSync } from 'node:fs';
import { lint, type Severity } from './rules.ts';

const EXIT_CODE_BY_SEVERITY: Record<Severity, number> = {
  error: 2,
  warning: 1,
  info: 0,
};

function readInput(path: string | undefined): string {
  if (path) return readFileSync(path, 'utf8');
  try {
    return readFileSync(0, 'utf8'); // fd 0 is stdin
  } catch {
    throw new Error('no file given and nothing piped in on stdin');
  }
}

const USAGE = `usage: header-lint [--json] [file]

Reads raw HTTP response headers (e.g. from \`curl -I\`), either from FILE or
stdin, and prints findings as line: severity rule message.

  --json    print findings as a JSON array on stdout instead of text
  -h, --help  show this message`;

function main(): void {
  const args = process.argv.slice(2);
  let json = false;
  let path: string | undefined;

  for (const arg of args) {
    if (arg === '--help' || arg === '-h') {
      console.log(USAGE);
      process.exit(0);
    } else if (arg === '--json') {
      json = true;
    } else if (arg.startsWith('-') && arg !== '-') {
      console.error(`header-lint: unknown option ${arg}\n${USAGE}`);
      process.exit(2);
    } else if (path === undefined) {
      path = arg === '-' ? undefined : arg;
    } else {
      console.error(`header-lint: only one input file is supported\n${USAGE}`);
      process.exit(2);
    }
  }

  let input: string;
  try {
    input = readInput(path);
  } catch (err) {
    console.error(`header-lint: ${(err as Error).message}`);
    process.exit(2);
  }

  const findings = lint(input);

  let worst = 0;
  for (const f of findings) {
    worst = Math.max(worst, EXIT_CODE_BY_SEVERITY[f.severity]);
  }

  if (json) {
    // Always emit an array, even when empty, so CI consumers can parse
    // the output without special-casing the clean run.
    console.log(JSON.stringify(findings, null, 2));
  } else if (findings.length === 0) {
    console.log('no findings');
  } else {
    for (const f of findings) {
      console.log(`${f.line}: ${f.severity.padEnd(7)} ${f.rule}  ${f.message}`);
    }
  }

  process.exit(worst);
}

main();
