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

function main(): void {
  const path = process.argv[2];

  if (path === '--help' || path === '-h') {
    console.log('usage: header-lint [file]\n\nReads raw HTTP response headers (e.g. from `curl -I`),');
    console.log('either from FILE or stdin, and prints findings as line:severity rule message.');
    process.exit(0);
  }

  let input: string;
  try {
    input = readInput(path);
  } catch (err) {
    console.error(`header-lint: ${(err as Error).message}`);
    process.exit(2);
  }

  const findings = lint(input);

  if (findings.length === 0) {
    console.log('no findings');
    process.exit(0);
  }

  let worst = 0;
  for (const f of findings) {
    console.log(`${f.line}: ${f.severity.padEnd(7)} ${f.rule}  ${f.message}`);
    worst = Math.max(worst, EXIT_CODE_BY_SEVERITY[f.severity]);
  }

  process.exit(worst);
}

main();
