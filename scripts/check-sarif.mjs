import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// Fail closed on missing reports, unsuccessful analysis, or any unsuppressed
// finding. Do not print snippets: scanner results may contain sensitive data.
const directory = process.argv[2];
if (!directory) throw new Error('SARIF directory required');
const files = readdirSync(directory).filter(name => name.endsWith('.sarif'));
if (files.length === 0) throw new Error('No SARIF reports produced');
let findings = 0;
for (const file of files) {
  const report = JSON.parse(readFileSync(join(directory, file), 'utf8'));
  if (!Array.isArray(report.runs) || report.runs.length === 0) throw new Error('Empty SARIF report');
  for (const run of report.runs) {
    if (run.invocations?.some(invocation => invocation.executionSuccessful === false)) {
      throw new Error('CodeQL analysis did not complete');
    }
    for (const result of run.results ?? []) {
      if (result.suppressions?.some(suppression => suppression.status === 'accepted')) {
        throw new Error('Suppressed findings require review; release is blocked');
      }
      findings++;
      console.error(file + ': ' + (result.ruleId ?? 'unknown rule'));
    }
  }
}
if (findings !== 0) throw new Error(findings + ' CodeQL findings block release');
console.log(files.length + ' CodeQL reports: no findings');
