import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

for (const [name, runs, accepted] of [
  ['clean', [{ results: [] }], true],
  ['finding', [{ results: [{ ruleId: 'security/problem' }] }], false],
  ['suppressed finding', [{ results: [{ suppressions: [{ status: 'accepted' }] }] }], false],
  ['failed analysis', [{ invocations: [{ executionSuccessful: false }], results: [] }], false],
  ['empty report', [], false],
  ['missing report', null, false],
]) {
  test(name, () => {
    const directory = mkdtempSync(join(tmpdir(), 'sarif-gate-'));
    try {
      if (runs) writeFileSync(join(directory, 'test.sarif'), JSON.stringify({ runs }));
      const result = spawnSync(process.execPath, ['scripts/check-sarif.mjs', directory]);
      assert.equal(result.status === 0, accepted);
    } finally { rmSync(directory, { recursive: true }); }
  });
}
