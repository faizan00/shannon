/**
 * Atomic JSON-file persistence, shared by every `save*` function that
 * writes one of this package's durable state files (`checkpoint.json`,
 * `state.json`, `world-model.json`, `provenance.json`, `state-graph.json`).
 *
 * A direct `writeFile` to the real path can be interrupted mid-write (a
 * killed process, an out-of-disk-space error partway through) and leave a
 * truncated, corrupted file behind. Writing to a temporary path first and
 * `rename`-ing it into place is atomic on POSIX filesystems — a reader
 * only ever sees the fully-written old file or the fully-written new one,
 * never a partial write.
 */

import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export async function writeFileAtomic(filePath: string, content: string): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tempPath, content, 'utf8');
  await rename(tempPath, filePath);
}
