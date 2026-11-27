// News image 27 Nov 2026 — the entry program (Node 22, standard library only).
//
// What it does: it takes entry.png from beside this file — a one-page
// summary of the world's news of Friday 27 November 2026, drawn for this
// entry — and writes it to /output/entry.png. Nothing else is read,
// nothing else is written, and the program runs the same way twice: the
// bytes it writes are always the bytes of entry.png.
//
// Safety: before copying, it checks that entry.png really is a 1024x1024
// PNG (magic bytes + IHDR dimensions + a well-formed chunk chain carrying
// at least one IDAT chunk + the IEND trailer) and that its sha256 is
// exactly the hash of the approved image. After copying, it reads the
// output back and checks the hash again, so a truncated or altered copy
// can never reach the judge.
//
// Outside the grader's container, MAKEFUN_OUTPUT_DIR stands in for /output:
//   mkdir -p out && MAKEFUN_OUTPUT_DIR=out node main.ts

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// sha256 of entry.png as built and approved, 27 Nov 2026.
const APPROVED_SHA256 =
  '72225f8114634532ab2f6e5e36954b84e81f28a64ed47c7ff1ce86e85af82a8c';

const PNG_MAGIC = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);

// The 12-byte IEND chunk (zero length, 'IEND', CRC ae426082) that must
// close every PNG. Hoisted to module scope so the check does not rebuild
// the same constant on every call.
const IEND_TRAILER = Buffer.from([
  0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
]);

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

// Walk a PNG's chunk chain and confirm it is well formed: every chunk
// ends inside the file, at least one IDAT chunk carries image data, and
// IEND is the last chunk with nothing after it. Returns true when the
// chain is sound, and throws a specific error otherwise.
function checkChunkChain(bytes: Buffer): boolean {
  let offset = 8;
  let seenIdat = false;
  while (offset + 8 <= bytes.length) {
    const length = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString('ascii');
    if (offset + 12 + length > bytes.length) {
      throw new Error(`entry.png chunk ${type} runs past the end of the file`);
    }
    if (type === 'IDAT') seenIdat = true;
    if (type === 'IEND') {
      // IEND is the last chunk: nothing may follow it. A file with junk
      // appended after IEND is not the approved image, even if the hash
      // were somehow right — and with the hash check below it cannot be.
      if (offset + 12 + length !== bytes.length) {
        throw new Error('entry.png has bytes after its IEND chunk');
      }
      break;
    }
    offset += 12 + length;
  }
  if (!seenIdat) {
    throw new Error('entry.png has no IDAT chunk — it carries no image data');
  }
  return true;
}

function readApprovedImage(): Buffer {
  const here = dirname(fileURLToPath(import.meta.url));
  const bytes = readFileSync(join(here, 'entry.png'));

  if (bytes.length < 24 || !bytes.subarray(0, 8).equals(PNG_MAGIC)) {
    throw new Error('entry.png is not a PNG file');
  }
  // The first chunk of a real PNG must be IHDR (bytes 12-16); a file with
  // the right magic but a different first chunk is not a PNG we trust.
  if (bytes.subarray(12, 16).toString('ascii') !== 'IHDR') {
    throw new Error('entry.png has no IHDR chunk where one belongs');
  }
  const width = bytes.readUInt32BE(16);
  const height = bytes.readUInt32BE(20);
  if (width !== 1024 || height !== 1024) {
    throw new Error(`entry.png is ${width}x${height}, expected 1024x1024`);
  }
  // A PNG must end with the 12-byte IEND chunk (zero length, 'IEND', CRC
  // ae426082). A file cut short mid-download fails here even before the
  // hash is consulted, so a truncated image is caught twice.
  if (bytes.length < 12 || !bytes.subarray(bytes.length - 12).equals(IEND_TRAILER)) {
    throw new Error('entry.png has no IEND trailer where one belongs');
  }
  // Walk the chunk chain: every chunk must end inside the file, and the
  // file must carry at least one IDAT chunk. This catches a file spliced
  // together from two PNGs, or one with a lying chunk length, even when
  // the magic, IHDR and IEND all look right on their own.
  checkChunkChain(bytes);
  if (sha256Hex(bytes) !== APPROVED_SHA256) {
    throw new Error(
      `entry.png sha256 mismatch: got ${sha256Hex(bytes)}, expected ${APPROVED_SHA256}`,
    );
  }
  return bytes;
}

function main(): void {
  const bytes = readApprovedImage();

  const outDir = process.env.MAKEFUN_OUTPUT_DIR ?? '/output';
  mkdirSync(outDir, { recursive: true });
  const target = join(outDir, 'entry.png');
  writeFileSync(target, bytes);

  const writtenBack = readFileSync(target);
  if (sha256Hex(writtenBack) !== APPROVED_SHA256) {
    throw new Error('the copied /output/entry.png failed its sha256 check');
  }
}

main();
