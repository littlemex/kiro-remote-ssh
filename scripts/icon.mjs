#!/usr/bin/env node
/**
 * Draw the extension's icon.
 *
 * Generated rather than committed as a binary. A repository that claims its
 * published archive contains only its own code should not also carry an opaque
 * image nobody can regenerate, and an icon produced by twenty lines of arithmetic
 * is easier to verify than one that arrived from somewhere.
 *
 * The mark is two nodes joined by a link, drawn on the diagonal: the whole
 * extension is about one machine standing in for another, and that is the
 * shortest way to say it without borrowing anyone else's shape.
 *
 * No dependencies. A PNG is a signature, a header chunk, image data compressed
 * with zlib, and an end marker, and Node has zlib.
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';

const SIZE = 128;

// Deliberately not the blues that editor remote tooling already uses, so the mark
// is not mistaken for one of them at a glance.
const BACKGROUND = [17, 46, 38]; // deep green
const FIELD = [30, 84, 66]; // the rounded plate
const LINK = [126, 224, 178]; // mint
const NEAR = [232, 255, 244]; // the near node, brightest

const pixels = Buffer.alloc(SIZE * SIZE * 4);

function put(x, y, [r, g, b], alpha = 1) {
    if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) {
        return;
    }
    const at = (y * SIZE + x) * 4;
    // Painted front to back, so a new colour blends over what is already there.
    const existing = [pixels[at], pixels[at + 1], pixels[at + 2]];
    const existingAlpha = pixels[at + 3] / 255;
    const outAlpha = alpha + existingAlpha * (1 - alpha);
    for (let channel = 0; channel < 3; channel += 1) {
        const value = ([r, g, b][channel] * alpha + existing[channel] * existingAlpha * (1 - alpha)) / (outAlpha || 1);
        pixels[at + channel] = Math.round(value);
    }
    pixels[at + 3] = Math.round(outAlpha * 255);
}

/** Coverage of one pixel by a shape, sampled 4x4, so edges are not jagged. */
function coverage(x, y, inside) {
    let hits = 0;
    for (let sy = 0; sy < 4; sy += 1) {
        for (let sx = 0; sx < 4; sx += 1) {
            if (inside(x + (sx + 0.5) / 4, y + (sy + 0.5) / 4)) {
                hits += 1;
            }
        }
    }
    return hits / 16;
}

function fill(inside, colour) {
    for (let y = 0; y < SIZE; y += 1) {
        for (let x = 0; x < SIZE; x += 1) {
            const alpha = coverage(x, y, inside);
            if (alpha > 0) {
                put(x, y, colour, alpha);
            }
        }
    }
}

const roundedSquare = (inset, radius) => (x, y) => {
    const lo = inset;
    const hi = SIZE - inset;
    if (x < lo || y < lo || x > hi || y > hi) {
        return false;
    }
    const cx = Math.min(Math.max(x, lo + radius), hi - radius);
    const cy = Math.min(Math.max(y, lo + radius), hi - radius);
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2;
};

const disc = (cx, cy, r) => (x, y) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r;

/** A thick segment with rounded ends, which is a disc swept along a line. */
const capsule = (x1, y1, x2, y2, r) => (x, y) => {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const length = dx * dx + dy * dy;
    const t = length === 0 ? 0 : Math.min(1, Math.max(0, ((x - x1) * dx + (y - y1) * dy) / length));
    const px = x1 + t * dx;
    const py = y1 + t * dy;
    return (x - px) ** 2 + (y - py) ** 2 <= r * r;
};

fill(roundedSquare(0, 26), BACKGROUND);
fill(roundedSquare(12, 20), FIELD);

// The link runs corner to corner: the far node up and right, the near node down
// and left, which is the direction the work travels.
const far = { x: 88, y: 42 };
const near = { x: 42, y: 88 };
fill(capsule(near.x, near.y, far.x, far.y, 7), LINK);
fill(disc(far.x, far.y, 15), LINK);
fill(disc(far.x, far.y, 7), FIELD);
fill(disc(near.x, near.y, 15), NEAR);
fill(disc(near.x, near.y, 7), FIELD);

function chunk(type, body) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(body.length);
    const payload = Buffer.concat([Buffer.from(type, 'ascii'), body]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(payload) >>> 0);
    return Buffer.concat([length, payload, crc]);
}

let crcTable;
function crc32(buffer) {
    if (!crcTable) {
        crcTable = new Int32Array(256);
        for (let n = 0; n < 256; n += 1) {
            let c = n;
            for (let k = 0; k < 8; k += 1) {
                c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
            }
            crcTable[n] = c;
        }
    }
    let c = -1;
    for (const byte of buffer) {
        c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
    }
    return c ^ -1;
}

const header = Buffer.alloc(13);
header.writeUInt32BE(SIZE, 0);
header.writeUInt32BE(SIZE, 4);
header[8] = 8; // bit depth
header[9] = 6; // colour type: truecolour with alpha
const raw = Buffer.alloc((SIZE * 4 + 1) * SIZE);
for (let y = 0; y < SIZE; y += 1) {
    raw[y * (SIZE * 4 + 1)] = 0; // no per-row filter, so the output is predictable
    pixels.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}

const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
]);

const output = process.argv[2] ?? 'icon.png';
writeFileSync(output, png);
console.log(`wrote ${output} (${SIZE}x${SIZE}, ${png.length} bytes)`);
