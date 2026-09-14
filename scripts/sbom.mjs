#!/usr/bin/env node
/**
 * Emit a CycloneDX bill of materials for this project.
 *
 * Written here, with no dependencies, on purpose. A bill of materials whose
 * generation requires an account somewhere is not something every reader of this
 * repository can produce, and the point of publishing one is that anyone can check
 * it against the tree in front of them. Tools that consume CycloneDX — Amazon
 * Inspector among them — remain useful, but they consume this rather than being
 * required to produce it.
 *
 * Two things it records that matter more than the component list:
 *
 * - The shipped bundle's own SHA-256, so the artifact and the inventory are tied
 *   together rather than published side by side and hoped to match.
 * - The integrity value the lockfile recorded for every dependency, which is what
 *   makes a substituted tarball detectable rather than merely unlikely.
 *
 * Runtime dependencies are marked as such. There are none, and an inventory is a
 * better place to demonstrate that than a sentence in a readme.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const manifest = JSON.parse(readFileSync('package.json', 'utf8'));
const lock = existsSync('package-lock.json') ? JSON.parse(readFileSync('package-lock.json', 'utf8')) : { packages: {} };

/** `sha512-<base64>` in a lockfile is CycloneDX's SHA-512 with a hex encoding. */
function toHash(integrity) {
    if (typeof integrity !== 'string') {
        return undefined;
    }
    const [algorithm, encoded] = integrity.split('-', 2);
    const alg = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256', sha1: 'SHA-1' }[algorithm];
    if (!alg || !encoded) {
        return undefined;
    }
    return { alg, content: Buffer.from(encoded, 'base64').toString('hex') };
}

const directRuntime = new Set(Object.keys(manifest.dependencies ?? {}));
const directDev = new Set(Object.keys(manifest.devDependencies ?? {}));

const components = [];
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (!path || !entry.version) {
        continue;
    }
    const name = path.replace(/^node_modules\//, '').replace(/.*\/node_modules\//, '');
    const hash = toHash(entry.integrity);
    components.push({
        'bom-ref': `pkg:npm/${name}@${entry.version}`,
        type: 'library',
        name,
        version: entry.version,
        purl: `pkg:npm/${name}@${entry.version}`,
        scope: directRuntime.has(name) ? 'required' : 'optional',
        ...(hash ? { hashes: [hash] } : {}),
        properties: [
            {
                name: 'kiro-remote-ssh:dependency-kind',
                // The distinction the reader cares about: what ships with the
                // extension, versus what only ever ran on a build machine.
                value: directRuntime.has(name)
                    ? 'runtime (ships with the extension)'
                    : directDev.has(name)
                      ? 'build-time (direct)'
                      : 'build-time (transitive)',
            },
            ...(entry.resolved ? [{ name: 'kiro-remote-ssh:resolved-from', value: entry.resolved }] : []),
        ],
    });
}

const bundlePath = 'dist/extension.js';
const bundleHashes = existsSync(bundlePath)
    ? [{ alg: 'SHA-256', content: createHash('sha256').update(readFileSync(bundlePath)).digest('hex') }]
    : [];

const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
        // No timestamp. A bill of materials that differs between two runs of the
        // same tree cannot be compared, and comparison is the only reason to
        // publish one.
        component: {
            'bom-ref': `pkg:npm/${manifest.name}@${manifest.version}`,
            type: 'application',
            name: manifest.name,
            version: manifest.version,
            purl: `pkg:npm/${manifest.name}@${manifest.version}`,
            licenses: [{ license: { id: manifest.license } }],
            ...(bundleHashes.length ? { hashes: bundleHashes } : {}),
        },
        tools: [{ vendor: 'kiro-remote-ssh', name: 'scripts/sbom.mjs' }],
        properties: [
            {
                name: 'kiro-remote-ssh:runtime-dependency-count',
                value: String(directRuntime.size),
            },
        ],
    },
    components: components.sort((a, b) => a['bom-ref'].localeCompare(b['bom-ref'])),
};

const output = process.argv[2] ?? 'sbom.cdx.json';
writeFileSync(output, `${JSON.stringify(bom, null, 2)}\n`);
console.log(`wrote ${output}`);
console.log(`  components            ${components.length}`);
console.log(`  runtime dependencies  ${directRuntime.size}`);
console.log(`  bundle digest         ${bundleHashes[0]?.content ?? '(bundle not built)'}`);
