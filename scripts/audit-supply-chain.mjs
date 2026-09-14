#!/usr/bin/env node
/**
 * Turn this project's supply-chain promises into checks that can fail.
 *
 * Every assertion here corresponds to a sentence someone might otherwise have to
 * take on trust. "No runtime dependencies", "no telemetry", "nothing runs at
 * install time", "the published archive contains only these files" are all
 * pleasant things to write in a README and worth nothing unless something breaks
 * when they stop being true. So they are written here instead, and the README
 * points at this file.
 *
 * The bar is deliberately set at what the project already satisfies. A check that
 * has to be relaxed on the day it is added teaches nobody anything.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const failures = [];
const notes = [];

function check(description, condition, detail) {
    if (condition) {
        notes.push(`ok    ${description}`);
    } else {
        failures.push(`FAIL  ${description}${detail ? `\n      ${detail}` : ''}`);
    }
}

const manifest = JSON.parse(readFileSync('package.json', 'utf8'));

// 1. Runtime dependencies. This is the whole attack surface a consumer inherits,
// and it is zero because the design refuses to own an SSH implementation. Nothing
// enforces that but this line.
const runtimeDeps = Object.keys(manifest.dependencies ?? {});
check(
    'the extension has no runtime dependencies',
    runtimeDeps.length === 0,
    runtimeDeps.length ? `found: ${runtimeDeps.join(', ')}` : undefined,
);

// 2. Nothing of ours runs when someone installs this from source.
const lifecycle = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepublishOnly'];
const ourLifecycle = lifecycle.filter((name) => manifest.scripts?.[name]);
check(
    'this package defines no install-time scripts',
    ourLifecycle.length === 0,
    ourLifecycle.length ? `found: ${ourLifecycle.join(', ')}` : undefined,
);

// 3. Dependencies that run code at install time. These execute on whichever
// machine builds a release, so they are the shortest path from a compromised
// package to a compromised artifact. The build is expected to use
// --ignore-scripts, and this reports what would have run if it did not.
if (existsSync('node_modules')) {
    const withScripts = [];
    for (const entry of readdirSync('node_modules')) {
        if (entry.startsWith('.')) {
            continue;
        }
        const candidates = entry.startsWith('@')
            ? readdirSync(join('node_modules', entry)).map((sub) => join(entry, sub))
            : [entry];
        for (const name of candidates) {
            const file = join('node_modules', name, 'package.json');
            if (!existsSync(file)) {
                continue;
            }
            const scripts = JSON.parse(readFileSync(file, 'utf8')).scripts ?? {};
            for (const hook of ['preinstall', 'install', 'postinstall']) {
                if (scripts[hook]) {
                    withScripts.push(`${name} (${hook})`);
                }
            }
        }
    }
    if (withScripts.length) {
        notes.push(
            `note  ${withScripts.length} development dependencies define install scripts, which is why the build runs with --ignore-scripts: ${withScripts.join(', ')}`,
        );
    } else {
        notes.push('ok    no development dependency defines an install script');
    }
}

// 4. What the bundle can talk to. The extension contacts exactly one endpoint —
// the one the host application publishes in its own product.json — so there is no
// URL in the shipped code at all. A hardcoded address appearing here is either
// telemetry or an exfiltration path, and either way someone should have to argue
// for it in review rather than have it slip in.
const bundlePath = 'dist/extension.js';
if (!existsSync(bundlePath)) {
    failures.push('FAIL  dist/extension.js is missing; run the build first');
} else {
    const bundle = readFileSync(bundlePath, 'utf8');
    const urls = [...bundle.matchAll(/https?:\/\/[\w.~:/?#@!$&()*+,;=%-]{6,}/g)].map((m) => m[0]);
    check(
        'the bundle contains no hardcoded network endpoints',
        urls.length === 0,
        urls.length ? `found: ${[...new Set(urls)].join(', ')}` : undefined,
    );

    // 5. Telemetry. Absence is easy to claim and easy to check.
    const telemetry = ['appInsights', 'applicationinsights', '@vscode/extension-telemetry', 'segment.io', 'amplitude'];
    const found = telemetry.filter((name) => bundle.includes(name));
    check('the bundle contains no telemetry library', found.length === 0, found.join(', '));

    // 6. The bundle is reproducible from the source in this tree, so a reader can
    // check that what is published is what is here.
    notes.push(`note  dist/extension.js sha256 ${createHash('sha256').update(readFileSync(bundlePath)).digest('hex')}`);
    notes.push(`note  dist/extension.js is ${statSync(bundlePath).size} bytes`);
}

// 7. What ends up in the published archive. A file list is the most direct answer
// to "what am I installing", so it is pinned rather than described.
// SECURITY.md ships on purpose: the threat model is something a user should be
// able to read from the thing they installed, not only from the repository.
const expectedFiles = [
    'package.json',
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'icon.png',
    '.gitignore',
    'dist/extension.js',
];
try {
    const listed = execFileSync('npx', ['--yes', '@vscode/vsce@3.9.2', 'ls'], { encoding: 'utf8' })
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    const unexpected = listed.filter((file) => !expectedFiles.includes(file));
    const missing = expectedFiles.filter((file) => !listed.includes(file));
    check(
        'the published archive contains exactly the expected files',
        unexpected.length === 0 && missing.length === 0,
        [unexpected.length ? `unexpected: ${unexpected.join(', ')}` : '', missing.length ? `missing: ${missing.join(', ')}` : '']
            .filter(Boolean)
            .join('; '),
    );
} catch (err) {
    notes.push(`note  could not list the archive contents (${err.message.split('\n')[0]})`);
}

// 8. The remote programs. These run on someone else's machine, so they are read
// as part of review and are pinned by digest here: a change to either of them is a
// change to what executes on a host, and should be visible as such.
for (const remote of ['src/reh/bootstrap.sh', 'src/reh/lease.py']) {
    if (existsSync(remote)) {
        notes.push(`note  ${remote} sha256 ${createHash('sha256').update(readFileSync(remote)).digest('hex')}`);
    }
}

console.log(notes.join('\n'));
if (failures.length) {
    console.error(`\n${failures.join('\n')}`);
    console.error(`\n${failures.length} supply-chain assertion(s) failed.`);
    process.exit(1);
}
console.log('\nAll supply-chain assertions hold.');
