import { build, context } from 'esbuild';

const options = {
    entryPoints: ['src/extension.ts'],
    bundle: true,
    outfile: 'dist/extension.js',
    external: ['vscode'],
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    sourcemap: true,
    logLevel: 'info',
    // The bootstrap script is delivered to the remote host on stdin, so it has to
    // travel inside the bundle rather than being read from disk at runtime.
    loader: { '.sh': 'text', '.py': 'text' },
};

if (process.argv.includes('--watch')) {
    const ctx = await context(options);
    await ctx.watch();
} else {
    await build(options);
}
