import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

await build({
    entryPoints: [fileURLToPath(new URL('./src/tiptap.js', import.meta.url))],
    outfile: fileURLToPath(new URL('../static/js/tiptap.min.js', import.meta.url)),
    bundle: true,
    minify: true,
    format: 'iife',
    target: 'es2020',
    legalComments: 'inline',
});
