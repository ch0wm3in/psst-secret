import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

await build({
    entryPoints: [
        fileURLToPath(new URL('../../static/js/crypto.js', import.meta.url)),
        fileURLToPath(new URL('../../static/js/password-strength.js', import.meta.url)),
        fileURLToPath(new URL('../../static/js/receive-access.js', import.meta.url)),
        fileURLToPath(new URL('../../static/js/secret-generator.js', import.meta.url)),
        fileURLToPath(new URL('../../static/js/wordlist-en.js', import.meta.url)),
    ],
    outdir: fileURLToPath(new URL('../static/js/', import.meta.url)),
    outExtension: { '.js': '.min.js' },
    minify: true,
    target: 'es2020',
    legalComments: 'inline',
});