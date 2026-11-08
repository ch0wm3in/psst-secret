import { build } from 'esbuild';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const scripts = path => fileURLToPath(new URL(`../../static/js/${path}`, import.meta.url));
const outdir = fileURLToPath(new URL('../static/js/', import.meta.url));
const nodeModules = fileURLToPath(new URL('./node_modules/', import.meta.url));

// @psst-secret/crypto is linked from packages/crypto, which has no node_modules of its
// own here, so its dependencies resolve from this directory and must use the same pins.
const readJson = path => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const theme = readJson('./package.json').dependencies;
for (const [name, version] of Object.entries(readJson('../../packages/crypto/package.json').dependencies)) {
    if (theme[name] !== version) {
        throw new Error(`${name} is ${version} in packages/crypto but ${theme[name]} in theme/static_src`);
    }
}

// crypto.js imports @psst-secret/crypto and is bundled; the other scripts are standalone.
await build({
    entryPoints: [scripts('crypto.js')],
    outdir,
    outExtension: { '.js': '.min.js' },
    bundle: true,
    // static/js is outside this directory, so point module resolution here.
    nodePaths: [nodeModules],
    preserveSymlinks: true,
    format: 'iife',
    minify: true,
    target: 'es2020',
    legalComments: 'inline',
});

await build({
    entryPoints: [
        scripts('password-strength.js'),
        scripts('receive-access.js'),
        scripts('receive-history.js'),
        scripts('rich-text.js'),
        scripts('secret-generator.js'),
        scripts('wordlist-en.js'),
    ],
    outdir,
    outExtension: { '.js': '.min.js' },
    minify: true,
    target: 'es2020',
    legalComments: 'inline',
});
