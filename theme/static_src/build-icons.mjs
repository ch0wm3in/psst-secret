import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';

const sources = [
    { directory: new URL('../../templates/', import.meta.url), extension: '.html' },
    { directory: new URL('../../whispers/', import.meta.url), extension: '.py' },
];
const outputDirectory = new URL('../static/icons/', import.meta.url);

const styleDirectories = {
    outline: '24/outline',
    solid: '24/solid',
    mini: '20/solid',
    micro: '16/solid',
};

// Matches {% icon "style/name" %} in templates and "outline/name"-style literals in Python.
const patterns = {
    '.html': /\{%\s*icon\s+["']([a-z]+\/)?([a-z0-9-]+)["']/g,
    '.py': /["'](outline\/|solid\/|mini\/|micro\/)([a-z0-9-]+)["']/g,
};

const icons = new Set();
for (const { directory, extension } of sources) {
    for (const entry of await readdir(directory, { recursive: true })) {
        if (!entry.endsWith(extension) || entry.split(/[\\/]/).includes('tests')) continue;
        const source = await readFile(new URL(entry, directory), 'utf8');
        for (const [, prefix, name] of source.matchAll(patterns[extension])) {
            icons.add(`${prefix ? prefix.slice(0, -1) : 'outline'}/${name}`);
        }
    }
}

const symbols = [];
for (const icon of [...icons].sort()) {
    const [style, name] = icon.split('/');
    if (!styleDirectories[style]) {
        throw new Error(`Unknown heroicons style "${style}" in {% icon "${icon}" %}`);
    }
    const file = new URL(`./node_modules/heroicons/${styleDirectories[style]}/${name}.svg`, import.meta.url);
    let svg;
    try {
        svg = await readFile(file, 'utf8');
    } catch {
        throw new Error(`Unknown heroicon "${icon}"`);
    }
    const [, attributes, body] = svg.match(/<svg([^>]*)>([\s\S]*?)<\/svg>/);
    const kept = attributes.replace(/\s(xmlns|aria-hidden|data-slot)="[^"]*"/g, '');
    symbols.push(`<symbol id="${style}-${name}"${kept}>${body.trim()}</symbol>`);
}

await mkdir(outputDirectory, { recursive: true });
await writeFile(
    new URL('heroicons.svg', outputDirectory),
    `<svg xmlns="http://www.w3.org/2000/svg"><!-- Heroicons, MIT License, Tailwind Labs -->${symbols.join('')}</svg>\n`,
);
console.log(`Built heroicons sprite with ${symbols.length} icon(s).`);
