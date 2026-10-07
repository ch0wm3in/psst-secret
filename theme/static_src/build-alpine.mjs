import { copyFile, mkdir } from 'node:fs/promises';

const outputDirectory = new URL('../static/js/', import.meta.url);

await mkdir(outputDirectory, { recursive: true });
await copyFile(
    new URL('./node_modules/alpinejs/dist/cdn.min.js', import.meta.url),
    new URL('alpine.min.js', outputDirectory),
);