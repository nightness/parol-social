#!/usr/bin/env node
// ParolNet PWA Build Script
// Bundles JS modules, computes integrity hashes, updates sw.js, generates build-info.
//
// Usage:
//   node pwa/build.mjs              # Production build
//   node pwa/build.mjs --watch      # Dev mode (watch + serve)

import * as esbuild from 'esbuild';
import { createHash } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { execSync } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const isWatch = process.argv.includes('--watch');

// ── Files that get integrity-hashed in sw.js ────────────────
const HASHED_FILES = ['app.js', 'styles.css', 'crypto-store.js', 'index.html'];

function sha256(filePath) {
    const data = readFileSync(filePath);
    return createHash('sha256').update(data).digest('hex');
}

function patchSwHashes() {
    const swPath = join(__dirname, 'sw.js');
    let sw = readFileSync(swPath, 'utf8');

    for (const name of HASHED_FILES) {
        const hash = sha256(join(__dirname, name));
        // Match:  'filename':  'hexhash'  (with any whitespace)
        const re = new RegExp(`'${name.replace('.', '\\.')}':\\s*'[0-9a-f]+'`);
        sw = sw.replace(re, `'${name}': '${hash}'`);
    }

    writeFileSync(swPath, sw);
    console.log('  SW hashes updated');
}

function generateBuildInfo() {
    const date = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
    let commit = 'unknown';
    try { commit = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim(); } catch {}
    const info = `window.BUILD_INFO={date:'dev ${date}',dev:true};`;
    writeFileSync(join(__dirname, 'build-info.js'), info);
    console.log(`  Build info: ${date} (${commit})`);
}

// ── esbuild config ──────────────────────────────────────────
const config = {
    entryPoints: ['src/boot.js'],
    bundle: true,
    outfile: 'app.js',
    format: 'esm',
    sourcemap: true,
    target: ['es2020'],
    absWorkingDir: __dirname,
    external: [
        './crypto-store.js',
        './data-export.js',
        './relay-client.js',
        './pkg/parolnet_wasm.js',
        './network-config.js',
        './build-info.js',
    ],
};

// ── Run ─────────────────────────────────────────────────────
if (isWatch) {
    const ctx = await esbuild.context(config);
    await ctx.watch();
    console.log('Watching for changes...');
} else {
    console.log('Building PWA JS...');
    const t0 = performance.now();
    await esbuild.build(config);
    const ms = Math.round(performance.now() - t0);
    console.log(`  Bundled in ${ms}ms`);
    patchSwHashes();
    generateBuildInfo();
    console.log('Done.');
}
