#!/usr/bin/env node
import { readFile, writeFile, mkdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { artifactText, compilePlan, createReviewRequest, parsePublicInput } from './plan.mjs';
import { exampleInput } from './example.mjs';

const root = new URL('./', import.meta.url);
const help = 'Usage: node bootstrap/cli.mjs example | plan --input public.json --out NEW_DIRECTORY | review --input public.json --plan-digest SHA256 --operation ID --out NEW_FILE | render --out NEW_HTML | preview [--port 8765]';
function argsFor(names) {
  const args = process.argv.slice(3), values = {};
  if (args.length % 2 !== 0) throw new Error('invalid-options');
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    if (!names.includes(key) || Object.hasOwn(values, key) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('invalid-options');
    values[key] = args[i + 1];
  }
  return values;
}
function requireOptions(options, names) { if (names.some(name => !options[name])) throw new Error('invalid-options'); }
async function readInput(path) {
  if (!path.endsWith('.json')) throw new Error('invalid-input-file');
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 65536) throw new Error('invalid-input-file');
  return parsePublicInput(await readFile(path, 'utf8'));
}
async function writeJSON(path, value) { await writeFile(path, artifactText(value), { flag: 'wx', mode: 0o600 }); }
async function render() {
  const [html, css, plan, example, review] = await Promise.all(['index.html', 'style.css', 'plan.mjs', 'example.mjs', 'review.mjs'].map(name => readFile(new URL(name, root), 'utf8')));
  const reference = await readFile(new URL('../src/service/op-reference.mjs', root), 'utf8');
  const script = [reference, plan, example, review].map(source => source.replace(/^import .*;\n/gm, '')).join('\n').replace(/^export /gm, '');
  const digest = text => createHash('sha256').update(text).digest('base64');
  return html.replace("script-src 'self'; style-src 'self'", `script-src 'sha256-${digest(script)}'; style-src 'sha256-${digest(css)}'`)
    .replace('<link rel="stylesheet" href="/style.css">', `<style>${css}</style>`)
    .replace('<script type="module" src="/review.mjs"></script>', `<script type="module">${script}</script>`);
}
async function preview(portText = '8765') {
  if (!/^[0-9]{1,5}$/.test(portText) || Number(portText) < 1024 || Number(portText) > 65535) throw new Error('invalid-options');
  const port = Number(portText);
  const files = new Map(await Promise.all(['index.html', 'style.css', 'plan.mjs', 'example.mjs', 'review.mjs'].map(async name => [name === 'index.html' ? '/' : `/${name}`, { body: await readFile(new URL(name, root)), type: name.endsWith('.html') ? 'text/html' : name.endsWith('.css') ? 'text/css' : 'text/javascript' }])));
  files.set('/src/service/op-reference.mjs', { body: await readFile(new URL('../src/service/op-reference.mjs', root)), type: 'text/javascript' });
  const server = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store'); response.setHeader('X-Content-Type-Options', 'nosniff'); response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'");
    if (request.headers.host !== `127.0.0.1:${port}` || !['GET', 'HEAD'].includes(request.method)) { response.writeHead(403); response.end('Preview request rejected.'); return; }
    const file = files.get(request.url);
    if (!file) { response.writeHead(404); response.end('Not found.'); return; }
    response.setHeader('Content-Type', `${file.type}; charset=utf-8`); response.writeHead(200); response.end(request.method === 'HEAD' ? undefined : file.body);
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000;
  await new Promise((resolveReady, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolveReady); });
  process.stdout.write(`Offline bootstrap review: http://127.0.0.1:${port}/\nApply is disabled. Stop with Ctrl-C.\n`);
}
try {
  const command = process.argv[2];
  if (command === 'example') {
    argsFor([]); process.stdout.write(JSON.stringify(exampleInput(), null, 2) + '\n');
  } else if (command === 'plan') {
    const args = argsFor(['--input', '--out']); requireOptions(args, ['--input', '--out']);
    const plan = await compilePlan(await readInput(args['--input']));
    const out = resolve(args['--out']); await mkdir(out, { mode: 0o700 });
    await writeJSON(join(out, 'bootstrap-plan.json'), plan);
    await writeJSON(join(out, 'wrangler.bootstrap.json'), plan.artifacts.wrangler);
    await writeJSON(join(out, 'public-runtime-config.json'), plan.artifacts.publicRuntimeConfig);
    await writeJSON(join(out, 'image-runtime-config.json'), plan.artifacts.imageRuntimeConfig);
    process.stdout.write(`Dry-run plan SHA-256: ${plan.digest}\n${plan.blockers.length} commissioning blockers; apply unavailable.\n`);
  } else if (command === 'review') {
    const args = argsFor(['--input', '--plan-digest', '--operation', '--out']); requireOptions(args, ['--input', '--plan-digest', '--operation', '--out']);
    const review = await createReviewRequest(await readInput(args['--input']), args['--plan-digest'], args['--operation']);
    await writeJSON(args['--out'], review); process.stdout.write('Unauthenticated operation review request written; no approval or execution.\n');
  } else if (command === 'render') {
    const args = argsFor(['--out']); requireOptions(args, ['--out']);
    await writeFile(args['--out'], await render(), { flag: 'wx', mode: 0o600 }); process.stdout.write('Self-contained offline review UI written.\n');
  } else if (command === 'preview') { const args = argsFor(['--port']); await preview(args['--port']); }
  else { throw new Error('invalid-options'); }
} catch (error) {
  const known = new Set(['invalid-public-input', 'plan-changed', 'unknown-operation']);
  process.stderr.write(known.has(error.code) ? error.message + '\n' : 'Bootstrap command refused or failed. Check the public input, fresh output path, and options. No input values are echoed.\n');
  if (error.message === 'invalid-options') process.stderr.write(help + '\n');
  process.exitCode = 1;
}
