// Copies the static web app into www/, which Capacitor bundles into the iOS app.
// index.html stays the single source of truth at the repo root (GitHub Pages
// keeps serving it from there); www/ is generated output and is git-ignored.
import { cpSync, mkdirSync, rmSync, existsSync } from 'node:fs';

const FILES = ['index.html', 'privacy.html', 'tailwind.css', 'logo.png', 'bg-coffee.jpg', 'manifest.webmanifest', 'sw.js'];

rmSync('www', { recursive: true, force: true });
mkdirSync('www');
for (const f of FILES) {
  if (!existsSync(f)) { console.error(`missing ${f}`); process.exit(1); }
  cpSync(f, `www/${f}`);
}
console.log(`www/ ready (${FILES.length} files)`);
