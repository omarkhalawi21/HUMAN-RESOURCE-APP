// Builds privacy.html (the public privacy policy page, used as the App Store
// "Privacy Policy URL") from PRIVACY_NOTICE.md. Run after editing the notice:
//   npm run privacy
// Blockquotes in the notice are internal notes (consent-form instructions,
// template disclaimer) and are left out of the public page.
import { readFileSync, writeFileSync } from 'node:fs';

const md = readFileSync('PRIVACY_NOTICE.md', 'utf8');
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const inline = s => esc(s)
  .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  .replace(/(^|[\s(])_(.+?)_(?=[\s).,]|$)/g, '$1<em>$2</em>');

function render(block) {
  const out = [];
  const lines = block.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l.trim() || l.startsWith('>') || /^---\s*$/.test(l)) continue;
    let m;
    if ((m = l.match(/^(#{1,3}) (.*)/))) { out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`); continue; }
    if (l.startsWith('|')) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith('|')) rows.push(lines[i++]);
      i--;
      const cells = r => r.replace(/^\||\|$/g, '').split('|').map(c => inline(c.trim()));
      const [head, , ...body] = rows;
      out.push('<table><thead><tr>' + cells(head).map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>'
        + body.map(r => '<tr>' + cells(r).map(c => `<td>${c}</td>`).join('') + '</tr>').join('') + '</tbody></table>');
      continue;
    }
    if (l.startsWith('- ')) {
      const items = [];
      while (i < lines.length && lines[i].startsWith('- ')) items.push(lines[i++].slice(2));
      i--;
      out.push('<ul>' + items.map(t => `<li>${inline(t)}</li>`).join('') + '</ul>');
      continue;
    }
    const para = [l];
    while (i + 1 < lines.length && lines[i + 1].trim() && !/^(#|\||- |>|---)/.test(lines[i + 1])) para.push(lines[++i]);
    out.push(`<p>${para.map(inline).join('<br>')}</p>`);
  }
  return out.join('\n');
}

// The notice is English first, then Arabic starting at the second top-level heading.
const split = md.search(/^# .*[؀-ۿ]/m);
const en = md.slice(0, split), ar = md.slice(split);

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Privacy Policy | Hassad Team</title>
<link rel="icon" href="logo.png">
<!-- Generated from PRIVACY_NOTICE.md by scripts/build-privacy.mjs. Do not edit by hand. -->
<style>
  body { margin: 0; background: #faf7f2; color: #1f2937; font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Tahoma, sans-serif; }
  main { max-width: 820px; margin: 0 auto; padding: 32px 20px 64px; }
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  header img { width: 56px; height: 56px; }
  nav a { color: #871e2d; margin-right: 16px; }
  section { background: #fff; border-radius: 12px; padding: 8px 24px 24px; margin-top: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  h1 { color: #871e2d; font-size: 1.6rem; } h2 { font-size: 1.15rem; margin-top: 1.8em; }
  table { border-collapse: collapse; width: 100%; font-size: .95rem; }
  th, td { border: 1px solid #e5e7eb; padding: 8px 10px; text-align: start; vertical-align: top; }
  th { background: #f6efe6; }
  [dir=rtl] { font-family: Tahoma, "Geeza Pro", sans-serif; }
</style>
</head>
<body>
<main>
<header><img src="logo.png" alt="Hassad"><strong>Hassad Team</strong></header>
<nav><a href="#en">English</a><a href="#ar">العربية</a></nav>
<section id="en" lang="en" dir="ltr">
${render(en)}
</section>
<section id="ar" lang="ar" dir="rtl">
${render(ar)}
</section>
</main>
</body>
</html>
`;
writeFileSync('privacy.html', html);
console.log('privacy.html written');
