// Logs into the Vault/OpenBao web UI with a token and opens KV folders, over
// the DevTools protocol of a headless Chrome, without dependencies.
//
//   node ui.mjs <base url> <chrome binary> <token> proxy|direct
//
// "proxy": the folders the token's policies name must be visible.
// "direct": against Vault itself, they must not be (baseline).
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [base, chromeBin, token, mode] = process.argv.slice(2);
const shots = process.env.UI_SHOTS;
const profile = mkdtempSync(join(tmpdir(), 'vkr-ui-'));
const port = 19700 + Math.floor(Math.random() * 200);
const chrome = spawn(chromeBin, ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`, '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const ok = (cond, what) => { console.log(`${cond ? 'ok  ' : 'FAIL'} [${mode}] ${what}`); if (!cond) failures++; };

let ws;
// Chrome on a busy CI runner has taken more than 20 s to open its DevTools port.
for (let i = 0; i < 240 && !ws; i++) {
  try {
    const t = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
    ws = new WebSocket(t.find((x) => x.type === 'page').webSocketDebuggerUrl);
  } catch { await sleep(250); }
}
if (!ws) {
  console.log(`FAIL [${mode}] Chrome did not open its DevTools port ${port} within 60 s`);
  chrome.kill();
  rmSync(profile, { recursive: true, force: true });
  process.exit(1);
}
await new Promise((r) => { ws.onopen = r; });
let id = 0;
const pending = new Map();
ws.onmessage = (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (x) => (await send('Runtime.evaluate', { expression: x, returnByValue: true, awaitPromise: true })).result?.result?.value;
const until = async (x, ms = 20000) => {
  for (let t = 0; t < ms; t += 250) { if (await ev(x)) return true; await sleep(250); }
  return false;
};
const shot = async (name) => {
  if (!shots) return;
  const r = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(join(shots, `${mode}-${name}.png`), Buffer.from(r.result.data, 'base64'));
};
const text = () => ev('document.body ? document.body.innerText : ""');
// Lines of the page, to tell "team-b/" as a list entry from other text.
const lines = async () => (await text()).split('\n').map((s) => s.trim());

try {
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Page.navigate', { url: `${base}/ui/vault/auth?with=token` });
  const input = `[...document.querySelectorAll('input')].find(i => i.type === 'password' || i.name === 'token' || i.id === 'token')`;
  ok(await until(`!!(${input})`), 'login form with a token field');
  await ev(`(${input}).focus()`);
  await send('Input.insertText', { text: token });
  await sleep(300);
  await ev(`(() => { const b = [...document.querySelectorAll('button')].find(b => b.type === 'submit' || /sign in/i.test(b.innerText)); b.click(); })()`);
  ok(await until(`!location.pathname.includes('/auth')`), 'logged in');
  await shot('1-after-login');

  // Vault 1.15+ uses /secrets/<mount>/kv/list, older UIs /secrets/<mount>/list.
  const roots = [`${base}/ui/vault/secrets/kv/kv/list`, `${base}/ui/vault/secrets/kv/list`];
  let root = '';
  for (const r of roots) {
    await send('Page.navigate', { url: r });
    await sleep(1500);
    const seen = await until(`document.body.innerText.includes('team-a/') || document.body.innerText.includes('team-b/') || /not (authorized|permitted)|permission denied|don.t have access|403/i.test(document.body.innerText)`, 8000);
    if (seen && !(await text()).match(/page not found|route.*not found/i)) { root = r; break; }
  }
  await shot('2-mount-root');
  const rootLines = await lines();
  if (mode === 'proxy') {
    ok(root !== '', `KV mount page loaded (${root})`);
    for (const f of ['team-a/', 'team-b/', 'shared/', 'alice/']) ok(rootLines.includes(f), `root lists ${f}`);
    ok(!rootLines.includes('hidden/') && !rootLines.includes('bob/') && !rootLines.includes('top'), 'root hides hidden/, bob/, top');

    await send('Page.navigate', { url: `${root}/team-b/` });
    await until(`document.body.innerText.includes('config')`, 10000);
    await shot('3-team-b');
    const tb = await lines();
    ok(tb.includes('config'), 'team-b/ lists config');
    ok(!tb.includes('other'), 'team-b/ hides other');
  } else {
    await sleep(3000);
    ok(!rootLines.includes('team-b/'), 'Vault UI without proxy does not list team-b/');
  }
} catch (e) {
  ok(false, `exception: ${e.message}`);
} finally {
  if (failures) console.log((await text().catch(() => '')).slice(0, 1500));
  chrome.kill();
  try { rmSync(profile, { recursive: true, force: true }); } catch {}
}
process.exit(failures ? 1 : 0);
