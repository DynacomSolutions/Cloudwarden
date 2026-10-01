import { html, raw } from 'hono/html'

export interface Nav {
  subject: string
  csrf: string
}

// Sidebar colours mirror the web vault 2026.9 nav tokens (--color-nav-bg-primary, its hover and
// strong variants) in light and dark mode, so the admin area looks like part of the vault.
const CSS = `
:root{color-scheme:light dark;--bg:#f3f6f9;--card:#fff;--fg:#1b2029;--muted:#5b6574;--line:#e3e7ed;--hover:#eef3fb;--zebra:#f9fafc;--accent:#175ddc;--accent-hover:#1252c2;--accent-fg:#fff;--danger:#c0262d;--danger-hover:#a51f25;--ok:#1b7f3b;--okbg:#e4f5ea;--badbg:#fbe7e8;--offbg:#eceff3;--side:#0d43af;--side-fg:#fff;--side-hover:rgba(0,0,0,.2);--side-active:#0c3276;--side-line:rgba(255,255,255,.25);--input:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#10141c;--card:#1a202b;--fg:#e6e9ef;--muted:#9aa5b8;--line:#2b3342;--hover:#222b3a;--zebra:#1e2531;--accent:#6c9bff;--accent-hover:#8fb2ff;--accent-fg:#0b1020;--danger:#e0575d;--danger-hover:#f07a80;--ok:#4cc27a;--okbg:#14301f;--badbg:#3a1a1d;--offbg:#252d3b;--side:#1d293d;--side-fg:#fff;--side-hover:rgba(132,150,176,.2);--side-active:#45556c;--side-line:rgba(255,255,255,.25);--input:#10141c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent)}
.shell{display:flex;min-height:100vh}
.side{width:230px;flex:none;background:var(--side);color:var(--side-fg);display:flex;flex-direction:column;padding:16px 12px}
.logo{font-size:20px;font-weight:700;color:#fff;padding:6px 12px 20px;letter-spacing:-.2px;line-height:1.2}
.logo span{color:#fff;font-weight:400}
.side nav{display:flex;flex-direction:column;gap:2px}
.side nav a{color:var(--side-fg);text-decoration:none;padding:9px 12px;border-radius:6px;font-weight:500}
.side nav a:hover{background:var(--side-hover);color:var(--side-fg)}
.side nav a.back{margin-top:12px;border-top:1px solid var(--side-line);border-radius:0 0 6px 6px}
.side nav a.active{background:var(--side-active);color:var(--side-fg)}
.content{flex:1;min-width:0;display:flex;flex-direction:column}
.top{background:var(--card);border-bottom:1px solid var(--line);padding:10px 24px;display:flex;align-items:center;gap:12px;min-height:56px}
.top .title{font-weight:600;font-size:16px;margin-right:auto}
.top .who{color:var(--muted);font-size:13px}
main{padding:24px;max-width:1100px;width:100%}
h1{font-size:22px;font-weight:600;margin:0 0 16px}
h2{font-size:16px;font-weight:600;margin:0 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px}
.card.stat{margin:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.stat b{display:block;font-size:26px;font-weight:600;color:var(--accent)}
.muted{color:var(--muted);font-size:13px}
.wrap{overflow-x:auto;padding:0}
.card.wrap>h2{padding:16px 16px 0}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap;background:var(--zebra)}
tbody tr:nth-child(even){background:var(--zebra)}
tbody tr:hover{background:var(--hover)}
tbody tr:last-child td{border-bottom:0}
input[type=email],input[type=password],input[type=text]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:6px;background:var(--input);color:var(--fg);font:inherit}
input:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
button,a.btn{font:inherit;font-weight:600;padding:7px 14px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;text-decoration:none;display:inline-block;line-height:1.4}
button:hover,a.btn:hover{background:var(--hover)}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
button.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
button.danger,a.btn.danger{background:var(--danger);color:#fff;border-color:var(--danger)}
button.danger:hover,a.btn.danger:hover{background:var(--danger-hover);border-color:var(--danger-hover)}
button.sm,a.btn.sm{padding:3px 10px;font-size:12px}
form.inline{display:inline}
.actions{display:flex;flex-wrap:wrap;gap:6px}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.bad{background:var(--badbg);color:var(--danger)}
.badge.off{background:var(--offbg);color:var(--muted)}
.flash{border:1px solid var(--line);border-left:4px solid var(--accent);background:var(--card);padding:10px 14px;margin-bottom:16px;border-radius:8px}
.narrow{max-width:440px;margin:24px auto}
label{display:block;margin:12px 0 6px;font-weight:600}
.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.auth .box{width:100%;max-width:420px}
.auth .logo{color:var(--accent);text-align:center;font-size:24px;padding:0 0 16px}
.auth .logo span{color:var(--fg)}
.auth .card{padding:24px}
.auth h1{font-size:18px}
@media(max-width:760px){
.shell{flex-direction:column}
.side{width:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:4px 12px;padding:8px 12px}
.logo{padding:4px 8px}
.side nav{flex-direction:row;flex-wrap:wrap}
.top{padding:8px 16px}
main{padding:16px}
}
`

const NAV_ITEMS: [string, string][] = [
  ['Dashboard', '/admin'],
  ['Users', '/admin/users'],
  ['Organisations', '/admin/orgs'],
  ['Diagnostics', '/admin/diagnostics'],
]

const logo = html`<div class="logo">Cloudwarden <span>Admin</span></div>`

export function layout(title: string, nonce: string, body: unknown, nav?: Nav) {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${title} - Cloudwarden Admin</title>
<style nonce="${nonce}">${raw(CSS)}</style>
</head>
<body>
${
  nav
    ? html`<div class="shell">
<aside class="side">${logo}<nav>${NAV_ITEMS.map(([label, href]) => html`<a href="${href}"${label === title ? raw(' class="active" aria-current="page"') : ''}>${label}</a>`)}<a class="back" href="/#/vault">Back to vault</a></nav></aside>
<div class="content">
<header class="top"><span class="title">${title}</span><span class="who">Signed in as ${nav.subject}</span>
<form class="inline" method="post" action="/admin/logout"><input type="hidden" name="csrf" value="${nav.csrf}"><button type="submit">Sign out</button></form></header>
<main>${body}</main>
</div></div>`
    : html`<div class="auth"><div class="box">${logo}${body}</div></div>`
}
</body>
</html>`
}

export const flash = (msg: string | undefined) =>
  msg ? html`<div class="flash" role="status">${msg}</div>` : ''

export const loginPage = (nonce: string, error?: string) =>
  layout(
    'Sign in',
    nonce,
    html`<div>
${error ? html`<div class="flash" role="alert">${error}</div>` : ''}
<div class="card"><h1>Recovery sign-in</h1>
<p class="muted">For when no admin can sign in to the web vault. Normal admin access is through the vault: <a href="/#/login">sign in</a> and choose Instance admin.</p></div>
<div class="card"><h1>Email me a sign-in link</h1>
<form method="post" action="/admin/recovery/magic-link">
<label for="email">Email address</label>
<input id="email" type="email" name="email" autocomplete="email" required>
<p><button class="primary" type="submit">Send link</button></p>
</form></div>
<div class="card"><h1>Admin token</h1>
<form method="post" action="/admin/recovery/token">
<label for="token">Token</label>
<input id="token" type="password" name="token" autocomplete="current-password" required>
<p><button class="primary" type="submit">Sign in</button></p>
</form></div></div>`,
  )

export const landingPage = (nonce: string) =>
  layout(
    'Sign in',
    nonce,
    html`<div class="card"><h1>Admin sign-in</h1>
<p>Instance admins sign in with their normal vault account. Sign in to the web vault, then choose <b>Instance admin</b> in the side navigation.</p>
<p><a class="btn" href="/#/login">Go to the web vault</a></p>
<p class="muted">Locked out? Use <a href="/admin/recovery">recovery sign-in</a>.</p></div>`,
  )

export const linkSentPage = (nonce: string) =>
  layout(
    'Check your email',
    nonce,
    html`<div class="card"><h1>Check your email</h1>
<p>If that address is an admin, a link was sent. It works once and expires in 15 minutes.</p>
<p><a href="/admin/recovery">Back</a></p></div>`,
  )

export const magicConfirmPage = (nonce: string, token: string) =>
  layout(
    'Confirm sign-in',
    nonce,
    html`<div class="card"><h1>Confirm sign-in</h1>
<p>Press the button to finish signing in to the admin area.</p>
<form method="post" action="/admin/recovery/magic"><input type="hidden" name="token" value="${token}">
<button class="primary" type="submit">Sign in</button></form></div>`,
  )

export const messagePage = (nonce: string, title: string, text: string, nav?: Nav) =>
  layout(
    title,
    nonce,
    html`<div class="narrow card"><h1>${title}</h1><p>${text}</p><p><a href="/admin">Back</a></p></div>`,
    nav,
  )

export const confirmPage = (
  nonce: string,
  nav: Nav,
  title: string,
  text: string,
  action: string,
  back: string,
  button = 'Delete permanently',
) =>
  layout(
    title,
    nonce,
    html`<div class="narrow card"><h1>${title}</h1><p>${text}</p>
<form method="post" action="${action}"><input type="hidden" name="csrf" value="${nav.csrf}">
<div class="actions"><button class="danger" type="submit">${button}</button><a class="btn" href="${back}">Cancel</a></div></form></div>`,
    nav,
  )

export interface Stat {
  label: string
  value: string | number
}

export const statsGrid = (stats: Stat[]) =>
  html`<div class="grid">${stats.map((s) => html`<div class="card stat"><b>${s.value}</b><span class="muted">${s.label}</span></div>`)}</div>`

export const kvTable = (rows: [string, string | number | boolean][]) =>
  html`<div class="card wrap"><table><tbody>${rows.map(
    ([k, v]) =>
      html`<tr><th>${k}</th><td>${typeof v === 'boolean' ? (v ? html`<span class="badge ok">yes</span>` : html`<span class="badge off">no</span>`) : String(v)}</td></tr>`,
  )}</tbody></table></div>`

export const badge = (kind: 'ok' | 'bad' | 'off', text: string) =>
  html`<span class="badge ${kind}">${text}</span>`

export const fmtDate = (ms: number | null | undefined) =>
  ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 16) : 'never'

export const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${units[i]}`
}
