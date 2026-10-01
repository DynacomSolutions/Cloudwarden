import { html, raw } from 'hono/html'

export interface Nav {
  subject: string
  csrf: string
}

const CSS = `
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#16181d;--muted:#5d6572;--line:#e2e5ea;--accent:#2457d6;--accent-fg:#fff;--danger:#c62828;--ok:#1b7f3b;--warn:#a15c00}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e8eaee;--muted:#9aa3b2;--line:#2a2f3a;--accent:#6b93ff;--accent-fg:#0b0d12;--danger:#ff6b6b;--ok:#4cc27a;--warn:#e0a040}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{background:var(--card);border-bottom:1px solid var(--line)}
.bar{max-width:1000px;margin:0 auto;padding:12px 16px;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center}
.brand{font-weight:700;margin-right:auto}
nav{display:flex;flex-wrap:wrap;gap:4px 14px}
a{color:var(--accent)}
main{max-width:1000px;margin:0 auto;padding:16px}
h1{font-size:1.4rem;margin:8px 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat b{display:block;font-size:1.7rem}
.muted{color:var(--muted);font-size:.9rem}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}
input[type=email],input[type=password],input[type=text]{width:100%;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
button{font:inherit;padding:8px 14px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
a.btn{display:inline-block;padding:8px 14px;border-radius:6px;border:1px solid var(--line);color:var(--fg);text-decoration:none}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
button.danger{color:var(--danger);border-color:var(--danger)}
form.inline{display:inline}
.actions{display:flex;flex-wrap:wrap;gap:6px}
.tag{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--line);font-size:.8rem}
.ok{color:var(--ok)}.bad{color:var(--danger)}.warn{color:var(--warn)}
.flash{border-left:4px solid var(--accent);background:var(--card);padding:10px 14px;margin-bottom:16px;border-radius:6px}
.narrow{max-width:420px;margin:48px auto}
label{display:block;margin:12px 0 6px;font-weight:600}
`

export function layout(title: string, nonce: string, body: unknown, nav?: Nav) {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${title} - Cloudwarden admin</title>
<style nonce="${nonce}">${raw(CSS)}</style>
</head>
<body>
<header><div class="bar">
<span class="brand">Cloudwarden admin</span>
${
  nav
    ? html`<nav>
<a href="/admin">Dashboard</a><a href="/admin/users">Users</a><a href="/admin/orgs">Organisations</a><a href="/admin/diagnostics">Diagnostics</a>
</nav>
<form class="inline" method="post" action="/admin/logout"><input type="hidden" name="csrf" value="${nav.csrf}"><button type="submit">Sign out</button></form>`
    : ''
}
</div></header>
<main>${body}</main>
</body>
</html>`
}

export const flash = (msg: string | undefined) =>
  msg ? html`<div class="flash" role="status">${msg}</div>` : ''

export const loginPage = (nonce: string, error?: string) =>
  layout(
    'Sign in',
    nonce,
    html`<div class="narrow">
${error ? html`<div class="flash" role="alert">${error}</div>` : ''}
<div class="card"><h1>Email me a sign-in link</h1>
<form method="post" action="/admin/login/magic">
<label for="email">Email address</label>
<input id="email" type="email" name="email" autocomplete="email" required>
<p><button class="primary" type="submit">Send link</button></p>
</form></div>
<div class="card"><h1>Admin token</h1>
<form method="post" action="/admin/login/token">
<label for="token">Token</label>
<input id="token" type="password" name="token" autocomplete="current-password" required>
<p><button class="primary" type="submit">Sign in</button></p>
</form></div></div>`,
  )

export const linkSentPage = (nonce: string) =>
  layout(
    'Check your email',
    nonce,
    html`<div class="narrow card"><h1>Check your email</h1>
<p>If that address is an admin, a link was sent. It works once and expires in 15 minutes.</p>
<p><a href="/admin">Back</a></p></div>`,
  )

export const magicConfirmPage = (nonce: string, token: string) =>
  layout(
    'Confirm sign-in',
    nonce,
    html`<div class="narrow card"><h1>Confirm sign-in</h1>
<p>Press the button to finish signing in to the admin area.</p>
<form method="post" action="/admin/magic"><input type="hidden" name="token" value="${token}">
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
) =>
  layout(
    title,
    nonce,
    html`<div class="narrow card"><h1>${title}</h1><p>${text}</p>
<form method="post" action="${action}"><input type="hidden" name="csrf" value="${nav.csrf}">
<div class="actions"><button class="danger" type="submit">Delete permanently</button><a class="btn" href="${back}">Cancel</a></div></form></div>`,
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
      html`<tr><th>${k}</th><td>${typeof v === 'boolean' ? (v ? html`<span class="ok">yes</span>` : html`<span class="muted">no</span>`) : String(v)}</td></tr>`,
  )}</tbody></table></div>`

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
