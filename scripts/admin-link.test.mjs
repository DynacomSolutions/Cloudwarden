import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { Window } from 'happy-dom'

const SRC = readFileSync(new URL('../web-vault-overlay/admin-link.js', import.meta.url), 'utf8')

// Minimal shape of the 2026.9 vault side navigation.
const item = (href, text, icon) =>
  `<bit-nav-item class="item-host"><div class="tw-flex hover:tw-bg-x"><a class="nav-link tw-p-2 active" href="${href}" aria-current="page" aria-label="${text}" title="${text}" aria-describedby="tip-${text}" ng-reflect-text="${text}"><span class="sr" title="${text}">${text}</span><i class="bwi bwi-fw ${icon}"></i><span class="label">${text}</span></a></div></bit-nav-item>`
const NAV = `<nav aria-label="Side navigation"><div class="list">
${item('#/vault', 'Vaults', 'bwi-vault')}
${item('#/sends', 'Send', 'bwi-send')}
${item('#/reports', 'Reports', 'bwi-chart')}
<bit-nav-group class="group-host"><button class="tw-flex">Settings</button><div>${item('#/settings/account', 'My account', 'bwi-user')}</div></bit-nav-group>
</div><h2>More from Bitwarden</h2><a href="https://example.com">Other</a></nav>`

async function setup(isAdmin = true) {
  const window = new Window({ url: 'https://vault.example.com/#/vault' })
  const calls = []
  window.fetch = async (input, init) => {
    const url = String(input?.url ?? input)
    calls.push({ url, init })
    if (url.endsWith('/api/cloudwarden/me'))
      return new window.Response(JSON.stringify({ isAdmin }), { status: 200 })
    return new window.Response('{}', { status: 200 })
  }
  window.document.body.innerHTML = NAV
  window.eval(SRC)
  await window.fetch('/api/sync', { headers: { Authorization: 'Bearer tok' } })
  await new Promise((r) => setTimeout(r, 20))
  await window.happyDOM.waitUntilComplete()
  return { window, doc: window.document, calls }
}

test('inserts a cloned nav item after Settings with the same structure', async () => {
  const { doc } = await setup()
  const list = doc.querySelector('.list')
  const kids = [...list.children]
  const idx = kids.findIndex((k) => k.id === 'cloudwarden-admin-link')
  assert.ok(idx > 0, 'item inserted')
  assert.equal(kids[idx - 1].tagName.toLowerCase(), 'bit-nav-group')
  const el = kids[idx]
  assert.equal(el.tagName.toLowerCase(), 'bit-nav-item')
  assert.equal(el.className, 'item-host')
  const a = el.querySelector('a')
  assert.equal(a.getAttribute('href'), '/admin')
  assert.equal(a.className, 'nav-link tw-p-2')
  assert.equal(a.getAttribute('aria-current'), null)
  assert.equal(el.querySelector('.label').textContent, 'Instance admin')
  assert.equal(el.querySelector('i').className, 'bwi bwi-fw bwi-wrench')
  assert.equal(a.getAttribute('aria-label'), 'Instance admin')
  assert.equal(a.getAttribute('title'), 'Instance admin')
  assert.ok(!el.outerHTML.includes('Reports'), 'no Reports text or attribute left in the clone')
  assert.equal(doc.querySelectorAll('#cloudwarden-admin-link').length, 1)
})

test('falls back to after Reports without Settings, and re-inserts after a re-render', async () => {
  const { window, doc } = await setup()
  doc.querySelector('bit-nav-group').remove()
  doc.getElementById('cloudwarden-admin-link').remove()
  await new Promise((r) => setTimeout(r, 20))
  const kids = [...doc.querySelector('.list').children]
  const idx = kids.findIndex((k) => k.id === 'cloudwarden-admin-link')
  assert.equal(kids[idx - 1].querySelector('a').getAttribute('href'), '#/reports')
  // Angular replaces the whole list: exactly one item comes back.
  doc.querySelector('.list').outerHTML =
    `<div class="list">${item('#/reports', 'Reports', 'bwi-chart')}</div>`
  await new Promise((r) => setTimeout(r, 20))
  assert.equal(doc.querySelectorAll('#cloudwarden-admin-link').length, 1)
  window.close()
})

test('adds nothing for non-admins', async () => {
  const { doc } = await setup(false)
  assert.equal(doc.getElementById('cloudwarden-admin-link'), null)
})
