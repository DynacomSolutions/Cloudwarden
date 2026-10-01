// Cloudwarden: adds an "Instance admin" link to the web vault for admins (docs/admin.md).
// The vault's bearer token is only ever held in this closure. It is never logged, stored or put
// in a URL. Written defensively: if the vault DOM changes, it falls back to a small fixed button.
;(() => {
  const origFetch = window.fetch.bind(window)
  const ID = 'cloudwarden-admin-link'
  let bearer = null
  let isAdmin = false
  let checking = null
  let observer = null

  const apiPath = (url) => {
    try {
      const u = new URL(url, location.href)
      return u.origin === location.origin && u.pathname.startsWith('/api/') ? u.pathname : null
    } catch {
      return null
    }
  }

  const authOf = (input, init) => {
    const h = init?.headers ?? (input instanceof Request ? input.headers : null)
    if (!h) return null
    let v = null
    if (h instanceof Headers) v = h.get('Authorization')
    else if (Array.isArray(h)) v = h.find((p) => /^authorization$/i.test(p?.[0] ?? ''))?.[1]
    else v = h.Authorization ?? h.authorization
    const m = /^Bearer\s+(\S+)$/i.exec(v ?? '')
    return m ? m[1] : null
  }

  const reset = () => {
    // Vault logout ends the admin session too (no-op when there is none).
    if (isAdmin) {
      origFetch('/admin/session/end', { method: 'POST', credentials: 'same-origin' }).catch(
        () => {},
      )
    }
    bearer = null
    isAdmin = false
    observer?.disconnect()
    observer = null
    document.getElementById(ID)?.remove()
  }

  const check = (token) => {
    if (checking) return
    checking = origFetch('/api/cloudwarden/me', {
      headers: { Authorization: `Bearer ${token}` },
      credentials: 'same-origin',
    })
      .then((r) => (r.ok ? r.json() : { isAdmin: false }))
      .then((d) => {
        if (token !== bearer) return
        isAdmin = d?.isAdmin === true
        if (isAdmin) watch()
        else reset()
      })
      .catch(() => {})
      .finally(() => {
        checking = null
        if (bearer && bearer !== token) check(bearer)
      })
  }

  const open = async (e) => {
    e.preventDefault()
    const link = e.currentTarget
    if (!bearer) return
    try {
      const r = await origFetch('/admin/session/exchange', {
        method: 'POST',
        headers: { Authorization: `Bearer ${bearer}` },
        credentials: 'same-origin',
      })
      if (r.status === 204) {
        location.assign('/admin')
        return
      }
    } catch {}
    link.textContent = 'Admin sign-in failed'
  }

  const findNav = () =>
    document.querySelector('nav[aria-label="Side navigation"]') ??
    document.querySelector('bit-side-nav nav, [role="navigation"][aria-label*="navigation" i]')

  const textOf = (el) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim()
  const topItem = (el, nav) => {
    const item = el.closest('bit-nav-item, bit-nav-group, li')
    if (item && nav.contains(item)) return item
    let x = el
    while (
      x.parentElement &&
      x.parentElement !== nav &&
      x.parentElement.querySelectorAll('a[href]').length < 2
    )
      x = x.parentElement
    return x
  }

  // Builds the admin entry by cloning the vault's own Reports item (structure, classes, icon
  // wrapper), so it looks and hovers like its neighbours. Returns [item, anchor point] or null.
  const navItem = (nav) => {
    const links = [...nav.querySelectorAll('a[href]')]
    const reports =
      links.find((l) => /#\/reports\/?$/.test(l.getAttribute('href') ?? '')) ??
      links.find((l) => textOf(l) === 'Reports')
    if (!reports) return null
    const reportsItem = topItem(reports, nav)
    const settingsItem = [...(reportsItem.parentElement?.children ?? [])].find(
      (el) =>
        el !== reportsItem &&
        (el.querySelector('a[href*="settings"]') || /^Settings\b/.test(textOf(el))),
    )
    const item = reportsItem.cloneNode(true)
    for (const el of [item, ...item.querySelectorAll('*')]) {
      el.removeAttribute('id')
      el.removeAttribute('aria-current')
      for (const attr of [...el.attributes])
        if (/^(ng-reflect-|routerlink)/i.test(attr.name)) el.removeAttribute(attr.name)
      for (const cls of [...el.classList]) if (/(^|-)active$/.test(cls)) el.classList.remove(cls)
    }
    const a = item.matches('a[href]') ? item : item.querySelector('a[href]')
    a.setAttribute('href', '/admin')
    a.addEventListener('click', open)
    const icon = item.querySelector('[class*="bwi-"]')
    if (icon) {
      for (const cls of [...icon.classList])
        if (/^bwi-/.test(cls) && cls !== 'bwi-fw') icon.classList.remove(cls)
      icon.classList.add('bwi-wrench')
    }
    const walker = document.createTreeWalker(item, NodeFilter.SHOW_TEXT)
    let label = null
    for (let n = walker.nextNode(); n; n = walker.nextNode())
      if (n.nodeValue.trim() === textOf(reports)) label = n
    if (label) label.nodeValue = label.nodeValue.replace(textOf(reports), 'Instance admin')
    else a.textContent = 'Instance admin'
    a.setAttribute('title', 'Instance admin')
    item.id = ID
    return [item, settingsItem ?? reportsItem]
  }

  const render = () => {
    if (!isAdmin) return
    const existing = document.getElementById(ID)
    if (existing && existing.dataset.fallback !== 'true') return
    const nav = findNav()
    const built = nav ? navItem(nav) : null
    if (existing) {
      // Keep a correctly placed item; replace the fallback button once the nav is ready.
      if (!built) return
      existing.remove()
    }
    if (built) {
      built[1].after(built[0])
      return
    }
    const a = document.createElement('a')
    a.id = ID
    a.dataset.fallback = 'true'
    a.href = '/admin'
    a.textContent = 'Instance admin'
    a.addEventListener('click', open)
    Object.assign(a.style, {
      position: 'fixed',
      left: '12px',
      bottom: '12px',
      zIndex: '1000',
      padding: '6px 12px',
      borderRadius: '6px',
      background: '#175ddc',
      color: '#fff',
      font: '600 13px sans-serif',
      textDecoration: 'none',
    })
    document.body.appendChild(a)
  }

  const watch = () => {
    render()
    if (observer) return
    observer = new MutationObserver(() => {
      if (isAdmin) render()
    })
    observer.observe(document.body, { childList: true, subtree: true })
  }

  window.fetch = (input, init) => {
    const url = input instanceof Request ? input.url : String(input)
    const path = apiPath(url)
    const token = path ? authOf(input, init) : null
    const p = origFetch(input, init)
    if (!path) return p
    if (token && token !== bearer) {
      bearer = token
      check(token)
    }
    return p.then((r) => {
      if (r.status === 401 && token && token === bearer) reset()
      return r
    })
  }

  window.addEventListener('hashchange', () => {
    if (/^#\/(login|lock|logout)/.test(location.hash)) reset()
  })
})()
