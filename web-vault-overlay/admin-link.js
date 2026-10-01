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

  const render = () => {
    if (!isAdmin || document.getElementById(ID)) return
    const a = document.createElement('a')
    a.id = ID
    a.href = '/admin'
    a.textContent = 'Instance admin'
    a.addEventListener('click', open)
    const nav = findNav()
    const sibling = nav ? [...nav.querySelectorAll('a[href]')].pop() : null
    if (nav && sibling) {
      a.className = sibling.className
      let item = sibling
      while (item.parentElement && item.parentElement !== nav) item = item.parentElement
      let el = a
      if (item !== sibling) {
        // Mirror the list item wrapper so spacing matches the neighbouring entries.
        el = document.createElement(item.tagName === 'LI' ? 'li' : 'div')
        el.className = item.className
        el.appendChild(a)
        a.removeAttribute('id')
        el.id = ID
      }
      item.after(el)
      return
    }
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
      if (!isAdmin) return
      const el = document.getElementById(ID)
      // Move from the fallback button into the nav once the nav appears.
      if (el && el.style.position === 'fixed' && findNav()) el.remove()
      render()
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
