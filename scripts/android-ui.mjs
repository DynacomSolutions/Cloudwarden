// Minimal Android UI driver over adb and `uiautomator dump`, for scripts/capture-android-traffic.mjs
// (TASKS #388). Elements are found by their visible text or content description.
import { spawnSync } from 'node:child_process'

/** Resolves the adb binary: $ANDROID_HOME or $ANDROID_SDK_ROOT platform-tools, else the PATH. */
function adbBinary() {
  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT
  return sdk ? `${sdk}/platform-tools/adb` : 'adb'
}

export function createDevice(serial) {
  const adbBin = adbBinary()
  const adb = (...args) =>
    spawnSync(adbBin, ['-s', serial, ...args], { encoding: 'utf8', maxBuffer: 1 << 26 })
  const shell = (cmd) => adb('shell', cmd).stdout
  const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms))
  const attr = (node, name) => node.match(new RegExp(` ${name}="([^"]*)"`))?.[1] ?? ''
  const unescapeXml = (s) =>
    s
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&#10;/g, '\n')
      .replace(/&amp;/g, '&')

  /** The current screen as a list of nodes with text, description, bounds and centre. */
  const nodes = () => {
    adb('shell', 'uiautomator dump /sdcard/window.xml')
    const xml = adb('shell', 'cat /sdcard/window.xml').stdout
    return [...xml.matchAll(/<node [^>]*>/g)].map(([n]) => {
      const b = attr(n, 'bounds')
        .match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/)
        ?.slice(1)
        .map(Number) ?? [0, 0, 0, 0]
      return {
        text: unescapeXml(attr(n, 'text')),
        desc: unescapeXml(attr(n, 'content-desc')),
        editable: attr(n, 'class').includes('EditText'),
        bounds: b,
        cx: (b[0] + b[2]) >> 1,
        cy: (b[1] + b[3]) >> 1,
      }
    })
  }
  const matches = (n, query, exact) => {
    const test = (s) => (exact ? s === query : s.includes(query))
    return test(n.text) || test(n.desc)
  }
  const find = (query, { exact = false } = {}) => nodes().find((n) => matches(n, query, exact))

  const device = {
    adb,
    shell,
    sleep,
    nodes,
    find,
    /** Waits for an element; the error carries what was on screen. */
    async wait(query, { timeout = 30000, exact = false } = {}) {
      const end = Date.now() + timeout
      while (Date.now() < end) {
        const n = find(query, { exact })
        if (n) return n
        await sleep(600)
      }
      const seen = nodes()
        .filter((n) => n.text || n.desc)
        .map((n) => n.text || n.desc)
      throw new Error(`timed out waiting for "${query}"; on screen: ${JSON.stringify(seen)}`)
    },
    tapXY: (x, y) => adb('shell', `input tap ${x} ${y}`),
    async tap(query, opts) {
      const n = await device.wait(query, opts)
      device.tapXY(n.cx, n.cy)
      await sleep(600)
    },
    /** True when the element shows within `timeout` ms (it is not an error when it does not). */
    async appears(query, { timeout = 3000, exact = false } = {}) {
      try {
        await device.wait(query, { timeout, exact })
        return true
      } catch {
        return false
      }
    },
    key: (code) => adb('shell', `input keyevent ${code}`),
    swipeUp: () => adb('shell', 'input swipe 540 1800 540 700 300'),
    hideKeyboard() {
      if (/mInputShown=true/.test(shell('dumpsys input_method'))) device.key(4)
    },
    /** Replaces the content of the text field labelled `label`. */
    async fill(label, value, { exact = false } = {}) {
      let all = nodes()
      let lab = all.find((n) => matches(n, label, exact) && !n.editable)
      for (let i = 0; !lab && i < 20; i++) {
        await sleep(700)
        all = nodes()
        lab = all.find((n) => matches(n, label, exact) && !n.editable)
      }
      if (!lab)
        throw new Error(
          `no field labelled "${label}"; on screen: ${JSON.stringify(device.screen())}`,
        )
      const box = all
        .filter((n) => n.editable)
        .sort((a, b) => Math.abs(a.cy - lab.cy) - Math.abs(b.cy - lab.cy))[0]
      if (!box) throw new Error(`no text field near "${label}"`)
      device.tapXY(box.cx, box.cy)
      await sleep(400)
      adb('shell', 'input keycombination 113 29') // select all
      device.key(67)
      adb('shell', `input text '${value.replace(/ /g, '%s')}'`)
      await sleep(300)
      device.hideKeyboard()
      await sleep(400)
    },
    /** Names of everything on screen, for debugging. */
    screen: () =>
      nodes()
        .filter((n) => n.text || n.desc)
        .map((n) => n.text || n.desc),
  }
  return device
}
