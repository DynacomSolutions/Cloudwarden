// A small five-field cron evaluator (minute hour day-of-month month day-of-week, UTC) for rotation
// schedules. Supports `*`, lists, ranges and steps (`*/15`, `1-5`, `10-30/5`) and numeric names only.

interface Field {
  any: boolean
  values: Set<number>
}

const BOUNDS: [number, number][] = [
  [0, 59],
  [0, 23],
  [1, 31],
  [1, 12],
  [0, 7],
]

function parseField(text: string, min: number, max: number): Field | null {
  const values = new Set<number>()
  let any = false
  for (const part of text.split(',')) {
    const [range = '', stepText] = part.split('/')
    const step = stepText === undefined ? 1 : Number(stepText)
    if (!Number.isInteger(step) || step < 1 || part === '') return null
    let lo: number
    let hi: number
    if (range === '*') {
      lo = min
      hi = max
      if (stepText === undefined) any = true
    } else if (/^\d+$/.test(range)) {
      lo = Number(range)
      hi = stepText === undefined ? lo : max
    } else if (/^\d+-\d+$/.test(range)) {
      const [a = '', b = ''] = range.split('-')
      lo = Number(a)
      hi = Number(b)
    } else {
      return null
    }
    if (lo < min || hi > max || lo > hi) return null
    for (let v = lo; v <= hi; v += step) values.add(v)
  }
  return { any, values }
}

export interface Cron {
  fields: Field[]
}

/** Parses a five-field expression; null when it is not valid. */
export function parseCron(expression: string): Cron | null {
  const parts = expression.trim().split(/\s+/)
  if (parts.length !== 5) return null
  const fields: Field[] = []
  for (const [i, part] of parts.entries()) {
    const [min, max] = BOUNDS[i] as [number, number]
    const f = parseField(part, min, max)
    if (!f) return null
    fields.push(f)
  }
  // Day of week 7 is Sunday, like 0.
  const dow = fields[4] as Field
  if (dow.values.has(7)) dow.values.add(0)
  return { fields }
}

function dayMatches(cron: Cron, d: Date): boolean {
  const [, , dom, month, dow] = cron.fields as [Field, Field, Field, Field, Field]
  if (!month.values.has(d.getUTCMonth() + 1)) return false
  const domOk = dom.values.has(d.getUTCDate())
  const dowOk = dow.values.has(d.getUTCDay())
  // Like classic cron: when both day fields are restricted, either may match.
  if (!dom.any && !dow.any) return domOk || dowOk
  return domOk && dowOk
}

/** The first matching minute strictly after `after` (epoch ms), or null within five years. */
export function nextRun(expression: string, after: number): number | null {
  const cron = parseCron(expression)
  if (!cron) return null
  const [minute, hour, , month] = cron.fields as [Field, Field, Field, Field, Field]
  const t = new Date(Math.floor(after / 60_000) * 60_000 + 60_000)
  const limit = after + 5 * 366 * 24 * 3_600_000
  while (t.getTime() <= limit) {
    if (!month.values.has(t.getUTCMonth() + 1)) {
      t.setUTCMonth(t.getUTCMonth() + 1, 1)
      t.setUTCHours(0, 0, 0, 0)
    } else if (!dayMatches(cron, t)) {
      t.setUTCDate(t.getUTCDate() + 1)
      t.setUTCHours(0, 0, 0, 0)
    } else if (!hour.values.has(t.getUTCHours())) {
      t.setUTCHours(t.getUTCHours() + 1, 0, 0, 0)
    } else if (!minute.values.has(t.getUTCMinutes())) {
      t.setUTCMinutes(t.getUTCMinutes() + 1, 0, 0)
    } else {
      return t.getTime()
    }
  }
  return null
}
