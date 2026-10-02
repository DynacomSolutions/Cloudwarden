import { env } from 'cloudflare:workers'
import { expect, it, vi } from 'vitest'
import { BASE, registerUser } from './helpers'
import { actor, createOrg, type Mailbox, mailbox } from './org-helpers'

const PW = 'client-derived-hash'

const call = async (
  mb: Mailbox | null,
  path: string,
  body?: unknown,
  form?: Record<string, string>,
) => {
  const { default: app } = await import('../src/index')
  const headers: Record<string, string> = {}
  let payload: string | undefined
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    payload = new URLSearchParams(form).toString()
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  return app.fetch(new Request(`${BASE}${path}`, { method: 'POST', headers, body: payload }), {
    ...env,
    ...(mb ? { EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } : {}),
  })
}

const login = (mb: Mailbox, email: string, device: string, extra = {}) =>
  call(mb, '/identity/connect/token', undefined, {
    grant_type: 'password',
    username: email,
    password: PW,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: `browser ${device}`,
    deviceIdentifier: device,
    ...extra,
  })

it('resends the new device code after proving the master password', async () => {
  const mb = mailbox()
  await registerUser('resend-otp@example.com')
  expect((await login(mb, 'resend-otp@example.com', 'dev-a')).status).toBe(200)
  expect((await login(mb, 'resend-otp@example.com', 'dev-b')).status).toBe(400)
  await vi.waitFor(() => expect(mb.sent.length).toBe(1))

  const body = { email: 'resend-otp@example.com', masterPasswordHash: PW }
  expect(
    (await call(mb, '/api/accounts/resend-new-device-otp', { ...body, masterPasswordHash: 'x' }))
      .status,
  ).toBe(400)
  expect(
    (
      await call(mb, '/api/accounts/resend-new-device-otp', {
        ...body,
        email: 'nobody@example.com',
      })
    ).status,
  ).toBe(400)
  expect((await call(mb, '/api/accounts/resend-new-device-otp', body)).status).toBe(200)
  await vi.waitFor(() => expect(mb.sent.length).toBe(2))
  const fresh = /\b(\d{6})\b/.exec(mb.sent[1]?.text ?? '')?.[1] as string
  expect((await login(mb, 'resend-otp@example.com', 'dev-b', { newDeviceOtp: fresh })).status).toBe(
    200,
  )
})

it('lists no Send events for organisation members who read event logs', async () => {
  const owner = await actor('send-events-owner@example.com')
  const member = await actor('send-events-member@example.com')
  const { id } = await createOrg(owner)
  const path = `/api/organizations/${id}/sends/00000000-0000-0000-0000-000000000000/events`
  expect(await owner.json(path)).toMatchObject({ object: 'list', data: [] })
  expect((await member.call(path)).status).toBe(404)
})

it('answers the Azure Event Grid handshake and refuses anything else', async () => {
  const ok = await call(null, '/api/sends/file/validate/azure', [
    {
      eventType: 'Microsoft.EventGrid.SubscriptionValidationEvent',
      data: { validationCode: 'abc' },
    },
  ])
  expect(await ok.json()).toEqual({ validationResponse: 'abc' })
  expect(
    (await call(null, '/api/sends/file/validate/azure', [{ eventType: 'other' }])).status,
  ).toBe(400)
  expect((await call(null, '/api/sends/file/validate/azure', 'nope')).status).toBe(400)
})
