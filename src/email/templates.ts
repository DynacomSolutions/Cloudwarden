import type { EmailMessage } from './index'

type Template = Omit<EmailMessage, 'to'>

const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`)

const shell = (heading: string, paragraphs: string[], link?: { url: string; label: string }) => {
  const body = paragraphs.map((p) => `<p style="margin:0 0 16px">${esc(p)}</p>`).join('')
  const button = link
    ? `<p style="margin:24px 0"><a href="${esc(link.url)}" style="background:#2563eb;color:#ffffff;padding:12px 20px;border-radius:6px;text-decoration:none;display:inline-block">${esc(link.label)}</a></p><p style="margin:0 0 16px;font-size:13px;color:#555">If the button does not work, copy this address into your browser:<br>${esc(link.url)}</p>`
    : ''
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#f4f4f5;font-family:system-ui,sans-serif;color:#18181b"><div style="max-width:480px;margin:0 auto;background:#ffffff;padding:24px;border-radius:8px"><h1 style="font-size:20px;margin:0 0 16px">${esc(heading)}</h1>${body}${button}</div></body></html>`
}

const plain = (paragraphs: string[], link?: string) =>
  [...paragraphs, ...(link ? [link] : [])].join('\n\n')

export function magicLinkEmail(url: string, minutes: number): Template {
  const lines = [
    'Use the link below to sign in to the Cloudwarden admin area.',
    `It works once and expires in ${minutes} minutes. If you did not ask for it, ignore this message.`,
  ]
  return {
    subject: 'Your Cloudwarden admin sign-in link',
    text: plain(lines, url),
    html: shell('Admin sign-in', lines, { url, label: 'Continue to sign in' }),
  }
}

export function inviteEmail(registerUrl: string): Template {
  const lines = [
    'You have been invited to create an account on this Cloudwarden server.',
    'Choose the link below to register with this email address.',
  ]
  return {
    subject: 'You are invited to Cloudwarden',
    text: plain(lines, registerUrl),
    html: shell('You are invited', lines, { url: registerUrl, label: 'Create your account' }),
  }
}

export function genericEmail(subject: string, paragraphs: string[]): Template {
  return { subject, text: plain(paragraphs), html: shell(subject, paragraphs) }
}

export function twoFactorCodeEmail(code: string, minutes: number): Template {
  const lines = [
    `Your Cloudwarden verification code is ${code}.`,
    `It expires in ${minutes} minutes. If you did not request it, you can ignore this message.`,
  ]
  return {
    subject: 'Your Cloudwarden verification code',
    text: plain(lines),
    html: shell('Verification code', lines),
  }
}

export function orgInviteEmail(orgName: string, acceptUrl: string): Template {
  const lines = [
    `You have been invited to join the organization ${orgName} on this Cloudwarden server.`,
    'Choose the link below to accept. The link expires in five days.',
  ]
  return {
    subject: `Join ${orgName}`,
    text: plain(lines, acceptUrl),
    html: shell('Join an organization', lines, { url: acceptUrl, label: 'Join organization' }),
  }
}

export function emergencyInviteEmail(grantorName: string, acceptUrl: string): Template {
  const lines = [
    `${grantorName} has invited you to become an emergency contact on this Cloudwarden server.`,
    'Choose the link below to accept. The link expires in five days.',
  ]
  return {
    subject: 'Emergency access invitation',
    text: plain(lines, acceptUrl),
    html: shell('Emergency access invitation', lines, {
      url: acceptUrl,
      label: 'Accept invitation',
    }),
  }
}
