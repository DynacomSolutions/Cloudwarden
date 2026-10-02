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

export function genericEmail(rawSubject: string, paragraphs: string[]): Template {
  // The subject becomes a header: no line breaks, bounded length.
  const subject = rawSubject.replace(/[\r\n]+/g, ' ').slice(0, 200)
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

export function sendCodeEmail(code: string, minutes: number): Template {
  const lines = [
    `Your Cloudwarden verification code to view a Send is ${code}.`,
    `It expires in ${minutes} minutes. If you did not request it, you can ignore this message.`,
  ]
  return {
    subject: 'Your verification code to view a Send',
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

// Account notices (TASKS #261) -------------------------------------------------------------

const ignoreLine = 'If this was not you, change your master password and review your devices.'

export function passwordHintEmail(hint: string | null): Template {
  const lines = hint
    ? [
        'You asked for your master password hint. It is shown below.',
        `Your hint: ${hint}`,
        'If you did not ask for this, you can ignore this message. Your master password was not changed.',
      ]
    : [
        'You asked for your master password hint, but this account has no hint set.',
        'Your master password cannot be recovered. If you did not ask for this, you can ignore this message.',
      ]
  return {
    subject: 'Your master password hint',
    text: plain(lines),
    html: shell('Master password hint', lines),
  }
}

export function verifyEmailEmail(url: string): Template {
  const lines = [
    'Confirm that this email address belongs to your Cloudwarden account.',
    'Choose the link below. It expires in five days.',
  ]
  return {
    subject: 'Verify your email address',
    text: plain(lines, url),
    html: shell('Verify your email address', lines, { url, label: 'Verify email address' }),
  }
}

export function otpEmail(kind: 'new-device' | 'verification', code: string, minutes: number) {
  const lines =
    kind === 'new-device'
      ? [
          `Your Cloudwarden new device verification code is ${code}.`,
          `It expires in ${minutes} minutes. If you did not try to log in, change your master password.`,
        ]
      : [
          `Your Cloudwarden verification code is ${code}.`,
          `It expires in ${minutes} minutes. If you did not request it, you can ignore this message.`,
        ]
  const subject = kind === 'new-device' ? 'New device verification code' : 'Your verification code'
  return { subject, text: plain(lines), html: shell(subject, lines) } satisfies Template
}

export interface NewDeviceInfo {
  deviceName: string
  deviceType: string
  ip: string | null
  at: Date
}

export function newDeviceLoginEmail(info: NewDeviceInfo): Template {
  const lines = [
    'A new device logged in to your Cloudwarden account.',
    `Device: ${info.deviceName} (${info.deviceType})`,
    `Time: ${info.at.toUTCString()}`,
    ...(info.ip ? [`IP address: ${info.ip}`] : []),
    `If this was you, no action is needed. ${ignoreLine}`,
  ]
  return {
    subject: 'New device logged in',
    text: plain(lines),
    html: shell('New device logged in', lines),
  }
}

export function twoFactorChangedEmail(change: 'enabled' | 'disabled', provider: string): Template {
  const lines = [
    `Two-step login with ${provider} was ${change} on your Cloudwarden account.`,
    `If you did not do this, ${ignoreLine.toLowerCase()}`,
  ]
  return {
    subject: `Two-step login ${change}`,
    text: plain(lines),
    html: shell(`Two-step login ${change}`, lines),
  }
}

export function recoveryCodeUsedEmail(): Template {
  const lines = [
    'Your two-step login recovery code was used. All two-step login providers were turned off and the code was replaced.',
    `Turn two-step login back on in your account settings. ${ignoreLine}`,
  ]
  return {
    subject: 'Your recovery code was used',
    text: plain(lines),
    html: shell('Recovery code used', lines),
  }
}

export function emailChangedOldEmail(newEmail: string): Template {
  const lines = [
    `The email address of your Cloudwarden account was changed to ${newEmail}.`,
    `All sessions were signed out. ${ignoreLine}`,
  ]
  return {
    subject: 'Your account email address was changed',
    text: plain(lines),
    html: shell('Email address changed', lines),
  }
}

export function emailChangedNewEmail(): Template {
  const lines = [
    'This address is now the email address of a Cloudwarden account.',
    'Use it to log in from now on. You were signed out everywhere and need to log in again.',
  ]
  return {
    subject: 'Your account email address was changed',
    text: plain(lines),
    html: shell('Email address changed', lines),
  }
}

export function welcomeEmail(vaultUrl: string): Template {
  const lines = [
    'Welcome to Cloudwarden. Your account is ready.',
    'Log in from the web vault, the browser extension, the desktop app or the mobile app.',
  ]
  return {
    subject: 'Welcome to Cloudwarden',
    text: plain(lines, vaultUrl),
    html: shell('Welcome to Cloudwarden', lines, { url: vaultUrl, label: 'Open your vault' }),
  }
}

export function emergencyAcceptedEmail(granteeEmail: string): Template {
  const lines = [
    `${granteeEmail} accepted your emergency access invitation.`,
    'Confirm the contact in your account settings to finish setting up emergency access.',
  ]
  return {
    subject: 'Emergency contact accepted your invitation',
    text: plain(lines),
    html: shell('Invitation accepted', lines),
  }
}

export function emergencyConfirmedEmail(grantorName: string): Template {
  const lines = [`${grantorName} confirmed you as an emergency contact.`]
  return {
    subject: 'You are now an emergency contact',
    text: plain(lines),
    html: shell('Emergency contact confirmed', lines),
  }
}

export function emergencyApprovedEmail(grantorName: string, byTimeout: boolean): Template {
  const lines = [
    byTimeout
      ? `The wait time for your emergency access request to ${grantorName} has passed.`
      : `${grantorName} approved your emergency access request.`,
    'You can now view or take over the account from the emergency access page.',
  ]
  return {
    subject: 'Emergency access approved',
    text: plain(lines),
    html: shell('Emergency access approved', lines),
  }
}

export function emergencyRejectedEmail(grantorName: string): Template {
  const lines = [`${grantorName} rejected your emergency access request.`]
  return {
    subject: 'Emergency access rejected',
    text: plain(lines),
    html: shell('Emergency access rejected', lines),
  }
}

export function orgAcceptedEmail(orgName: string, memberEmail: string): Template {
  const lines = [
    `${memberEmail} accepted the invitation to ${orgName}.`,
    'Confirm the member in the organisation to give them access.',
  ]
  return {
    subject: `${memberEmail} accepted your invitation`,
    text: plain(lines),
    html: shell('Invitation accepted', lines),
  }
}

export function orgConfirmedEmail(orgName: string): Template {
  const lines = [`You were confirmed as a member of ${orgName}. Its items are now in your vault.`]
  return {
    subject: `You joined ${orgName}`,
    text: plain(lines),
    html: shell('Organisation membership confirmed', lines),
  }
}

export function deleteAccountEmail(url: string): Template {
  const lines = [
    'Someone asked to delete your Cloudwarden account. Everything in the account will be erased and this cannot be undone.',
    'If it was you, choose the link below. It expires in five days. If not, ignore this message and nothing happens.',
  ]
  return {
    subject: 'Confirm account deletion',
    text: plain(lines, url),
    html: shell('Confirm account deletion', lines, { url, label: 'Delete my account' }),
  }
}
