import { DurableObject } from 'cloudflare:workers'
import type { Bindings } from '../env'
import type { MsgValue } from '../notifications/msgpack'
import {
  clientMessageTypes,
  encodeInvocation,
  encodePing,
  handshakeError,
  handshakeOk,
  MSG_CLOSE,
  type Protocol,
  parseHandshake,
} from '../notifications/signalr'

/** Header the Worker sets (after verifying the token) to tag a socket with its device. */
export const DEVICE_HEADER = 'X-Cw-Device'
/** Header the Worker sets on anonymous hub connections: epoch ms when the hub must close. */
export const EXPIRES_HEADER = 'X-Cw-Expires-At'

/** Removes internal headers a client may have sent, so only the Worker can set them. */
export function stripInternalHeaders(headers: Headers): Headers {
  const out = new Headers(headers)
  out.delete(DEVICE_HEADER)
  out.delete(EXPIRES_HEADER)
  return out
}

/** What `push` delivers: a SignalR invocation addressed to every matching socket. */
export interface HubMessage {
  /** Client method name, `ReceiveMessage` on the user hub. */
  target: string
  /** Invocation arguments. */
  args: MsgValue[]
  /** Skip sockets whose device identifier equals this value. */
  excludeDevice?: string | null
  /** Close every socket after delivery (used for LogOut), except this device's sockets. */
  closeAfter?: boolean
  closeExceptDevice?: string | null
}

interface SocketState {
  /** Null until the SignalR handshake completes. */
  protocol: Protocol | null
  connectedAt: number
}

const PING_INTERVAL_MS = 15_000
/** A socket that has not completed the handshake by the next alarm after this is closed. */
const HANDSHAKE_TIMEOUT_MS = 10_000
const MAX_USER_SOCKETS = 25
const MAX_ANON_SOCKETS = 5

/** Socket tags are capped at 256 characters. */
export const deviceTag = (identifier: string) => `d:${identifier.slice(0, 200)}`

/**
 * Fan-out hub for live sync notifications. One instance per user (`/notifications/hub`)
 * and one per login-with-device request (`/notifications/anonymous-hub`).
 * Uses the WebSocket hibernation API so idle sockets cost nothing; per-socket protocol
 * state lives in the socket attachment so it survives hibernation.
 */
export class NotificationHub extends DurableObject<Bindings> {
  async fetch(request: Request): Promise<Response> {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 })
    }
    const pair = new WebSocketPair()
    const client = pair[0]
    const server = pair[1]
    const device = request.headers.get(DEVICE_HEADER)
    const expiresAt = Number(request.headers.get(EXPIRES_HEADER)) || null
    if (expiresAt) await this.ctx.storage.put('expiresAt', expiresAt)
    // Cap concurrent sockets: evict the oldest to make room.
    const open = this.ctx.getWebSockets()
    const cap = expiresAt ? MAX_ANON_SOCKETS : MAX_USER_SOCKETS
    for (const old of open.slice(0, Math.max(0, open.length - cap + 1))) this.closeQuietly(old)
    this.ctx.acceptWebSocket(server, device ? [deviceTag(device)] : [])
    server.serializeAttachment({ protocol: null, connectedAt: Date.now() } satisfies SocketState)
    await this.ctx.storage.setAlarm(Date.now() + HANDSHAKE_TIMEOUT_MS)
    return new Response(null, { status: 101, webSocket: client })
  }

  /** RPC: delivers a message to every handshaken socket. Returns the number of recipients. */
  async push(message: HubMessage): Promise<number> {
    let sent = 0
    const skip = message.excludeDevice ? deviceTag(message.excludeDevice) : null
    for (const ws of this.ctx.getWebSockets()) {
      if (skip && this.ctx.getTags(ws).includes(skip)) continue
      const state = ws.deserializeAttachment() as SocketState | null
      if (!state?.protocol) continue
      try {
        ws.send(encodeInvocation(state.protocol, message.target, message.args))
        sent++
        if (
          message.closeAfter &&
          !(
            message.closeExceptDevice &&
            this.ctx.getTags(ws).includes(deviceTag(message.closeExceptDevice))
          )
        ) {
          ws.close(1000, 'Signed out')
        }
      } catch {
        // The socket is closing; the runtime will call webSocketClose.
      }
    }
    return sent
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const state = (ws.deserializeAttachment() as SocketState | null) ?? {
      protocol: null,
      connectedAt: 0,
    }
    if (!state.protocol) {
      if (typeof message !== 'string') return this.reject(ws, 'Handshake must be a text frame.')
      const hs = parseHandshake(message)
      if (!hs) return this.reject(ws, 'Invalid handshake.')
      const { protocol, version } = hs.request
      if (protocol !== 'json' && protocol !== 'messagepack') {
        return this.reject(ws, `The protocol '${protocol}' is not supported.`)
      }
      if (version !== 1)
        return this.reject(ws, `The protocol version '${version}' is not supported.`)
      ws.serializeAttachment({ protocol, connectedAt: state.connectedAt } satisfies SocketState)
      ws.send(handshakeOk)
      return
    }
    if (clientMessageTypes(state.protocol, message).includes(MSG_CLOSE)) {
      ws.close(1000, 'Closed by client')
    }
    // Pings and any other client messages need no reply; the server pings on its own schedule.
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    try {
      ws.close(1000)
    } catch {
      // Already closed.
    }
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws)
  }

  /** Keep-alive and housekeeping: pings, handshake timeout and anonymous hub expiry. */
  async alarm(): Promise<void> {
    const now = Date.now()
    const expiresAt = (await this.ctx.storage.get<number>('expiresAt')) ?? null
    const expired = expiresAt !== null && now >= expiresAt
    const sockets = this.ctx.getWebSockets()
    let live = 0
    for (const ws of sockets) {
      const state = ws.deserializeAttachment() as SocketState | null
      if (expired || !state?.protocol) {
        if (expired || now - (state?.connectedAt ?? 0) >= HANDSHAKE_TIMEOUT_MS) {
          this.closeQuietly(ws)
          continue
        }
        live++
        continue
      }
      try {
        ws.send(encodePing(state.protocol))
        live++
      } catch {
        // Closing.
      }
    }
    if (live === 0) return
    const next = now + PING_INTERVAL_MS
    await this.ctx.storage.setAlarm(expiresAt !== null ? Math.min(next, expiresAt) : next)
  }

  private closeQuietly(ws: WebSocket): void {
    try {
      ws.close(1000, 'Closed')
    } catch {
      // Already closed.
    }
  }

  private reject(ws: WebSocket, error: string): void {
    ws.send(handshakeError(error))
    ws.close(1002, 'Handshake failed')
  }
}
