import { DurableObject } from 'cloudflare:workers'
import type { Bindings } from '../env'

/**
 * Fan-out hub for live sync notifications (Bitwarden `/notifications/hub`).
 * Uses the WebSocket hibernation API so idle sockets cost nothing.
 */
export class NotificationHub extends DurableObject<Bindings> {
  async fetch(request: Request): Promise<Response> {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 })
    }
    const pair = new WebSocketPair()
    const client = pair[0]
    const server = pair[1]
    this.ctx.acceptWebSocket(server)
    // TODO(TASKS #7): authenticate, tag the socket by user id, and send the SignalR handshake ack.
    return new Response(null, { status: 101, webSocket: client })
  }

  async webSocketMessage(_ws: WebSocket, _message: string | ArrayBuffer): Promise<void> {
    // TODO(TASKS #7): handle SignalR protocol frames. Echo nothing for now.
  }

  async webSocketClose(ws: WebSocket, code: number, _reason: string, _wasClean: boolean) {
    ws.close(code)
  }
}
