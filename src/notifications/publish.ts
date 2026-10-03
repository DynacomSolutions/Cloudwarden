import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import type { MsgValue } from './msgpack'
import { relaySend } from './relay'
import { sendWebPush } from './webpush'

/**
 * Bitwarden notification types, as sent in the `Type` field of `ReceiveMessage`.
 * Values match the official clients; do not renumber.
 */
export const PushType = {
  SyncCipherUpdate: 0,
  SyncCipherCreate: 1,
  SyncLoginDelete: 2,
  SyncFolderDelete: 3,
  SyncCiphers: 4,
  SyncVault: 5,
  SyncOrgKeys: 6,
  SyncFolderCreate: 7,
  SyncFolderUpdate: 8,
  SyncCipherDelete: 9,
  SyncSettings: 10,
  LogOut: 11,
  SyncSendCreate: 12,
  SyncSendUpdate: 13,
  SyncSendDelete: 14,
  AuthRequest: 15,
  AuthRequestResponse: 16,
  SyncOrganizations: 17,
  SyncOrganizationStatusChanged: 18,
  SyncOrganizationCollectionSettingChanged: 19,
  Notification: 20,
  NotificationStatus: 21,
  RefreshSecurityTasks: 22,
} as const
export type PushType = (typeof PushType)[keyof typeof PushType]

/** Client method the user hub invokes. */
export const USER_TARGET = 'ReceiveMessage'
/** Client method the anonymous hub invokes (the spelling is part of the wire contract). */
export const ANON_TARGET = 'AuthRequestResponseRecieved'

type Payload = { [key: string]: MsgValue }

const notificationArg = (type: PushType, payload: Payload, contextId: string | null) => ({
  ContextId: contextId,
  Type: type,
  Payload: payload,
})

/**
 * Sends a notification to every connected device of a user.
 *
 * Usage from a write route, after the database write has committed:
 *
 *   c.executionCtx.waitUntil(
 *     pushUserUpdate(c.env, user.uuid, PushType.SyncCipherUpdate, {
 *       Id: cipher.uuid, UserId: user.uuid, OrganizationId: null,
 *       CollectionIds: null, RevisionDate: new Date(cipher.updatedAt).toISOString(),
 *     }, c.var.auth.deviceIdentifier),
 *   )
 *
 * Payload shapes (PascalCase keys, as the clients read them):
 * - cipher types (0, 1, 2, 9): Id, UserId, OrganizationId, CollectionIds, RevisionDate
 * - folder types (3, 7, 8) and send types (12, 13, 14): Id, UserId, RevisionDate
 * - SyncVault, SyncCiphers, SyncSettings, SyncOrgKeys: UserId, Date
 * - LogOut: UserId, Date
 * - AuthRequest, AuthRequestResponse: Id, UserId
 *
 * `excludeDeviceIdentifier` is the device that made the change: it is sent as `ContextId`
 * (clients ignore their own events) and that device's sockets are skipped.
 * Never rejects: a failed push must not fail the write that triggered it.
 */
export async function pushUserUpdate(
  env: Bindings,
  userUuid: string,
  type: PushType,
  payload: Payload,
  excludeDeviceIdentifier?: string | null,
  options: { relay?: boolean } = {},
): Promise<void> {
  // A stand-in account of a federated member: the event goes to its home instance (TASKS #305).
  if (env.FEDERATION_ENABLED === 'true') {
    const { notifyPeerOfUser } = await import('../federation/hosting')
    if (await notifyPeerOfUser(env, userUuid, type, payload, excludeDeviceIdentifier ?? null))
      return
  }
  // Live sockets, the mobile relay and browser web push are independent: one failing never
  // blocks the others.
  await Promise.all([
    sendWebPush(
      env,
      userUuid,
      { type, payload, contextId: excludeDeviceIdentifier ?? null },
      excludeDeviceIdentifier,
    ),
    (async () => {
      try {
        const stub = env.NOTIFICATIONS.get(env.NOTIFICATIONS.idFromName(userUuid)) as unknown as {
          push(m: unknown): Promise<number>
        }
        await stub.push({
          target: USER_TARGET,
          args: [notificationArg(type, payload, excludeDeviceIdentifier ?? null)],
          excludeDevice: excludeDeviceIdentifier ?? null,
        })
      } catch (err) {
        log('error', 'notification.push_failed', { errorKind: errorKind(err) })
      }
    })(),
    options.relay === false
      ? Promise.resolve()
      : relaySend(env, {
          type,
          payload,
          userId: userUuid,
          excludeIdentifier: excludeDeviceIdentifier ?? null,
        }),
  ])
}

/**
 * Sends one event to every member of an organisation: each member's live sockets directly, and
 * the mobile relay once, targeted by organisation id instead of once per member. `excludeUserUuid`
 * with `excludeDeviceIdentifier` skips the acting device. The payload is the same for everyone,
 * so use it for organisation-wide events, not ones that carry a per-user `UserId`.
 */
export async function pushOrgUpdate(
  env: Bindings,
  organizationUuid: string,
  memberUuids: string[],
  type: PushType,
  payload: Payload,
  excludeDeviceIdentifier?: string | null,
  excludeUserUuid?: string | null,
): Promise<void> {
  await Promise.all([
    ...[...new Set(memberUuids)].map((uuid) =>
      pushUserUpdate(
        env,
        uuid,
        type,
        payload,
        uuid === excludeUserUuid ? (excludeDeviceIdentifier ?? null) : null,
        { relay: false },
      ),
    ),
    relaySend(env, {
      type,
      payload,
      organizationId: organizationUuid,
      excludeIdentifier: excludeDeviceIdentifier ?? null,
    }),
  ])
}

/**
 * Forces every session of the user to sign out, then closes their sockets (except the
 * originating device's). Call after a security stamp rotation.
 */
export async function pushLogOut(
  env: Bindings,
  userUuid: string,
  originDeviceIdentifier?: string | null,
): Promise<void> {
  const payload = { UserId: userUuid, Date: new Date().toISOString() }
  const relayDone = relaySend(env, {
    type: PushType.LogOut,
    payload,
    userId: userUuid,
    excludeIdentifier: originDeviceIdentifier ?? null,
  })
  try {
    const stub = env.NOTIFICATIONS.get(env.NOTIFICATIONS.idFromName(userUuid)) as unknown as {
      push(m: unknown): Promise<number>
    }
    await stub.push({
      target: USER_TARGET,
      args: [
        notificationArg(
          PushType.LogOut,
          { UserId: userUuid, Date: new Date().toISOString() },
          null,
        ),
      ],
      // Every socket is told, then closed so a stale session cannot keep listening.
      closeAfter: true,
      closeExceptDevice: originDeviceIdentifier ?? null,
    })
  } catch (err) {
    log('error', 'notification.push_failed', { errorKind: errorKind(err) })
  }
  await Promise.all([
    relayDone,
    sendWebPush(
      env,
      userUuid,
      { type: PushType.LogOut, payload, contextId: null },
      originDeviceIdentifier,
    ),
  ])
}

/** Name of the Durable Object serving the anonymous hub for one auth request. */
export const anonymousHubName = (authRequestId: string) => `anon:${authRequestId}`

/** Tells the device waiting on the anonymous hub that its auth request was answered. */
export async function pushAuthRequestResponse(
  env: Bindings,
  authRequestId: string,
  userUuid: string,
): Promise<void> {
  try {
    const stub = env.NOTIFICATIONS.get(
      env.NOTIFICATIONS.idFromName(anonymousHubName(authRequestId)),
    ) as unknown as { push(m: unknown): Promise<number> }
    await stub.push({
      target: ANON_TARGET,
      args: [
        notificationArg(
          PushType.AuthRequestResponse,
          { Id: authRequestId, UserId: userUuid },
          null,
        ),
      ],
    })
  } catch (err) {
    log('error', 'notification.push_failed', { errorKind: errorKind(err) })
  }
}
