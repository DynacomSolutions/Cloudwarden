// Subscription limits of an organisation for the Public API `organization/subscription` pair
// (TASKS #24.429). Cloudwarden has no billing, so the values are limits that an administrator or a
// tool such as the Bitwarden MCP server sets and reads back. Nothing is charged. A null value
// means no limit was set.
import { and, eq, ne, sql } from 'drizzle-orm'
import { z } from 'zod'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'
import { Status } from './constants'

export type SubscriptionRow = typeof schema.organizationSubscriptions.$inferSelect

const INT32_MAX = 2147483647
const limit = z.number().int().min(0).max(INT32_MAX).nullish()

/** Request body of `PUT /public/organization/subscription`. Null or missing fields change nothing. */
export const subscriptionUpdateSchema = z.object({
  passwordManager: z.object({ seats: limit, storage: limit, maxAutoScaleSeats: limit }).nullish(),
  secretsManager: z
    .object({
      seats: limit,
      maxAutoScaleSeats: limit,
      serviceAccounts: limit,
      maxAutoScaleServiceAccounts: limit,
    })
    .nullish(),
})
export type SubscriptionUpdate = z.infer<typeof subscriptionUpdateSchema>

export async function loadSubscription(db: Db, orgUuid: string) {
  const [row] = await db
    .select()
    .from(schema.organizationSubscriptions)
    .where(eq(schema.organizationSubscriptions.organizationUuid, orgUuid))
    .limit(1)
  return row
}

/** The response model of `GET /public/organization/subscription`. */
export function subscriptionJson(row: SubscriptionRow | undefined) {
  return {
    passwordManager: {
      seats: row?.seats ?? null,
      maxAutoScaleSeats: row?.maxAutoscaleSeats ?? null,
      storage: row?.storageGb ?? null,
    },
    secretsManager: {
      seats: row?.smSeats ?? null,
      maxAutoScaleSeats: row?.smMaxAutoscaleSeats ?? null,
      serviceAccounts: row?.smServiceAccounts ?? null,
      maxAutoScaleServiceAccounts: row?.smMaxAutoscaleServiceAccounts ?? null,
    },
  }
}

const pick = (next: number | null | undefined, current: number | null | undefined) =>
  next ?? current ?? null

function fail(errors: Record<string, string[]>): never {
  throw new ApiError(400, 'The request is invalid.', errors)
}

/** Members that hold a seat: every member that is not revoked. */
export async function occupiedSeats(db: Db, orgUuid: string): Promise<number> {
  const uo = schema.usersOrganizations
  const [r] = await db
    .select({ n: sql<number>`count(*)` })
    .from(uo)
    .where(and(eq(uo.organizationUuid, orgUuid), ne(uo.status, Status.Revoked)))
  return Number(r?.n ?? 0)
}

/**
 * Merges the update into the stored limits and returns the row to store. Throws 400 when the
 * seats are fewer than the members that hold one, or when an autoscale limit is below its seats.
 */
export async function mergeSubscription(
  db: Db,
  orgUuid: string,
  current: SubscriptionRow | undefined,
  update: SubscriptionUpdate,
  now: number,
): Promise<SubscriptionRow> {
  const pm = update.passwordManager
  const sm = update.secretsManager
  const row: SubscriptionRow = {
    organizationUuid: orgUuid,
    seats: pick(pm?.seats, current?.seats),
    maxAutoscaleSeats: pick(pm?.maxAutoScaleSeats, current?.maxAutoscaleSeats),
    storageGb: pick(pm?.storage, current?.storageGb),
    smSeats: pick(sm?.seats, current?.smSeats),
    smMaxAutoscaleSeats: pick(sm?.maxAutoScaleSeats, current?.smMaxAutoscaleSeats),
    smServiceAccounts: pick(sm?.serviceAccounts, current?.smServiceAccounts),
    smMaxAutoscaleServiceAccounts: pick(
      sm?.maxAutoScaleServiceAccounts,
      current?.smMaxAutoscaleServiceAccounts,
    ),
    updatedAt: now,
  }
  // A seat count that did not change needs no check: members may already exceed it, for example
  // after a restore, and that must not block an unrelated update.
  if (pm?.seats != null && pm.seats !== current?.seats) {
    const used = await occupiedSeats(db, orgUuid)
    if (pm.seats < used) {
      fail({
        'passwordManager.seats': [`Seats cannot be fewer than the ${used} members that use one.`],
      })
    }
  }
  if (row.seats !== null && row.maxAutoscaleSeats !== null && row.maxAutoscaleSeats < row.seats) {
    fail({ 'passwordManager.maxAutoScaleSeats': ['Maximum seats cannot be below the seats.'] })
  }
  if (
    row.smSeats !== null &&
    row.smMaxAutoscaleSeats !== null &&
    row.smMaxAutoscaleSeats < row.smSeats
  ) {
    fail({ 'secretsManager.maxAutoScaleSeats': ['Maximum seats cannot be below the seats.'] })
  }
  if (
    row.smServiceAccounts !== null &&
    row.smMaxAutoscaleServiceAccounts !== null &&
    row.smMaxAutoscaleServiceAccounts < row.smServiceAccounts
  ) {
    fail({
      'secretsManager.maxAutoScaleServiceAccounts': [
        'Maximum machine accounts cannot be below the machine accounts.',
      ],
    })
  }
  return row
}

/**
 * Statement that stores the merged row. A new row is inserted whole. An existing row gets only the
 * limits the request supplied, so two updates that run at the same time keep each other's values.
 */
export function subscriptionUpsert(db: Db, row: SubscriptionRow, update: SubscriptionUpdate) {
  const pm = update.passwordManager
  const sm = update.secretsManager
  const set: Partial<SubscriptionRow> = { updatedAt: row.updatedAt }
  if (pm?.seats != null) set.seats = row.seats
  if (pm?.maxAutoScaleSeats != null) set.maxAutoscaleSeats = row.maxAutoscaleSeats
  if (pm?.storage != null) set.storageGb = row.storageGb
  if (sm?.seats != null) set.smSeats = row.smSeats
  if (sm?.maxAutoScaleSeats != null) set.smMaxAutoscaleSeats = row.smMaxAutoscaleSeats
  if (sm?.serviceAccounts != null) set.smServiceAccounts = row.smServiceAccounts
  if (sm?.maxAutoScaleServiceAccounts != null)
    set.smMaxAutoscaleServiceAccounts = row.smMaxAutoscaleServiceAccounts
  return db
    .insert(schema.organizationSubscriptions)
    .values(row)
    .onConflictDoUpdate({ target: schema.organizationSubscriptions.organizationUuid, set })
}

/** The seat limit of the organisation, or null when none was set. */
export async function seatLimit(db: Db, orgUuid: string): Promise<number | null> {
  return (await loadSubscription(db, orgUuid))?.seats ?? null
}

/** The refusal for an organisation whose seats are all taken. */
export const seatsFullError = (seats: number) =>
  new ApiError(
    400,
    `You have reached the maximum number of users (${seats}) allowed for this organization.`,
  )

/** Whether `adding` more members fit in the seats. With no limit set, they always fit. */
export async function seatsAvailable(db: Db, orgUuid: string, adding = 1): Promise<boolean> {
  const seats = await seatLimit(db, orgUuid)
  return seats === null || (await occupiedSeats(db, orgUuid)) + adding <= seats
}

/** Throws the seat refusal unless `adding` more members fit. Call before any member is added. */
export async function assertSeatsAvailable(db: Db, orgUuid: string, adding = 1): Promise<void> {
  const seats = await seatLimit(db, orgUuid)
  if (seats !== null && (await occupiedSeats(db, orgUuid)) + adding > seats) {
    throw seatsFullError(seats)
  }
}
