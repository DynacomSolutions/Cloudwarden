// Secrets Manager row loading and wire shapes (TASKS #220). Shapes follow the generated API models
// of the GPL-licensed `bitwarden-api-api` crate (docs/secrets-manager.md).
import { eq, inArray } from 'drizzle-orm'
import { type Db, schema } from '../db'
import { ApiError } from '../errors'
import type { Rw } from './access'
import { MACHINE_SCOPE } from './auth'

export type Project = typeof schema.smProjects.$inferSelect
export type Secret = typeof schema.smSecrets.$inferSelect
export type ServiceAccount = typeof schema.smServiceAccounts.$inferSelect
export type AccessToken = typeof schema.smAccessTokens.$inferSelect
export interface ProjectRef {
  id: string
  name: string
}

const iso = (ms: number) => new Date(ms).toISOString()

/** D1 caps bound parameters per statement; query long id lists in slices. */
export async function inChunks<T>(ids: string[], load: (part: string[]) => Promise<T[]>) {
  const out: T[] = []
  for (let i = 0; i < ids.length; i += 80) out.push(...(await load(ids.slice(i, i + 80))))
  return out
}

export async function findProject(db: Db, uuid: string): Promise<Project> {
  const [p] = await db.select().from(schema.smProjects).where(eq(schema.smProjects.uuid, uuid))
  if (!p) throw new ApiError(404, 'Project not found.')
  return p
}

export async function findSecret(db: Db, uuid: string): Promise<Secret> {
  const [s] = await db.select().from(schema.smSecrets).where(eq(schema.smSecrets.uuid, uuid))
  if (!s) throw new ApiError(404, 'Secret not found.')
  return s
}

export async function findServiceAccount(db: Db, uuid: string): Promise<ServiceAccount> {
  const [sa] = await db
    .select()
    .from(schema.smServiceAccounts)
    .where(eq(schema.smServiceAccounts.uuid, uuid))
  if (!sa) throw new ApiError(404, 'Service account not found.')
  return sa
}

/** Projects of each secret, keyed by secret id. */
export async function projectsOfSecrets(db: Db, secretUuids: string[]) {
  const rows = await inChunks(secretUuids, (part) =>
    db
      .select({
        s: schema.smSecretsProjects.secretUuid,
        id: schema.smProjects.uuid,
        name: schema.smProjects.name,
      })
      .from(schema.smSecretsProjects)
      .innerJoin(
        schema.smProjects,
        eq(schema.smProjects.uuid, schema.smSecretsProjects.projectUuid),
      )
      .where(inArray(schema.smSecretsProjects.secretUuid, part)),
  )
  const out = new Map<string, ProjectRef[]>()
  for (const r of rows) out.set(r.s, [...(out.get(r.s) ?? []), { id: r.id, name: r.name }])
  return out
}

export const projectJson = (p: Project, rw: Rw) => ({
  object: 'project',
  id: p.uuid,
  organizationId: p.organizationUuid,
  name: p.name,
  creationDate: iso(p.createdAt),
  revisionDate: iso(p.updatedAt),
  read: rw.read,
  write: rw.write,
})

/** `BaseSecretResponseModel`: used by get-by-ids and sync. */
export const baseSecretJson = (s: Secret, projects: ProjectRef[]) => ({
  object: 'baseSecret',
  id: s.uuid,
  organizationId: s.organizationUuid,
  key: s.key,
  value: s.value,
  note: s.note,
  creationDate: iso(s.createdAt),
  revisionDate: iso(s.updatedAt),
  projects,
})

/** `SecretResponseModel`. */
export const secretJson = (s: Secret, projects: ProjectRef[], rw: Rw) => ({
  ...baseSecretJson(s, projects),
  object: 'secret',
  read: rw.read,
  write: rw.write,
})

/** One entry of `SecretWithProjectsListResponseModel.secrets` (no value or note). */
export const secretListJson = (s: Secret, projects: ProjectRef[], rw: Rw) => ({
  id: s.uuid,
  organizationId: s.organizationUuid,
  key: s.key,
  creationDate: iso(s.createdAt),
  revisionDate: iso(s.updatedAt),
  projects,
  read: rw.read,
  write: rw.write,
})

export const serviceAccountJson = (sa: ServiceAccount) => ({
  object: 'serviceAccount',
  id: sa.uuid,
  organizationId: sa.organizationUuid,
  name: sa.name,
  creationDate: iso(sa.createdAt),
  revisionDate: iso(sa.updatedAt),
})

export const accessTokenJson = (t: AccessToken) => ({
  object: 'accessToken',
  id: t.uuid,
  name: t.name,
  scopes: [MACHINE_SCOPE],
  expireAt: t.expiresAt === null ? null : iso(t.expiresAt),
  creationDate: iso(t.createdAt),
  revisionDate: iso(t.updatedAt),
})

export const list = <T>(data: T[]) => ({ object: 'list', data, continuationToken: null })
