import type { schema } from '../db'

export const folderJson = (f: typeof schema.folders.$inferSelect) => ({
  id: f.uuid,
  name: f.name,
  revisionDate: new Date(f.updatedAt).toISOString(),
  object: 'folder',
})
