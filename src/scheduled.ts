import { BACKUP_CRON, runBackup } from './backup'
import { notifyElapsedRecoveries } from './emergency-sweep'
import type { Bindings } from './env'
import { DELIVERY_CRON, deliverIntegrations } from './integrations/deliver'
import { errorKind, log } from './log'
import { purgeExpired } from './vault/purge'

/**
 * Cron entry point. The daily trigger exports D1 to R2 (TASKS #162); the hourly trigger purges
 * expired Sends and orphaned blobs (TASKS #84); the minute trigger delivers events to integrations
 * (TASKS #274). An invocation without a cron string (manual or
 * test) runs both. Each job is isolated in try/catch and awaited; a backup failure is rethrown so
 * the invocation is marked failed, a purge failure is logged and left for the next hour.
 */
export const scheduled = async (
  controller: ScheduledController,
  env: Bindings,
  _ctx: ExecutionContext,
): Promise<void> => {
  const both = !controller.cron
  const doBackup = both || controller.cron === BACKUP_CRON
  const doPurge = both || (controller.cron !== BACKUP_CRON && controller.cron !== DELIVERY_CRON)
  const doDeliver = both || controller.cron === DELIVERY_CRON

  let backupError: unknown
  let backupFailed = false
  if (doBackup) {
    try {
      await runBackup(env, new Date(controller.scheduledTime))
    } catch (err) {
      backupFailed = true
      backupError = err
    }
  }
  if (doPurge) {
    try {
      await purgeExpired(env)
    } catch (err) {
      log('error', 'purge.failed', { errorKind: errorKind(err) }, env)
    }
    try {
      await notifyElapsedRecoveries(env)
    } catch (err) {
      log('error', 'emergency_sweep.failed', { errorKind: errorKind(err) }, env)
    }
  }
  if (doDeliver) {
    try {
      await deliverIntegrations(env)
    } catch (err) {
      log('error', 'integrations.failed', { errorKind: errorKind(err) }, env)
    }
  }
  if (backupFailed) throw backupError
}
