// Privileged access management (PAM): numeric wire values and tunables. The integers are the
// ones the Bitwarden SDK models serialise (generated `bitwarden-api-api` enums). Docs:
// docs/privileged-access.md.

export const ConnectorStatus = { Enabled: 0, Disabled: 1 } as const
export const TargetMethod = { Automatic: 0, Manual: 1 } as const
export const TargetStatus = { Active: 0, Disabled: 1, PendingSeal: 2 } as const
export const RotationSource = { Scheduled: 0, OnDemand: 1, AccessEnd: 2 } as const
export const JobStatus = { Pending: 0, Claimed: 1, Succeeded: 2, Failed: 3, TimedOut: 4 } as const
export const AttemptStatus = { Executing: 0, Rotated: 1, Errored: 2, Abandoned: 3 } as const
export const SyncState = { TargetUnchanged: 0, TargetUpdated: 1, Indeterminate: 2 } as const
export const SessionTermination = { NotRequested: 0, Terminated: 1, TermFailed: 2 } as const

export const ApprovalMode = { Automatic: 0, Human: 1 } as const
export const DeciderKind = { Automatic: 0, Human: 1 } as const
export const Verdict = { Deny: 0, Approve: 1 } as const
export const RequestStatus = {
  Pending: 0,
  Approved: 1,
  Denied: 2,
  Cancelled: 3,
  Expired: 4,
} as const
export const LeaseStatus = { Active: 0, Expired: 1, Revoked: 2, Cancelled: 3 } as const

/** Scope and client id prefix of the access connector `client_credentials` grant. */
export const CONNECTOR_SCOPE = 'api.access-connector'
export const CONNECTOR_CLIENT_PREFIX = 'access-connector.'
export const CONNECTOR_TOKEN_TTL_SECONDS = 3600

const SECOND = 1000
const MINUTE = 60 * SECOND
const HOUR = 60 * MINUTE

/** A connector that has not called a connector endpoint within this time shows as offline. */
export const CONNECTOR_OFFLINE_AFTER_MS = 2 * MINUTE
/** The heartbeat write is conditional on this interval; polling faster gains nothing. */
export const HEARTBEAT_MIN_INTERVAL_MS = 30 * SECOND
/** How long a connector holds a claim before the sweep may release the job. */
export const CLAIM_LEASE_MS = 5 * MINUTE
/** A rotation job that nobody finishes by then is timed out. */
export const JOB_LIFETIME_MS = 6 * HOUR
/** Cooldown between two on-demand rotations of one configuration. */
export const ON_DEMAND_COOLDOWN_MS = MINUTE
/** Longest error code and detail a connector may report. */
export const MAX_ERROR_CODE = 64
export const MAX_ERROR_DETAIL = 256
export const MAX_FAILURE_REASON = 300

/** A pending request nobody decides expires after this time. */
export const PENDING_TTL_MS = 7 * 24 * HOUR
/** An approved request the requester never activates expires after this time. */
export const APPROVAL_TTL_MS = 24 * HOUR
export const DEFAULT_LEASE_SECONDS = HOUR / SECOND
export const MAX_LEASE_SECONDS = 30 * 24 * 3600
/** Rows returned by one list call. */
export const LIST_LIMIT = 200
