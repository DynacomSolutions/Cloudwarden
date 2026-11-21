# Access Intelligence reports

Routes under `/api/reports` that the Access Intelligence (risk insights) screens call (TASKS #435). Request and response shapes follow the generated SDK API crate; behaviour is Cloudwarden's own.

## Who may call

Every route except the Azure callback needs a signed-in user who holds the `accessReports` permission in the organization: owners, admins and custom members with the permission. Everyone else, including members of other organizations, gets `404`, so the routes do not show which organizations exist. Cloudwarden has no plans, so no plan check applies.

`useRiskInsights` stays `false` on the organization profile. The web client reads it, and the `AccessIntelligenceNewArchitecture` feature flag is not set in `featureStates`, so the screens stay hidden until a later change turns both on. The routes work now for any client that calls them.

## Routes

| Method and path | What it does |
|---|---|
| `GET member-access/{org}` | One row per member and granted collection. Reads real data from D1: direct grants, group grants, access-all members and groups, two-factor state, recovery key and key connector. A member without grants has one row with no collection. |
| `GET member-cipher-details/{org}` | One row per member with the ids of every live item the member can reach. |
| `GET password-health-report-applications/{org}` | The critical applications of the organization. |
| `POST password-health-report-applications` | Adds applications (up to 200 per request, 10 000 per organization). |
| `DELETE password-health-report-application` | Drops applications by id. `400` when the organization has none. |
| `POST organizations/{org}` | Creates a report (see below). |
| `GET organizations/{org}/latest` | The newest complete report, `404` when none. |
| `GET`, `PATCH`, `DELETE organizations/{org}/{report}` | Read, update and delete one report. A report of another organization answers `404`. |
| `GET`, `PATCH organizations/{org}/data/summary/{report}` | The encrypted summary of one report, and its update. |
| `GET organizations/{org}/data/summary?startDate&endDate` | Summaries of reports created in the range, oldest first, at most 1000. |
| `GET`, `PATCH organizations/{org}/data/application/{report}` | The encrypted application data of one report, and its update. |
| `POST organizations/{org}/{report}/file?reportFileId=` | Uploads the report file. |
| `GET organizations/{org}/{report}/file/download` | Downloads the uploaded file. |
| `GET organizations/{org}/{report}/file/renew?reportFileId=` | Returns the upload URL again while the file is missing. |
| `POST organizations/file/validate/azure` | Event Grid callback of the official cloud. Answers the subscription handshake and refuses every other event. |

## Storage

- Summary, application data, the content key and the metrics are small strings kept in the `organization_reports` D1 table. The metrics are stored as JSON. PATCH routes replace only the fields they receive.
- The report blob lives in R2 under `org-reports/{org}/{report}/`. The `ATTACHMENTS` bucket is used, the same as for attachments and Send files.
- The critical applications are rows of `password_health_report_applications`.

## Creating a report

- With `fileSize` (1 byte to 100 MB) the report is reserved. The response holds `reportFileUploadUrl`, the report and `fileUploadType` 0 (direct). The client posts the file as `multipart/form-data` to that URL with its bearer token.
- Without `fileSize` the inline `reportData` is stored in R2 and the report returns at once, with the data.
- The upload streams into R2 in 8 MiB parts, so memory stays low. The stored size may differ from the declared size by up to 1 MiB, because clients may count the file before framing. The stored length replaces the declared one. Any other size drops the report and its blob and answers `400`.
- One upload runs at a time per report (`409` otherwise). A finished file cannot be uploaded again.
- The download URL and the "latest" report appear only after the upload finishes.
- At most 10 unfinished file reports per organization within 24 hours. The scheduled purge deletes unfinished file reports older than 24 hours with their partial blobs. Deleting a report or the organization deletes its blobs.

## Not covered

The Azure blob storage path (`fileUploadType` 1, signed URLs, Event Grid validation of uploads) does not exist here, since files live in R2.
