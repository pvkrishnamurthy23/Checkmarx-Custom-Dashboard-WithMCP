# Checkmarx One API notes and verification checklist

Spec section 1 says **do not invent API fields**. The models and normalisers were written from the public API reference
(swagger at `<CX_BASE_URL>/spec/v1/`) and tested against **synthetic** fixtures. This file lists every assumption and how to confirm it.
Mark each item when verified (date, tenant, who) and update the fixture + test.

## VERIFIED against the live tenant (2026-10-16, region `ind`, tenant `calibo1`; read-only probes, about 40 calls)
| Item | Result |
|------|--------|
| Token (api key) at `https://ind.iam.checkmarx.net/auth/realms/<tenant>/protocol/openid-connect/token` | Works; IAM host pattern `<prefix>.iam.checkmarx.net` confirmed |
| `/api/projects` | `projects[]`, `totalCount`, `filteredTotalCount`; fields `id,name,createdAt,updatedAt,groups,tags{k:""},repoUrl,mainBranch,applicationIds,criticality,origin` match the model. `mainBranch` may be empty |
| `/api/applications` | `applications[]` with `id,name,criticality,tags,projectIds,rules` match |
| `/api/scans` | `scans[]`, `filteredTotalCount`; `id,status,branch,createdAt,updatedAt,projectId,engines[],statusDetails[{name,status,details,startDate,endDate}],initiator,sourceType,sourceOrigin,metadata` match. Filters `branch`, `statuses`, `project-id`, `scan-ids`, `from-date` work |
| Scan engine names | `sast, kics, apisec, containers, sca, microengines, general`. **`microengines` = secret detection (2ms) + scorecard (SSCS)**; `metadata.configs[type=microengines].value` = `{"2ms":"true","scorecard":"false"}` decides. `general` is not an engine. Mapped in `ScanModel.engine_keys` |
| `/api/projects/last-scan` | Works with `project-ids` (50 accepted), `branch`, `scan-status`, `limit`; returns `{projectId: {id,createdAt,updatedAt,status,branch,engines,...}}`; only projects with a matching scan appear |
| `/api/scan-summary?scan-ids=` | `scansSummaries[].scanId` plus blocks `sastCounters, kicsCounters, scaCounters, scaPackagesCounters (ignored), scaContainersCounters (OLD shape: severityVulnerabilitiesCounters), containersCounters (new: severityCounters), apiSecCounters, microEnginesCounters`. Standard blocks have `severityCounters[{severity,counter}]`, `stateCounters`, `statusCounters`, `severityStatusCounters`, `totalCounter`. No separate SSCS block (scorecard is inside `microEnginesCounters`) |
| `/api/results` | `results[]`, `totalCount`; `limit=500` accepted (one call for a typical scan). Common fields: `type,id,alternateId,similarityId,status,state,severity,created,firstFoundAt,foundAt,firstScanId,description,data,vulnerabilityDetails` |
| Result types | `sast`, `kics`, `sca`, `containers`, `sscs-secret-detection` (all map correctly through `TYPE_RULES`). API Security results were not present in the sampled scans (`apiSecCounters.severityCounters` was empty): still unverified |
| `similarityId` | Present for every engine seen. **SCA and Containers use the bare CVE** (not unique across packages/images). `alternateId` is unique per result in every case checked, so `finding_id = alternateId` and the lifecycle key appends package (SCA) or image+package (Containers). Before this fix 23 containers and 11 SCA findings were silently collapsed |
| SAST fields | `data.queryName, languageName, nodes[0].fileName/line, group`; `vulnerabilityDetails.cweId (int), compliances[]` (OWASP category). All populated 100% in the sample |
| KICS fields | `data.queryName, fileName, line, platform`; `vulnerabilityDetails.cweId`; populated 100% |
| SCA fields | `data.packageIdentifier ("Maven-org.x:y-1.2.3"), recommendedVersion`; `vulnerabilityDetails.cveName, cvssScore, cweId, cvss{attackVector,...}`. 99% have a fix version. `cvss.attackVector` ("NETWORK") exists, so the network-vector toggle is now implementable (ADR 0012) |
| Containers fields | `data.imageName, imageTag, packageName, packageVersion`; `vulnerabilityDetails.cveName/cvssScore/cweId`. **No fixed/recommended version in the results**, so "fix available %" is 0% for containers until another source is found |
| Secrets fields | `data.ruleName, fileName, line, validity, snippet (masked)`; `vulnerabilityDetails` is empty |
| Counts reconcile | After loading the same 7 scans, findings-derived totals equal the API `scan-summary` totals: sast 315, sca 392, kics 171, containers 167, secrets 4 |
| Incremental flag | `metadata.configs[type=sast].value.incremental` is `"true"`/`"false"`: the *configured* mode (ADR 0013) |
| Swagger | `<base>/spec/v1/` serves a Swagger UI that loads per-service YAML (`/spec/v1/mumbai-*.yaml`) |

Still **unverified**: API Security result representation, portal deep-link pattern (`CX_DEEPLINK_TEMPLATE`), SSCS scorecard results (needs a scan with
`scorecard=true`), custom states, `Partial`/`Canceled` scan statuses, the minimum Checkmarx role set.

## How to capture a fixture
1. Set real credentials in `.env`, then in a Python shell:
   ```python
   import asyncio, json
   from cxdash.config import get_settings
   from cxdash.sync.scheduler import open_api
   async def grab():
       async with open_api(get_settings()) as api:
           http = api._http
           print(json.dumps(await http.get("/api/projects", limit=3, offset=0), indent=2))
   asyncio.run(grab())
   ```
2. Sanitise (names, repo URLs, hashes, paths, snippets), save into `tests/fixtures/`, keep the file name.
3. `python -m pytest tests/unit/test_normalize.py tests/integration` and fix the mapping that fails.

## Endpoints used (all GET; paths live only in `cx_client/endpoints.py`)
| Purpose | Request | Parameters we send | Verified |
|---------|---------|--------------------|----------|
| Projects | `/api/projects` | `limit`, `offset` | [ ] |
| Applications | `/api/applications` | `limit`, `offset` | [ ] |
| Scans | `/api/scans` | `limit`, `offset`, `branch`, `from-date` | [ ] |
| Scan summary | `/api/scan-summary` | `scan-ids=a,b,c` (batches of 20) | [ ] |
| Results | `/api/results` | `scan-id`, `limit`, `offset` | [ ] |
| Token (IAM, POST) | `{CX_IAM_URL}/auth/realms/{tenant}/protocol/openid-connect/token` | form: api key -> `grant_type=refresh_token`, `client_id=ast-app`; oauth -> `client_credentials` | [ ] |

Parameter spellings (`from-date`, `scan-ids`, `scan-id`) follow the spec table; confirm in Swagger.

## Assumptions by risk (spec section 16)
| # | Assumption | Where | How to verify |
|---|------------|-------|---------------|
| 1 | `scan-summary` returns `scansSummaries[]` with blocks `sastCounters`, `scaCounters`, `kicsCounters`, `scaContainersCounters`/`containersCounters`, `apiSecCounters`, `microEnginesCounters` (secrets), `sscsCounters`, each with `severityCounters[{severity,counter}]` and `stateCounters[{state,counter}]`. `microEnginesCounters -> secrets` is now verified; there is no separate `sscsCounters` | `normalize.SUMMARY_KEY_TO_ENGINE` | Capture one summary for a scan that ran every engine; unknown blocks are logged (`unknown scan-summary block ignored`) |
| 2 | Result `type` substrings: `secret`->secrets, `sscs`/`scorecard`->sscs, `kics`/`iac`->kics, `container`->containers, `apisec`->apisec, `sca`->sca, `sast`->sast. How API Security results are distinguished from SAST is **unknown** | `normalize.TYPE_RULES` (ordered mapping table) | Inspect `/api/results` on a project with each engine; unknown types are logged (`unknown result type ignored`) and skipped |
| 3 | `similarityId` exists per result; otherwise a hash of (engine, title, file, line, package, cve) is used | `BaseNormalizer.normalize`, `fallback_similarity` | Check each engine's result for `similarityId`; fallback ids start with `h:` |
| 4 | IAM host is `iam.checkmarx.net` with the same regional prefix as the base URL | `Settings.iam_url` | Compare with your portal URL; override with `CX_IAM_URL` |
| 5 | Portal deep link `{ui_base}/results/{scan_id}/{project_id}/{engine}` | `CX_DEEPLINK_TEMPLATE`, `cx_client/deeplink.py` | Open a finding in the portal, copy the URL pattern, set the template |
| 6 | Result field paths: SAST `data.queryName/languageName/nodes[0].fileName,line`, `vulnerabilityDetails.cweId/compliances`; SCA `data.packageIdentifier/recommendedVersion`, `vulnerabilityDetails.cveName/cvssScore`; containers `data.imageName/imageTag/packageName/packageVersion/recommendedVersion`; KICS `data.queryName/fileName/line/platform`; Secrets `data.ruleName/fileName/line/validity`; SSCS `data.ruleName/name/checkName` | `normalize.py` per-engine classes | Compare a captured result with the class; add fields in the matching `_specific` |
| 7 | Scan `statusDetails[].name` values (`sast`, `sca`, `kics`, `sca-container`, ...) and statuses `Completed/Failed/Partial/Running/Queued/Canceled` | `repositories._engine_key`, `domain.py` | Capture a scan with a failed engine |
| 8 | Engine status "ok" strings `completed/success/succeeded` | `sync/findings.py::_OK_ENGINE_STATUSES` | Same capture as 7 |
| 9 | Pagination: `limit`/`offset`, short page ends the loop | `CheckmarxHttpClient.paged` | Check `totalCount` vs items for a project list |
| 10 | Results of a latest scan exclude findings already FIXED (derived counters exclude status in `CX_CLOSED_STATUSES` anyway) | `FindingRepository.derive_counters` | Compare counts with the portal |
| 11 | The "exploitable (network vector)" and "direct vs transitive" SCA fields exist somewhere in the SCA result | not implemented (ADR 0012) | Locate the fields, add columns + migration |

## Minimum Checkmarx role set
To be documented after testing (spec section 12). Needed: read access to projects, applications, scans, scan summaries and results.
Record the exact built-in roles/permissions you used here: `__________`.

## Deprecations to watch
Results Summary API is replaced by `/api/sast-scan-summary` (not used; only needed for extra SAST breakdowns). Keep paths in `endpoints.py` so
drift is a one-file change; contract tests (`tests/unit/test_normalize.py`) catch shape drift when fixtures are refreshed.
