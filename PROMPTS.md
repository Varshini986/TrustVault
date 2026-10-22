# AI-assisted work log

This log records the work performed in the available workspace. Entries are
dated 2026-10-22 because this workspace contains only the current session's
snapshot; they are not presented as a week of historical activity. The
security changes were committed together when the repository became available;
the links point to that real commit. No earlier commits or prompts are
invented.

## 2026-10-22 — Inspect document authorization

- **Asked:** Review the existing Flask routes and tests against the requirement
  that document access be decided server-side on every route.
- **Produced:** A route-level authorization review and a baseline test run.
- **What was wrong:** The baseline test suite could not import the application:
  the role decorator registered protected views under the same `decorator`
  endpoint name. The existing cross-user test covered download only.
- **Did instead:** Simplified the role wrapper and added a test that probes the
  document list, detail, download, edit, grant, and delete surfaces as an
  ungranted user. `test_ungranted_user_cannot_reach_document_through_any_route`
  now verifies both denial and that the document remains unchanged.
- **Commit:** [4af5f03](https://github.com/Varshini986/TrustVault/commit/4af5f036a8544e59b8de5cb565e864860ef5c3b9)

## 2026-10-22 — Separate edit from sharing authority

- **Asked:** Keep edit grants useful without letting a grantee widen access or
  delete the owner's document.
- **Produced:** Separate document-management authorization from metadata edit
  authorization in the server routes and detail template.
- **What was wrong:** The starter used `can_edit` for grant/revoke and delete,
  allowing every edit grantee to share onward or destroy the document. The
  first patch also had a nested-wrapper return typo, caught during direct code
  inspection before the test run.
- **Did instead:** Grant/revoke/delete now require document ownership or the
  explicit admin override; edit grantees can still edit title/category. Added
  `test_edit_grant_cannot_manage_access_or_delete`.
- **Commit:** [4af5f03](https://github.com/Varshini986/TrustVault/commit/4af5f036a8544e59b8de5cb565e864860ef5c3b9)

## 2026-10-22 — Check audit-chain correctness

- **Asked:** Inspect whether the audit chain remains verifiable with long
  details and concurrent appends.
- **Produced:** A focused audit review and a tampering test.
- **What was wrong:** The starter calculated a digest before truncating the
  stored detail to 500 characters, which could make a valid event fail later
  verification. A read-then-write append could also let concurrent writers
  choose the same previous hash.
- **Did instead:** Truncate before hashing and acquire SQLite's write lock
  before reading the chain tip. Added
  `test_audit_chain_verification_detects_database_tampering`; the documented
  domain-change/audit-append transaction gap remains accepted.
- **Commit:** [4af5f03](https://github.com/Varshini986/TrustVault/commit/4af5f036a8544e59b8de5cb565e864860ef5c3b9)

## 2026-10-22 — Scope search results

- **Asked:** Add the requested date search while preventing search controls
  from revealing metadata for inaccessible documents.
- **Produced:** Inclusive date filters plus title, original filename, owner,
  and category searching.
- **What was wrong:** The starter loaded category choices globally, even for a
  user whose document list was scoped. That exposed category names belonging
  to other users' documents.
- **Did instead:** Scope category facets to the same owned/granted document
  predicate as search results; reject malformed and reversed date ranges.
  Added `test_search_is_scoped_and_supports_date_filters`.
- **Commit:** [4af5f03](https://github.com/Varshini986/TrustVault/commit/4af5f036a8544e59b8de5cb565e864860ef5c3b9)

## 2026-10-22 — Verify tests and operator documentation

- **Asked:** Expand the security tests and document the route/role contract,
  schema, and accepted threat model.
- **Produced:** Route authorization tests, `API.md`, `schema.sql`, and updated
  README/threat documentation.
- **What was wrong:** One new registration test initially expected a rendered
  200 response, but successful registration correctly redirects to sign-in.
  Also, a local test run initially lacked the declared pytest dependency.
- **Did instead:** Corrected the expectation to 302 and installed only the
  dependencies already declared in `requirements.txt`; reran the suite.
- **Commit:** [4af5f03](https://github.com/Varshini986/TrustVault/commit/4af5f036a8544e59b8de5cb565e864860ef5c3b9)

## 2026-10-22 — Prepare the free Render demo

- **Asked:** Prepare a deployable no-card Flask demo with judge accounts, a
  sample document and clear operational limits.
- **Produced:** A Render blueprint, Gunicorn process configuration, a health
  endpoint and opt-in startup seeding for synthetic admin/owner/viewer
  accounts. Render generates each demo password; no password is committed.
- **What was wrong:** Free local storage is ephemeral, so uploaded documents,
  SQLite rows and the audit chain can disappear on restart or redeploy. My
  first smoke check also ran from the starter folder instead of the Git clone;
  `/healthz` returned 404, showing that I had tested the wrong checkout.
- **Did instead:** Made the target explicitly demo-only, documented the
  storage/data-loss limitation, seeded only synthetic content when enabled,
  verified viewer login/read access, health response and repeat startup from
  the clone, and reran the 13 existing tests. I did not claim the service is
  live at that point: connecting the GitHub repository to Render and creating
  its service still required the account owner.
- **Commit:** [25310cf](https://github.com/Varshini986/TrustVault/commit/25310cf2205b0108577260c1b912f5932c4d13a3)

## 2026-10-22 — Deploy and check the live service

- **Asked:** Continue after Render signup and publish the configured Blueprint.
- **Produced:** Render accepted the public repository's Blueprint and created
  the free `trustvault-demo` web service.
- **What was wrong:** The Blueprint form required a name not prefilled from
  `render.yaml`. The logged-in Render account also had no GitHub provider
  connection, so repository discovery was empty.
- **Did instead:** Used Render's public-repository URL option, set the
  Blueprint name to `TrustVault Demo`, and deployed. Checked the public landing
  page and `/healthz` response; health returned `{"status":"ok"}`. The app uses
  generated passwords, so I did not copy those secrets into chat or source.
  Free-tier local SQLite and uploads remain ephemeral.
- **Commit:** [15031da](https://github.com/Varshini986/TrustVault/commit/15031da98678a7520946462b72c7eac29bbdabdc)

## Reused context

The supplied TrustVault challenge and the existing README/threat model were
the reusable task context. No separate repository prompt, agent, or instruction
file was supplied with this snapshot.
