# TrustVault Threat Model

## Assets
- Confidential document contents and metadata
- User credentials and authenticated sessions
- Document-level permission grants
- Audit events used to investigate access

## Trust boundaries
- Browser to Flask backend
- Flask backend to SQLite database
- Flask backend to private file storage
- Administrator actions versus ordinary user actions

## Threats and initial mitigations

### T1 — Insecure direct object reference (IDOR)
**Attack:** A user changes `/documents/12` to `/documents/13`.
**Mitigation:** Every document route loads the document and checks the current user's access on the server. Inaccessible and missing documents return the same 404 response.
**Verification:** `test_ungranted_user_cannot_reach_document_through_any_route` checks list, detail, download, edit, permission-change, and delete routes, including direct POSTs.

### T2 — Access after revocation
**Attack:** A previously authorized viewer reuses a URL after access is revoked.
**Mitigation:** Current grants are checked on every document request; no long-lived public file URLs are issued.
**Verification:** `test_read_grant_download_and_immediate_revoke`; downloads use `Cache-Control: private, no-store`.
**Residual risk:** Revocation prevents subsequent server requests, but cannot recall bytes already downloaded or stop a request already in progress.

### T3 — Privilege escalation
**Attack:** A visitor registers as an administrator or a viewer calls upload/edit endpoints.
**Mitigation:** Public registration always assigns owner; role checks are enforced on protected routes.
**Verification:** `test_viewer_cannot_upload_and_denial_is_audited` and `test_public_registration_cannot_choose_an_admin_role`.

### T4 — Malicious or oversized upload
**Attack:** Upload an executable, a file with a misleading extension, or an oversized file.
**Mitigation:** Extension allowlist, 10 MB request limit, generated storage name, basic signature checks for PDF/images.
**Residual risk:** This does not replace malware scanning, deep content validation, or safe document parsing.
**Verification:** Rejected extensions and oversized requests produce denied audit events.

### T5 — Audit log alteration
**Attack:** A user attempts to edit or delete audit events.
**Mitigation:** No application route permits direct audit editing; records include a previous hash and event hash.
**Residual risk:** A database-level attacker could rewrite the entire chain. Production should sign and export checkpoints to independent append-only storage.
**Verification:** `test_audit_chain_verification_detects_database_tampering`.

### T6 — Session theft or CSRF
**Attack:** Steal a session cookie or trick an authenticated user into submitting a state-changing request.
**Mitigation:** HttpOnly/SameSite session cookie flags, Flask-WTF CSRF protection, HTTPS in deployment.
**Residual risk:** Secure cookies must be enabled behind HTTPS; production also needs session expiration/rotation policy and monitoring.
**Verification:** `test_missing_csrf_token_is_rejected_and_audited`.

### T7 — Credential guessing
**Attack:** Repeated login attempts.
**Mitigation:** Password hashing and generic login errors.
**Residual risk:** Rate limiting and MFA are not implemented in this prototype.

### T8 — Private file exposure
**Attack:** Guess a storage filename or access a static path.
**Mitigation:** Files live outside `static/`, use random storage names, and are delivered only through an authorized route.
**Residual risk:** Host-level file permissions and backups must be secured operationally.

### T9 — An edit grantee widens access or destroys a document
**Attack:** A user with edit access grants access to another account or deletes the file.
**Mitigation:** `edit` permits metadata changes only. Grant/revoke and delete routes require document ownership (or the documented administrator override).
**Verification:** `test_edit_grant_cannot_manage_access_or_delete`.

### T10 — Search facets reveal another user's metadata
**Attack:** A viewer inspects category options or searches guessed document IDs/names to infer private documents.
**Mitigation:** Search rows and category facets are scoped to owned/granted documents; detail/download/edit/permission/delete routes recheck authorization. Query filters include title, original filename, owner and inclusive dates.
**Verification:** `test_search_is_scoped_and_supports_date_filters` checks inaccessible titles/categories and date validation.

### T11 — Reusing cached or previously downloaded content after revocation
**Attack:** A former grantee retries a URL or reuses a browser/shared-cache response after access is revoked.
**Mitigation:** No bearer URLs are issued; downloads authorize against the current grant and send `Cache-Control: private, no-store`.
**Accepted limitation:** No server can revoke a plaintext copy already saved by an authorized user or reliably cancel an in-progress stream.

### T12 — Audit chain fork under concurrent writes
**Attack:** Two application writes read the same previous audit hash and append divergent next events.
**Mitigation:** Audit appends acquire a SQLite `BEGIN IMMEDIATE` write lock before reading the previous hash, serializing chain creation. The detail value is truncated before hashing and storage.
**Accepted limitation:** This depends on SQLite's single-database locking model and does not provide independent immutability or durable off-host backups.

### T13 — Domain change succeeds but audit append fails
**Attack:** A process or disk failure occurs after a document/permission/role mutation commits but before its audit append commits.
**Mitigation:** Audit write failures surface as failed requests; the hash chain is separately verified by administrators.
**Accepted limitation:** Domain mutations and audit appends are not yet one database transaction. A production implementation should append the event in the same transaction as each protected mutation and alert on storage failures.

### T14 — Administrator abuse or compromise
**Attack:** A compromised administrator uses the intentional global override to inspect or change any document.
**Mitigation:** Admin role changes and document operations are audited, public registration cannot create admins, and the console exposes recent events and chain verification.
**Accepted risk:** Admins have broad access by design. Production needs MFA, least-privilege operational roles, independent audit exports, and alerting.

### T15 — Password guessing and public account abuse
**Attack:** An attacker automates registration or guesses passwords.
**Mitigation:** Passwords are hashed, credentials require at least 12 characters, and login failures are audited.
**Accepted risk:** No rate limiting, MFA, invite workflow, or account lockout is implemented.

## Deliberately not built in this prototype
- Public share links
- Folder inheritance
- External identity providers and MFA
- Malware scanning and document sanitization
- Full version history and recovery
- Independent, immutable audit-log storage

## Accepted risks for the hackathon prototype
The prototype prioritizes core access-control behavior and demonstrable tests over production operations. It must not be used for real confidential business data until the residual risks above are addressed.
