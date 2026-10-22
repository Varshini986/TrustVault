# TrustVault — Secure Document Vault (Hackathon Starter)

A local Flask prototype for secure document management, per-document permissions, and an audit trail.

## Requirements
- Python 3.10+
- pip

## 1. Create a virtual environment

### Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt:
```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 2. Set a persistent secret key

For a local PowerShell session:
```powershell
$env:TRUSTVAULT_SECRET_KEY = "replace-this-with-a-long-random-secret"
```

For macOS/Linux:
```bash
export TRUSTVAULT_SECRET_KEY="replace-this-with-a-long-random-secret"
```

Do not commit a production secret to Git. Set `TRUSTVAULT_HTTPS=1` only when running behind HTTPS.

## 3. Start the application
```bash
python app.py
```
Open http://127.0.0.1:5000

Register an account. Public registration creates `owner` accounts only; it cannot create an administrator.
The SQLite database is initialized automatically from [`schema.sql`](./schema.sql) on startup.

## 4. Create the first administrator (local development only)

Stop the app, then run this command from the project directory. Replace `your_username` with your registered username:
```bash
python -c "import sqlite3; c=sqlite3.connect('instance/trustvault.sqlite3'); c.execute(\"UPDATE users SET role='admin' WHERE username='your_username'\"); c.commit(); c.close()"
```
Restart the app and sign in again. This is a local bootstrap shortcut, not a production admin-provisioning process.

To test a viewer account, use the admin console to change a second user's role to Viewer. Owners can grant per-document Read or Edit access to non-admin accounts.

## Permission model

- **Admin:** operational break-glass access to every document, account roles,
  recent activity, and audit verification. Admin access is intentional and
  each document operation is recorded.
- **Owner:** can upload documents and manage/delete documents they own.
- **Viewer:** cannot upload. A read grant allows viewing/downloading; an edit
  grant additionally allows changing the title and category.
- **Document ownership** stays with the owner if their account role changes.
  An edit grantee cannot delete a document or grant/revoke other people's
  access. Only the document owner or an administrator can manage grants.

Every document request checks the current database permission; there are no
public file URLs. Downloads set `Cache-Control: private, no-store`. This stops
browser/shared-cache reuse, but cannot erase a copy someone already downloaded.
See [API.md](./API.md) for the endpoint authorization matrix.

## 5. Run automated tests
```bash
python -m pytest -q
```

The tests cover cross-user access through document routes, grant/revoke
behavior, editor privilege boundaries, viewer upload restrictions, search
isolation/date filters, rejected file extensions, denied-access audit events,
admin policy, and audit-chain tampering.

## What is implemented
- Password hashing and session cookies with HttpOnly and SameSite settings
- CSRF protection on forms
- Owner/admin/viewer roles
- Private file storage, generated storage names, size limit and extension allowlist
- Basic file signature checks for PDF and common images
- Per-document read/edit grants
- Server-side authorization on detail, download, edit, delete and permission routes
- Audit events including denied access attempts
- SHA-256 hash chain verification page
- Search by title/owner and category
- Admin user-role view and recent audit events
- Date-range search and caller-scoped category options

## Security notes — read before deployment
This is a hackathon prototype, not a production-certified document vault.

1. The audit hash chain is tamper-evident but not immutable if an attacker can rewrite the database and recompute the chain. Production should export signed checkpoints to separately controlled append-only storage.
2. File validation is basic. Extension/signature checks are not malware scanning and do not safely parse every format. Consider quarantine, malware scanning, and content-disarm/reconstruction for risky file types.
3. The app uses SQLite and local disk. Production requires backups, access-controlled storage, encryption-at-rest/key management, monitoring, secure deployment, and a documented recovery plan.
4. Public registration makes owners. A real organization should use an invite/admin approval workflow.
5. The current prototype's administrator can read documents and edit metadata by policy. Decide whether your deployment should instead require explicit grants for administrators and update tests/policy accordingly.
6. No rate limiting, MFA, account recovery, or external identity provider is included yet.
7. Use HTTPS in deployment, set a stable secret key, disable debug mode, and run behind a production WSGI server.
8. Uploads are limited to 10 MB. DOCX and CSV content are not deeply inspected in this prototype.
9. Audit events are written by the app. A production design should protect logs against privileged tampering and include request IDs, client/network context where lawful, and retention controls.

## Project documentation and remaining delivery

- **Live demo:** https://trustvault-demo-8fuc.onrender.com/
  The public health check is https://trustvault-demo-8fuc.onrender.com/healthz.
  Free-tier data is temporary; do not upload real confidential documents.
- Seeded sign-in usernames: `demo-admin` (administrator), `demo-owner`
  (document owner), and `demo-viewer` (read-only grantee). Their generated
  passwords are in the matching `TRUSTVAULT_DEMO_*_PASSWORD` variables in the
  Render service environment. They are intentionally not published in this
  public README; use synthetic content only.
- [API.md](./API.md) documents routes and who may call them.
- [THREATS.md](./THREATS.md) records mitigations and accepted risks.
- [PROMPTS.md](./PROMPTS.md) records the available AI-assisted work history.
- See [DEPLOYMENT.md](./DEPLOYMENT.md) for deploy configuration and free-tier
  limitations. A demo video and submission-form write-up are not included.

## Deliberately not built

- Public share links, folders/inherited permissions, and external identity
  providers/MFA
- Malware scanning, document sanitization, version history, and recovery
- Independent immutable audit storage, automated deployments, and hosted
  backups

## License
Hackathon starter; adapt as needed.
