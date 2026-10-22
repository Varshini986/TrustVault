# Render demo deployment

This blueprint creates a free Render web service for demonstration. It is
deliberately a **throwaway demo deployment**, not a place for real company
documents: Render's free service has an ephemeral filesystem, so the SQLite
database and uploaded documents can disappear after a restart or redeploy.
The free service can also sleep while idle. There is no persistent disk in
this setup.

## Deploy

1. Sign in to Render and choose **New > Blueprint**.
2. Connect `Varshini986/TrustVault` and select its `main` branch.
3. Review `render.yaml` and create the service. The blueprint generates a
   persistent Flask secret and unique passwords for the three demo accounts.
4. Wait for the first deploy to finish. Open the service's **Environment**
   page and note the generated values for the demo password variables. These
   are secrets; do not paste them into chat or a public issue.
5. Open the service URL. `/healthz` should return `{"status":"ok"}`. Sign in
   using the corresponding username and generated password below.

| Role | Username | Password setting |
|---|---|---|
| Administrator | `demo-admin` | `TRUSTVAULT_DEMO_ADMIN_PASSWORD` |
| Document owner | `demo-owner` | `TRUSTVAULT_DEMO_OWNER_PASSWORD` |
| Viewer | `demo-viewer` | `TRUSTVAULT_DEMO_VIEWER_PASSWORD` |

The owner has a synthetic `Demo: Quarterly planning` text file, shared with
the viewer as read-only. The seed runs only when the database has no users,
and does not reset accounts or data on subsequent starts. When Render's
ephemeral filesystem is replaced, the app starts with a fresh database and
seeds the demo again.

The generated passwords are intentionally not committed here. If the
evaluation requires credentials in the README, copy the generated values from
your Render dashboard yourself, and label them as demo-only. Because the
repository is public, anybody can read credentials committed to it. Keep the
service limited to synthetic data and rotate the passwords after evaluation.

## Configuration and accepted limitations

- `TRUSTVAULT_SECRET_KEY` is generated once by Render and must remain stable
  while the service uses the same data.
- `TRUSTVAULT_HTTPS=1` enables secure session cookies behind Render's HTTPS
  proxy.
- `TRUSTVAULT_DEMO_SEED=1` enables initial synthetic accounts and document.
  Startup fails explicitly if any configured demo password is missing or
  shorter than 12 characters.
- `gunicorn` runs one worker to keep SQLite locking behavior predictable. Do
  not scale this setup to multiple instances.
- SQLite, uploaded files, audit chain, and grants are local to the ephemeral
  service. There are no backup or recovery guarantees.
- A downloaded copy cannot be revoked. Do not upload any real, sensitive, or
  personal data to this instance.

For a durable deployment, move relational data to managed PostgreSQL, document
blobs to private object storage, and audit checkpoints to independently
controlled append-only storage. That production architecture is deliberately
not configured in this free demo.
