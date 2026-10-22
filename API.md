# TrustVault endpoint access

All application endpoints are Flask HTML routes and use the session cookie for
authentication. Every POST form requires a valid Flask-WTF CSRF token. For a
document ID, a missing document and a document the caller cannot read both
return 404. Unauthenticated requests to protected pages redirect to sign-in.

## Roles and document permissions

- **Admin:** system oversight role. Admins can inspect/manage every document,
  manage user roles, and verify the audit chain. This is an intentional
  break-glass access policy and admin actions are audited.
- **Owner:** can upload documents and manage the permissions and lifecycle of
  documents they own.
- **Viewer:** cannot upload. A viewer may read a document with a `read` or
  `edit` grant and may edit its title/category with an `edit` grant.
- **Document owner:** ownership confers read, edit, delete, and grant/revoke
  rights regardless of the account's current global role. A global role change
  does not silently transfer or remove existing document ownership.
- **Edit grantee:** may change document title/category only. Edit does not
  permit deleting the document or changing its grants.

## Routes

| Method | Path | Allowed callers | Behavior |
|---|---|---|---|
| GET | `/` | Anyone | Landing page or redirect to document list |
| GET | `/healthz` | Anyone | Non-sensitive hosting health check (`{"status":"ok"}`) |
| GET, POST | `/register` | Anyone | Creates an `owner`; submitted roles are ignored |
| GET, POST | `/login` | Anyone | Authenticates and creates a session |
| POST | `/logout` | Any signed-in user | Ends the session |
| GET | `/documents` | Any signed-in user | Own and explicitly granted documents; admins see all |
| GET, POST | `/documents/upload` | Owner, admin | Validates and stores a private file |
| GET | `/documents/<id>` | Owner, admin, read/edit grantee | Document metadata and permitted controls |
| GET | `/documents/<id>/download` | Owner, admin, read/edit grantee | Streams the file; response is `private, no-store` |
| GET, POST | `/documents/<id>/edit` | Owner, admin, edit grantee | Changes title/category only |
| POST | `/documents/<id>/permissions` | Owner, admin | Grants `read`/`edit` or revokes a grant |
| POST | `/documents/<id>/delete` | Owner, admin | Deletes document metadata and stored file |
| GET | `/admin` | Admin | Lists users and recent audit events |
| POST | `/admin/users/<id>/role` | Admin | Changes an account role |
| GET | `/admin/audit/verify` | Admin | Verifies the audit hash chain |

## Document-list filters

`GET /documents` accepts `q` (title, original filename, or owner username),
`category`, `from` and `to` (`YYYY-MM-DD`, inclusive). Both result rows and
category options are limited to the caller's accessible documents, except for
admins.

## Authorization and audit behavior

Authorization is enforced by the server on every document route; templates only
hide controls and are not a security boundary. A grant is read from the
database for each request, so revocation blocks subsequent requests. Protected
document attempts that fail authorization are recorded with a denied outcome.
The audit verification page detects edits/deletions within the chain but does
not make the database immutable; see [THREATS.md](./THREATS.md).
