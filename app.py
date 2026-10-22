import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    send_file, session, url_for
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TRUSTVAULT_DB", ROOT / "instance" / "trustvault.sqlite3"))
UPLOAD_DIR = Path(os.environ.get("TRUSTVAULT_UPLOAD_DIR", ROOT / "private_uploads"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx", ".csv"}

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("TRUSTVAULT_HTTPS", "0") == "1",
        DEMO_SEED_ENABLED=os.environ.get("TRUSTVAULT_DEMO_SEED", "0") == "1",
        DEMO_ADMIN_PASSWORD=os.environ.get("TRUSTVAULT_DEMO_ADMIN_PASSWORD"),
        DEMO_OWNER_PASSWORD=os.environ.get("TRUSTVAULT_DEMO_OWNER_PASSWORD"),
        DEMO_VIEWER_PASSWORD=os.environ.get("TRUSTVAULT_DEMO_VIEWER_PASSWORD"),
    )
    if test_config:
        app.config.update(test_config)

    db_path = Path(app.config.get("DATABASE", DB_PATH))
    upload_dir = Path(app.config.get("UPLOAD_DIR", UPLOAD_DIR))
    upload_dir.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    app.config["DATABASE"] = str(db_path)
    app.config["UPLOAD_DIR"] = str(upload_dir)
    CSRFProtect(app)

    def connect_db():
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db():
        conn = connect_db()
        schema = ROOT / "schema.sql"
        conn.executescript(schema.read_text(encoding="utf-8"))
        conn.commit()
        conn.close()

    def now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def audit(actor_id, action, document_id=None, target_user_id=None,
              outcome="success", details=""):
        """Append-only application audit event with a hash chain.
        This is tamper-evident for ordinary application-level changes, not
        immutable against an attacker who can rewrite the database and hashes.
        """
        conn = connect_db()
        conn.execute("BEGIN IMMEDIATE")
        last = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = last["event_hash"] if last else "GENESIS"
        created = now()
        details = details[:500]
        payload = "|".join([
            str(actor_id or ""), action, str(document_id or ""),
            str(target_user_id or ""), outcome, details, created, previous
        ])
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        conn.execute("""INSERT INTO audit_events
            (actor_id, action, document_id, target_user_id, outcome, details,
             created_at, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (actor_id, action, document_id, target_user_id, outcome,
             details, created, previous, digest))
        conn.commit()
        conn.close()

    def seed_demo():
        if not app.config["DEMO_SEED_ENABLED"]:
            return

        passwords = {
            "demo-admin": app.config["DEMO_ADMIN_PASSWORD"],
            "demo-owner": app.config["DEMO_OWNER_PASSWORD"],
            "demo-viewer": app.config["DEMO_VIEWER_PASSWORD"],
        }
        if any(not value or len(value) < 12 for value in passwords.values()):
            raise RuntimeError(
                "Demo seeding requires TRUSTVAULT_DEMO_ADMIN_PASSWORD, "
                "TRUSTVAULT_DEMO_OWNER_PASSWORD, and "
                "TRUSTVAULT_DEMO_VIEWER_PASSWORD with at least 12 characters each."
            )

        conn = connect_db()
        if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            conn.close()
            return

        created = now()
        user_ids = {}
        sample = (
            b"TrustVault synthetic demonstration file. "
            b"Contains no real confidential information.\n"
        )
        stored_name = secrets.token_hex(24) + ".txt"
        sample_path = Path(app.config["UPLOAD_DIR"]) / stored_name
        sample_path.write_bytes(sample)
        try:
            conn.execute("BEGIN IMMEDIATE")
            for username, role in (
                ("demo-admin", "admin"),
                ("demo-owner", "owner"),
                ("demo-viewer", "viewer"),
            ):
                cursor = conn.execute(
                    "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                    (username, generate_password_hash(passwords[username]), role, created),
                )
                user_ids[username] = cursor.lastrowid

            cursor = conn.execute("""INSERT INTO documents
                (owner_id,title,original_name,stored_name,category,file_size,sha256,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (user_ids["demo-owner"], "Demo: Quarterly planning",
                 "demo-planning.txt", stored_name, "Demo", len(sample),
                 hashlib.sha256(sample).hexdigest(), created, created))
            doc_id = cursor.lastrowid
            conn.execute("""INSERT INTO grants(document_id,user_id,permission,created_at)
                VALUES(?,?,?,?)""",
                (doc_id, user_ids["demo-viewer"], "read", created))
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            sample_path.unlink(missing_ok=True)
            conn.close()
            raise
        conn.close()

        audit(user_ids["demo-admin"], "demo_seed", details="Created demo accounts")
        audit(user_ids["demo-owner"], "upload", doc_id, details="Seeded synthetic demo document")
        audit(user_ids["demo-owner"], "grant_permission", doc_id,
              target_user_id=user_ids["demo-viewer"], details="Seeded read grant")

    def current_user():
        if "user_id" not in session:
            return None
        conn = connect_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        conn.close()
        return user

    @app.before_request
    def load_user():
        g.user = current_user()

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not g.user:
                audit(None, "access_denied", kwargs.get("doc_id"),
                      outcome="denied", details=f"Unauthenticated request to {request.endpoint}")
                flash("Please sign in first.", "warning")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def roles_required(*roles):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not g.user:
                    audit(None, "access_denied", kwargs.get("doc_id"),
                          outcome="denied", details=f"Unauthenticated request to {request.endpoint}")
                    flash("Please sign in first.", "warning")
                    return redirect(url_for("login"))
                if g.user["role"] not in roles:
                    audit(g.user["id"], "access_denied", kwargs.get("doc_id"),
                          outcome="denied", details=f"Role {g.user['role']} denied for {request.endpoint}")
                    abort(403)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def get_document(doc_id):
        conn = connect_db()
        doc = conn.execute("""
            SELECT d.*, u.username AS owner_name
            FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?
        """, (doc_id,)).fetchone()
        conn.close()
        return doc

    def permission_for(user, doc):
        if not user or not doc:
            return None
        if user["role"] == "admin" or user["id"] == doc["owner_id"]:
            return "edit"
        conn = connect_db()
        row = conn.execute(
            "SELECT permission FROM grants WHERE document_id=? AND user_id=?",
            (doc["id"], user["id"])
        ).fetchone()
        conn.close()
        return row["permission"] if row else None

    def can_read(user, doc):
        return permission_for(user, doc) in ("read", "edit")

    def can_edit(user, doc):
        return permission_for(user, doc) == "edit"

    def can_manage(user, doc):
        return bool(user and doc and (
            user["role"] == "admin" or user["id"] == doc["owner_id"]
        ))

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("documents"))
        return render_template("index.html")

    @app.route("/healthz")
    def health_check():
        return jsonify(status="ok")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            # Public registration deliberately cannot create an administrator.
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
                flash("Username must be 3–30 characters: letters, numbers, dot, dash or underscore.", "danger")
                return render_template("register.html")
            if len(password) < 12:
                flash("Use a password with at least 12 characters.", "danger")
                return render_template("register.html")
            conn = connect_db()
            try:
                conn.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                             (username, generate_password_hash(password), "owner", now()))
                conn.commit()
            except sqlite3.IntegrityError:
                flash("That username is already registered.", "danger")
                conn.close()
                return render_template("register.html")
            user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
            conn.close()
            audit(user_id, "register", outcome="success", details="New owner account")
            flash("Account created. You can now sign in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            conn = connect_db()
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            conn.close()
            if not user or not check_password_hash(user["password_hash"], password):
                audit(user["id"] if user else None, "login", outcome="denied",
                      details=f"Failed login for username={username[:80]}")
                flash("Invalid username or password.", "danger")
                return render_template("login.html")
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            audit(user["id"], "login", details="Successful login")
            return redirect(url_for("documents"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        audit(g.user["id"], "logout", details="User signed out")
        session.clear()
        flash("You have signed out.", "success")
        return redirect(url_for("index"))

    @app.route("/documents")
    @login_required
    def documents():
        search = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "").strip()[:60]
        start_date = request.args.get("from", "").strip()
        end_date = request.args.get("to", "").strip()
        for value in (start_date, end_date):
            if value:
                try:
                    parsed_date = datetime.strptime(value, "%Y-%m-%d")
                except ValueError:
                    abort(400)
                if parsed_date.date().isoformat() != value:
                    abort(400)
        if start_date and end_date and start_date > end_date:
            abort(400)

        conn = connect_db()
        if g.user["role"] == "admin":
            scope = "1=1"
            scope_params = []
        else:
            scope = """(d.owner_id=? OR EXISTS (
                SELECT 1 FROM grants gr WHERE gr.document_id=d.id AND gr.user_id=?
            ))"""
            scope_params = [g.user["id"], g.user["id"]]
        sql = f"""SELECT d.*, u.username AS owner_name
                  FROM documents d JOIN users u ON u.id=d.owner_id
                  WHERE {scope}"""
        params = list(scope_params)
        if search:
            sql += " AND (d.title LIKE ? OR d.original_name LIKE ? OR u.username LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        if category:
            sql += " AND d.category=?"
            params.append(category)
        if start_date:
            sql += " AND substr(d.created_at,1,10)>=?"
            params.append(start_date)
        if end_date:
            sql += " AND substr(d.created_at,1,10)<=?"
            params.append(end_date)
        sql += " ORDER BY d.created_at DESC"
        rows = conn.execute(sql, params).fetchall()
        cats = conn.execute(
            f"""SELECT DISTINCT d.category FROM documents d
                WHERE {scope} ORDER BY d.category""",
            scope_params
        ).fetchall()
        conn.close()
        return render_template("documents.html", documents=rows, q=search,
                               category=category, categories=[r["category"] for r in cats],
                               start_date=start_date, end_date=end_date)

    @app.route("/documents/upload", methods=["GET", "POST"])
    @roles_required("admin", "owner")
    def upload():
        if request.method == "POST":
            file = request.files.get("file")
            title = request.form.get("title", "").strip()[:120]
            category = request.form.get("category", "General").strip()[:60] or "General"
            if not file or not file.filename:
                flash("Choose a file to upload.", "danger")
                audit(g.user["id"], "upload", outcome="denied", details="No file selected")
                return render_template("upload.html")
            safe_name = secure_filename(file.filename)
            ext = Path(safe_name).suffix.lower()
            if not safe_name or ext not in ALLOWED_EXTENSIONS:
                flash("File type not allowed. Allowed: PDF, TXT, PNG, JPG, DOCX, CSV.", "danger")
                audit(g.user["id"], "upload", outcome="denied", details="Rejected file extension")
                return render_template("upload.html")
            content = file.read(MAX_UPLOAD_BYTES + 1)
            if len(content) > MAX_UPLOAD_BYTES:
                flash("File exceeds 10 MB limit.", "danger")
                audit(g.user["id"], "upload", outcome="denied", details="Upload exceeded size limit")
                return render_template("upload.html")
            if not content:
                flash("Empty files are not allowed.", "danger")
                audit(g.user["id"], "upload", outcome="denied", details="Empty file rejected")
                return render_template("upload.html")
            # Basic signature checks for common formats; extension alone is not trusted.
            signatures = {".pdf": content.startswith(b"%PDF-"),
                          ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
                          ".jpg": content.startswith(b"\xff\xd8\xff"),
                          ".jpeg": content.startswith(b"\xff\xd8\xff")}
            if ext in signatures and not signatures[ext]:
                flash("File content does not match its extension.", "danger")
                audit(g.user["id"], "upload", outcome="denied", details="Signature mismatch")
                return render_template("upload.html")
            stored = secrets.token_hex(24) + ext
            target = Path(app.config["UPLOAD_DIR"]) / stored
            target.write_bytes(content)
            stamp = now()
            conn = connect_db()
            cur = conn.execute("""INSERT INTO documents
                (owner_id,title,original_name,stored_name,category,file_size,sha256,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (g.user["id"], title or safe_name, safe_name, stored, category,
                 len(content), hashlib.sha256(content).hexdigest(), stamp, stamp))
            doc_id = cur.lastrowid
            conn.commit()
            conn.close()
            audit(g.user["id"], "upload", doc_id, details=f"Uploaded {safe_name}")
            flash("Document uploaded securely.", "success")
            return redirect(url_for("document_detail", doc_id=doc_id))
        return render_template("upload.html")

    @app.route("/documents/<int:doc_id>")
    @login_required
    def document_detail(doc_id):
        doc = get_document(doc_id)
        if not doc or not can_read(g.user, doc):
            audit(g.user["id"], "read_metadata", doc_id, outcome="denied",
                  details="Missing document or read grant")
            abort(404)  # Avoid disclosing whether an inaccessible document exists.
        audit(g.user["id"], "read_metadata", doc_id, details="Opened document detail")
        conn = connect_db()
        grants = conn.execute("""SELECT gr.user_id, gr.permission, u.username
            FROM grants gr JOIN users u ON u.id=gr.user_id
            WHERE gr.document_id=? ORDER BY u.username""", (doc_id,)).fetchall() if can_manage(g.user, doc) else []
        users = conn.execute("SELECT id, username, role FROM users WHERE id != ? ORDER BY username",
                             (doc["owner_id"],)).fetchall() if can_manage(g.user, doc) else []
        conn.close()
        return render_template("document_detail.html", doc=doc, grants=grants,
                               users=users, can_edit=can_edit(g.user, doc),
                               can_manage=can_manage(g.user, doc),
                               my_permission=permission_for(g.user, doc))

    @app.route("/documents/<int:doc_id>/download")
    @login_required
    def download(doc_id):
        doc = get_document(doc_id)
        if not doc or not can_read(g.user, doc):
            audit(g.user["id"], "download", doc_id, outcome="denied",
                  details="Missing document or read grant")
            abort(404)
        path = Path(app.config["UPLOAD_DIR"]) / doc["stored_name"]
        if not path.is_file():
            audit(g.user["id"], "download", doc_id, outcome="error", details="Stored file missing")
            abort(404)
        audit(g.user["id"], "download", doc_id, details="Authorized download")
        response = send_file(path, as_attachment=True, download_name=doc["original_name"])
        response.headers["Cache-Control"] = "private, no-store"
        return response

    @app.route("/documents/<int:doc_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_document(doc_id):
        doc = get_document(doc_id)
        if not doc or not can_edit(g.user, doc):
            audit(g.user["id"], "edit_metadata", doc_id, outcome="denied",
                  details="Missing document or edit grant")
            abort(404)
        if request.method == "POST":
            title = request.form.get("title", "").strip()[:120]
            category = request.form.get("category", "General").strip()[:60] or "General"
            if not title:
                flash("Title is required.", "danger")
                return render_template("edit_document.html", doc=doc)
            conn = connect_db()
            conn.execute("UPDATE documents SET title=?, category=?, updated_at=? WHERE id=?",
                         (title, category, now(), doc_id))
            conn.commit()
            conn.close()
            audit(g.user["id"], "edit_metadata", doc_id, details="Updated title/category")
            flash("Document details updated.", "success")
            return redirect(url_for("document_detail", doc_id=doc_id))
        return render_template("edit_document.html", doc=doc)

    @app.route("/documents/<int:doc_id>/permissions", methods=["POST"])
    @login_required
    def change_permission(doc_id):
        doc = get_document(doc_id)
        if not doc or not can_manage(g.user, doc):
            audit(g.user["id"], "change_permission", doc_id, outcome="denied",
                  details="Missing document or document manager permission")
            abort(404)
        user_id = request.form.get("user_id", type=int)
        permission = request.form.get("permission", "")
        action = request.form.get("action", "grant")
        conn = connect_db()
        target = conn.execute("SELECT id, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not target or target["id"] == doc["owner_id"] or target["role"] == "admin":
            conn.close()
            audit(g.user["id"], "change_permission", doc_id, target_user_id=user_id,
                  outcome="denied", details="Invalid permission target")
            flash("Choose a valid non-owner, non-admin account.", "danger")
            return redirect(url_for("document_detail", doc_id=doc_id))
        if action == "revoke":
            conn.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc_id, user_id))
            audit_action = "revoke_permission"
            detail = "Revoked access"
        elif action == "grant" and permission in ("read", "edit"):
            conn.execute("""INSERT INTO grants(document_id,user_id,permission,created_at)
                VALUES(?,?,?,?) ON CONFLICT(document_id,user_id)
                DO UPDATE SET permission=excluded.permission, created_at=excluded.created_at""",
                (doc_id, user_id, permission, now()))
            audit_action = "grant_permission"
            detail = f"Granted {permission}"
        else:
            conn.close()
            audit(g.user["id"], "change_permission", doc_id, target_user_id=user_id,
                  outcome="denied", details="Invalid permission or action")
            flash("Invalid permission.", "danger")
            return redirect(url_for("document_detail", doc_id=doc_id))
        conn.commit()
        conn.close()
        audit(g.user["id"], audit_action, doc_id, target_user_id=user_id, details=detail)
        flash("Permissions updated.", "success")
        return redirect(url_for("document_detail", doc_id=doc_id))

    @app.route("/documents/<int:doc_id>/delete", methods=["POST"])
    @login_required
    def delete_document(doc_id):
        doc = get_document(doc_id)
        if not doc or not can_manage(g.user, doc):
            audit(g.user["id"], "delete", doc_id, outcome="denied",
                  details="Missing document or document manager permission")
            abort(404)
        conn = connect_db()
        conn.execute("DELETE FROM documents WHERE id=?", (doc_id,))
        conn.commit()
        conn.close()
        path = Path(app.config["UPLOAD_DIR"]) / doc["stored_name"]
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            audit(g.user["id"], "delete", doc_id, outcome="error",
                  details=f"Document record deleted; file cleanup failed ({type(error).__name__})")
            flash("Document record deleted, but stored-file cleanup failed. Contact an administrator.", "danger")
        else:
            audit(g.user["id"], "delete", doc_id, details="Deleted document and stored file")
            flash("Document deleted.", "success")
        return redirect(url_for("documents"))

    @app.route("/admin")
    @roles_required("admin")
    def admin():
        conn = connect_db()
        users = conn.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
        events = conn.execute("""SELECT a.*, u.username AS actor_name
            FROM audit_events a LEFT JOIN users u ON u.id=a.actor_id
            ORDER BY a.id DESC LIMIT 200""").fetchall()
        conn.close()
        return render_template("admin.html", users=users, events=events)

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @roles_required("admin")
    def set_role(user_id):
        role = request.form.get("role", "")
        if role not in ("admin", "owner", "viewer"):
            abort(400)
        if user_id == g.user["id"] and role != "admin":
            flash("You cannot remove your own administrator role here.", "danger")
            return redirect(url_for("admin"))
        conn = connect_db()
        target = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            conn.close()
            abort(404)
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        conn.commit()
        conn.close()
        audit(g.user["id"], "change_role", target_user_id=user_id, details=f"Set role to {role}")
        flash("User role updated.", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/audit/verify")
    @roles_required("admin")
    def verify_audit():
        conn = connect_db()
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        conn.close()
        previous = "GENESIS"
        valid = True
        for row in rows:
            payload = "|".join([
                str(row["actor_id"] or ""), row["action"], str(row["document_id"] or ""),
                str(row["target_user_id"] or ""), row["outcome"], row["details"],
                row["created_at"], previous
            ])
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous or not hmac.compare_digest(row["event_hash"], expected):
                valid = False
                break
            previous = row["event_hash"]
        return render_template("audit_verify.html", valid=valid, count=len(rows))

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, message="You do not have permission to perform this action."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="This resource was not found or you do not have access."), 404

    @app.errorhandler(413)
    def too_large(_):
        user = getattr(g, "user", None)
        is_upload = request.endpoint == "upload"
        audit(user["id"] if user else None,
              "upload" if is_upload else "request_rejected",
              outcome="denied", details="Request exceeded size limit")
        message = "Upload exceeds the 10 MB limit." if is_upload else "Request exceeds the allowed size."
        return render_template("error.html", code=413, message=message), 413

    @app.errorhandler(CSRFError)
    def csrf_rejected(_):
        user = current_user()
        view_args = request.view_args or {}
        audit(user["id"] if user else None, "csrf_denied", view_args.get("doc_id"),
              outcome="denied", details=f"CSRF validation failed at {request.endpoint}")
        return render_template("error.html", code=400,
                               message="The form token is missing or invalid. Reload the page and try again."), 400

    with app.app_context():
        init_db()
        seed_demo()
    return app

app = create_app()

if __name__ == "__main__":
    # Local development only. Use a production WSGI server for deployment.
    app.run(debug=False)
