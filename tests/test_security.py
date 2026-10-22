import io
import os
import sqlite3
import tempfile
from datetime import date

import pytest

from app import create_app


@pytest.fixture()
def app():
    temp = tempfile.TemporaryDirectory()
    root = temp.name
    application = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key-only",
        "DATABASE": os.path.join(root, "test.sqlite3"),
        "UPLOAD_DIR": os.path.join(root, "uploads"),
    })
    yield application
    temp.cleanup()


def database(app, query, parameters=()):
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        return conn.execute(query, parameters).fetchall()
    finally:
        conn.close()


def register(client, username, password="long-test-password"):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def login(client, username, password="long-test-password"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def upload_text(client, title="Private file", category="Test"):
    return client.post(
        "/documents/upload",
        data={
            "title": title,
            "category": category,
            "file": (io.BytesIO(b"secret contents"), "secret.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def document_id(app):
    return database(app, "SELECT id FROM documents ORDER BY id DESC LIMIT 1")[0][0]


def user_id(app, username):
    return database(app, "SELECT id FROM users WHERE username=?", (username,))[0][0]


def set_role(app, username, role):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    conn.commit()
    conn.close()


def test_ungranted_user_cannot_reach_document_through_any_route(app):
    owner = app.test_client()
    outsider = app.test_client()
    register(owner, "owner_one")
    register(outsider, "outsider_one")
    login(owner, "owner_one")
    assert upload_text(owner, "Secret contract").status_code == 200
    doc_id = document_id(app)
    login(outsider, "outsider_one")

    assert b"Secret contract" not in outsider.get("/documents").data
    assert outsider.get(f"/documents/{doc_id}").status_code == 404
    assert outsider.get(f"/documents/{doc_id}/download").status_code == 404
    assert outsider.get(f"/documents/{doc_id}/edit").status_code == 404
    assert outsider.post(f"/documents/{doc_id}/edit", data={
        "title": "Stolen", "category": "Changed"
    }).status_code == 404
    assert outsider.post(f"/documents/{doc_id}/permissions", data={
        "user_id": user_id(app, "outsider_one"),
        "permission": "edit",
        "action": "grant",
    }).status_code == 404
    assert outsider.post(f"/documents/{doc_id}/delete").status_code == 404

    assert database(app, "SELECT title FROM documents WHERE id=?", (doc_id,))[0][0] == "Secret contract"
    assert len(database(
        app,
        "SELECT id FROM audit_events WHERE actor_id=? AND document_id=? AND outcome='denied'",
        (user_id(app, "outsider_one"), doc_id),
    )) >= 5


def test_read_grant_download_and_immediate_revoke(app):
    owner = app.test_client()
    viewer = app.test_client()
    register(owner, "owner_two")
    register(viewer, "viewer_two")
    login(owner, "owner_two")
    upload_text(owner, "Shared file")
    doc_id = document_id(app)
    viewer_id_value = user_id(app, "viewer_two")

    owner.post(f"/documents/{doc_id}/permissions", data={
        "user_id": viewer_id_value, "permission": "read", "action": "grant"
    })
    login(viewer, "viewer_two")
    allowed = viewer.get(f"/documents/{doc_id}/download")
    assert allowed.status_code == 200
    assert allowed.data == b"secret contents"
    assert allowed.headers["Cache-Control"] == "private, no-store"

    owner.post(f"/documents/{doc_id}/permissions", data={
        "user_id": viewer_id_value, "action": "revoke"
    })
    assert viewer.get(f"/documents/{doc_id}/download").status_code == 404
    assert database(
        app, "SELECT id FROM audit_events WHERE action='revoke_permission' AND target_user_id=?",
        (viewer_id_value,),
    )


def test_edit_grant_cannot_manage_access_or_delete(app):
    owner = app.test_client()
    editor = app.test_client()
    register(owner, "owner_three")
    register(editor, "editor_three")
    login(owner, "owner_three")
    upload_text(owner, "Editable file")
    doc_id = document_id(app)
    editor_id = user_id(app, "editor_three")
    owner.post(f"/documents/{doc_id}/permissions", data={
        "user_id": editor_id, "permission": "edit", "action": "grant"
    })

    login(editor, "editor_three")
    assert editor.get(f"/documents/{doc_id}/edit").status_code == 200
    assert editor.post(f"/documents/{doc_id}/edit", data={
        "title": "Edited title", "category": "Test"
    }).status_code == 302
    assert editor.post(f"/documents/{doc_id}/permissions", data={
        "user_id": editor_id, "permission": "edit", "action": "grant"
    }).status_code == 404
    assert editor.post(f"/documents/{doc_id}/delete").status_code == 404
    assert database(app, "SELECT id FROM documents WHERE id=?", (doc_id,))


def test_viewer_cannot_upload_and_denial_is_audited(app):
    client = app.test_client()
    register(client, "viewer_four")
    set_role(app, "viewer_four", "viewer")
    login(client, "viewer_four")

    assert client.get("/documents/upload").status_code == 403
    assert database(
        app,
        "SELECT id FROM audit_events WHERE action='access_denied' AND outcome='denied'",
    )


def test_public_registration_cannot_choose_an_admin_role(app):
    client = app.test_client()
    response = client.post("/register", data={
        "username": "not_admin",
        "password": "long-test-password",
        "role": "admin",
    })
    assert response.status_code == 302
    assert database(app, "SELECT role FROM users WHERE username='not_admin'")[0][0] == "owner"


def test_invalid_file_extension_is_rejected_and_audited(app):
    client = app.test_client()
    register(client, "owner_five")
    login(client, "owner_five")

    response = client.post("/documents/upload", data={
        "title": "Nope",
        "category": "Test",
        "file": (io.BytesIO(b"executable?"), "bad.exe"),
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"File type not allowed" in response.data
    assert database(
        app,
        "SELECT id FROM audit_events WHERE action='upload' AND outcome='denied'",
    )


def test_oversized_upload_is_rejected_and_audited(app):
    client = app.test_client()
    register(client, "owner_six")
    login(client, "owner_six")

    response = client.post("/documents/upload", data={
        "title": "Too large",
        "category": "Test",
        "file": (io.BytesIO(b"x" * (10 * 1024 * 1024 + 1024)), "large.txt"),
    }, content_type="multipart/form-data")

    assert response.status_code == 413
    assert database(
        app,
        "SELECT id FROM audit_events WHERE action='upload' AND outcome='denied'",
    )


def test_failed_login_is_audited(app):
    client = app.test_client()
    register(client, "owner_six")
    client.post("/login", data={"username": "owner_six", "password": "wrong-password"})
    assert database(
        app,
        "SELECT action,outcome FROM audit_events WHERE action='login' ORDER BY id DESC LIMIT 1",
    ) == [("login", "denied")]


def test_unauthenticated_document_request_is_audited(app):
    owner = app.test_client()
    register(owner, "owner_seven")
    login(owner, "owner_seven")
    upload_text(owner)
    doc_id = document_id(app)

    response = app.test_client().get(f"/documents/{doc_id}/download")
    assert response.status_code == 302
    assert database(
        app,
        "SELECT actor_id,action,outcome,document_id FROM audit_events "
        "WHERE action='access_denied' ORDER BY id DESC LIMIT 1",
    ) == [(None, "access_denied", "denied", doc_id)]


def test_missing_csrf_token_is_rejected_and_audited():
    temp = tempfile.TemporaryDirectory()
    root = temp.name
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "csrf-test-secret",
        "DATABASE": os.path.join(root, "test.sqlite3"),
        "UPLOAD_DIR": os.path.join(root, "uploads"),
    })
    response = application.test_client().post("/documents/93/delete")

    assert response.status_code == 400
    assert database(
        application,
        "SELECT actor_id,action,outcome,document_id FROM audit_events "
        "ORDER BY id DESC LIMIT 1",
    ) == [(None, "csrf_denied", "denied", 93)]
    temp.cleanup()


def test_search_is_scoped_and_supports_date_filters(app):
    first = app.test_client()
    second = app.test_client()
    register(first, "owner_eight")
    register(second, "owner_nine")
    login(first, "owner_eight")
    upload_text(first, "Visible report", "Visible category")
    login(second, "owner_nine")
    upload_text(second, "Hidden report", "Private category")

    page = first.get(
        f"/documents?from={date.today().isoformat()}&to={date.today().isoformat()}"
    )
    assert b"Visible report" in page.data
    assert b"Hidden report" not in page.data
    assert b"Private category" not in page.data
    assert first.get("/documents?from=not-a-date").status_code == 400
    assert first.get("/documents?from=2026-1-1").status_code == 400
    assert first.get("/documents?from=2026-02-02&to=2026-01-01").status_code == 400


def test_admin_policy_can_view_all_documents_and_admin_activity(app):
    owner = app.test_client()
    admin = app.test_client()
    register(owner, "owner_ten")
    login(owner, "owner_ten")
    upload_text(owner, "Admin-reviewed report")
    register(admin, "admin_ten")
    set_role(app, "admin_ten", "admin")
    login(admin, "admin_ten")

    assert b"Admin-reviewed report" in admin.get("/documents").data
    assert admin.get(f"/documents/{document_id(app)}").status_code == 200
    assert admin.get("/admin").status_code == 200


def test_audit_chain_verification_detects_database_tampering(app):
    client = app.test_client()
    register(client, "admin_eleven")
    set_role(app, "admin_eleven", "admin")
    login(client, "admin_eleven")
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute(
        "UPDATE audit_events SET details='tampered' WHERE id="
        "(SELECT MIN(id) FROM audit_events)"
    )
    conn.commit()
    conn.close()

    response = client.get("/admin/audit/verify")
    assert response.status_code == 200
    assert b"Integrity check failed" in response.data
