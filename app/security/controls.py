from pathlib import PurePath

from werkzeug.utils import secure_filename

ALLOWED_RESUME_EXTENSIONS = {"pdf", "doc", "docx"}
MAX_RESUME_BYTES = 5 * 1024 * 1024


def validate_resume_upload(filename, content_length):
    if not isinstance(filename, str) or not filename.strip():
        return False, None, "Choose a file with a name."
    safe_name = secure_filename(PurePath(filename.replace("\\", "/")).name)
    if not safe_name or "." not in safe_name:
        return False, None, "The file must have an allowed extension."
    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_RESUME_EXTENSIONS:
        return False, None, "Only PDF, DOC, or DOCX resumes are allowed."
    if not isinstance(content_length, int) or content_length <= 0 or content_length > MAX_RESUME_BYTES:
        return False, None, "The file must be between 1 byte and 5 MB."
    return True, safe_name, "File passed the extension and size checks."


def owns_resource(owner_id, current_user_id):
    return owner_id is not None and current_user_id is not None and owner_id == current_user_id


def parameterized_lookup(email):
    import sqlite3

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE applicants (email TEXT, name TEXT)")
        connection.executemany(
            "INSERT INTO applicants (email, name) VALUES (?, ?)",
            [("student@example.edu", "Sample Student"), ("reviewer@example.edu", "Sample Reviewer")],
        )
        return connection.execute(
            "SELECT name FROM applicants WHERE email = ?", (email,)
        ).fetchall()
    finally:
        connection.close()
