import os
import ipaddress
from functools import wraps
from flask_wtf.csrf import CSRFProtect

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)

from database import (
    initialize_database,
    register_student,
    authenticate_student,
    get_student_progress,
    get_connection,
    ADMIN_PERMISSION_NAMES,
    get_user_role,
    get_admin_permissions,
    owner_set_admin,
    owner_remove_admin,
    login_attempts_blocked,
    record_login_failure,
    clear_login_failures
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required")

app.config["WTF_CSRF_TIME_LIMIT"] = 3600
csrf = CSRFProtect(app)

# Validate the Neon database during application startup.
initialize_database()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "student_id" not in session:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def owner_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "student_id" not in session:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login"))

        with get_connection() as connection:
            user = connection.execute(
                "SELECT role FROM students WHERE id = %s",
                (session["student_id"],)
            ).fetchone()

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        if user["role"] != "owner":
            abort(403)

        return view(*args, **kwargs)
    return wrapped_view


def permission_required(permission):
    if permission not in ADMIN_PERMISSION_NAMES:
        raise ValueError("Unknown admin permission")

    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            student_id = session.get("student_id")

            if student_id is None:
                flash("Please sign in to continue.", "error")
                return redirect(url_for("login"))

            role = get_user_role(student_id)

            if role is None:
                session.clear()
                return redirect(url_for("login"))

            if role == "owner":
                return view(*args, **kwargs)

            if role != "admin":
                abort(403)

            permissions = get_admin_permissions(student_id)

            if not permissions.get(permission, False):
                abort(403)

            return view(*args, **kwargs)

        return wrapped_view
    return decorator


@app.route("/owner")
@owner_required
def owner_dashboard():
    return (
        "<html lang='ar' dir='rtl'><meta charset='UTF-8'>"
        "<h1>لوحة المالك</h1>"
        "<p>تم التحقق من صلاحية المالك.</p>"
        "<a href='/owner/admins'>إدارة المشرفين والصلاحيات</a>"
        "</html>"
    )


@app.route("/owner/admins", methods=["GET", "POST"])
@owner_required
def manage_admins():
    if request.method == "POST":
        action = request.form.get("action", "")
        raw_target_id = request.form.get("target_id", "").strip()

        try:
            target_id = int(raw_target_id)
            if target_id < 1:
                raise ValueError
        except ValueError:
            flash("رقم الحساب غير صالح.", "error")
            return redirect(url_for("manage_admins"))

        if action == "set_admin":
            selected = set(request.form.getlist("permissions"))
            unknown = selected - ADMIN_PERMISSION_NAMES

            if unknown:
                flash("تم إرسال صلاحية غير معروفة.", "error")
            else:
                permissions = {
                    name: name in selected
                    for name in ADMIN_PERMISSION_NAMES
                }
                success, message = owner_set_admin(
                    session["student_id"], target_id, permissions
                )
                flash(message, "success" if success else "error")

        elif action == "remove_admin":
            success, message = owner_remove_admin(
                session["student_id"], target_id
            )
            flash(message, "success" if success else "error")

        else:
            flash("نوع العملية غير صالح.", "error")

        return redirect(url_for("manage_admins"))

    with get_connection() as connection:
        users = connection.execute(
            "SELECT id, username, role FROM students ORDER BY id"
        ).fetchall()

    return render_template(
        "admins.html",
        users=users,
        csrf_token=__import__(
            "flask_wtf.csrf", fromlist=["generate_csrf"]
        ).generate_csrf()
    )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/network-lab")
def network_lab():
    return render_template("labs/network.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        username = request.form.get("username", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        success, message = register_student(full_name, username, email, password)

        if success:
            flash("Account created successfully. Please sign in.", "success")
            return redirect(url_for("login"))

        flash(message, "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        if client_ip in ("127.0.0.1", "::1"):
            try:
                client_ip = str(ipaddress.ip_address(
                    request.headers.get("CF-Connecting-IP", "")
                ))
            except ValueError:
                pass
        login_key = f"{client_ip}:{username.lower()}"

        if login_attempts_blocked(login_key):
            flash("Too many attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429

        student = authenticate_student(username, password)

        if student:
            clear_login_failures(login_key)
            session.clear()
            session["student_id"] = student["id"]
            session["username"] = student["username"]
            return redirect(url_for("dashboard"))

        record_login_failure(login_key)
        flash("Invalid username/email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have signed out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/admin/students")
@permission_required("view_students")
def admin_students():
    with get_connection() as connection:
        users = connection.execute(
            "SELECT id, username, role FROM students ORDER BY id"
        ).fetchall()
    return render_template("admin_students.html", users=users)


@app.route("/dashboard")
@login_required
def dashboard():
    progress = get_student_progress(session["student_id"])

    if progress is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", **progress)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
