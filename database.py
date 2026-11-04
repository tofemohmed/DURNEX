import os
import time

import psycopg
from psycopg.rows import dict_row
from werkzeug.security import generate_password_hash, check_password_hash


ADMIN_PERMISSION_NAMES = {
    "view_students",
    "view_grades",
    "manage_students",
    "delete_students",
    "manage_lessons",
    "manage_quizzes",
    "manage_admins",
    "manage_settings",
}


def get_connection():
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")

    return psycopg.connect(database_url, row_factory=dict_row)


def initialize_database():
    required_tables = {
        "students",
        "admin_permissions",
        "admin_audit_log",
        "quiz_results",
        "lesson_progress",
        "login_attempts",
    }

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
        """).fetchall()

        existing_tables = {row["tablename"] for row in rows}
        missing_tables = required_tables - existing_tables

        if missing_tables:
            raise RuntimeError(
                f"Missing database tables: {', '.join(sorted(missing_tables))}"
            )


def register_student(full_name, username, email, password):
    full_name = full_name.strip()
    username = username.strip()
    email = email.strip().lower()

    if not full_name or not username or not email or not password:
        return False, "All fields are required."

    if len(full_name) < 3:
        return False, "Full name must contain at least 3 characters."

    if len(username) < 3:
        return False, "Username must contain at least 3 characters."

    if len(password) < 12:
        return False, "Password must contain at least 12 characters."

    password_hash = generate_password_hash(password)

    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO students
                    (full_name, username, email, password_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (full_name, username, email, password_hash),
            )

        return True, "Account created successfully."

    except psycopg.IntegrityError:
        return False, "Username or email is already registered."


def authenticate_student(username_or_email, password):
    identifier = username_or_email.strip()

    with get_connection() as connection:
        student = connection.execute(
            """
            SELECT *
            FROM students
            WHERE LOWER(username) = LOWER(%s)
               OR LOWER(email) = LOWER(%s)
            """,
            (identifier, identifier),
        ).fetchone()

    if student and check_password_hash(student["password_hash"], password):
        return dict(student)

    return None


def save_quiz_result(student_id, quiz_name, score, total_questions):
    if total_questions <= 0 or score < 0 or score > total_questions:
        raise ValueError("Invalid quiz score.")

    with get_connection() as connection:
        student = connection.execute(
            "SELECT id FROM students WHERE id = %s",
            (student_id,),
        ).fetchone()

        if student is None:
            raise ValueError("Student does not exist.")

        connection.execute(
            """
            INSERT INTO quiz_results
                (student_id, quiz_name, score, total_questions)
            VALUES (%s, %s, %s, %s)
            """,
            (student_id, quiz_name, score, total_questions),
        )


def get_student_progress(student_id):
    with get_connection() as connection:
        student = connection.execute(
            """
            SELECT id, full_name, username, email, level, created_at
            FROM students
            WHERE id = %s
            """,
            (student_id,),
        ).fetchone()

        if student is None:
            return None

        results = connection.execute(
            """
            SELECT quiz_name, score, total_questions, completed_at
            FROM quiz_results
            WHERE student_id = %s
            ORDER BY id DESC
            """,
            (student_id,),
        ).fetchall()

        lessons = connection.execute(
            """
            SELECT lesson_name, completed, completed_at
            FROM lesson_progress
            WHERE student_id = %s
            ORDER BY id
            """,
            (student_id,),
        ).fetchall()

    return {
        "student": dict(student),
        "quiz_results": [dict(row) for row in results],
        "lessons": [dict(row) for row in lessons],
    }


def update_student_level(student_id, new_level):
    if new_level not in {"Beginner", "Intermediate", "Advanced"}:
        raise ValueError("Invalid learning level.")

    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE students SET level = %s WHERE id = %s",
            (new_level, student_id),
        )

        return cursor.rowcount == 1


def get_user_role(student_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT role FROM students WHERE id = %s",
            (student_id,),
        ).fetchone()

    return row["role"] if row else None


def get_admin_permissions(student_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM admin_permissions WHERE student_id = %s",
            (student_id,),
        ).fetchone()

    if row is None:
        return {name: False for name in ADMIN_PERMISSION_NAMES}

    return {
        name: bool(row[name])
        for name in ADMIN_PERMISSION_NAMES
    }


def owner_set_admin(actor_id, target_id, permissions):
    if not isinstance(permissions, dict):
        return False, "Invalid permissions."

    if set(permissions) - ADMIN_PERMISSION_NAMES:
        return False, "Unknown permission."

    if any(value not in (True, False, 0, 1) for value in permissions.values()):
        return False, "Permission values must be boolean."

    with get_connection() as connection:
        actor = connection.execute(
            "SELECT role FROM students WHERE id = %s",
            (actor_id,),
        ).fetchone()

        if actor is None or actor["role"] != "owner":
            return False, "Only the owner can manage administrators."

        target = connection.execute(
            "SELECT id, role FROM students WHERE id = %s",
            (target_id,),
        ).fetchone()

        if target is None:
            return False, "Target account not found."

        if target["role"] == "owner":
            return False, "The owner's account cannot be modified here."

        connection.execute(
            "UPDATE students SET role = 'admin' WHERE id = %s",
            (target_id,),
        )

        values = {
            name: int(bool(permissions.get(name, False)))
            for name in ADMIN_PERMISSION_NAMES
        }

        connection.execute(
            """
            INSERT INTO admin_permissions (
                student_id, view_students, view_grades, manage_students,
                delete_students, manage_lessons, manage_quizzes,
                manage_admins, manage_settings
            )
            VALUES (
                %(student_id)s, %(view_students)s, %(view_grades)s,
                %(manage_students)s, %(delete_students)s,
                %(manage_lessons)s, %(manage_quizzes)s,
                %(manage_admins)s, %(manage_settings)s
            )
            ON CONFLICT (student_id) DO UPDATE SET
                view_students = EXCLUDED.view_students,
                view_grades = EXCLUDED.view_grades,
                manage_students = EXCLUDED.manage_students,
                delete_students = EXCLUDED.delete_students,
                manage_lessons = EXCLUDED.manage_lessons,
                manage_quizzes = EXCLUDED.manage_quizzes,
                manage_admins = EXCLUDED.manage_admins,
                manage_settings = EXCLUDED.manage_settings
            """,
            {"student_id": target_id, **values},
        )

        connection.execute(
            """
            INSERT INTO admin_audit_log
                (actor_id, action, target_type, target_id, details)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                actor_id,
                "admin_permissions_updated",
                "student",
                target_id,
                "Administrator role and permissions updated by owner",
            ),
        )

    return True, "Administrator permissions updated."


def owner_remove_admin(actor_id, target_id):
    with get_connection() as connection:
        actor = connection.execute(
            "SELECT role FROM students WHERE id = %s",
            (actor_id,),
        ).fetchone()

        if actor is None or actor["role"] != "owner":
            return False, "Only the owner can remove administrators."

        target = connection.execute(
            "SELECT role FROM students WHERE id = %s",
            (target_id,),
        ).fetchone()

        if target is None:
            return False, "Target account not found."

        if target["role"] == "owner":
            return False, "The owner's account cannot be changed."

        if target["role"] != "admin":
            return False, "Target account is not an administrator."

        connection.execute(
            "UPDATE students SET role = 'student' WHERE id = %s",
            (target_id,),
        )

        connection.execute(
            "DELETE FROM admin_permissions WHERE student_id = %s",
            (target_id,),
        )

        connection.execute(
            """
            INSERT INTO admin_audit_log
                (actor_id, action, target_type, target_id, details)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                actor_id,
                "admin_removed",
                "student",
                target_id,
                "Administrator role removed by owner",
            ),
        )

    return True, "Administrator role removed."


def login_attempts_blocked(identifier):
    key = identifier.strip().lower()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT attempts, first_attempt
            FROM login_attempts
            WHERE login_key = %s
            """,
            (key,),
        ).fetchone()

        if row is None:
            return False

        if time.time() - row["first_attempt"] >= 900:
            connection.execute(
                "DELETE FROM login_attempts WHERE login_key = %s",
                (key,),
            )
            return False

        return row["attempts"] >= 5


def record_login_failure(identifier):
    key = identifier.strip().lower()
    now = time.time()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO login_attempts (login_key, attempts, first_attempt)
            VALUES (%s, 1, %s)
            ON CONFLICT (login_key) DO UPDATE SET
                attempts = CASE
                    WHEN %s - login_attempts.first_attempt >= 900 THEN 1
                    ELSE login_attempts.attempts + 1
                END,
                first_attempt = CASE
                    WHEN %s - login_attempts.first_attempt >= 900 THEN %s
                    ELSE login_attempts.first_attempt
                END
            """,
            (key, now, now, now, now),
        )


def clear_login_failures(identifier):
    key = identifier.strip().lower()

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM login_attempts WHERE login_key = %s",
            (key,),
        )
