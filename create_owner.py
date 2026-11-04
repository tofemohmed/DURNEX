from getpass import getpass

import psycopg
from database import get_connection, initialize_database
from werkzeug.security import generate_password_hash

USERNAME = "الدر"


def main():
    initialize_database()

    with get_connection() as connection:
        existing_owner = connection.execute(
            "SELECT username FROM students WHERE role = 'owner' LIMIT 1"
        ).fetchone()

        if existing_owner:
            print("توقف: يوجد حساب مالك بالفعل. لن يتم إنشاء حساب آخر.")
            return

        existing_user = connection.execute(
            "SELECT username FROM students WHERE LOWER(username) = LOWER(%s)",
            (USERNAME,),
        ).fetchone()

        if existing_user:
            print("توقف: اسم المستخدم موجود مسبقاً. لم يتم تغيير الحساب.")
            return

    print("=== إعداد حساب المالك الرئيسي ===")
    email = input("أدخل البريد الإلكتروني للمالك: ").strip().lower()

    if not email or "@" not in email:
        print("خطأ: البريد الإلكتروني غير صالح.")
        return

    password = getpass("أدخل كلمة مرور قوية (12 حرفاً على الأقل): ")
    confirm = getpass("أعد كتابة كلمة المرور: ")

    if len(password) < 12:
        print("خطأ: كلمة المرور يجب أن تكون 12 حرفاً على الأقل.")
        return

    if password != confirm:
        print("خطأ: كلمتا المرور غير متطابقتين.")
        return

    try:
        with get_connection() as connection:
            if connection.execute(
                "SELECT 1 FROM students WHERE LOWER(username) = LOWER(%s)",
                (USERNAME,),
            ).fetchone():
                print("توقف: الحساب موجود بالفعل.")
                return

            if connection.execute(
                "SELECT 1 FROM students WHERE LOWER(email) = LOWER(%s)",
                (email,),
            ).fetchone():
                print("توقف: البريد الإلكتروني مستخدم بحساب آخر.")
                return

            owner = connection.execute(
                """
                INSERT INTO students
                    (full_name, username, email, password_hash, role)
                VALUES (%s, %s, %s, %s, 'owner')
                RETURNING id
                """,
                (
                    "الدر",
                    USERNAME,
                    email,
                    generate_password_hash(password),
                ),
            ).fetchone()

            owner_id = owner["id"]

            connection.execute(
                """
                INSERT INTO admin_audit_log
                    (actor_id, action, target_type, target_id, details)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    owner_id,
                    "owner_created",
                    "student",
                    owner_id,
                    "Owner account initialized from local terminal",
                ),
            )

        print("\nتم إنشاء حساب المالك بنجاح.")
        print("اسم المستخدم: الدر")

    except psycopg.IntegrityError:
        print("تعذر إنشاء الحساب بسبب تعارض في البيانات.")
        print("لم تُحذف حسابات الطلاب الموجودة.")

    finally:
        password = None
        confirm = None


if __name__ == "__main__":
    main()
