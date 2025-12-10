import logging
import os
import re
import secrets
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, render_template, request, redirect, url_for, session, abort, flash

from config import get_db_conn
from hospital_db_setup import encrypt_data, decrypt_data
# Project authors: Suksham Fulzele (ID: 989686048), Sahil Shekhar Desai (ID: 989485311), Sruthi Satyavarapu (ID: 989492060), Sriyuktha Sanagavarapu (ID: 989483329)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # Toggle HTTPS-only cookies and redirects via REQUIRE_HTTPS env (set to "1" in prod)
    SESSION_COOKIE_SECURE=os.environ.get("REQUIRE_HTTPS", "0") == "1",
    REMEMBER_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # limit form size to reduce abuse
    REQUIRE_HTTPS=os.environ.get("REQUIRE_HTTPS", "0") == "1",
)

# Rotating file log to keep audit trail short-lived on disk
log_path = os.environ.get("APP_LOG_FILE", "/tmp/hospital_app.log")
handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_patient_record(patient_id: int):
    """Fetch and decrypt a single patient with optional sensitive fields."""
    conn = cur = None
    try:
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT p.patient_id, p.first_name, p.last_name, p.dob, p.gender,
                   p.phone_number, p.email, ps.mrn, ps.home_address, ps.insurance_policy, ps.card_last4
            FROM Patient p
            LEFT JOIN Patient_Sensitive ps ON ps.patient_id = p.patient_id
            WHERE p.patient_id = %s
            """,
            (patient_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        # Decrypt fields that are stored encrypted
        row["email"] = decrypt_data(row["email"]) if row.get("email") else ""
        row["phone_number"] = decrypt_data(row["phone_number"]) if row.get("phone_number") else ""
        row["mrn"] = decrypt_data(row["mrn"]) if row.get("mrn") else ""
        row["home_address"] = decrypt_data(row["home_address"]) if row.get("home_address") else ""
        row["insurance_policy"] = decrypt_data(row["insurance_policy"]) if row.get("insurance_policy") else ""
        return row
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# Role-based access control
ROLES = {
    'PATIENT': 'patient',
    'STAFF': 'staff',
    'ADMIN': 'admin'
}

def get_current_user_role():
    """Get the current user's role from session"""
    return session.get('user_role')

def require_login(f):
    """Decorator to require user to be logged in"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_role(*allowed_roles):
    """Decorator to require specific role(s)"""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                flash("Please log in to access this page.", "error")
                return redirect(url_for('login'))
            user_role = session.get('user_role')
            if user_role not in allowed_roles:
                flash("You don't have permission to access this page.", "error")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Context processor to make user info available to all templates
@app.context_processor
def inject_user():
    return dict(
        is_logged_in=session.get('logged_in', False),
        user_role=session.get('user_role'),
        user_name=session.get('user_name', 'User')
    )


def generate_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def require_csrf() -> None:
    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")
    if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
        abort(400, description="Invalid CSRF token")


def sanitize_card_number(raw_card: str) -> str:
    digits_only = re.sub(r"\D", "", raw_card or "")
    if len(digits_only) < 12 or len(digits_only) > 19:
        raise ValueError("Card number must be 12-19 digits.")
    return digits_only


app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.before_request
def enforce_security():
    session.permanent = True
    if app.config["REQUIRE_HTTPS"] and not request.is_secure and request.headers.get("X-Forwarded-Proto", "http") != "https":
        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=301)
    if request.method == "POST":
        require_csrf()


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "base-uri 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if app.config["REQUIRE_HTTPS"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def index():
    # If not logged in, redirect to login page
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    # If logged in, show the main dashboard
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    # Main dashboard page (only accessible after login)
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        if not EMAIL_REGEX.match(email):
            return render_template("login.html", error="Enter a valid email address.")
        
        if not password:
            return render_template("login.html", error="Password is required.")
        
        # Check credentials against Users table
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor(dictionary=True)
            
            # Look up user by email
            cur.execute("""
                SELECT user_id, email, password_hash, role, reference_id, is_active
                FROM Users
                WHERE email = %s AND is_active = TRUE
            """, (email,))
            
            user = cur.fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                # Valid credentials
                session['logged_in'] = True
                session['user_role'] = user['role']
                session['user_id'] = user['user_id']
                
                # Get user name and set reference_id based on role
                if user['role'] == 'patient':
                    session['patient_id'] = user['reference_id']
                    # Get patient name
                    if user['reference_id']:
                        cur.execute("SELECT first_name, last_name FROM Patient WHERE patient_id = %s", (user['reference_id'],))
                        patient = cur.fetchone()
                        if patient:
                            session['user_name'] = f"{patient['first_name']} {patient['last_name']}"
                        else:
                            session['user_name'] = "Patient"
                    else:
                        session['user_name'] = "Patient"
                elif user['role'] in ['staff', 'admin']:
                    # Get staff name if reference_id exists
                    if user['reference_id']:
                        cur.execute("SELECT first_name, last_name FROM Staff WHERE staff_id = %s", (user['reference_id'],))
                        staff = cur.fetchone()
                        if staff:
                            session['user_name'] = f"{staff['first_name']} {staff['last_name']}"
                        else:
                            session['user_name'] = "Staff" if user['role'] == 'staff' else "Administrator"
                    else:
                        session['user_name'] = "Staff" if user['role'] == 'staff' else "Administrator"
                
                flash(f"Welcome! You have successfully logged in.", "success")
                return redirect(url_for("dashboard"))
            else:
                return render_template("login.html", error="Invalid email or password.")
                
        except Exception as e:
            print(f"Login error: {e}")
            app.logger.error(f"Login error: {str(e)}", exc_info=True)
            return render_template("login.html", error="An error occurred during login. Please try again.")
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/patient", methods=["GET", "POST"])
@require_login
def patient_form():
    """Patient registration - accessible to staff/admin only"""
    user_role = get_current_user_role()
    
    # Only staff and admin can register patients
    # (Patients register themselves through a different flow if needed)
    if user_role not in ['staff', 'admin']:
        flash("Only staff and administrators can register new patients.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        conn = cur = None
        try:
            # Read form fields
            full_name = request.form.get("full_name", "").strip()
            dob = request.form.get("dob", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            address = request.form.get("address", "").strip()
            mrn = request.form.get("mrn", "").strip()
            diagnosis = request.form.get("diagnosis", "").strip()
            insurance = request.form.get("insurance", "").strip()

            # Prepare form data dictionary for re-rendering on errors
            form_data = {
                "full_name": full_name,
                "dob": dob,
                "email": email,
                "phone": phone,
                "address": address,
                "mrn": mrn,
                "diagnosis": diagnosis,
                "insurance": insurance
            }

            # Basic server-side validation
            validation_errors = []
            if len(full_name) < 2:
                validation_errors.append("Full name must be at least 2 characters.")
            if not dob:
                validation_errors.append("Date of birth is required.")
            if not EMAIL_REGEX.match(email):
                validation_errors.append("A valid email address is required.")
            if len(mrn) < 3:
                validation_errors.append("Medical Record Number (MRN) must be at least 3 characters.")
            
            if validation_errors:
                for error in validation_errors:
                    flash(error, "error")
                return render_template("patient_form.html", form_data=form_data), 400
            sanitized_phone = re.sub(r"\D", "", phone)
            if phone and len(sanitized_phone) < 7:
                flash("Phone number must be at least 7 digits.", "error")
                form_data["phone"] = phone  # Keep original phone value
                return render_template("patient_form.html", form_data=form_data), 400
            phone = sanitized_phone

            # Split full_name into first_name and last_name
            name_parts = full_name.split(maxsplit=1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            # Connect to DB
            conn = get_db_conn()
            cur = conn.cursor()

            # Encrypt sensitive fields
            encrypted_email = encrypt_data(email)
            encrypted_phone = encrypt_data(phone)
            encrypted_address = encrypt_data(address) if address else None
            encrypted_insurance = encrypt_data(insurance) if insurance else None
            encrypted_mrn = encrypt_data(mrn)

            # 1) Store in Patient table (matching existing database schema)
            cur.execute(
                """
                INSERT INTO Patient (first_name, last_name, dob, gender, phone_number, email, ssn, state_id, primary_doctor_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (first_name, last_name, dob, "Unknown", encrypted_phone, encrypted_email, encrypt_data(""), encrypt_data(""), None),
            )
            patient_id = cur.lastrowid

            # 2) Store encrypted diagnosis in Medical_Record
            encrypted_diagnosis = encrypt_data(diagnosis)
            cur.execute(
                """
                INSERT INTO Medical_Record (patient_id, doctor_id, diagnosis, treatment_plan)
                VALUES (%s, %s, %s, %s)
                """,
                (patient_id, None, encrypted_diagnosis, encrypt_data("")),
            )

            # 3) Store masked identifiers (MRN, address) in a dedicated table
            cur.execute(
                """
                INSERT INTO Patient_Sensitive (patient_id, mrn, home_address, insurance_policy, card_last4)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (patient_id, encrypted_mrn, encrypted_address, encrypted_insurance, None),
            )

            # 4) Create user account for the patient
            # Generate a default password
            # NOTE: No email service configured, so displaying temporary password on screen
            # In production, this password should be sent via email instead of displaying it
            default_password = secrets.token_urlsafe(8)  # Generate random password
            password_hash = generate_password_hash(default_password)
            
            try:
                cur.execute("""
                    INSERT INTO Users (email, password_hash, role, reference_id, is_active)
                    VALUES (%s, %s, %s, %s, %s)
                """, (email.lower(), password_hash, 'patient', patient_id, True))
            except Exception as user_error:
                # If user already exists, that's okay (might be updating)
                print(f"Note: User account creation: {user_error}")
            
            conn.commit()
            
            # Only auto-login if registering as a patient (not when staff registers)
            # Staff/admin registering patients should not be auto-logged in as that patient
            user_role = get_current_user_role()
            if user_role == 'patient' or not session.get('logged_in'):
                # This is a self-registration, auto-login
                # Look up the user account we just created
                cur.execute("SELECT user_id FROM Users WHERE email = %s AND role = 'patient'", (email.lower(),))
                user_account = cur.fetchone()
                if user_account:
                    session['logged_in'] = True
                    session['user_id'] = user_account[0]
                    session['user_role'] = 'patient'
                    session['patient_id'] = patient_id
                    session['user_name'] = f"{first_name} {last_name}"
                    flash(f"Patient registered successfully! Patient ID: {patient_id}. Your temporary password is: {default_password} (Note: Displaying password on screen is not secure, but no email/messaging service is implemented, so this is the alternative method.)", "success")
                    return redirect(url_for("success"))
                else:
                    flash(f"Patient registered successfully! Patient ID: {patient_id}. Please contact admin for login credentials.", "success")
                    return redirect(url_for("success"))
            else:
                # Staff/admin registered a patient, don't auto-login
                flash(f"Patient registered successfully! Patient ID: {patient_id}. Default password: {default_password} (Note: Displaying password on screen is not secure, but no email/messaging service is implemented, so this is the alternative method.)", "success")
                return redirect(url_for("list_patients"))

        except Exception as e:
            # Helpful for debugging & assignment explanation
            error_msg = str(e)
            print("ERROR IN POST /patient:", repr(e))
            app.logger.error(f"Database error in patient_form: {error_msg}", exc_info=True)
            if conn:
                conn.rollback()
            # Reconstruct form_data from request for error display
            form_data = {
                "full_name": request.form.get("full_name", "").strip(),
                "dob": request.form.get("dob", "").strip(),
                "email": request.form.get("email", "").strip(),
                "phone": request.form.get("phone", "").strip(),
                "address": request.form.get("address", "").strip(),
                "mrn": request.form.get("mrn", "").strip(),
                "diagnosis": request.form.get("diagnosis", "").strip(),
                "insurance": request.form.get("insurance", "").strip()
            }
            # Show more specific error message to help debug
            flash(f"Error while saving to DB: {error_msg}", "error")
            return render_template("patient_form.html", form_data=form_data), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    # GET: show the secure intake form
    return render_template("patient_form.html", form_data={})


@app.route("/patient/<int:patient_id>")
@require_login
def patient_detail(patient_id: int):
    # Patients can only view their own records, staff/admin can view any
    user_role = get_current_user_role()
    if user_role == 'patient' and session.get('user_id') != patient_id:
        flash("You can only view your own patient record.", "error")
        return redirect(url_for("dashboard"))
    record = get_patient_record(patient_id)
    if not record:
        abort(404)
    return render_template("patient_detail.html", patient=record)


@app.route("/patient/<int:patient_id>/edit", methods=["GET", "POST"])
@require_login
def patient_edit(patient_id: int):
    # Patients can only edit their own records, staff/admin can edit any
    user_role = get_current_user_role()
    if user_role == 'patient' and session.get('user_id') != patient_id:
        flash("You can only edit your own patient record.", "error")
        return redirect(url_for("dashboard"))
    record = get_patient_record(patient_id)
    if not record:
        abort(404)

    if request.method == "POST":
        conn = cur = None
        try:
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            address = request.form.get("address", "").strip()
            mrn = request.form.get("mrn", "").strip()
            insurance = request.form.get("insurance", "").strip()

            if len(full_name) < 2 or not EMAIL_REGEX.match(email):
                flash("Please provide valid name and email.", "error")
                return render_template("patient_edit.html", patient=record), 400

            sanitized_phone = re.sub(r"\\D", "", phone)
            name_parts = full_name.split(maxsplit=1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE Patient
                SET first_name=%s, last_name=%s, phone_number=%s, email=%s
                WHERE patient_id=%s
                """,
                (first_name, last_name, encrypt_data(sanitized_phone), encrypt_data(email), patient_id),
            )
            cur.execute(
                """
                UPDATE Patient_Sensitive
                SET mrn=%s, home_address=%s, insurance_policy=%s
                WHERE patient_id=%s
                """,
                (encrypt_data(mrn), encrypt_data(address), encrypt_data(insurance), patient_id),
            )
            conn.commit()
            flash("Patient updated.", "success")
            return redirect(url_for("patient_detail", patient_id=patient_id))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Edit error:", repr(e))
            flash("Unable to update patient.", "error")
            return render_template("patient_edit.html", patient=record), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    # Prefill with decrypted values
    record["full_name"] = f"{record.get('first_name','')} {record.get('last_name','')}".strip()
    return render_template("patient_edit.html", patient=record)


@app.route("/staff", methods=["GET", "POST"])
@require_role('admin')
def staff_form():
    template_kwargs = dict(
        form_title="Staff Registration",
        form_subtitle="Register a new staff member",
        form_action="/staff",
        submit_button_text="Register Staff",
        form_fields=[
            {'name': 'first_name', 'label': 'First Name', 'type': 'text', 'required': True, 'row': True},
            {'name': 'last_name', 'label': 'Last Name', 'type': 'text', 'required': True, 'row': True},
            {'name': 'role', 'label': 'Role', 'type': 'select', 'required': True,
             'options': [
                 {'value': '', 'label': 'Select Role'},
                 {'value': 'Doctor', 'label': 'Doctor'},
                 {'value': 'Nurse', 'label': 'Nurse'},
                 {'value': 'Administrator', 'label': 'Administrator'},
                 {'value': 'Receptionist', 'label': 'Receptionist'},
                 {'value': 'Technician', 'label': 'Technician'},
                 {'value': 'Other', 'label': 'Other'}
             ]},
            {'name': 'email', 'label': 'Email Address', 'type': 'email', 'required': True},
            {'name': 'phone_number', 'label': 'Phone Number', 'type': 'tel', 'required': True}
        ]
    )

    if request.method == "POST":
        conn = cur = None
        try:
            email = request.form.get("email", "").strip()
            phone_number = request.form.get("phone_number", "").strip()
            if not EMAIL_REGEX.match(email):
                flash("Enter a valid email address.", "error")
                return render_template("form.html", **template_kwargs), 400
            if len(re.sub(r"\D", "", phone_number)) < 7:
                flash("Phone number must be at least 7 digits.", "error")
                return render_template("form.html", **template_kwargs), 400

            conn = get_db_conn()
            cur = conn.cursor()

            encrypted_email = encrypt_data(email)
            encrypted_phone = encrypt_data(phone_number)

            cur.execute(
                """INSERT INTO Staff (first_name, last_name, role, email, phone_number)
                   VALUES (%s, %s, %s, %s, %s)""",
                (request.form.get("first_name"), request.form.get("last_name"), 
                 request.form.get("role"), encrypted_email, encrypted_phone)
            )
            staff_id = cur.lastrowid
            
            # Create user account for the staff member
            # Generate a default password
            # NOTE: No email service configured, so displaying temporary password on screen
            # In production, this password should be sent via email instead of displaying it
            default_password = secrets.token_urlsafe(8)  # Generate random password
            password_hash = generate_password_hash(default_password)
            
            # Determine user role (staff or admin based on staff role)
            staff_role = request.form.get("role", "").strip()
            user_role = 'admin' if staff_role.lower() == 'administrator' else 'staff'
            
            try:
                cur.execute("""
                    INSERT INTO Users (email, password_hash, role, reference_id, is_active)
                    VALUES (%s, %s, %s, %s, %s)
                """, (email.lower(), password_hash, user_role, staff_id, True))
            except Exception as user_error:
                # If user already exists, that's okay
                print(f"Note: User account creation: {user_error}")
            
            conn.commit()
            flash(f"Staff registered successfully! Default password: {default_password} (Note: Displaying password on screen is not secure, but no email/messaging service is implemented, so this is the alternative method.)", "success")
            return redirect(url_for("success"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Staff registration error:", repr(e))
            flash("Unable to save staff record.", "error")
            return render_template("form.html", **template_kwargs), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template("form.html", **template_kwargs)


@app.route("/appointment", methods=["GET", "POST"])
@require_login
def appointment_form():
    user_role = get_current_user_role()
    user_id = session.get('patient_id') or session.get('user_id')
    
    # For patients: auto-fill patient_id, for staff/admin: allow selecting any patient
    if user_role == 'patient':
        # Patients can only book for themselves
        form_fields = [
            {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': False, 'placeholder': 'Enter Staff/Doctor ID (optional)'},
            {'name': 'appointment_date', 'label': 'Appointment Date & Time', 'type': 'datetime-local', 'required': True},
        ]
        patient_id_val = user_id
        status = "Scheduled"  # Default for patients
    else:
        # Staff/admin can book for any patient
        form_fields = [
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': False, 'placeholder': 'Enter Staff/Doctor ID (optional)'},
            {'name': 'appointment_date', 'label': 'Appointment Date & Time', 'type': 'datetime-local', 'required': True},
            {'name': 'status', 'label': 'Status', 'type': 'select', 'required': False,
             'options': [
                 {'value': 'Scheduled', 'label': 'Scheduled', 'selected': True},
                 {'value': 'Confirmed', 'label': 'Confirmed'},
                 {'value': 'Cancelled', 'label': 'Cancelled'},
                 {'value': 'Completed', 'label': 'Completed'}
             ]}
        ]

    if request.method == "POST":
        conn = cur = None
        try:
            if user_role == 'patient':
                # Patient ID is already set from session
                doctor_id_raw = request.form.get("doctor_id", "").strip()
                appt_date = request.form.get("appointment_date")
                if not appt_date:
                    flash("Appointment date is required.", "error")
                    return redirect(url_for("appointment_form"))
            else:
                # Staff/admin: get from form
                patient_id_raw = request.form.get("patient_id", "").strip()
                doctor_id_raw = request.form.get("doctor_id", "").strip()
                appt_date = request.form.get("appointment_date")
                status = request.form.get("status", "Scheduled")
                
                if not patient_id_raw or not appt_date:
                    flash("Patient ID and appointment date are required.", "error")
                    return render_template("form.html",
                                           form_title="Book Appointment",
                                           form_subtitle="Schedule a new appointment",
                                           form_action="/appointment",
                                           submit_button_text="Book Appointment",
                                           form_fields=form_fields), 400

                try:
                    patient_id_val = int(patient_id_raw)
                except ValueError:
                    flash("Patient ID must be a number.", "error")
                    return render_template("form.html",
                                           form_title="Book Appointment",
                                           form_subtitle="Schedule a new appointment",
                                           form_action="/appointment",
                                           submit_button_text="Book Appointment",
                                           form_fields=form_fields), 400

            doctor_id_val = None
            if doctor_id_raw:
                try:
                    doctor_id_val = int(doctor_id_raw)
                except ValueError:
                    flash("Doctor ID must be a number.", "error")
                    return render_template("form.html",
                                           form_title="Book Appointment",
                                           form_subtitle="Schedule a new appointment",
                                           form_action="/appointment",
                                           submit_button_text="Book Appointment",
                                           form_fields=form_fields), 400

            conn = get_db_conn()
            cur = conn.cursor()

            # Validate patient exists
            cur.execute("SELECT patient_id FROM Patient WHERE patient_id=%s", (patient_id_val,))
            if not cur.fetchone():
                flash("Patient ID not found. Please register the patient first.", "error")
                return render_template("form.html",
                                       form_title="Book Appointment",
                                       form_subtitle="Schedule a new appointment",
                                       form_action="/appointment",
                                       submit_button_text="Book Appointment",
                                       form_fields=form_fields), 400

            # Insert appointment
            cur.execute(
                """INSERT INTO Appointment (patient_id, doctor_id, appointment_date, status)
                   VALUES (%s, %s, %s, %s)""",
                (patient_id_val, doctor_id_val, appt_date, status)
            )
            conn.commit()
            flash("Appointment booked successfully!", "success")
            return redirect(url_for("success", message="Appointment booked successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Appointment creation error:", repr(e))
            flash("Unable to create appointment. Please check IDs and try again.", "error")
            return render_template("form.html",
                                   form_title="Book Appointment",
                                   form_subtitle="Schedule a new appointment",
                                   form_action="/appointment",
                                   submit_button_text="Book Appointment",
                                   form_fields=form_fields), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template("form.html",
        form_title="Book Appointment",
        form_subtitle="Schedule a new appointment",
        form_action="/appointment",
        submit_button_text="Book Appointment",
        form_fields=form_fields)


@app.route("/medical-record", methods=["GET", "POST"])
@require_role('staff', 'admin')
def medical_record_form():
    if request.method == "POST":
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor()

            encrypted_diagnosis = encrypt_data(request.form.get("diagnosis", ""))
            encrypted_treatment = encrypt_data(request.form.get("treatment_plan", ""))
            
            cur.execute(
                """INSERT INTO Medical_Record (patient_id, doctor_id, diagnosis, treatment_plan)
                   VALUES (%s, %s, %s, %s)""",
                (request.form.get("patient_id"), request.form.get("doctor_id"),
                 encrypted_diagnosis, encrypted_treatment)
            )
            conn.commit()
            return redirect(url_for("success", message="Medical record saved successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Medical record error:", repr(e))
            flash("Unable to save medical record. Check IDs and try again.", "error")
            return render_template("form.html",
                form_title="Medical Record",
                form_subtitle="Add a new medical record",
                form_action="/medical-record",
                submit_button_text="Save Medical Record",
                form_fields=[
                    {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
                    {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Staff/Doctor ID'},
                    {'name': 'diagnosis', 'label': 'Diagnosis', 'type': 'textarea', 'required': True, 'placeholder': 'Enter diagnosis details'},
                    {'name': 'treatment_plan', 'label': 'Treatment Plan', 'type': 'textarea', 'required': True, 'placeholder': 'Enter treatment plan details'}
                ]), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template("form.html",
        form_title="Medical Record",
        form_subtitle="Add a new medical record",
        form_action="/medical-record",
        submit_button_text="Save Medical Record",
        form_fields=[
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Staff/Doctor ID'},
            {'name': 'diagnosis', 'label': 'Diagnosis', 'type': 'textarea', 'required': True, 'placeholder': 'Enter diagnosis details'},
            {'name': 'treatment_plan', 'label': 'Treatment Plan', 'type': 'textarea', 'required': True, 'placeholder': 'Enter treatment plan details'}
        ])


@app.route("/my-bills")
@require_login
def view_my_bills():
    """Patients can view their own bills"""
    user_role = get_current_user_role()
    user_id = session.get('patient_id') or session.get('user_id')
    
    if user_role != 'patient':
        flash("This page is for patients only.", "error")
        return redirect(url_for("dashboard"))
    
    conn = cur = None
    try:
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        
        # Get all bills for this patient
        cur.execute("""
            SELECT billing_id, total_amount, paid_amount, status, created_at, payment_due_date
            FROM Billing
            WHERE patient_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        
        bills = cur.fetchall()
        
        # Get payment transactions for each bill
        for bill in bills:
            cur.execute("""
                SELECT amount, paid_at, status, note
                FROM Payment_Transactions
                WHERE billing_id = %s
                ORDER BY paid_at DESC
            """, (bill['billing_id'],))
            bill['payments'] = cur.fetchall()
        
        return render_template("my_bills.html", bills=bills)
    except Exception as e:
        print(f"Error fetching bills: {e}")
        flash("Unable to load billing information.", "error")
        return redirect(url_for("dashboard"))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/patients")
@require_role('staff', 'admin')
def list_patients():
    """List all patients for staff/admin to search and view"""
    conn = cur = None
    try:
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        
        # Get search query if provided
        search_query = request.args.get('search', '').strip()
        
        if search_query:
            # Search by name or patient ID (can't search encrypted email directly)
            # Try to match patient ID first (numeric)
            try:
                patient_id_search = int(search_query)
                cur.execute("""
                    SELECT p.patient_id, p.first_name, p.last_name, 
                           p.email, p.phone_number, p.dob
                    FROM Patient p
                    WHERE p.patient_id = %s
                    ORDER BY p.patient_id DESC
                    LIMIT 50
                """, (patient_id_search,))
            except ValueError:
                # Not a number, search by name
                cur.execute("""
                    SELECT p.patient_id, p.first_name, p.last_name, 
                           p.email, p.phone_number, p.dob
                    FROM Patient p
                    WHERE p.first_name LIKE %s 
                       OR p.last_name LIKE %s
                       OR CONCAT(p.first_name, ' ', p.last_name) LIKE %s
                    ORDER BY p.patient_id DESC
                    LIMIT 50
                """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
        else:
            # Get recent patients (last 50)
            cur.execute("""
                SELECT p.patient_id, p.first_name, p.last_name, 
                       p.email, p.phone_number, p.dob
                FROM Patient p
                ORDER BY p.patient_id DESC
                LIMIT 50
            """)
        
        patients = cur.fetchall()
        
        # Decrypt sensitive fields
        for patient in patients:
            if patient.get('email'):
                try:
                    patient['email'] = decrypt_data(patient['email'])
                except Exception as e:
                    patient['email'] = '[Encrypted]'
            if patient.get('phone_number'):
                try:
                    patient['phone_number'] = decrypt_data(patient['phone_number'])
                except Exception as e:
                    patient['phone_number'] = '[Encrypted]'
        
        return render_template("patient_list.html", patients=patients, search_query=search_query)
    except Exception as e:
        error_msg = str(e)
        print(f"Error listing patients: {error_msg}")
        app.logger.error(f"Error listing patients: {error_msg}", exc_info=True)
        flash(f"Unable to load patient list: {error_msg}", "error")
        return redirect(url_for("dashboard"))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/billing", methods=["GET", "POST"])
@require_role('admin')
def billing_form():
    if request.method == "POST":
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor()

            cur.execute(
                """INSERT INTO Billing (patient_id, total_amount, status, payment_due_date)
                   VALUES (%s, %s, %s, %s)""",
                (request.form.get("patient_id"), request.form.get("total_amount"),
                 request.form.get("status", "Pending"), request.form.get("payment_due_date") or None)
            )
            conn.commit()
            return redirect(url_for("success", message="Billing record created successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Billing creation error:", repr(e))
            flash("Unable to save billing record. Check patient ID and amounts.", "error")
            return render_template("form.html",
                form_title="Billing",
                form_subtitle="Create a new billing record",
                form_action="/billing",
                submit_button_text="Create Billing Record",
                form_fields=[
                    {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
                    {'name': 'total_amount', 'label': 'Total Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
                    {'name': 'status', 'label': 'Status', 'type': 'select', 'required': False,
                     'options': [
                         {'value': 'Pending', 'label': 'Pending', 'selected': True},
                         {'value': 'Paid', 'label': 'Paid'},
                         {'value': 'Overdue', 'label': 'Overdue'},
                         {'value': 'Cancelled', 'label': 'Cancelled'}
                     ]},
                    {'name': 'payment_due_date', 'label': 'Payment Due Date', 'type': 'datetime-local', 'required': False}
                ]), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template("form.html",
        form_title="Billing",
        form_subtitle="Create a new billing record",
        form_action="/billing",
        submit_button_text="Create Billing Record",
        form_fields=[
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'total_amount', 'label': 'Total Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
            {'name': 'status', 'label': 'Status', 'type': 'select', 'required': False,
             'options': [
                 {'value': 'Pending', 'label': 'Pending', 'selected': True},
                 {'value': 'Paid', 'label': 'Paid'},
                 {'value': 'Overdue', 'label': 'Overdue'},
                 {'value': 'Cancelled', 'label': 'Cancelled'}
             ]},
            {'name': 'payment_due_date', 'label': 'Payment Due Date', 'type': 'datetime-local', 'required': False}
        ])


@app.route("/payment", methods=["GET", "POST"])
@require_login
def payment_form():
    user_role = get_current_user_role()
    # For patients, use patient_id from session, for others use user_id
    if user_role == 'patient':
        user_id = session.get('patient_id') or session.get('user_id')
    else:
        user_id = session.get('user_id')
    
    # For patients: show their bills and payment methods
    if user_role == 'patient':
        if request.method == "POST":
            conn = cur = None
            try:
                conn = get_db_conn()
                cur = conn.cursor(dictionary=True)
                
                billing_id = request.form.get("billing_id", "").strip()
                payment_method_id = request.form.get("payment_method_id", "").strip()
                payment_amount = request.form.get("payment_amount", "").strip()
                
                # Validate inputs
                if not billing_id or not payment_method_id or not payment_amount:
                    flash("All fields are required.", "error")
                    return redirect(url_for("payment_form"))
                
                try:
                    billing_id_val = int(billing_id)
                    payment_method_id_val = int(payment_method_id) if payment_method_id else None
                    payment_amount_val = Decimal(payment_amount).quantize(Decimal("0.01"))
                except (ValueError, InvalidOperation):
                    flash("Invalid input values.", "error")
                    return redirect(url_for("payment_form"))
                
                # Verify billing belongs to this patient
                cur.execute("SELECT patient_id, total_amount, status FROM Billing WHERE billing_id = %s", (billing_id_val,))
                billing = cur.fetchone()
                if not billing:
                    flash("Billing record not found.", "error")
                    return redirect(url_for("payment_form"))
                
                if billing['patient_id'] != user_id:
                    flash("You can only make payments for your own bills.", "error")
                    return redirect(url_for("payment_form"))
                
                # Verify payment method belongs to this patient
                if payment_method_id_val:
                    cur.execute("SELECT payment_method_id, type, last4 FROM Payment_Methods WHERE payment_method_id = %s AND patient_id = %s", 
                              (payment_method_id_val, user_id))
                    pm = cur.fetchone()
                    if not pm:
                        flash("Invalid payment method.", "error")
                        return redirect(url_for("payment_form"))
                
                # Generate random transaction ID
                transaction_id = secrets.token_hex(16)  # 32 character hex string
                encrypted_transaction = encrypt_data(transaction_id)
                
                # Store transaction info in note field
                payment_method_type = pm['type'] if pm else 'CARD'
                payment_method_last4 = pm['last4'] if pm else 'N/A'
                transaction_note = f"Payment Method: {payment_method_type} ending in {payment_method_last4}; Transaction ID: {transaction_id}"
                
                # Insert into Payment_Transactions
                cur.execute(
                    """INSERT INTO Payment_Transactions (billing_id, patient_id, payment_method_id, amount, paid_at, status, note)
                       VALUES (%s, %s, %s, %s, NOW(), %s, %s)""",
                    (billing_id_val, user_id, payment_method_id_val, payment_amount_val, 'Posted', transaction_note)
                )
                
                conn.commit()
                flash(f"Payment processed successfully! Transaction ID: {transaction_id}", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                if conn:
                    conn.rollback()
                print("Payment processing error:", repr(e))
                flash(f"Unable to process payment: {str(e)}", "error")
                return redirect(url_for("payment_form"))
            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()
        
        # GET: Show patient's payment history and ability to make new payments
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor(dictionary=True)
            
            # Get patient's bills (for making payments)
            cur.execute("""
                SELECT billing_id, total_amount, paid_amount, status, created_at, payment_due_date
                FROM Billing
                WHERE patient_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
            bills = cur.fetchall()
            
            # Get patient's payment methods
            cur.execute("""
                SELECT payment_method_id, type, last4, is_default
                FROM Payment_Methods
                WHERE patient_id = %s
                ORDER BY is_default DESC, created_at DESC
            """, (user_id,))
            payment_methods = cur.fetchall()
            
            # Get patient's payment history (transactions)
            cur.execute("""
                SELECT pt.payment_id, pt.billing_id, pt.amount, pt.paid_at, pt.status, pt.note,
                       b.total_amount as bill_total
                FROM Payment_Transactions pt
                JOIN Billing b ON pt.billing_id = b.billing_id
                WHERE pt.patient_id = %s
                ORDER BY pt.paid_at DESC
            """, (user_id,))
            payment_history = cur.fetchall()
            
            return render_template("patient_payment.html", bills=bills, payment_methods=payment_methods, payment_history=payment_history)
        except Exception as e:
            print(f"Error loading payment page: {e}")
            flash("Unable to load payment information.", "error")
            return redirect(url_for("dashboard"))
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    # For admin only: use the original form-based approach for payment processing
    if user_role not in ['patient', 'admin']:
        flash("Payment processing is only available to administrators.", "error")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor()

            encrypted_method = encrypt_data(request.form.get("payment_method", ""))
            encrypted_transaction = encrypt_data(request.form.get("transaction_id", ""))
            
            # Get patient_id from billing_id
            cur.execute("SELECT patient_id FROM Billing WHERE billing_id = %s", (request.form.get("billing_id"),))
            billing_row = cur.fetchone()
            if not billing_row:
                flash("Billing ID not found.", "error")
                return render_template("form.html",
                    form_title="Payment Processing",
                    form_subtitle="Process a payment for a billing record",
                    form_action="/payment",
                    submit_button_text="Process Payment",
                    form_fields=[
                        {'name': 'billing_id', 'label': 'Billing ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Billing ID'},
                        {'name': 'payment_amount', 'label': 'Payment Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
                        {'name': 'payment_date', 'label': 'Payment Date', 'type': 'datetime-local', 'required': True},
                        {'name': 'payment_method', 'label': 'Payment Method', 'type': 'text', 'required': True, 'placeholder': 'e.g., Credit Card, Debit Card, Cash'},
                        {'name': 'transaction_id', 'label': 'Transaction ID', 'type': 'text', 'required': True, 'placeholder': 'Enter transaction ID'}
                    ]), 400
            
            patient_id = billing_row[0]
            
            # Try to find a matching Payment_Methods record for this patient (optional)
            payment_method_id = None
            cur.execute("SELECT payment_method_id FROM Payment_Methods WHERE patient_id = %s AND is_default = TRUE LIMIT 1", (patient_id,))
            pm_row = cur.fetchone()
            if pm_row:
                payment_method_id = pm_row[0]
            
            # Store transaction info in note field
            payment_method_name = request.form.get('payment_method', '')
            transaction_note = f"Payment Method: {payment_method_name}; Transaction ID: [encrypted]"
            
            # Use Payment_Transactions
            cur.execute(
                """INSERT INTO Payment_Transactions (billing_id, patient_id, payment_method_id, amount, paid_at, status, note)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (request.form.get("billing_id"), patient_id, payment_method_id, request.form.get("payment_amount"),
                 request.form.get("payment_date"), 'Posted', transaction_note)
            )
            conn.commit()
            return redirect(url_for("success", message="Payment processed successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Payment processing error:", repr(e))
            flash("Unable to process payment. Check billing ID and amounts.", "error")
            return render_template("form.html",
                form_title="Payment Processing",
                form_subtitle="Process a payment for a billing record",
                form_action="/payment",
                submit_button_text="Process Payment",
                form_fields=[
                    {'name': 'billing_id', 'label': 'Billing ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Billing ID'},
                    {'name': 'payment_amount', 'label': 'Payment Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
                    {'name': 'payment_date', 'label': 'Payment Date', 'type': 'datetime-local', 'required': True},
                    {'name': 'payment_method', 'label': 'Payment Method', 'type': 'text', 'required': True, 'placeholder': 'e.g., Credit Card, Debit Card, Cash'},
                    {'name': 'transaction_id', 'label': 'Transaction ID', 'type': 'text', 'required': True, 'placeholder': 'Enter transaction ID'}
                ]), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    # Only admin can access payment processing form
    if user_role != 'admin':
        flash("Payment processing is only available to administrators.", "error")
        return redirect(url_for("dashboard"))
    
    return render_template("form.html",
        form_title="Payment Processing",
        form_subtitle="Process a payment for a billing record",
        form_action="/payment",
        submit_button_text="Process Payment",
        form_fields=[
            {'name': 'billing_id', 'label': 'Billing ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Billing ID'},
            {'name': 'payment_amount', 'label': 'Payment Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
            {'name': 'payment_date', 'label': 'Payment Date', 'type': 'datetime-local', 'required': True},
            {'name': 'payment_method', 'label': 'Payment Method', 'type': 'text', 'required': True, 'placeholder': 'e.g., Credit Card, Debit Card, Cash'},
            {'name': 'transaction_id', 'label': 'Transaction ID', 'type': 'text', 'required': True, 'placeholder': 'Enter transaction ID'}
        ])


@app.route("/add-payment-method", methods=["GET", "POST"])
@require_login
def add_payment_method():
    """Add a new payment method (credit card) for the logged-in patient"""
    user_role = get_current_user_role()
    user_id = session.get('patient_id') or session.get('user_id')
    
    # Only patients can add payment methods
    if user_role != 'patient':
        flash("Only patients can add payment methods.", "error")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        conn = cur = None
        try:
            card_number = request.form.get("card_number", "").strip()
            zip_code = request.form.get("zip_code", "").strip()
            
            # Server-side validation
            errors = []
            
            # Validate card number: exactly 16 digits
            card_digits_only = re.sub(r'\D', '', card_number)
            if len(card_digits_only) != 16:
                errors.append("Credit card number must be exactly 16 digits.")
            elif not card_digits_only.isdigit():
                errors.append("Credit card number must contain only numbers.")
            
            # Validate zip code: numbers only, 5 digits (US standard, but flexible)
            zip_digits_only = re.sub(r'\D', '', zip_code)
            if not zip_digits_only or len(zip_digits_only) < 5:
                errors.append("Zip code must be at least 5 digits.")
            elif not zip_digits_only.isdigit():
                errors.append("Zip code must contain only numbers.")
            
            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template("add_payment_method.html", 
                                     form_data={"card_number": card_number, "zip_code": zip_code})
            
            # Use cleaned card number (digits only)
            card_number_clean = card_digits_only
            zip_code_clean = zip_digits_only
            
            conn = get_db_conn()
            cur = conn.cursor(dictionary=True)
            
            # Check if patient exists
            cur.execute("SELECT patient_id FROM Patient WHERE patient_id = %s", (user_id,))
            if not cur.fetchone():
                flash("Patient record not found.", "error")
                return redirect(url_for("dashboard"))
            
            # Extract last 4 digits for display
            card_last4 = card_number_clean[-4:]
            
            # Encrypt the full card number (following security protocols)
            encrypted_card = encrypt_data(card_number_clean)
            
            # Check if this is the first payment method (make it default)
            cur.execute("SELECT COUNT(*) as count FROM Payment_Methods WHERE patient_id = %s", (user_id,))
            count_result = cur.fetchone()
            is_first = count_result['count'] == 0 if count_result else True
            
            # Insert into Payment_Methods table
            cur.execute(
                """
                INSERT INTO Payment_Methods (patient_id, type, last4, data_enc, is_default)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, 'CARD', card_last4, encrypted_card, is_first)
            )
            
            conn.commit()
            flash(f"Payment method added successfully! Card ending in {card_last4} has been saved.", "success")
            return redirect(url_for("payment_form"))
            
        except Exception as e:
            if conn:
                conn.rollback()
            print(f"Error adding payment method: {e}")
            app.logger.error(f"Error adding payment method: {str(e)}", exc_info=True)
            flash(f"Unable to add payment method: {str(e)}", "error")
            form_data = {
                "card_number": request.form.get("card_number", ""),
                "zip_code": request.form.get("zip_code", "")
            }
            return render_template("add_payment_method.html", form_data=form_data)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    # GET: Show the form
    return render_template("add_payment_method.html", form_data={})


@app.route("/admin/tables")
@require_role('admin')
def admin_view_tables():
    """Admin view to browse any database table"""
    conn = cur = None
    try:
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        
        # Get the selected table name
        table_name = request.args.get('table', '').strip()
        page = int(request.args.get('page', 1))
        limit = 50
        offset = (page - 1) * limit
        
        # Get list of all tables in the database
        cur.execute("""
            SELECT TABLE_NAME 
            FROM information_schema.TABLES 
            WHERE TABLE_SCHEMA = DATABASE()
            ORDER BY TABLE_NAME
        """)
        all_tables = [row['TABLE_NAME'] for row in cur.fetchall()]
        
        table_data = None
        total_rows = 0
        columns = []
        
        if table_name:
            # Validate table name to prevent SQL injection
            if table_name not in all_tables:
                flash(f"Table '{table_name}' not found.", "error")
                return render_template("admin_tables.html", 
                                     tables=all_tables, 
                                     selected_table=None,
                                     table_data=None,
                                     columns=[],
                                     page=1,
                                     total_pages=0)
            
            # Get column information
            cur.execute(f"""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """, (table_name,))
            columns = cur.fetchall()
            
            # Get total row count
            cur.execute(f"SELECT COUNT(*) as count FROM `{table_name}`")
            total_rows = cur.fetchone()['count']
            total_pages = (total_rows + limit - 1) // limit
            
            # Get table data with pagination
            cur.execute(f"SELECT * FROM `{table_name}` LIMIT %s OFFSET %s", (limit, offset))
            table_data = cur.fetchall()
            
            # Try to decrypt BLOB fields that might be encrypted
            for row in table_data:
                for key, value in row.items():
                    if isinstance(value, bytes) and value:
                        try:
                            # Try to decrypt - if it fails, keep as is
                            decrypted = decrypt_data(value)
                            row[key] = decrypted
                        except:
                            # If decryption fails, show as hex or base64
                            try:
                                row[key] = f"[BLOB: {len(value)} bytes]"
                            except:
                                row[key] = "[Binary Data]"
        
        return render_template("admin_tables.html",
                             tables=all_tables,
                             selected_table=table_name,
                             table_data=table_data,
                             columns=columns,
                             page=page,
                             total_pages=total_pages if table_name else 0,
                             total_rows=total_rows)
    except Exception as e:
        error_msg = str(e)
        print(f"Error viewing tables: {error_msg}")
        app.logger.error(f"Error viewing tables: {error_msg}", exc_info=True)
        flash(f"Unable to load table data: {error_msg}", "error")
        return redirect(url_for("dashboard"))
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/success")
def success():
    message = request.args.get("message", "Your information has been successfully submitted and securely stored in the system.")
    return render_template("success.html", success_message=message)


if __name__ == "__main__":
    ssl_ctx = "adhoc" if app.config["REQUIRE_HTTPS"] else None
    # Debug disabled by default to avoid leaking stack traces; enable via FLASK_ENV=development if needed.
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "5000"))
    app.run(host=host, port=port, debug=False, ssl_context=ssl_ctx)
