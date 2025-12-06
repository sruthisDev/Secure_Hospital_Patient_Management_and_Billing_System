import logging
import os
import re
import secrets
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, url_for, session, abort

from config import get_db_conn
from hospital_db_setup import encrypt_data, decrypt_data

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


# Context processor to make is_logged_in available to all templates
@app.context_processor
def inject_user():
    return dict(is_logged_in=session.get('logged_in', False))


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
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not EMAIL_REGEX.match(email):
            return render_template("login.html", error="Enter a valid email address.")
        
        # Check if patient exists by email (email is encrypted, so we need to decrypt and compare)
        patient_id = None
        patients = []
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            # Get all patients and decrypt emails to find match
            cur.execute("SELECT patient_id, email FROM Patient")
            patients = cur.fetchall()
        except Exception as e:
            print(f"Login error while querying database: {e}")
            return render_template("login.html", error="Unable to process login right now. Please try again.")
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

        # Find patient with matching email
        for p in patients:
            encrypted_email = p[1]
            if not encrypted_email:
                continue
            try:
                decrypted_email = decrypt_data(encrypted_email).strip().lower()
                if decrypted_email == email:
                    patient_id = p[0]
                    break
            except Exception as decrypt_err:
                print(f"Skipping patient {p[0]} due to decrypt error: {decrypt_err}")
                continue

        if patient_id:
            session['logged_in'] = True
            session['patient_id'] = patient_id
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Email not found. Please register first.")
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/patient", methods=["GET", "POST"])
def patient_form():
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
            card = request.form.get("card", "").strip()
            amount = request.form.get("amount", "").strip()

            # Basic server-side validation
            if len(full_name) < 2 or not dob or not EMAIL_REGEX.match(email) or len(mrn) < 3:
                return render_template("patient_form.html", error="Please provide valid required fields."), 400
            sanitized_phone = re.sub(r"\D", "", phone)
            if phone and len(sanitized_phone) < 7:
                return render_template("patient_form.html", error="Phone number must be at least 7 digits."), 400
            phone = sanitized_phone

            try:
                card_number = sanitize_card_number(card)
            except ValueError as ve:
                return render_template("patient_form.html", error=str(ve)), 400

            try:
                amount_value = Decimal(amount).quantize(Decimal("0.01"))
                if amount_value < 0:
                    raise InvalidOperation
            except (InvalidOperation, ValueError):
                return render_template("patient_form.html", error="Billing amount must be a positive number."), 400

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

            # 3) Store billing info in Billing table
            cur.execute(
                """
                INSERT INTO Billing (patient_id, total_amount, status)
                VALUES (%s, %s, %s)
                """,
                (patient_id, amount_value, "Pending"),
            )
            billing_id = cur.lastrowid

            # 4) Store encrypted card data in Payment table
            encrypted_card = encrypt_data(card_number)
            cur.execute(
                """
                INSERT INTO Payment (billing_id, payment_amount, payment_date, payment_method, transaction_id)
                VALUES (%s, %s, NOW(), %s, %s)
                """,
                (billing_id, amount_value, encrypted_card, encrypt_data("")),
            )

            # 5) Store masked identifiers (last4, MRN, address) in a dedicated table
            cur.execute(
                """
                INSERT INTO Patient_Sensitive (patient_id, mrn, home_address, insurance_policy, card_last4)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (patient_id, encrypted_mrn, encrypted_address, encrypted_insurance, card_number[-4:]),
            )

            conn.commit()
            # Auto-login after registration
            session['logged_in'] = True
            session['patient_id'] = patient_id
            
            # Redirect to the nice success page
            return redirect(url_for("success"))

        except Exception as e:
            # Helpful for debugging & assignment explanation
            print("ERROR IN POST /patient:", repr(e))
            if conn:
                conn.rollback()
            return render_template("patient_form.html", error="Error while saving to DB."), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    # GET: show the secure intake form
    return render_template("patient_form.html")


@app.route("/staff", methods=["GET", "POST"])
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
                return render_template("form.html", error="Enter a valid email address.", **template_kwargs), 400
            if len(re.sub(r"\D", "", phone_number)) < 7:
                return render_template("form.html", error="Phone number must be at least 7 digits.", **template_kwargs), 400

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
            conn.commit()
            return redirect(url_for("success", message="Staff registered successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Staff registration error:", repr(e))
            return "Unable to save staff record.", 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template("form.html", **template_kwargs)


@app.route("/appointment", methods=["GET", "POST"])
def appointment_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor()

            cur.execute(
                """INSERT INTO Appointment (patient_id, doctor_id, appointment_date, status)
                   VALUES (%s, %s, %s, %s)""",
                (request.form.get("patient_id"), request.form.get("doctor_id"),
                 request.form.get("appointment_date"), request.form.get("status", "Scheduled"))
            )
            conn.commit()
            return redirect(url_for("success", message="Appointment booked successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Appointment creation error:", repr(e))
            return "Unable to create appointment.", 500
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
        form_fields=[
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Staff/Doctor ID'},
            {'name': 'appointment_date', 'label': 'Appointment Date & Time', 'type': 'datetime-local', 'required': True},
            {'name': 'status', 'label': 'Status', 'type': 'select', 'required': False,
             'options': [
                 {'value': 'Scheduled', 'label': 'Scheduled', 'selected': True},
                 {'value': 'Confirmed', 'label': 'Confirmed'},
                 {'value': 'Cancelled', 'label': 'Cancelled'},
                 {'value': 'Completed', 'label': 'Completed'}
             ]}
        ])


@app.route("/medical-record", methods=["GET", "POST"])
def medical_record_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
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
            return "Unable to save medical record.", 500
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


@app.route("/billing", methods=["GET", "POST"])
def billing_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
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
            return "Unable to save billing record.", 500
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
def payment_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        conn = cur = None
        try:
            conn = get_db_conn()
            cur = conn.cursor()

            encrypted_method = encrypt_data(request.form.get("payment_method", ""))
            encrypted_transaction = encrypt_data(request.form.get("transaction_id", ""))
            
            cur.execute(
                """INSERT INTO Payment (billing_id, payment_amount, payment_date, payment_method, transaction_id)
                   VALUES (%s, %s, %s, %s, %s)""",
                (request.form.get("billing_id"), request.form.get("payment_amount"),
                 request.form.get("payment_date"), encrypted_method, encrypted_transaction)
            )
            conn.commit()
            return redirect(url_for("success", message="Payment processed successfully!"))
        except Exception as e:
            if conn:
                conn.rollback()
            print("Payment processing error:", repr(e))
            return "Unable to process payment.", 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
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
