import os
import mysql.connector
from mysql.connector import errorcode
from crypto_utils import encrypt_value, decrypt_value
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Load environment variables from .env file
load_dotenv()


def encrypt_data(plain_text: str) -> str:
    """Encrypt sensitive values with AES-256-GCM (base64 payload)."""
    return encrypt_value(plain_text or "")


def decrypt_data(encrypted_data) -> str:
    """Decrypt AES-256-GCM payload pulled from the database."""
    if encrypted_data in (None, b"", ""):
        return ""
    if isinstance(encrypted_data, bytes):
        encrypted_data = encrypted_data.decode("utf-8")
    return decrypt_value(encrypted_data)

def connect_to_db():
    """Connect to the MySQL database"""
    return mysql.connector.connect(
        host="localhost",
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASS"),
    )

def create_database_and_tables():
    """Create the database and tables with foreign keys and encrypted columns"""
    db_connection = connect_to_db()
    cursor = db_connection.cursor()
    
    # Create the hospital database if it does not exist
    cursor.execute("CREATE DATABASE IF NOT EXISTS secure_hospital_db;")
    cursor.execute("USE secure_hospital_db;")
    
    # Create the Users table for authentication (must be first)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('patient', 'staff', 'admin') NOT NULL,
        reference_id INT,                 -- Links to patient_id or staff_id based on role
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_role (role),
        INDEX idx_reference (role, reference_id)
    );
    """)
    
    # Create the Staff table first (no dependencies)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Staff (
        staff_id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL,
        email BLOB,                       -- Encrypted email address
        phone_number BLOB,                -- Encrypted phone number
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """)
    
    # Create the Patient table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Patient (
        patient_id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        dob DATE NOT NULL,
        gender VARCHAR(10) NOT NULL,
        phone_number BLOB,                -- Encrypted phone number
        email BLOB,                       -- Encrypted email
        ssn BLOB,                         -- Encrypted Social Security Number (or other gov't ID)
        state_id BLOB,                    -- Encrypted State ID
        primary_doctor_id INT,            -- Foreign Key (Links to Staff)
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (primary_doctor_id) REFERENCES Staff(staff_id)
    );
    """)
    
    # Create the Appointment table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Appointment (
        appointment_id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        doctor_id INT,
        appointment_date DATETIME,
        status VARCHAR(20) DEFAULT 'Scheduled',  -- Status of the appointment
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES Patient(patient_id),
        FOREIGN KEY (doctor_id) REFERENCES Staff(staff_id)
    );
    """)
    
    # Create the Medical Record table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Medical_Record (
        record_id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        doctor_id INT,
        diagnosis BLOB,                     -- Encrypted diagnosis
        treatment_plan BLOB,                -- Encrypted treatment plan
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES Patient(patient_id),
        FOREIGN KEY (doctor_id) REFERENCES Staff(staff_id)
    );
    """)
    
    def safe_create_index(sql_stmt):
        try:
            cursor.execute(sql_stmt)
        except mysql.connector.Error as exc:
            if exc.errno == errorcode.ER_DUP_KEYNAME:
                return
            raise

    # Create the Billing table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Billing (
        billing_id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        total_amount DECIMAL(10, 2) NOT NULL,
        paid_amount DECIMAL(10, 2) DEFAULT 0.00,
        status VARCHAR(20) DEFAULT 'Pending',
        payment_due_date DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES Patient(patient_id)
    );
    """)
    safe_create_index("CREATE INDEX idx_billing_patient ON Billing(patient_id);")
    safe_create_index("CREATE INDEX idx_billing_status ON Billing(status);")

    # Create the Payment_Methods table (store encrypted method data)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Payment_Methods (
        payment_method_id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT NOT NULL,
        type ENUM('CARD','BANK') NOT NULL,
        last4 VARCHAR(4),
        data_enc BLOB NOT NULL,             -- Encrypted full payment payload
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES Patient(patient_id)
    );
    """)
    safe_create_index("CREATE INDEX idx_paymethod_patient ON Payment_Methods(patient_id);")
    safe_create_index("CREATE INDEX idx_paymethod_default ON Payment_Methods(patient_id, is_default);")

    # Create the Payment_Transactions table (all payments made)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Payment_Transactions (
        payment_id INT AUTO_INCREMENT PRIMARY KEY,
        billing_id INT NOT NULL,
        patient_id INT NOT NULL,
        payment_method_id INT,
        amount DECIMAL(10, 2) NOT NULL,
        paid_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(20) DEFAULT 'Posted',
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (billing_id) REFERENCES Billing(billing_id),
        FOREIGN KEY (patient_id) REFERENCES Patient(patient_id),
        FOREIGN KEY (payment_method_id) REFERENCES Payment_Methods(payment_method_id)
    );
    """)
    safe_create_index("CREATE INDEX idx_payment_tx_billing ON Payment_Transactions(billing_id);")
    safe_create_index("CREATE INDEX idx_payment_tx_patient ON Payment_Transactions(patient_id);")

    # Create table for additional sensitive identifiers (address, MRN, insurance)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Patient_Sensitive (
        sensitive_id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT NOT NULL,
        mrn BLOB NOT NULL,                    -- Encrypted MRN
        home_address BLOB,                    -- Encrypted address
        insurance_policy BLOB,                -- Encrypted insurance policy number
        card_last4 VARCHAR(12),               -- Last 4-6 digits only (no full PAN storage)
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES Patient(patient_id) ON DELETE CASCADE
    );
    """)
    safe_create_index("CREATE INDEX idx_sensitive_patient ON Patient_Sensitive(patient_id);")
    
    # Audit log table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Audit_Log (
        audit_id INT AUTO_INCREMENT PRIMARY KEY,
        table_name VARCHAR(255) NOT NULL,
        record_id INT NOT NULL,
        action VARCHAR(50) NOT NULL,
        changed_by VARCHAR(255),
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        old_data TEXT,
        new_data TEXT
    );
    """)
    safe_create_index("CREATE INDEX idx_audit_table_record ON Audit_Log(table_name, record_id);")

    # Triggers for audit logging
    triggers = [
        # Patient updates
        ("DROP TRIGGER IF EXISTS trg_patient_before_update;", """
        CREATE TRIGGER trg_patient_before_update
        BEFORE UPDATE ON Patient
        FOR EACH ROW
        BEGIN
            INSERT INTO Audit_Log (table_name, record_id, action, changed_by, old_data, new_data)
            VALUES (
                'Patient',
                OLD.patient_id,
                'UPDATE',
                'SYSTEM',
                CONCAT('{\"first_name\":\"', OLD.first_name, '\",\"last_name\":\"', OLD.last_name, '\",\"dob\":\"', OLD.dob, '\",\"gender\":\"', OLD.gender, '\"}'),
                CONCAT('{\"first_name\":\"', NEW.first_name, '\",\"last_name\":\"', NEW.last_name, '\",\"dob\":\"', NEW.dob, '\",\"gender\":\"', NEW.gender, '\"}')
            );
        END;
        """),
        # Patient sensitive updates
        ("DROP TRIGGER IF EXISTS trg_patient_sensitive_before_update;", """
        CREATE TRIGGER trg_patient_sensitive_before_update
        BEFORE UPDATE ON Patient_Sensitive
        FOR EACH ROW
        BEGIN
            INSERT INTO Audit_Log (table_name, record_id, action, changed_by, old_data, new_data)
            VALUES (
                'Patient_Sensitive',
                OLD.sensitive_id,
                'UPDATE',
                'SYSTEM',
                CONCAT('{\"card_last4\":\"', OLD.card_last4, '\"}'),
                CONCAT('{\"card_last4\":\"', NEW.card_last4, '\"}')
            );
        END;
        """),
        # Billing updates
        ("DROP TRIGGER IF EXISTS trg_billing_before_update;", """
        CREATE TRIGGER trg_billing_before_update
        BEFORE UPDATE ON Billing
        FOR EACH ROW
        BEGIN
            INSERT INTO Audit_Log (table_name, record_id, action, changed_by, old_data, new_data)
            VALUES (
                'Billing',
                OLD.billing_id,
                'UPDATE',
                'SYSTEM',
                CONCAT('{\"total_amount\":', OLD.total_amount, ',\"paid_amount\":', OLD.paid_amount, ',\"status\":\"', OLD.status, '\"}'),
                CONCAT('{\"total_amount\":', NEW.total_amount, ',\"paid_amount\":', NEW.paid_amount, ',\"status\":\"', NEW.status, '\"}')
            );
        END;
        """),
        # Payment methods updates
        ("DROP TRIGGER IF EXISTS trg_paymethod_before_update;", """
        CREATE TRIGGER trg_paymethod_before_update
        BEFORE UPDATE ON Payment_Methods
        FOR EACH ROW
        BEGIN
            INSERT INTO Audit_Log (table_name, record_id, action, changed_by, old_data, new_data)
            VALUES (
                'Payment_Methods',
                OLD.payment_method_id,
                'UPDATE',
                'SYSTEM',
                CONCAT('{\"type\":\"', OLD.type, '\",\"last4\":\"', OLD.last4, '\",\"is_default\":', OLD.is_default, '}'),
                CONCAT('{\"type\":\"', NEW.type, '\",\"last4\":\"', NEW.last4, '\",\"is_default\":', NEW.is_default, '}')
            );
        END;
        """),
        # Payment transactions inserts (log new payments)
        ("DROP TRIGGER IF EXISTS trg_payment_tx_after_insert;", """
        CREATE TRIGGER trg_payment_tx_after_insert
        AFTER INSERT ON Payment_Transactions
        FOR EACH ROW
        BEGIN
            INSERT INTO Audit_Log (table_name, record_id, action, changed_by, new_data)
            VALUES (
                'Payment_Transactions',
                NEW.payment_id,
                'INSERT',
                'SYSTEM',
                CONCAT('{\"billing_id\":', NEW.billing_id, ',\"patient_id\":', NEW.patient_id, ',\"amount\":', NEW.amount, ',\"status\":\"', NEW.status, '\"}')
            );
        END;
        """)
    ]

    for drop_sql, create_sql in triggers:
        cursor.execute(drop_sql)
        cursor.execute(create_sql)
        db_connection.commit()

    db_connection.commit()
    cursor.close()
    db_connection.close()
    
    print("Database and tables created successfully!")


def create_initial_users():
    """Create initial user accounts for admin, staff, and patient"""
    db_connection = connect_to_db()
    db_connection.database = "secure_hospital_db"
    cursor = db_connection.cursor()
    
    try:
        # Check if users already exist
        cursor.execute("SELECT COUNT(*) as count FROM Users")
        existing_count = cursor.fetchone()[0]
        
        if existing_count > 0:
            print(f"Users table already has {existing_count} users. Skipping initial user creation.")
            return
        
        # Create initial admin user (no reference_id needed for admin)
        admin_password_hash = generate_password_hash('default')
        cursor.execute("""
            INSERT INTO Users (email, password_hash, role, reference_id, is_active)
            VALUES (%s, %s, %s, %s, %s)
        """, ('root@gmail.com', admin_password_hash, 'admin', None, True))
        
        # Create initial staff user (will need to link to staff_id later)
        staff_password_hash = generate_password_hash('staff123')
        cursor.execute("""
            INSERT INTO Users (email, password_hash, role, reference_id, is_active)
            VALUES (%s, %s, %s, %s, %s)
        """, ('staff@hospital.com', staff_password_hash, 'staff', None, True))
        
        # Create initial patient user (will need to link to patient_id later)
        patient_password_hash = generate_password_hash('patient123')
        cursor.execute("""
            INSERT INTO Users (email, password_hash, role, reference_id, is_active)
            VALUES (%s, %s, %s, %s, %s)
        """, ('patient@hospital.com', patient_password_hash, 'patient', None, True))
        
        db_connection.commit()
        print("Initial users created successfully!")
        print("  Admin: root@gmail.com / default")
        print("  Staff: staff@hospital.com / staff123")
        print("  Patient: patient@hospital.com / patient123")
    except Exception as e:
        print(f"Error creating initial users: {e}")
        db_connection.rollback()
    finally:
        cursor.close()
        db_connection.close()

def insert_patient_data(db_connection, patient_data):
    """Insert patient data into the database after encrypting sensitive fields"""
    cursor = db_connection.cursor()
    
    # Encrypt sensitive fields
    encrypted_phone = encrypt_data(patient_data['phone_number'])
    encrypted_email = encrypt_data(patient_data['email'])
    encrypted_ssn = encrypt_data(patient_data['ssn'])
    encrypted_state_id = encrypt_data(patient_data['state_id'])
    
    # Prepare the SQL insert query
    query = """
        INSERT INTO Patient (first_name, last_name, dob, gender, phone_number, email, ssn, state_id, primary_doctor_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    
    data = (
        patient_data['first_name'],
        patient_data['last_name'],
        patient_data['dob'],
        patient_data['gender'],
        encrypted_phone,
        encrypted_email,
        encrypted_ssn,
        encrypted_state_id,
        patient_data.get('primary_doctor_id', None)
    )
    
    # Execute the query and commit the changes
    cursor.execute(query, data)
    db_connection.commit()
    patient_id = cursor.lastrowid
    cursor.close()
    
    print(f"Patient data inserted successfully! Patient ID: {patient_id}")
    return patient_id

def get_patient_data(db_connection, patient_id):
    """Retrieve patient data from the database and decrypt sensitive fields"""
    cursor = db_connection.cursor()
    
    # Query to fetch patient data
    query = "SELECT * FROM Patient WHERE patient_id = %s"
    cursor.execute(query, (patient_id,))
    result = cursor.fetchone()
    
    if result:
        # Decrypt the sensitive fields
        decrypted_phone = decrypt_data(result[5])  # phone_number
        decrypted_email = decrypt_data(result[6])  # email
        decrypted_ssn = decrypt_data(result[7])    # ssn
        decrypted_state_id = decrypt_data(result[8])  # state_id
        
        # Return the decrypted data
        return {
            'patient_id': result[0],
            'first_name': result[1],
            'last_name': result[2],
            'dob': result[3],
            'gender': result[4],
            'phone_number': decrypted_phone,
            'email': decrypted_email,
            'ssn': decrypted_ssn,
            'state_id': decrypted_state_id,
            'primary_doctor_id': result[9]
        }
    else:
        print("Patient not found!")
        return None

def insert_staff_data(db_connection, staff_data):
    """Insert staff data into the database after encrypting sensitive fields"""
    cursor = db_connection.cursor()
    
    # Encrypt sensitive fields
    encrypted_email = encrypt_data(staff_data['email'])
    encrypted_phone = encrypt_data(staff_data['phone_number'])
    
    query = """
        INSERT INTO Staff (first_name, last_name, role, email, phone_number)
        VALUES (%s, %s, %s, %s, %s)
    """
    
    data = (
        staff_data['first_name'],
        staff_data['last_name'],
        staff_data['role'],
        encrypted_email,
        encrypted_phone
    )
    
    cursor.execute(query, data)
    db_connection.commit()
    staff_id = cursor.lastrowid
    cursor.close()
    
    print(f"Staff data inserted successfully! Staff ID: {staff_id}")
    return staff_id

def main():
    # Step 1: Create Database and Tables
    create_database_and_tables()
    
    # Step 2: Create initial users
    create_initial_users()
    
    # Step 3: Connect to the database
    db_connection = connect_to_db()
    db_connection.database = "secure_hospital_db"
    
    # Step 3: Insert staff data first (required for foreign key)
    staff_data = {
        'first_name': 'Dr. Jane',
        'last_name': 'Smith',
        'role': 'Doctor',
        'email': 'jane.smith@hospital.com',
        'phone_number': '555-0100'
    }
    staff_id = insert_staff_data(db_connection, staff_data)
    
    # Step 4: Insert patient data
    patient_data = {
        'first_name': 'John',
        'last_name': 'Doe',
        'dob': '1990-01-01',
        'gender': 'Male',
        'phone_number': '123-456-7890',
        'email': 'john.doe@example.com',
        'ssn': '123-45-6789',
        'state_id': 'CA1234567',
        'primary_doctor_id': staff_id
    }
    patient_id = insert_patient_data(db_connection, patient_data)
    
    # Step 5: Retrieve and display patient data
    retrieved_data = get_patient_data(db_connection, patient_id)
    if retrieved_data:
        print("\nRetrieved Patient Data:")
        print(f"Name: {retrieved_data['first_name']} {retrieved_data['last_name']}")
        print(f"Email: {retrieved_data['email']}")
        print(f"Phone: {retrieved_data['phone_number']}")
    
    db_connection.close()

if __name__ == "__main__":
    main()
