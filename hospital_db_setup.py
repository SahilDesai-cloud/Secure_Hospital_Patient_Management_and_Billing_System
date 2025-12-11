import os
from datetime import datetime, timedelta
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
    
    # Ensure primary_doctor_id is integer or None, never boolean
    primary_doctor_id = patient_data.get('primary_doctor_id', None)
    if primary_doctor_id is not None:
        primary_doctor_id = int(primary_doctor_id)
    
    data = (
        patient_data['first_name'],
        patient_data['last_name'],
        patient_data['dob'],
        patient_data['gender'],
        encrypted_phone,
        encrypted_email,
        encrypted_ssn,
        encrypted_state_id,
        primary_doctor_id
    )
    
    # Execute the query and commit the changes
    cursor.execute(query, data)
    db_connection.commit()
    patient_id = int(cursor.lastrowid)  # Ensure integer, not boolean
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
    staff_id = int(cursor.lastrowid)  # Ensure integer, not boolean
    cursor.close()
    
    print(f"Staff data inserted successfully! Staff ID: {staff_id}")
    return staff_id

def insert_comprehensive_dummy_data():
    """Insert comprehensive dummy data for all tables with correct information"""
    db_connection = connect_to_db()
    db_connection.database = "secure_hospital_db"
    cursor = db_connection.cursor()
    
    try:
        # Check if dummy data already exists
        cursor.execute("SELECT COUNT(*) FROM Staff")
        staff_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM Patient")
        patient_count = cursor.fetchone()[0]
        
        if staff_count > 0 and patient_count > 0:
            print(f"Database already has {staff_count} staff and {patient_count} patients. Skipping dummy data insertion.")
            cursor.close()
            db_connection.close()
            return
        
        print("\nInserting comprehensive dummy data for all tables...")
        
        # Insert multiple staff members (excluding Dr. Jane Smith - Staff ID 1)
        staff_members = [
            {'first_name': 'Dr. Michael', 'last_name': 'Johnson', 'role': 'Doctor', 'email': 'michael.johnson@hospital.com', 'phone_number': '555-0101'},
            {'first_name': 'Dr. Sarah', 'last_name': 'Williams', 'role': 'Doctor', 'email': 'sarah.williams@hospital.com', 'phone_number': '555-0102'},
            {'first_name': 'Dr. Robert', 'last_name': 'Brown', 'role': 'Doctor', 'email': 'robert.brown@hospital.com', 'phone_number': '555-0103'},
            {'first_name': 'Nurse', 'last_name': 'Emily', 'role': 'Nurse', 'email': 'emily.nurse@hospital.com', 'phone_number': '555-0200'},
            {'first_name': 'Nurse', 'last_name': 'James', 'role': 'Nurse', 'email': 'james.nurse@hospital.com', 'phone_number': '555-0201'},
        ]
        
        staff_ids = []
        for staff_data in staff_members:
            staff_id = insert_staff_data(db_connection, staff_data)
            staff_ids.append(staff_id)
        
        # Insert multiple patients with complete information (excluding John Doe - Patient ID 1 and Jane Smith patient)
        # Ensure all staff_ids are integers to prevent boolean values in ID columns
        patients = [
            {
                'first_name': 'Michael', 'last_name': 'Brown', 'dob': '1992-08-10', 'gender': 'Male',
                'phone_number': '555-345-6789', 'email': 'michael.brown@email.com',
                'ssn': '345-67-8901', 'state_id': 'TX4567890', 'primary_doctor_id': int(staff_ids[0])
            },
            {
                'first_name': 'Emily', 'last_name': 'Davis', 'dob': '1988-12-05', 'gender': 'Female',
                'phone_number': '555-456-7890', 'email': 'emily.davis@email.com',
                'ssn': '456-78-9012', 'state_id': 'FL7890123', 'primary_doctor_id': int(staff_ids[1])
            },
            {
                'first_name': 'David', 'last_name': 'Wilson', 'dob': '1995-03-25', 'gender': 'Male',
                'phone_number': '555-567-8901', 'email': 'david.wilson@email.com',
                'ssn': '567-89-0123', 'state_id': 'IL2345678', 'primary_doctor_id': int(staff_ids[0])
            },
            {
                'first_name': 'Sarah', 'last_name': 'Miller', 'dob': '1991-07-18', 'gender': 'Female',
                'phone_number': '555-678-9012', 'email': 'sarah.miller@email.com',
                'ssn': '678-90-1234', 'state_id': 'WA3456789', 'primary_doctor_id': int(staff_ids[2])
            },
        ]
        
        patient_ids = []
        for patient_data in patients:
            patient_id = insert_patient_data(db_connection, patient_data)
            patient_ids.append(patient_id)
        
        # Insert Patient_Sensitive data (excluding Patient ID 1 - John Doe and Jane Smith)
        sensitive_data_list = [
            {'patient_id': patient_ids[0], 'mrn': 'MRN003456', 'home_address': '789 Pine Road, Houston, TX 77001', 'insurance_policy': 'INS-345678901', 'card_last4': '3456'},
            {'patient_id': patient_ids[1], 'mrn': 'MRN004567', 'home_address': '321 Elm Street, Miami, FL 33101', 'insurance_policy': 'INS-456789012', 'card_last4': '4567'},
            {'patient_id': patient_ids[2], 'mrn': 'MRN005678', 'home_address': '654 Maple Drive, Chicago, IL 60601', 'insurance_policy': 'INS-567890123', 'card_last4': '5678'},
            {'patient_id': patient_ids[3], 'mrn': 'MRN006789', 'home_address': '987 Cedar Lane, Seattle, WA 98101', 'insurance_policy': 'INS-678901234', 'card_last4': '6789'},
        ]
        
        for sensitive_data in sensitive_data_list:
            # Ensure patient_id is integer, not boolean
            patient_id_val = int(sensitive_data['patient_id']) if sensitive_data['patient_id'] is not None else None
            cursor.execute("""
                INSERT INTO Patient_Sensitive (patient_id, mrn, home_address, insurance_policy, card_last4)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                patient_id_val,
                encrypt_data(sensitive_data['mrn']),
                encrypt_data(sensitive_data['home_address']),
                encrypt_data(sensitive_data['insurance_policy']),
                sensitive_data['card_last4']
            ))
        
        # Insert Appointments (excluding appointments with Patient ID 1 and Staff ID 1)
        appointments = [
            {'patient_id': patient_ids[0], 'doctor_id': staff_ids[0], 'appointment_date': datetime.now() + timedelta(days=3, hours=9), 'status': 'Scheduled'},
            {'patient_id': patient_ids[1], 'doctor_id': staff_ids[1], 'appointment_date': datetime.now() - timedelta(days=2, hours=15), 'status': 'Completed'},
            {'patient_id': patient_ids[2], 'doctor_id': staff_ids[0], 'appointment_date': datetime.now() + timedelta(days=4, hours=13), 'status': 'Scheduled'},
            {'patient_id': patient_ids[3], 'doctor_id': staff_ids[1], 'appointment_date': datetime.now() - timedelta(days=1, hours=10), 'status': 'Completed'},
        ]
        
        for apt in appointments:
            cursor.execute("""
                INSERT INTO Appointment (patient_id, doctor_id, appointment_date, status)
                VALUES (%s, %s, %s, %s)
            """, (int(apt['patient_id']), int(apt['doctor_id']), apt['appointment_date'], apt['status']))
        
        # Insert Medical Records (excluding records for Patient ID 1 and Staff ID 1)
        medical_records = [
            {'patient_id': patient_ids[0], 'doctor_id': staff_ids[0], 'diagnosis': 'Common Cold', 'treatment_plan': 'Rest, fluids, over-the-counter cold medication. Return if symptoms persist beyond 7 days.'},
            {'patient_id': patient_ids[1], 'doctor_id': staff_ids[1], 'diagnosis': 'Migraine', 'treatment_plan': 'Sumatriptan 50mg as needed for acute attacks. Avoid known triggers. Stress management recommended.'},
            {'patient_id': patient_ids[2], 'doctor_id': staff_ids[0], 'diagnosis': 'Asthma', 'treatment_plan': 'Albuterol inhaler 2 puffs every 4-6 hours as needed. Avoid allergens. Annual flu shot recommended.'},
            {'patient_id': patient_ids[3], 'doctor_id': staff_ids[2], 'diagnosis': 'Seasonal Allergies', 'treatment_plan': 'Loratadine 10mg daily. Nasal spray as needed. Allergy testing recommended if symptoms persist.'},
        ]
        
        for record in medical_records:
            cursor.execute("""
                INSERT INTO Medical_Record (patient_id, doctor_id, diagnosis, treatment_plan)
                VALUES (%s, %s, %s, %s)
            """, (
                int(record['patient_id']),  # Ensure integer
                int(record['doctor_id']),   # Ensure integer
                encrypt_data(record['diagnosis']),
                encrypt_data(record['treatment_plan'])
            ))
        
        # Insert Billing records (excluding Patient ID 1)
        billing_records = [
            {'patient_id': patient_ids[0], 'total_amount': 300.00, 'paid_amount': 300.00, 'status': 'Paid', 'payment_due_date': datetime.now() - timedelta(days=5)},
            {'patient_id': patient_ids[1], 'total_amount': 1200.00, 'paid_amount': 0.00, 'status': 'Pending', 'payment_due_date': datetime.now() + timedelta(days=45)},
            {'patient_id': patient_ids[2], 'total_amount': 450.00, 'paid_amount': 450.00, 'status': 'Paid', 'payment_due_date': datetime.now() - timedelta(days=10)},
            {'patient_id': patient_ids[3], 'total_amount': 850.00, 'paid_amount': 425.00, 'status': 'Partial', 'payment_due_date': datetime.now() + timedelta(days=15)},
        ]
        
        billing_ids = []
        for billing in billing_records:
            cursor.execute("""
                INSERT INTO Billing (patient_id, total_amount, paid_amount, status, payment_due_date)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                int(billing['patient_id']),  # Ensure integer
                billing['total_amount'],
                billing['paid_amount'],
                billing['status'],
                billing['payment_due_date']
            ))
            billing_ids.append(int(cursor.lastrowid))  # Ensure integer, not boolean
        
        # Insert Payment Methods (excluding Patient ID 1)
        payment_methods = [
            {'patient_id': patient_ids[0], 'type': 'BANK', 'last4': '3456', 'data_enc': encrypt_data('{"account_number":"****3456","routing":"123456789","account_type":"checking"}'), 'is_default': True},
            {'patient_id': patient_ids[1], 'type': 'CARD', 'last4': '4567', 'data_enc': encrypt_data('{"card_number":"****4567","expiry":"09/25","cvv":"***","name":"Emily Davis"}'), 'is_default': True},
            {'patient_id': patient_ids[2], 'type': 'BANK', 'last4': '5678', 'data_enc': encrypt_data('{"account_number":"****5678","routing":"987654321","account_type":"savings"}'), 'is_default': True},
            {'patient_id': patient_ids[3], 'type': 'CARD', 'last4': '6789', 'data_enc': encrypt_data('{"card_number":"****6789","expiry":"03/26","cvv":"***","name":"Sarah Miller"}'), 'is_default': True},
        ]
        
        payment_method_ids = []
        for pm in payment_methods:
            cursor.execute("""
                INSERT INTO Payment_Methods (patient_id, type, last4, data_enc, is_default)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                int(pm['patient_id']),  # Ensure integer
                pm['type'],
                pm['last4'],
                pm['data_enc'],
                pm['is_default']
            ))
            payment_method_ids.append(int(cursor.lastrowid))  # Ensure integer, not boolean
        
        # Insert Payment Transactions (excluding Patient ID 1)
        payment_transactions = [
            {'billing_id': billing_ids[0], 'patient_id': patient_ids[0], 'payment_method_id': payment_method_ids[0], 'amount': 300.00, 'status': 'Posted', 'note': 'Full payment for treatment'},
            {'billing_id': billing_ids[2], 'patient_id': patient_ids[2], 'payment_method_id': payment_method_ids[2], 'amount': 450.00, 'status': 'Posted', 'note': 'Full payment completed'},
            {'billing_id': billing_ids[3], 'patient_id': patient_ids[3], 'payment_method_id': payment_method_ids[3], 'amount': 425.00, 'status': 'Posted', 'note': 'Partial payment - balance due'},
        ]
        
        for pt in payment_transactions:
            cursor.execute("""
                INSERT INTO Payment_Transactions (billing_id, patient_id, payment_method_id, amount, status, note)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                int(pt['billing_id']),        # Ensure integer
                int(pt['patient_id']),        # Ensure integer
                int(pt['payment_method_id']),  # Ensure integer
                pt['amount'],
                pt['status'],
                pt['note']
            ))
        
        # Link Users to Staff and Patients (link to first available staff/patient, not Staff ID 1 or Patient ID 1)
        if len(staff_ids) > 0 and len(patient_ids) > 0:
            cursor.execute("UPDATE Users SET reference_id = %s WHERE email = 'staff@hospital.com'", (int(staff_ids[0]),))
            cursor.execute("UPDATE Users SET reference_id = %s WHERE email = 'patient@hospital.com'", (int(patient_ids[0]),))
        
        db_connection.commit()
        print(f"\n✓ Successfully inserted dummy data:")
        print(f"  - {len(staff_members)} staff members")
        print(f"  - {len(patients)} patients")
        print(f"  - {len(sensitive_data_list)} patient sensitive records")
        print(f"  - {len(appointments)} appointments")
        print(f"  - {len(medical_records)} medical records")
        print(f"  - {len(billing_records)} billing records")
        print(f"  - {len(payment_methods)} payment methods")
        print(f"  - {len(payment_transactions)} payment transactions")
        print("  All sensitive data encrypted before storage.")
        
    except Exception as e:
        print(f"Error inserting dummy data: {e}")
        db_connection.rollback()
        raise
    finally:
        cursor.close()
        db_connection.close()


def main():
    # Step 1: Create Database and Tables
    print("="*60)
    print("Creating database and tables...")
    print("="*60)
    create_database_and_tables()
    
    # Step 2: Create initial users
    print("\n" + "="*60)
    print("Creating initial users...")
    print("="*60)
    create_initial_users()
    
    # Step 3: Insert comprehensive dummy data
    print("\n" + "="*60)
    print("Inserting comprehensive dummy data...")
    print("="*60)
    insert_comprehensive_dummy_data()
    
    print("\n" + "="*60)
    print("Database setup completed successfully!")
    print("="*60)

if __name__ == "__main__":
    main()
