import os
import mysql.connector

# --------------------------------------------------------
# Load credentials from environment variables
# --------------------------------------------------------
DB_USER = os.environ.get("DB_USER")
DB_PASS = os.environ.get("DB_PASS")

if not DB_USER or not DB_PASS:
    raise RuntimeError("Environment variables DB_USER and DB_PASS must be set.")

# --------------------------------------------------------
# Connect to MySQL server
# --------------------------------------------------------
print("[1] Connecting to MySQL server...")

server_conn = mysql.connector.connect(
    host="localhost",
    user=DB_USER,
    password=DB_PASS
)
server_cursor = server_conn.cursor()

# --------------------------------------------------------
# Create database if not exists
# --------------------------------------------------------
print("[2] Creating database 'secure_hospital_db'...")
server_cursor.execute("CREATE DATABASE IF NOT EXISTS secure_hospital_db;")
server_cursor.close()
server_conn.close()

# --------------------------------------------------------
# Connect to the database
# --------------------------------------------------------
print("[3] Connecting to secure_hospital_db...")

conn = mysql.connector.connect(
    host="localhost",
    user=DB_USER,
    password=DB_PASS,
    database="secure_hospital_db"
)
cur = conn.cursor()

# --------------------------------------------------------
# SQL schema (tables, indexes, constraints)
# --------------------------------------------------------
print("[4] Creating tables...")

SCHEMA_SQL = """

-- TABLE 1: persons
CREATE TABLE IF NOT EXISTS persons (
    person_id      INT AUTO_INCREMENT PRIMARY KEY,
    full_name      VARCHAR(255) NOT NULL,
    date_of_birth  VARCHAR(50) NOT NULL,
    birthplace     VARCHAR(255) NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE INDEX idx_person_name ON persons(full_name);
CREATE INDEX idx_person_dob ON persons(date_of_birth);


-- TABLE 2: government_ids
CREATE TABLE IF NOT EXISTS government_ids (
    gov_id              INT AUTO_INCREMENT PRIMARY KEY,
    person_id           INT NOT NULL,

    ssn_enc             BLOB,
    drivers_license_enc BLOB,
    passport_enc        BLOB,
    state_id_enc        BLOB,
    vehicle_reg_enc     BLOB,

    iv                  BLOB NOT NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (person_id) REFERENCES persons(person_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX idx_gov_person ON government_ids(person_id);


-- TABLE 3: contact_info
CREATE TABLE IF NOT EXISTS contact_info (
    contact_id    INT AUTO_INCREMENT PRIMARY KEY,
    person_id     INT NOT NULL,

    address_enc   BLOB,
    email         VARCHAR(255) NOT NULL,
    phone_enc     BLOB,
    ip_address    VARCHAR(100),

    iv            BLOB NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (person_id) REFERENCES persons(person_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX idx_contact_person ON contact_info(person_id);
CREATE INDEX idx_contact_email ON contact_info(email);


-- TABLE 4: financial_accounts
CREATE TABLE IF NOT EXISTS financial_accounts (
    fin_id                INT AUTO_INCREMENT PRIMARY KEY,
    person_id             INT NOT NULL,

    card_number_enc       BLOB,
    card_last4            VARCHAR(4),
    bank_account_enc      BLOB,
    routing_number_enc    BLOB,
    insurance_account_enc BLOB,

    iv                    BLOB NOT NULL,
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (person_id) REFERENCES persons(person_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX idx_fin_person ON financial_accounts(person_id);


-- TABLE 5: health_genetic_info
CREATE TABLE IF NOT EXISTS health_genetic_info (
    health_id             INT AUTO_INCREMENT PRIMARY KEY,
    person_id             INT NOT NULL,

    medical_record_id_enc BLOB,
    genetic_data_enc      BLOB,

    iv                    BLOB NOT NULL,
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (person_id) REFERENCES persons(person_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX idx_health_person ON health_genetic_info(person_id);


-- TABLE 6: audit_log (for all triggers)
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id    INT AUTO_INCREMENT PRIMARY KEY,
    table_name  VARCHAR(255) NOT NULL,
    record_id   INT NOT NULL,
    action      VARCHAR(50) NOT NULL,
    changed_by  VARCHAR(255),
    changed_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    old_data    TEXT
);

CREATE INDEX idx_audit_table_record ON audit_log(table_name, record_id);


-- TABLE 7: appointments (NEW TABLE)
CREATE TABLE IF NOT EXISTS appointments (
    appt_id        INT AUTO_INCREMENT PRIMARY KEY,
    person_id      INT NOT NULL,
    doctor_name    VARCHAR(255) NOT NULL,
    appt_datetime  DATETIME NOT NULL,
    purpose_enc    BLOB,
    iv             BLOB NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (person_id) REFERENCES persons(person_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

"""

# --------------------------------------------------------
# Execute the schema SQL
# --------------------------------------------------------
for statement in SCHEMA_SQL.split(";"):
    stmt = statement.strip()
    if stmt:
        try:
            cur.execute(stmt + ";")
        except mysql.connector.Error as e:
            print("Error executing:", stmt)
            print("MySQL Error:", e)

print("[✓] Tables created.")

# --------------------------------------------------------
# Create all triggers (tamper-control)
# --------------------------------------------------------
print("[5] Creating triggers...")

TRIGGERS = [

# Trigger 1: persons before update
("""
DROP TRIGGER IF EXISTS trg_persons_before_update;
""",
"""
CREATE TRIGGER trg_persons_before_update
BEFORE UPDATE ON persons
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, changed_by, old_data)
    VALUES (
        'persons',
        OLD.person_id,
        'UPDATE',
        'SYSTEM',
        CONCAT(
            '{',
            '"full_name":"', OLD.full_name, '",',
            '"date_of_birth":"', OLD.date_of_birth, '",',
            '"birthplace":"', OLD.birthplace, '"',
            '}'
        )
    );
END;
"""
),

# Trigger 2: government_ids
("""
DROP TRIGGER IF EXISTS trg_gov_before_update;
""",
"""
CREATE TRIGGER trg_gov_before_update
BEFORE UPDATE ON government_ids
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, changed_by, old_data)
    VALUES (
        'government_ids',
        OLD.gov_id,
        'UPDATE',
        'SYSTEM',
        '{ "encrypted_fields_changed": true }'
    );
END;
"""
),

# Trigger 3: appointments
("""
DROP TRIGGER IF EXISTS trg_appt_before_update;
""",
"""
CREATE TRIGGER trg_appt_before_update
BEFORE UPDATE ON appointments
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, changed_by, old_data)
    VALUES (
        'appointments',
        OLD.appt_id,
        'UPDATE',
        'SYSTEM',
        CONCAT(
            '{',
            '"doctor_name":"', OLD.doctor_name, '",',
            '"appt_datetime":"', OLD.appt_datetime, '"',
            '}'
        )
    );
END;
"""
)

]

# Execute triggers
for drop_sql, create_sql in TRIGGERS:
    try:
        cur.execute(drop_sql)
        cur.execute(create_sql)
        conn.commit()
    except mysql.connector.Error as e:
        print("Trigger creation error:", e)

print("[✓] Triggers created successfully.")

cur.close()
conn.close()

print("\n[✓] Database setup complete.")
