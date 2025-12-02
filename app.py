from flask import Flask, render_template, request, redirect
from config import get_db_conn
from crypto_utils import encrypt_value

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def patient_form():
    if request.method == "POST":
        try:
            # Read form fields
            full_name = request.form.get("full_name", "").strip()
            dob = request.form.get("dob", "").strip()          # HTML date input (YYYY-MM-DD)
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            address = request.form.get("address", "").strip()
            mrn = request.form.get("mrn", "").strip()
            diagnosis = request.form.get("diagnosis", "").strip()
            insurance = request.form.get("insurance", "").strip()
            card = request.form.get("card", "").strip()
            amount = request.form.get("amount", "").strip()

            # Basic server-side validation
            if len(full_name) < 2 or "@" not in email or len(mrn) < 3 or len(card) < 4:
                return "Invalid input", 400

            # Connect to DB
            conn = get_db_conn()
            cur = conn.cursor()

            # 1) Store PII in patients
            cur.execute(
                """
                INSERT INTO patients (full_name, dob, email, phone, address)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (full_name, dob, email, phone, address),
            )
            patient_id = cur.lastrowid

            # 2) Store encrypted PHI in medical_records
            cur.execute(
                """
                INSERT INTO medical_records (patient_id, mrn_enc, diagnosis_enc)
                VALUES (%s, %s, %s)
                """,
                (patient_id, encrypt_value(mrn), encrypt_value(diagnosis)),
            )

            # 3) Store encrypted insurance data
            cur.execute(
                """
                INSERT INTO insurance (patient_id, insurance_policy_enc, provider_name)
                VALUES (%s, %s, %s)
                """,
                (patient_id, encrypt_value(insurance), "Unknown"),
            )

            # 4) Store billing info
            cur.execute(
                """
                INSERT INTO billing (patient_id, amount, status)
                VALUES (%s, %s, %s)
                """,
                (patient_id, amount, "PENDING"),
            )
            billing_id = cur.lastrowid

            # 5) Store encrypted card data in payments
            cur.execute(
                """
                INSERT INTO payments (billing_id, card_number_enc)
                VALUES (%s, %s)
                """,
                (billing_id, encrypt_value(card)),
            )

            conn.commit()
            cur.close()
            conn.close()

            # Redirect to the nice success page
            return redirect("/success")

        except Exception as e:
            # Helpful for debugging & assignment explanation
            print("ERROR IN POST /:", repr(e))
            return f"Error while saving to DB: {e}", 500

    # GET: show the secure intake form
    return render_template("patient_form.html")


@app.route("/success")
def success():
    # Uses your styled success.html
    return render_template("success.html")


if __name__ == "__main__":
    # Debug on for development; mention in report this wouldn't be used in prod
    app.run(host="0.0.0.0", port=5000, debug=True)
