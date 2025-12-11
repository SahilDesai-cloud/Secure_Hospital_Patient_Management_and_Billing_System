# Secure Hospital Patient Management and Billing System

A secure web application for managing hospital patients, staff, appointments, medical records, and billing with comprehensive security features including data encryption, audit logging, and role-based access control.

## Prerequisites

- Python 3.7 or higher
- MySQL Server 5.7 or higher
- MySQL user with database creation privileges

## Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MySQL database credentials:**
   
   Create a `.env` file in the project root with your MySQL credentials:
   ```
   DB_USER=your_mysql_username
   DB_PASS=your_mysql_password
   ```
   
   Example:
   ```
   DB_USER=root
   DB_PASS=mypassword
   ```

## Running the Application

1. **Start MySQL server** (if not already running)

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Access the application:**
   
   Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

## Important Notes

- **Database Setup**: The database and tables are created automatically when you first run `app.py`. No manual database setup is required.
- **Dummy Data**: The application automatically inserts sample data for testing purposes on first run.

## Login Credentials

The following test accounts are created automatically:

| Role | Email | Password |
|------|-------|----------|
| **Admin** | root@gmail.com | default |
| **Staff** | staff@hospital.com | staff123 |
| **Patient** | patient@hospital.com | patient123 |

## Features

- **Role-based Access Control**: Admin, Staff, and Patient roles with different permissions
- **Data Encryption**: Sensitive patient data (SSN, addresses, medical records) encrypted at rest
- **Audit Logging**: All database changes tracked with timestamps and user information
- **Security Compliance**: CSRF protection, secure sessions, security headers, and data masking
- **Database Management**: Admin can view all database tables with horizontal scrolling
- **Patient Management**: Register patients, view appointments, medical records, and billing

## Project Authors

- Suksham Fulzele (ID: 989686048)
- Sahil Shekhar Desai (ID: 989485311)
- Sruthi Satyavarapu (ID: 989492060)
- Sriyuktha Sanagavarapu (ID: 989483329)
