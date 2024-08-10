import streamlit as st  # type: ignore
import sqlite3
import bcrypt  # type: ignore
import pandas as pd  # type: ignore
from datetime import datetime
import os

# Page configuration
st.set_page_config(page_title="Login and Register", page_icon="🔒", layout="centered")

# Database setup and functions
def create_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'User'
        )
    ''')
    conn.commit()
    conn.close()

def add_role_column():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        # Check if 'role' column exists
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        if 'role' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT "User"')
            conn.commit()
    except sqlite3.OperationalError as e:
        st.write("An error occurred:", e)
    finally:
        conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def insert_user(username, password, role):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hash_password(password), role))
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password, role FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return result[1]  # Return the role
    return None

# Ensure the database and table exist
create_db()
add_role_column()  # Add the role column if it doesn't exist

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None
if "invoices" not in st.session_state:
    st.session_state.invoices = []

# Main function
def main():
    # Add sidebar for navigation
    st.sidebar.title("Main Menu")
    if not st.session_state.logged_in:
        page = st.sidebar.radio("Select Page", ["Login", "HR Login", "Accountant Login"])
    else:
        if st.session_state.role == "User":
            page = st.sidebar.radio("Select Page", ["Invoice Uploader"])
        elif st.session_state.role == "HR":
            page = st.sidebar.radio("Select Page", ["HR Page"])
        elif st.session_state.role == "Accountant":
            page = st.sidebar.radio("Select Page", ["Accountant"])

    # Sidebar branding (optional)
    logo_path = r"C:\Users\SBAL036\Pictures\SBA LOGO.jpg"
    if os.path.exists(logo_path):
        st.sidebar.image(logo_path, width=200)  # Adjust width as needed
    else:
        st.sidebar.write("Logo not found.")

    st.sidebar.markdown("### SBA")

    # Determine which page to display based on sidebar selection
    if page == "Login":
        if not st.session_state.logged_in:
            st.title("Welcome! Please log in or register to continue.")
            tab_login, tab_register = st.tabs(["Login", "Register"])
            with tab_login:
                login_form()
            with tab_register:
                register_form()
        else:
            st.rerun()

    elif page == "HR Login":
        if not st.session_state.logged_in:
            st.title("HR Login")
            login_form(role="HR")
        else:
            st.rerun()

    elif page == "Accountant Login":
        if not st.session_state.logged_in:
            st.title("Accountant Login")
            login_form(role="Accountant")
        else:
            st.rerun()

    elif page == "HR Page":
        if st.session_state.logged_in and st.session_state.role == "HR":
            hr_page()
        else:
            st.write("You need to log in as HR to access this page.")

    elif page == "Accountant":
        if st.session_state.logged_in and st.session_state.role == "Accountant":
            accountant_page()
        else:
            st.write("You need to log in as Accountant to access this page.")

    elif page == "Invoice Uploader":
        if st.session_state.logged_in and st.session_state.role == "User":
            invoice_uploader()
        else:
            st.write("You need to log in to access this page.")

# Login form function
def login_form(role=None):
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
    
    if submit_button:
        user_role = authenticate_user(username, password)
        if user_role and (role is None or user_role == role):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = user_role
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Invalid username or password")

# Register form function
def register_form():
    st.header("Register")
    with st.form("register_form"):
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")
        role = st.selectbox("Role", ["HR", "Accountant", "User"])  # Add more roles as needed
        submit_button = st.form_submit_button("Register")
    
    if submit_button:
        if username and password:
            try:
                insert_user(username, password, role)
                st.success("Registration successful! Please log in.")
            except sqlite3.IntegrityError:
                st.error("Username already exists.")
        else:
            st.error("Please provide both username and password.")

# Invoice uploader page function
def invoice_uploader():
    st.title(f"Welcome, {st.session_state.username}!")
    st.write("This is the invoice uploader page.")

    # Create form for supplier name and file upload
    with st.form(key='invoice_form'):
        supplier = st.text_input("Supplier Name")
        uploaded_file = st.file_uploader("Upload Document", type=["pdf", "docx", "xlsx"])
        submit_button = st.form_submit_button(label='Submit Invoice')

    if submit_button:
        if supplier and uploaded_file:
            # Process the uploaded file to extract details like invoice number and amount
            invoice_number, amount = extract_invoice_details(uploaded_file)
            
            # Create a dictionary with invoice details
            invoice_details = {
                "Supplier Name": supplier,
                "Invoice Number": invoice_number,
                "Amount": amount,
                "Submit Date": datetime.today().strftime('%Y-%m-%d')  # Current date
            }
            
            # Add the details to the session state
            st.session_state.invoices.append(invoice_details)
            
            # Display success message
            st.success("Invoice submitted successfully!")
        
        else:
            st.error("Please provide both supplier name and upload a file.")

    # Display the table with invoice details
    if st.session_state.invoices:
        st.write("Submitted Invoices:")
        df = pd.DataFrame(st.session_state.invoices)
        st.table(df)

# Function to extract invoice details from the uploaded file
def extract_invoice_details(uploaded_file):
    # Logic to extract invoice number and amount from the uploaded file.
    # This will vary based on the file type (PDF, DOCX, XLSX) and the format of the content.
    # For simplicity, I'll provide placeholders.
    
    # Example of how you might extract data (adjust based on your file format)
    invoice_number = "INV12345"  # Placeholder logic
    amount = "$1,000.00"  # Placeholder logic
    
    return invoice_number, amount

# HR page function
def hr_page():
    st.write("HR page content here...")

# Accountant page function
def accountant_page():
    st.write("Accountant page content here...")

if __name__ == "__main__":
    main()
