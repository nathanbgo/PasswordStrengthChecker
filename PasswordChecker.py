import re
import bcrypt
import sqlite3

def load_common_passwords(file_path):
    with open(file_path, 'r', encoding='latin-1') as file:
        common_passwords = {line.strip() for line in file}
    return common_passwords

def check_password_strength(password, common_passwords_file):

    # Check for minimum length
    if len(password) < 8:
        return "Password is too short. It should be at least 8 characters."

    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return "Password should contain at least one uppercase letter."

    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return "Password should contain at least one lowercase letter."

    # Check for at least one digit
    if not re.search(r'[0-9]', password):
        return "Password should contain at least one digit."

    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password should contain at least one special character."

    # Load common passwords from the file
    common_passwords = load_common_passwords(common_passwords_file)

    # Check if the password is a common one
    if password.lower() in common_passwords:
        return "Password is too common and easy to guess."

    return "Password is strong!"

def hash_password(password):
    """Hash the password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def store_password_in_db(hashed_password, db_file='passwords.db'):
    """Store the hashed password in an SQLite database."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password TEXT NOT NULL
    )
    ''')

    # Insert hashed password into the table
    cursor.execute('INSERT INTO users (password) VALUES (?)', (hashed_password,))
    conn.commit()
    conn.close()

def main():
    # Input password
    password = input("Enter your password: ")
    
    # Path to common passwords file (e.g., rockyou.txt)
    common_passwords_file = 'rockyou.txt'
    
    # Check password strength
    result = check_password_strength(password, common_passwords_file)
    if result != "Password is strong!":
        print(result)
    else:
        print(result)
        
        # Hash the password
        hashed_password = hash_password(password)
        
        # Store the hashed password in the database
        store_password_in_db(hashed_password)
        
        print("Password has been hashed and stored in the database.")

if __name__ == "__main__":
    main()
