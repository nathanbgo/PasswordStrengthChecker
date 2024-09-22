# PasswordStrengthChecker
Password Strength Checker and Hasher
This Python script checks the strength of user-provided passwords and ensures they meet common security criteria such as length, character variety, and absence from a list of common passwords (e.g., rockyou.txt). After validating the password strength, it hashes the password using bcrypt and securely stores the hashed password in an SQLite database.

Features:
Checks password strength based on length, uppercase, lowercase, digits, and special characters.
Compares the password against a list of common passwords for added security.
Hashes passwords with bcrypt for secure storage.
Stores hashed passwords in an SQLite database.
