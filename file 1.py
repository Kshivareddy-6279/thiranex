# Password Strength Analyzer
# Features:
# 1. Checks password length, complexity, and uniqueness
# 2. Suggests stronger passwords
# 3. Stores old passwords securely using SHA-256 hash
# 4. Prevents password reuse

import re
import random
import string
import hashlib
import os

# File to store old password hashes
PASSWORD_FILE = "old_passwords.txt"


# -----------------------------------
# Hash Password using SHA-256
# -----------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# -----------------------------------
# Load Old Password Hashes
# -----------------------------------
def load_old_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return set()

    with open(PASSWORD_FILE, "r") as file:
        return set(line.strip() for line in file.readlines())


# -----------------------------------
# Save New Password Hash
# -----------------------------------
def save_password(password):
    hashed = hash_password(password)

    with open(PASSWORD_FILE, "a") as file:
        file.write(hashed + "\n")


# -----------------------------------
# Check Password Strength
# -----------------------------------
def analyze_password(password):

    score = 0
    feedback = []

    # Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Uppercase Check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Lowercase Check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Number Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Special Character Check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    # Common Password Check
    common_passwords = [
        "123456",
        "password",
        "qwerty",
        "admin",
        "welcome"
    ]

    if password.lower() in common_passwords:
        feedback.append("This is a very common password.")
        score = 0

    # Reused Password Check
    old_passwords = load_old_passwords()

    if hash_password(password) in old_passwords:
        feedback.append("Password has already been used before.")
        score -= 1

    # Strength Level
    if score >= 6:
        strength = "Very Strong"
    elif score >= 4:
        strength = "Strong"
    elif score >= 2:
        strength = "Medium"
    else:
        strength = "Weak"

    return strength, feedback


# -----------------------------------
# Generate Strong Password Suggestion
# -----------------------------------
def generate_strong_password(length=14):

    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*"
    )

    password = ''.join(random.choice(characters) for _ in range(length))

    return password


# -----------------------------------
# Main Program
# -----------------------------------
print("========== PASSWORD STRENGTH ANALYZER ==========")

password = input("Enter your password: ")

strength, feedback = analyze_password(password)

print("\nPassword Strength:", strength)

if feedback:
    print("\nSuggestions:")
    for item in feedback:
        print("-", item)

# Suggest stronger password if needed
if strength in ["Weak", "Medium"]:
    print("\nSuggested Strong Password:")
    print(generate_strong_password())

# Save password if strong enough
if strength in ["Strong", "Very Strong"]:
    save_password(password)
    print("\nPassword saved securely.")