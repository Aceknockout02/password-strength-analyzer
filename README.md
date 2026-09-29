# password-strength-analyzer
For my Thiranex Project.
"""
Password Strength Analyzer
Checks length, complexity and uniqueness, suggests a stronger password,
and (optionally) blocks reuse of old passwords using SQLite + SHA-256 hashing.
"""

import getpass
import hashlib
import secrets
import sqlite3
import string

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "admin", "welcome", "iloveyou", "password1", "111111", "monkey",
}

DB_FILE = "passwords.db"


# ---------- Database (stores only hashes, never plain passwords) ----------
def init_db():
    con = sqlite3.connect(DB_FILE)
    con.execute("CREATE TABLE IF NOT EXISTS old_passwords (hash TEXT PRIMARY KEY)")
    con.commit()
    return con


def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def is_reused(con, password):
    row = con.execute("SELECT 1 FROM old_passwords WHERE hash = ?", (hash_pw(password),))
    return row.fetchone() is not None


def save_password(con, password):
    con.execute("INSERT OR IGNORE INTO old_passwords VALUES (?)", (hash_pw(password),))
    con.commit()


# ---------- Analysis ----------
def analyze(password):
    score, tips = 0, []

    # Length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        tips.append("Use 12+ characters.")
    else:
        tips.append("Too short - use at least 8 (ideally 12+) characters.")

    # Complexity
    checks = [
        (any(c.islower() for c in password), "Add lowercase letters."),
        (any(c.isupper() for c in password), "Add uppercase letters."),
        (any(c.isdigit() for c in password), "Add numbers."),
        (any(c in string.punctuation for c in password), "Add symbols (!@#$...)."),
    ]
    for passed, tip in checks:
        if passed:
            score += 1
        else:
            tips.append(tip)

    # Uniqueness
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        tips.append("This is a very common password - avoid it!")
    if len(set(password)) < len(password) / 2:
        score -= 1
        tips.append("Too many repeated characters.")

    score = max(0, min(score, 6))
    label = ["Very Weak", "Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"][score]
    return score, label, tips


def suggest_password(length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pw = "".join(secrets.choice(chars) for _ in range(length))
        if analyze(pw)[0] == 6:
            return pw


# ---------- Main ----------
def main():
    con = init_db()
    print("=== Password Strength Analyzer ===")
    password = getpass.getpass("Enter a password to check: ")

    score, label, tips = analyze(password)
    print(f"\nStrength: {label} ({score}/6)")

    if is_reused(con, password):
        print("Warning: you have used this password before!")
        score = 0

    for tip in tips:
        print(" -", tip)

    if score < 5:
        print("\nSuggested stronger password:", suggest_password())
    else:
        save_password(con, password)
        print("\nGreat password! (hash saved to prevent future reuse)")


if __name__ == "__main__":
    main()
